#!/usr/bin/env node
// Blackbaud (myschoolapp) gradebook fetcher. Runs on the Mac under launchd.
//
// It drives a dedicated, already-signed-in Chrome profile over the DevTools protocol,
// calls the same JSON endpoints the parent portal uses, encrypts the result with the
// site password, and pushes blackbaud.enc to the repo. The Google password is never
// stored: if Blackbaud's session lapses, "Sign in with Google" completes from the
// profile's saved Google session; if Google wants a real sign-in, we send an alert.
//
// Config: ~/.config/homework-hq/bb.env  (BB_HOST, BB_STUDENT_ID, BB_EMAIL, PAGE_PASSWORD, NTFY_TOPIC)
import { execFileSync, spawnSync } from "node:child_process";
import { createHash, webcrypto as wc } from "node:crypto";
import { existsSync, readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HOME = homedir();
const REPO = join(dirname(fileURLToPath(import.meta.url)), "..");
const CONF_DIR = join(HOME, ".config/homework-hq");
const STATE = join(CONF_DIR, "bb-state.json");
const GB_SNAPSHOT = join(CONF_DIR, "bb-gradebook.json");   // last full gradebook, for change detection
const GB_CHANGES = join(CONF_DIR, "bb-changes.json");      // append-only change log
const GB_DAILY = join(CONF_DIR, "gradebook-snapshots");    // one dated copy per day, kept as a record
const PROFILE = join(HOME, ".homework-hq-chrome");
const PORT = 9335;
const KDF_ITERATIONS = 600_000; // must match build.py / index.html
const HEARTBEAT_HOURS = 6;      // push at least this often so the site can show "checked X ago"

const env = Object.fromEntries(readFileSync(join(CONF_DIR, "bb.env"), "utf8").split("\n")
  .filter((l) => l.includes("=") && !l.trim().startsWith("#"))
  .map((l) => { const i = l.indexOf("="); return [l.slice(0, i).trim(), l.slice(i + 1).trim().replace(/^["']|["']$/g, "")]; }));
const BASE = `https://${env.BB_HOST}`;
const SID = env.BB_STUDENT_ID;
const state = existsSync(STATE) ? JSON.parse(readFileSync(STATE, "utf8")) : {};
const saveState = () => { mkdirSync(CONF_DIR, { recursive: true }); writeFileSync(STATE, JSON.stringify(state, null, 2)); };
const log = (...a) => console.log(new Date().toISOString(), ...a);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function notify(title, body, key) {
  if (!env.NTFY_TOPIC) return;
  if (key && state[key] && Date.now() - state[key] < 12 * 3600e3) return; // at most every 12h
  await fetch(`https://ntfy.sh/${env.NTFY_TOPIC}`, { method: "POST", body, headers: { Title: title, Tags: "warning" } }).catch(() => {});
  if (key) { state[key] = Date.now(); saveState(); }
}

/* ---------------- Chrome / CDP ---------------- */
async function targets() {
  const r = await fetch(`http://127.0.0.1:${PORT}/json`).catch(() => null);
  return r?.ok ? r.json() : null;
}

async function ensureChrome() {
  if (await targets()) return;
  log("starting Chrome");
  spawnSync("open", ["-gna", "Google Chrome", "--args", `--user-data-dir=${PROFILE}`, `--remote-debugging-port=${PORT}`,
    "--no-first-run", "--no-default-browser-check", `${BASE}/app?svcid=edu`]);
  for (let i = 0; i < 30 && !(await targets()); i++) await sleep(1000);
  if (!(await targets())) throw new Error("Chrome did not start");
  await sleep(5000);
}

const pages = async () => ((await targets()) || []).filter((t) => t.type === "page");
const closeTarget = (t) => fetch(`http://127.0.0.1:${PORT}/json/close/${t.id}`).catch(() => {});

async function portalPage() {
  const all = await pages();
  let t = all.find((t) => t.url.includes(env.BB_HOST) && !t.url.includes("#login")) || all.find((t) => t.url.includes(env.BB_HOST));
  if (!t) {
    const r = await fetch(`http://127.0.0.1:${PORT}/json/new?${encodeURIComponent(`${BASE}/app?svcid=edu`)}`, { method: "PUT" });
    t = await r.json();
    await sleep(6000);
  }
  return cdp(t.webSocketDebuggerUrl);
}

function cdp(wsUrl) {
  const ws = new WebSocket(wsUrl);
  let id = 0;
  const pending = new Map();
  ws.onmessage = (m) => { const d = JSON.parse(m.data); if (d.id && pending.has(d.id)) { pending.get(d.id)(d); pending.delete(d.id); } };
  const ready = new Promise((res, rej) => { ws.onopen = res; ws.onerror = rej; });
  const send = async (method, params = {}) => {
    await ready;
    const n = ++id;
    ws.send(JSON.stringify({ id: n, method, params }));
    // Never wait forever: a navigating or frozen tab can swallow a reply.
    const d = await Promise.race([
      new Promise((res) => pending.set(n, res)),
      sleep(30000).then(() => { pending.delete(n); throw new Error(`${method}: timed out`); }),
    ]);
    if (d.error) throw new Error(`${method}: ${d.error.message}`);
    return d.result;
  };
  const evaluate = async (expr) => {
    const r = await send("Runtime.evaluate", { expression: expr, awaitPromise: true, returnByValue: true });
    if (r.exceptionDetails) throw new Error(r.exceptionDetails.exception?.description || "evaluate failed");
    return r.result.value;
  };
  return { send, evaluate, close: () => ws.close() };
}

/* ---------------- session ---------------- */
async function apiGet(page, path) {
  const res = await page.evaluate(`fetch(${JSON.stringify(path)}, {credentials: "include", headers: {Accept: "application/json"}})
    .then(async r => ({status: r.status, body: await r.text()}))`);
  if (res.status !== 200) throw Object.assign(new Error(`${path.split("?")[0]} -> ${res.status}`), { status: res.status });
  return JSON.parse(res.body);
}

async function signedIn(page) {
  try { return (await apiGet(page, "/api/webapp/context")).UserInfo?.UserId > 0; } catch { return false; }
}

// Real (trusted) mouse click: sign-in pages with invisible reCAPTCHA can ignore element.click().
async function clickWhere(page, finderJs) {
  const box = await page.evaluate(`(() => { const el = (${finderJs}); if (!el) return null;
    el.scrollIntoView({block: "center"}); const r = el.getBoundingClientRect(); return {x: r.x + r.width / 2, y: r.y + r.height / 2}; })()`).catch(() => null);
  if (!box) return false;
  for (const type of ["mouseMoved", "mousePressed", "mouseReleased"])
    await page.send("Input.dispatchMouseEvent", { type, x: box.x, y: box.y, button: "left", clickCount: 1 });
  return true;
}

// Run fn against one tab, then detach.
async function onTab(target, fn) {
  const c = cdp(target.webSocketDebuggerUrl);
  try { return await fn(c); } catch { return null; } finally { c.close(); }
}

// Re-login. The flow hops tabs and pages: portal email box -> Blackbaud ID hub ("Continue
// with Google") -> Google account chooser -> back to the portal. Watch every tab and push
// each step along; anything needing a password is left for a human.
async function login() {
  log("session expired; signing in through Google");
  for (const t of await pages())
    if (/app\.blackbaud\.com\/signin|accounts\.google\.com|#login/.test(t.url)) await closeTarget(t);
  await fetch(`http://127.0.0.1:${PORT}/json/new?${encodeURIComponent(`${BASE}/app?svcid=edu#login`)}`, { method: "PUT" });
  const deadline = Date.now() + 150_000;
  let emailSent = false, needHuman = false;
  while (Date.now() < deadline && !needHuman) {
    await sleep(3000);
    for (const t of await pages()) {
      if (t.url.includes("app.blackbaud.com/signin")) {
        await onTab(t, (p) => clickWhere(p, `[...document.querySelectorAll("button")].find(b => /continue with google/i.test(b.innerText))`));
        await sleep(3000);
      } else if (t.url.includes("accounts.google.com")) {
        needHuman = !!(await onTab(t, async (p) => {
          await clickWhere(p, `document.querySelector('[data-identifier=${JSON.stringify(env.BB_EMAIL)}]') ||
            [...document.querySelectorAll('[data-email]')].find(e => e.dataset.email === ${JSON.stringify(env.BB_EMAIL)})`);
          await sleep(3000);
          return p.evaluate(`!!document.querySelector('input[type=password]:not([aria-hidden=true])')`);
        }));
      } else if (t.url.includes(env.BB_HOST) && t.url.includes("#login") && !emailSent) {
        emailSent = !!(await onTab(t, (p) => p.evaluate(`(() => { const u = document.querySelector("#Username"); if (!u) return false;
          u.value = ${JSON.stringify(env.BB_EMAIL)}; u.dispatchEvent(new Event("input", {bubbles: true})); u.dispatchEvent(new Event("change", {bubbles: true}));
          document.querySelector("#nextBtn")?.click(); return true; })()`)));
      }
    }
    const portal = (await pages()).find((t) => t.url.includes(env.BB_HOST) && !t.url.includes("#login"));
    if (portal && (await onTab(portal, signedIn))) {
      for (const t of await pages()) if (t.id !== portal.id) await closeTarget(t); // tidy up
      log("signed in");
      return true;
    }
  }
  log(needHuman ? "Google is asking for a password" : "sign-in timed out");
  return false;
}

/* ---------------- data ---------------- */
const text = (h) => (h || "").replace(/<\/(div|p)>/gi, "\n").replace(/<[^>]+>/g, " ").replace(/&nbsp;|&#160;/g, " ")
  .replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&#39;/g, "'")
  .replace(/[ \t]+/g, " ").replace(/\s*\n\s*/g, "\n").trim();
const isoLocal = (s) => { // "9/25/2026 3:00 AM" (school-local) -> "2026-09-25T03:00"
  const m = /^(\d+)\/(\d+)\/(\d{4})(?: (\d+):(\d+) (AM|PM))?/.exec(s || ""); if (!m) return null;
  let h = +(m[4] || 0); if (m[6] === "PM" && h < 12) h += 12; if (m[6] === "AM" && h === 12) h = 0;
  return `${m[3]}-${m[1].padStart(2, "0")}-${m[2].padStart(2, "0")}T${String(h).padStart(2, "0")}:${m[5] || "00"}`;
};

function schoolYearLabel(d = new Date()) {
  const y = d.getMonth() >= 6 ? d.getFullYear() : d.getFullYear() - 1; // school year flips in July
  return `${y} - ${y + 1}`;
}

async function collect(page) {
  const Y = encodeURIComponent(schoolYearLabel());
  const terms = await apiGet(page, `/api/DataDirect/StudentGroupTermList/?studentUserId=${SID}&schoolYearLabel=${Y}&personaId=1`);
  // Every duration of the year (semesters + full year), so finished quarters stay reachable
  // after the semester changes over.
  const durations = terms.map((t) => t.DurationId);
  const groupsFor = (mp) => apiGet(page, `/api/datadirect/ParentStudentUserAcademicGroupsGet?userId=${SID}&schoolYearLabel=${Y}&memberLevel=3&persona=1&durationList=${durations.join(",")}&markingPeriodId=${mp}`);
  const isClass = (g) => !/^(lunch|homeroom)\b/i.test(g.sectionidentifier || "");
  const groups = (await groupsFor("")).filter(isClass);
  const clean = (s) => s.replace(/\s*-\s*\d+\s*\(.*\)$/, "").replace(/\s*-\s*PLTW$/, "");

  // Marking periods per duration. Asking with a blank marking period only works while the
  // current quarter has grades; on the first day of a quarter it returns nothing, so always
  // ask for each quarter by id.
  const markingPeriods = [];
  for (const t of terms) {
    const lead = groups.filter((g) => g.DurationId === t.DurationId).map((g) => ({ LeadSectionId: g.leadsectionid }));
    if (!lead.length) continue;
    try {
      const ds = encodeURIComponent(JSON.stringify([{ DurationId: t.DurationId, LeadSectionList: lead }]));
      for (const m of await apiGet(page, `/api/gradebook/GradeBookMyDayMarkingPeriods?durationSectionList=${ds}&userId=${SID}&personaId=1`))
        if (!markingPeriods.some((x) => x.id === m.MarkingPeriodId))
          markingPeriods.push({ id: m.MarkingPeriodId, title: m.MarkingPeriodDescription, current: !!m.CurrentMarkingPeriod, duration: t.DurationDescription, durationId: t.DurationId });
    } catch (e) { log("marking periods:", e.message); }
  }
  markingPeriods.sort((a, b) => a.id - b.id);
  const cur = markingPeriods.find((m) => m.current) || markingPeriods.at(-1) || null;
  const quarter = cur ? { id: cur.id, title: cur.title } : null;

  // Report card: each quarter up to the current one, graded by course name (sections change
  // between semesters, course names don't).
  const report = [];
  const byMp = {};
  const rowCache = {};
  const rowsFor = async (mp, sec) => (rowCache[`${mp}|${sec}`] ??= await apiGet(page,
    `/api/gradebook/AssignmentPerformanceStudent?sectionId=${sec}&markingPeriodId=${mp}&studentId=${SID}`).catch((e) => { log("gradebook:", e.message); return null; }));
  for (const m of markingPeriods) {
    if (cur && m.id > cur.id) break;
    const rows = (await groupsFor(m.id)).filter(isClass);
    byMp[m.id] = rows;
    report.push({ id: m.id, title: m.title, current: m.id === cur?.id,
      grades: rows.filter((g) => g.markingperiodid === m.id).map((g) => ({ course: clean(g.sectionidentifier), grade: g.cumgrade != null ? +g.cumgrade : null })) });
  }

  // Live detail for the current quarter: every class, even before any grade is posted.
  const sections = [];
  // Only this semester's sections (plus any full-year ones); next semester's are listed too.
  const fullYear = terms.filter((t) => t.OfferingType === 3).map((t) => t.DurationId);
  const inTerm = (g) => !cur || g.DurationId === cur.durationId || fullYear.includes(g.DurationId);
  const curRows = (cur ? byMp[cur.id] || [] : groups).filter(inTerm);
  for (const g of curRows) {
    const rows = (cur ? await rowsFor(cur.id, g.sectionid) : null) || [];
    const categories = {};
    for (const r of rows) categories[r.AssignmentType] ??= { name: r.AssignmentType, avg: parseFloat(r.Percentage) || null, weight: r.Weight ?? null, n: 0 };
    rows.forEach((r) => categories[r.AssignmentType].n++);
    sections.push({
      id: g.sectionid,
      name: clean(g.sectionidentifier),
      period: (/\((.*)\)$/.exec(g.sectionidentifier) || [])[1] || "",
      teacher: g.groupownername, email: g.groupowneremail, room: g.room,
      grade: g.cumgrade != null && g.markingperiodid === cur?.id ? +g.cumgrade : null,
      total: rows[0] ? { points: rows[0].TotalPoints, max: rows[0].TotalMaxPoints } : null,
      categories: Object.values(categories),
      assignments: rows.map((r) => ({
        id: r.AssignmentId, name: text(r.AssignmentShortDescription), type: r.AssignmentType,
        assigned: isoLocal(r.DateAssigned), due: isoLocal(r.DateDue),
        points: r.Points == null || r.Points === "" ? null : +r.Points, max: r.MaxPoints,
        pct: r.AssignmentPercentage, missing: !!r.Missing, late: !!r.Late, exempt: !!r.Exempt,
        incomplete: !!r.Incomplete, extra: !!r.ExtraCredit, counts: r.IncludeCumulativeGrade !== false,
        comment: text(r.Comment),
      })),
    });
  }

  const absences = [];
  try {
    const cats = await apiGet(page, `/api/datadirect/ParentStudentUserAttendance/?userId=${SID}&personaId=1&schoolYearLabel=${Y}`);
    for (const c of cats) {
      const recs = await apiGet(page, `/api/attendancestudent/ListRecordDetail?excuseCategoryId=${c.excuse_category_id}&userId=${SID}&schoolYear=${Y}`);
      for (const r of recs) absences.push({ category: r.ExcuseCategoryDescription, type: r.ExcuseDescription, comment: text(r.Comment),
        class: r.GroupName.replace(/\s*-\s*\d+\s*\(.*\)$/, ""), at: isoLocal(r.CalendarDate) });
    }
  } catch (e) { log("attendance:", e.message); }

  let conduct = null;
  try {
    const c = await apiGet(page, `/api/datadirect/ParentStudentUserConduct?studentUserId=${SID}&viewerPersonaId=1&levelNum=1424&schoolYearLabel=${Y}`);
    conduct = { infractions: c[0]?.infraction_total ?? 0 };
  } catch (e) { log("conduct:", e.message); }

  // Class schedule for today and the next school days (blocks, rooms, special days like PSAT).
  const schedule = {};
  for (let d = 0, found = 0; d < 7 && found < 3; d++) {
    const day = new Date(Date.now() + d * 864e5).toLocaleDateString("en-CA", { timeZone: "America/New_York" });
    try {
      const rows = await apiGet(page, `/api/schedule/MyDayCalendarStudentList/?userId=${SID}&scheduleDate=${day}&personaId=1&sharedView=true`);
      const blocks = rows.filter((r) => !r.CanceledInd).map((r) => ({
        title: r.CourseTitle.replace(/\s*-\s*\d+$/, ""), block: r.Block, start: r.MyDayStartTime, end: r.MyDayEndTime,
        room: [r.BuildingName, r.RoomNumber].filter(Boolean).join(" "), section: r.SectionId,
      }));
      if (blocks.length) { schedule[day] = blocks; found++; }
    } catch (e) { log("schedule:", e.message); }
  }

  // Full gradebook of every quarter so far (teachers keep editing finished quarters until
  // grades close), for change tracking. A section whose fetch failed is marked so its
  // assignments are not reported as removed.
  const gradebook = { taken_at: new Date().toISOString(), mps: [], titles: {}, rows: {}, grades: {}, failed: [] };
  for (const m of markingPeriods) {
    if (cur && m.id > cur.id) break;
    gradebook.mps.push(m.id);
    gradebook.titles[m.id] = m.title;
    for (const g of (byMp[m.id] || []).filter((g) => g.markingperiodid === m.id)) {
      const course = clean(g.sectionidentifier);
      if (g.cumgrade != null) gradebook.grades[`${m.id}|${course}`] = +g.cumgrade;
      const rows = await rowsFor(m.id, g.sectionid);
      if (!rows) { gradebook.failed.push(`${m.id}|${g.sectionid}`); continue; }
      for (const r of rows) gradebook.rows[`${m.id}|${g.sectionid}|${r.AssignmentId ?? r.AssignmentIndexId}`] = {
        mp: m.id, quarter: m.title, course, id: r.AssignmentId ?? r.AssignmentIndexId, name: text(r.AssignmentShortDescription),
        type: r.AssignmentType, due: isoLocal(r.DateDue)?.slice(0, 10) || null,
        points: r.Points == null || r.Points === "" ? null : +r.Points, max: r.MaxPoints, missing: !!r.Missing, late: !!r.Late,
        exempt: !!r.Exempt, counts: r.IncludeCumulativeGrade !== false, extra: !!r.ExtraCredit, comment: text(r.Comment),
      };
    }
  }

  return { quarter, markingPeriods, report, sections, absences, conduct, schedule, gradebook, curMp: cur?.id ?? null };
}

/* ---------------- gradebook change tracking ---------------- */
const readJson = (f, dflt) => { try { return JSON.parse(readFileSync(f, "utf8")); } catch { return dflt; } };
const pts = (r) => r.points == null ? "no score" : `${r.points}/${r.max}`;

// Compare two gradebook snapshots. Only quarters (and sections) present and fetched in both
// are compared, so a new quarter or a failed fetch is a silent baseline, never "removed".
function diffGradebook(prev, next, curMp, removedLog) {
  const ev = [];
  const window = { since: prev.taken_at, at: next.taken_at };
  const comparable = (k) => { const [mp, sec] = k.split("|"); return prev.mps.includes(+mp) && next.mps.includes(+mp)
    && !(prev.failed || []).includes(`${mp}|${sec}`) && !next.failed.includes(`${mp}|${sec}`); };
  const add = (e) => ev.push({ ...window, pastQuarter: e.mp !== curMp, ...e });
  const byId = (rows) => { const m = {}; for (const [k, r] of Object.entries(rows)) (m[r.id] ??= []).push(k); return m; };
  const nextIds = byId(next.rows), prevIds = byId(prev.rows);

  for (const [k, r] of Object.entries(prev.rows)) {
    if (next.rows[k] || !comparable(k)) continue;
    const elsewhere = (nextIds[r.id] || []).map((x) => next.rows[x]).find((x) => x.mp !== r.mp);
    if (elsewhere) add({ kind: "moved", flag: true, mp: r.mp, quarter: r.quarter, course: r.course, name: r.name,
      detail: `moved from ${r.quarter} to ${elsewhere.quarter} (${pts(r)})` });
    else {
      add({ kind: "removed", flag: true, mp: r.mp, quarter: r.quarter, course: r.course, name: r.name,
        detail: `removed from ${r.quarter} (was ${pts(r)}, ${r.type}, due ${r.due})` });
      removedLog[r.id] = { quarter: r.quarter, at: next.taken_at };
    }
  }
  for (const [k, r] of Object.entries(next.rows)) {
    const o = prev.rows[k];
    if (!o) {
      if (!comparable(k) || (prevIds[r.id] || []).some((x) => prev.rows[x].mp !== r.mp && !next.rows[x])) continue; // moved: reported above
      const back = removedLog[r.id];
      if (back) { delete removedLog[r.id]; add({ kind: "moved", flag: true, mp: r.mp, quarter: r.quarter, course: r.course, name: r.name,
        detail: `added to ${r.quarter} (${pts(r)}); it was removed from ${back.quarter} on ${back.at.slice(0, 10)}` }); }
      else add({ kind: "added", flag: r.mp !== curMp, mp: r.mp, quarter: r.quarter, course: r.course, name: r.name,
        detail: `new in ${r.quarter}: ${pts(r)}${r.missing ? ", marked missing" : ""}` });
      continue;
    }
    const d = [];
    let flag = r.mp !== curMp;
    if (o.points !== r.points) { d.push(`score ${pts(o)} → ${pts(r)}`); if (o.points != null && (r.points == null || r.points < o.points)) flag = true; }
    else if (o.max !== r.max) { d.push(`out of ${o.max} → ${r.max}`); flag = true; }
    if (o.missing !== r.missing) { d.push(r.missing ? "marked missing" : "no longer missing"); if (r.missing) flag = true; }
    if (o.exempt !== r.exempt) { d.push(r.exempt ? "exempted" : "no longer exempt"); flag = true; }
    if (o.counts !== r.counts) { d.push(r.counts ? "now counts toward the grade" : "no longer counts toward the grade"); flag = true; }
    if (o.late !== r.late) d.push(r.late ? "marked late" : "no longer late");
    if (o.type !== r.type) { d.push(`category ${o.type} → ${r.type}`); flag = true; }
    if (o.name !== r.name) d.push(`renamed from "${o.name}"`);
    if (o.comment !== r.comment && r.comment) d.push(`teacher comment: "${r.comment.slice(0, 160)}"`);
    if (d.length) add({ kind: "changed", flag, mp: r.mp, quarter: r.quarter, course: r.course, name: r.name, detail: d.join("; ") });
  }
  for (const [k, g] of Object.entries(next.grades)) {
    const o = prev.grades[k] == null ? null : +prev.grades[k], [mp, course] = [+k.split("|")[0], k.split("|").slice(1).join("|")];
    if (o == null || !prev.mps.includes(mp) || Math.abs(o - g) < 0.005) continue;
    add({ kind: "grade", flag: mp !== curMp || g < o, mp, quarter: next.titles[mp] || "",
      course, name: "Quarter grade", from: o, to: g, detail: `${o.toFixed(2)}% → ${g.toFixed(2)}%` });
  }
  return ev;
}

async function trackGradebook(gb, curMp) {
  mkdirSync(GB_DAILY, { recursive: true });
  const day = new Date().toLocaleDateString("en-CA", { timeZone: "America/New_York" });
  writeFileSync(join(GB_DAILY, `${day}.json`), JSON.stringify(gb)); // latest of the day
  const prev = readJson(GB_SNAPSHOT, null);
  const log_ = readJson(GB_CHANGES, { events: [], removed: {} });
  const ev = prev ? diffGradebook(prev, gb, curMp, log_.removed) : [];
  writeFileSync(GB_SNAPSHOT, JSON.stringify(gb));
  if (ev.length) {
    log_.events.push(...ev);
    writeFileSync(GB_CHANGES, JSON.stringify(log_, null, 1));
    log(`gradebook changes: ${ev.length} (${ev.filter((e) => e.flag).length} flagged)`);
    const flagged = ev.filter((e) => e.flag);
    if (flagged.length) await notify(`Gradebook changed: ${[...new Set(flagged.map((e) => e.course))].join(", ")}`,
      flagged.slice(0, 8).map((e) => `${e.course} (${e.quarter.replace("Quarter ", "Q")}): ${e.name}: ${e.detail}`).join("\n").slice(0, 1500));
  }
  return log_.events.slice(-400);
}

/* ---------------- encrypt + publish ---------------- */
async function encrypt(obj, password) {
  const salt = wc.getRandomValues(new Uint8Array(16)), iv = wc.getRandomValues(new Uint8Array(12));
  const base = await wc.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveKey"]);
  const key = await wc.subtle.deriveKey({ name: "PBKDF2", hash: "SHA-256", salt, iterations: KDF_ITERATIONS }, base,
    { name: "AES-GCM", length: 256 }, false, ["encrypt"]);
  const ct = new Uint8Array(await wc.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(JSON.stringify(obj))));
  const b64 = (b) => Buffer.from(b).toString("base64");
  return JSON.stringify({ v: 1, iter: KDF_ITERATIONS, salt: b64(salt), iv: b64(iv), ct: b64(ct) });
}

const git = (...args) => execFileSync("git", ["-C", REPO, ...args], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });

async function publish(data) {
  const hash = createHash("sha256").update(JSON.stringify(data)).digest("hex");
  const stale = Date.now() - (state.lastPush || 0) > HEARTBEAT_HOURS * 3600e3;
  const changed = hash !== state.lastHash;
  if (!changed && !stale) { log("no change"); return false; }
  git("pull", "-q", "--rebase");
  writeFileSync(join(REPO, "blackbaud.enc"), await encrypt({ fetched_at: new Date().toISOString(), ...data }, env.PAGE_PASSWORD));
  git("add", "blackbaud.enc");
  git("commit", "-q", "-m", changed ? "blackbaud: update" : "blackbaud: heartbeat");
  git("push", "-q");
  Object.assign(state, { lastHash: hash, lastPush: Date.now() }); saveState();
  log(changed ? "pushed update" : "pushed heartbeat");
  return true;
}

// GitHub's cron drops runs, so the Mac kicks the site rebuild itself (also refreshes Canvas).
function dispatch(checkedAt) {
  const args = ["workflow", "run", "update.yml", "-R", env.GH_REPO || "eggheadengineer/homework-hq"];
  if (checkedAt) args.push("-f", `bb_checked=${checkedAt}`);
  const r = spawnSync("gh", args, { encoding: "utf8" });
  log(r.status === 0 ? "dispatched site rebuild" : `dispatch failed: ${(r.stderr || "").trim().slice(0, 200)}`);
}

async function main() {
  const hour = new Date().getHours();
  if (hour < 6 && !process.argv.includes("--now")) return; // quiet overnight (local time)
  await ensureChrome();
  let page = await portalPage();
  try {
    if (!(await signedIn(page))) {
      page.close();
      const ok = await login();
      page = await portalPage();
      if (!ok || !(await signedIn(page))) {
        log("LOGIN NEEDED");
        await notify("Homework HQ: Blackbaud sign-in needed",
          "Blackbaud logged out and Google wants a real sign-in. On the MacBook, open the Homework HQ Chrome window and sign in with Google.", "loginAlert");
        process.exitCode = 2;
        dispatch(null); // still refresh Canvas
        return;
      }
    }
    state.loginAlert = 0;
    const { gradebook, curMp, ...data } = await collect(page);
    data.changes = await trackGradebook(gradebook, curMp);
    log(`sections=${data.sections.length} assignments=${data.sections.reduce((n, s) => n + s.assignments.length, 0)} absences=${data.absences.length}`);
    const checkedAt = new Date().toISOString();
    if (!(await publish(data))) dispatch(checkedAt); // a push already triggers a rebuild
  } finally { page.close(); }
}

// Hard stop so a stuck run can never block the next launchd run.
setTimeout(() => { log("ERROR run exceeded 4 minutes; exiting"); process.exit(3); }, 240_000).unref();

main().catch(async (e) => {
  log("ERROR", e.message);
  await notify("Homework HQ: Blackbaud fetch failing", e.message.slice(0, 200), "errorAlert");
  process.exitCode = 1;
});
