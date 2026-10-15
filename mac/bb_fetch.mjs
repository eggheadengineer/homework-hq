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
  const current = terms.filter((t) => t.CurrentInd === 1).map((t) => t.DurationId);
  const groups = await apiGet(page, `/api/datadirect/ParentStudentUserAcademicGroupsGet?userId=${SID}&schoolYearLabel=${Y}&memberLevel=3&persona=1&durationList=${current.join(",")}&markingPeriodId=`);
  const graded = groups.filter((g) => g.markingperiodid);

  let quarter = null;
  try {
    const ds = encodeURIComponent(JSON.stringify(terms.filter((t) => current.includes(t.DurationId)).map((t) => ({
      DurationId: t.DurationId, LeadSectionList: graded.filter((g) => g.DurationId === t.DurationId).map((g) => ({ LeadSectionId: g.leadsectionid })),
    })).filter((d) => d.LeadSectionList.length)));
    const mps = await apiGet(page, `/api/gradebook/GradeBookMyDayMarkingPeriods?durationSectionList=${ds}&userId=${SID}&personaId=1`);
    const mp = mps.find((m) => m.CurrentMarkingPeriod);
    if (mp) quarter = { id: mp.MarkingPeriodId, title: mp.MarkingPeriodDescription };
  } catch (e) { log("marking periods:", e.message); }

  const sections = [];
  for (const g of graded) {
    const rows = await apiGet(page, `/api/gradebook/AssignmentPerformanceStudent?sectionId=${g.sectionid}&markingPeriodId=${g.markingperiodid}&studentId=${SID}`);
    const categories = {};
    for (const r of rows) categories[r.AssignmentType] ??= { name: r.AssignmentType, avg: parseFloat(r.Percentage) || null, weight: r.Weight ?? null, n: 0 };
    rows.forEach((r) => categories[r.AssignmentType].n++);
    sections.push({
      id: g.sectionid,
      name: g.sectionidentifier.replace(/\s*-\s*\d+\s*\(.*\)$/, "").replace(/\s*-\s*PLTW$/, ""),
      period: (/\((.*)\)$/.exec(g.sectionidentifier) || [])[1] || "",
      teacher: g.groupownername, email: g.groupowneremail, room: g.room,
      grade: g.cumgrade != null ? +g.cumgrade : null,
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

  return { quarter, sections, absences, conduct, schedule };
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
    const data = await collect(page);
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
