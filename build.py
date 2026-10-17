#!/usr/bin/env python3
"""Pull the student's Canvas data, decide what matters, and write an encrypted site/data.enc.

Runs in GitHub Actions on a schedule (see .github/workflows/update.yml) or locally
with a .env file. Needs CANVAS_BASE_URL, CANVAS_TOKEN, PAGE_PASSWORD; NTFY_TOPIC is
optional (push alerts for newly missing work and new grades).

Nothing but counts is printed, because Actions logs on a public repo are public.
"""
import base64
import html
import json
import os
import re
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from dateutil.parser import isoparse

HERE = Path(__file__).resolve().parent
SITE = HERE / "site"
HISTORY = HERE / "history.enc"
LOCAL_TZ = ZoneInfo("America/New_York")
KDF_ITERATIONS = 600_000  # must match index.html
LOW_SCORE = 70.0
# Submission types where "unsubmitted" means nothing: the work is handed in on paper/in class.
OFFLINE_TYPES = {"none", "on_paper", "not_graded", "wiki_page", "external_tool"}
ASSESSMENT = re.compile(r"\b(test|quiz|exam|midterm|final|assessment)\b", re.I)
# Work that exists to win points back: corrections, retakes, late-work folders, extra credit.
RECOVERY = re.compile(r"correction|retake|re-take|redo|late work|extra credit|make[- ]?up|test fix", re.I)


# ---------------------------------------------------------------- config / crypto
def load_env() -> None:
    env = HERE / ".env"
    if env.exists():
        for line in env.read_text().splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip().strip("'\""))


def _key(password: str, salt: bytes) -> bytes:
    return PBKDF2HMAC(hashes.SHA256(), 32, salt, KDF_ITERATIONS).derive(password.encode())


def encrypt(obj, password: str) -> str:
    salt, iv = secrets.token_bytes(16), secrets.token_bytes(12)
    ct = AESGCM(_key(password, salt)).encrypt(iv, json.dumps(obj, separators=(",", ":")).encode(), None)
    b64 = lambda b: base64.b64encode(b).decode()
    return json.dumps({"v": 1, "iter": KDF_ITERATIONS, "salt": b64(salt), "iv": b64(iv), "ct": b64(ct)})


def decrypt(blob: str, password: str):
    d = json.loads(blob)
    raw = lambda k: base64.b64decode(d[k])
    return json.loads(AESGCM(_key(password, raw("salt"))).decrypt(raw("iv"), raw("ct"), None))


# ---------------------------------------------------------------- canvas
class Canvas:
    def __init__(self, base: str, token: str):
        self.base = base.rstrip("/")
        self.s = requests.Session()
        self.s.headers.update({"Authorization": f"Bearer {token}", "Accept": "application/json"})

    def get(self, path, params=None):
        url, params, out = f"{self.base}{path}", {"per_page": 100, **(params or {})}, []
        while url:
            r = self.s.get(url, params=params, timeout=30)
            if r.status_code == 401:
                raise SystemExit("Canvas token rejected (expired or revoked). Make a new one and update the CANVAS_TOKEN secret.")
            r.raise_for_status()
            data = r.json()
            out.extend(data if isinstance(data, list) else [data])
            url, params = r.links.get("next", {}).get("url"), None
        return out


def dt(s):
    try:
        return isoparse(s).astimezone(timezone.utc) if s else None
    except (ValueError, TypeError):
        return None


def iso(d):
    return d.isoformat(timespec="seconds") if d else None


def strip_html(s, limit=600):
    text = html.unescape(re.sub(r"<[^>]+>", " ", s or ""))
    text = re.sub(r"\s+", " ", text).strip()
    return text if len(text) <= limit else text[:limit].rsplit(" ", 1)[0] + "…"


def course_label(name: str):
    """'Algebra II- Zetwick' -> ('Algebra II', 'Zetwick')."""
    name = name.strip()
    m = re.match(r"(.+?)\s*-\s*([A-Z][\w'’]+)$", name)
    return (m.group(1).strip(), m.group(2)) if m else (name, "")


TOOLS = {"quiz-lti": "Canvas Quizzes", "noredink": "NoRedInk", "assignments.google.com": "Google Assignments", "edpuzzle": "Edpuzzle", "pltw": "PLTW",
         "wayground": "Wayground", "quizizz": "Wayground", "vhlcentral": "VHL Central", "ck12": "CK-12"}


def tool_name(a):
    """Name of the outside site an external-tool assignment opens, if any."""
    if "external_tool" not in (a.get("submission_types") or []):
        return None
    url = ((a.get("external_tool_tag_attributes") or {}).get("url") or "").lower()
    return next((v for k, v in TOOLS.items() if k in url), "an outside tool")


def classify(a, sub, now):
    if sub.get("excused"):
        return "excused"
    if sub.get("missing"):
        return "missing"
    if sub.get("score") is not None:
        return "graded"
    if sub.get("workflow_state") in ("submitted", "pending_review"):
        return "submitted"
    if a.get("grading_type") == "not_graded":
        return "ungraded"
    due = dt(a.get("due_at"))
    if not due:
        return "no_date"
    if due < now:
        return "past_offline" if set(a.get("submission_types") or []) <= OFFLINE_TYPES else "overdue"
    return "upcoming"


def pct(earned, possible):
    return round(100 * earned / possible, 1) if possible else None


# ---------------------------------------------------------------- build
def build(cv: Canvas, now: datetime):
    raw_courses = cv.get("/api/v1/courses", {"enrollment_state": "active", "include[]": ["teachers"]})

    periods = []
    for c in raw_courses:
        try:
            periods = [g for page in cv.get(f"/api/v1/courses/{c['id']}/grading_periods") for g in page.get("grading_periods", [])]
        except requests.HTTPError:
            continue
        if periods:
            break
    periods = [{"title": g["title"], "start": dt(g["start_date"]), "end": dt(g["end_date"])} for g in periods]
    quarter = next((g for g in periods if g["start"] <= now <= g["end"]), None)
    year_start = min((g["start"] for g in periods), default=now - timedelta(days=60))

    planner = {}
    for p in cv.get("/api/v1/planner/items", {"start_date": iso(now - timedelta(days=21)), "end_date": iso(now + timedelta(days=21))}):
        planner[(p.get("plannable_type"), p.get("plannable_id"))] = p

    courses, items, feedback = [], [], []
    for c in raw_courses:
        cid = c["id"]
        name, teacher = course_label(c.get("name") or f"Course {cid}")
        teachers = [t.get("display_name") for t in c.get("teachers") or [] if "Chair" not in (t.get("display_name") or "")]
        groups = {g["id"]: g["name"] for g in cv.get(f"/api/v1/courses/{cid}/assignment_groups")}
        assignments = cv.get(f"/api/v1/courses/{cid}/assignments", {"include[]": ["submission"], "order_by": "due_at"})
        comments = {s["assignment_id"]: s.get("submission_comments") or []
                    for s in cv.get(f"/api/v1/courses/{cid}/students/submissions",
                                    {"student_ids[]": "self", "include[]": ["submission_comments"]})}

        course_items = []
        for a in assignments:
            due = dt(a.get("due_at"))
            if due and due < year_start:
                continue
            sub = a.get("submission") or {}
            status = classify(a, sub, now)
            pl = (planner.get(("assignment", a["id"])) or {}).get("submissions") or {}
            group = groups.get(a.get("assignment_group_id"), "")
            teacher_comments = [
                {"who": cm.get("author_name"), "at": cm.get("created_at"), "text": cm.get("comment", "").strip(),
                 "from_teacher": cm.get("author_id") != sub.get("user_id")}
                for cm in comments.get(a["id"], []) if cm.get("comment")
            ]
            item = {
                "id": a["id"], "course_id": cid, "course": name, "name": a.get("name"),
                "due": iso(due), "points": a.get("points_possible"), "score": sub.get("score"),
                "pct": pct(sub["score"], a["points_possible"]) if sub.get("score") is not None and a.get("points_possible") else None,
                "status": status, "late": bool(sub.get("late")),
                "offline": set(a.get("submission_types") or []) <= OFFLINE_TYPES,
                "assessment": bool(ASSESSMENT.search(f"{a.get('name')} {group}")) and not RECOVERY.search(a.get("name") or ""),
                "recovery": bool(RECOVERY.search(a.get("name") or "")) or bool(pl.get("redo_request")),
                "group": group, "graded_at": sub.get("graded_at"), "submitted_at": sub.get("submitted_at"),
                "redo": bool(pl.get("redo_request")), "url": a.get("html_url"),
                "tool": tool_name(a),
                "desc": strip_html(a.get("description")), "comments": teacher_comments,
                "counts": not a.get("omit_from_final_grade") and bool(a.get("points_possible")) and not sub.get("excused"),
                "in_quarter": bool(quarter and due and quarter["start"] <= due <= quarter["end"]),
            }
            course_items.append(item)
            for cm in teacher_comments:
                feedback.append({**cm, "course": name, "assignment": item["name"], "url": item["url"], "assignment_id": a["id"]})

        q_items = [i for i in course_items if i["in_quarter"]] if quarter else course_items
        graded = [i for i in q_items if i["counts"] and i["score"] is not None]
        earned, possible = sum(i["score"] for i in graded), sum(i["points"] for i in graded)

        # Running quarter average in the order grades were entered -> trend line.
        trend, e, p = [], 0.0, 0.0
        for i in sorted(graded, key=lambda i: i["graded_at"] or i["due"] or ""):
            e, p = e + i["score"], p + i["points"]
            trend.append({"at": i["graded_at"] or i["due"], "pct": pct(e, p), "name": i["name"], "score_pct": i["pct"]})

        # What-if: the grade if each missing item were turned in for full credit.
        for i in q_items:
            if i["status"] in ("missing", "overdue") and i["counts"] and possible:
                score = i["score"] or 0
                in_avg = i["score"] is not None
                new_e = earned - score + i["points"]
                new_p = possible if in_avg else possible + i["points"]
                i["if_done"] = pct(new_e, new_p)

        courses.append({
            "id": cid, "name": name, "teacher": teacher or (teachers[0] if teachers else ""),
            "url": f"{cv.base}/courses/{cid}", "pct": pct(earned, possible), "earned": earned, "possible": possible,
            "graded": len(graded), "missing": sum(i["status"] in ("missing", "overdue") for i in q_items),
            "low": sum(1 for i in graded if i["pct"] is not None and i["pct"] < LOW_SCORE), "trend": trend,
        })
        items.extend(course_items)

    me = cv.get("/api/v1/users/self")[0]["id"]
    inbox = []
    for m in cv.get("/api/v1/conversations", {"per_page": 20}):
        when = dt(m.get("last_message_at"))
        if when and when > now - timedelta(days=45):
            inbox.append({"at": iso(when), "subject": m.get("subject"), "preview": strip_html(m.get("last_message"), 200),
                          "with": [p.get("name") for p in m.get("participants", []) if p.get("id") != me],
                          "unread": m.get("workflow_state") == "unread"})

    names = {c["id"]: course_label(c.get("name") or "")[0] for c in raw_courses}
    announcements, unseen_feedback = [], 0
    for s in cv.get("/api/v1/users/self/activity_stream", {"only_active_courses": True, "per_page": 100}):
        when = dt(s.get("created_at"))
        if s.get("type") == "Submission" and not s.get("read_state"):
            unseen_feedback += 1
        if s.get("type") != "Announcement" or not when or when < now - timedelta(days=21):
            continue
        announcements.append({"at": iso(when), "title": s.get("title"), "text": strip_html(s.get("message"), 900),
                              "course": names.get(s.get("course_id"), "School"), "unread": not s.get("read_state"),
                              "url": s.get("html_url")})

    feedback.sort(key=lambda f: f["at"] or "", reverse=True)
    return {
        "generated_at": iso(now),
        "quarter": {"title": quarter["title"], "start": iso(quarter["start"]), "end": iso(quarter["end"])} if quarter else None,
        "next_quarter": next(({"title": g["title"], "start": iso(g["start"])} for g in periods if g["start"] > now), None),
        "courses": sorted(courses, key=lambda c: (c["pct"] is None, c["pct"] or 0)),
        "items": items, "feedback": feedback[:60], "inbox": inbox,
        "announcements": sorted(announcements, key=lambda a: a["at"], reverse=True), "unseen_feedback": unseen_feedback,
    }


# ---------------------------------------------------------------- Blackbaud (official gradebook)
BLACKBAUD = HERE / "blackbaud.enc"


def norm(s):
    return re.sub(r"[^a-z0-9 ]", "", (s or "").lower().replace("&", "and")).strip()


def same_course(a, b):
    a, b = norm(a), norm(b)
    return bool(a and b) and (a == b or a.startswith(b) or b.startswith(a))


def same_assignment(a, b):
    a, b = norm(a), norm(b)
    if not a or not b:
        return False
    if a == b or (min(len(a), len(b)) >= 8 and (a in b or b in a)):
        return True
    ta, tb = set(a.split()), set(b.split())
    return len(ta & tb) / len(ta | tb) >= 0.6


def section_grade(section, override=None):
    """Blackbaud's grade math: category-weighted if the class has weights, else total points.
    `override` = (assignment_id, points) to answer "what if this were turned in?"."""
    cats = {}
    for a in section["assignments"]:
        pts = override[1] if override and a["id"] == override[0] else a["points"]
        if not a["counts"] or a["exempt"] or pts is None:
            continue
        c = cats.setdefault(a["type"], [0.0, 0.0])
        c[0] += pts
        c[1] += 0 if a["extra"] else a["max"]
    weights = {c["name"]: c.get("weight") for c in section["categories"]}
    if any(w is not None for w in weights.values()):
        used = [(weights.get(k) or 0, e / m) for k, (e, m) in cats.items() if m and (weights.get(k) or 0) > 0]
        total_w = sum(w for w, _ in used)
        return round(100 * sum(w * r for w, r in used) / total_w, 2) if total_w else None
    e, m = sum(v[0] for v in cats.values()), sum(v[1] for v in cats.values())
    return round(100 * e / m, 2) if m else None


def merge_official(data, bb):
    """Attach Blackbaud grades to Canvas courses and build one missing-work list from both."""
    data["official"] = {k: bb.get(k) for k in ("fetched_at", "quarter", "absences", "conduct", "schedule")}
    # The Mac only pushes blackbaud.enc when grades change; it passes its latest check time on dispatch.
    data["official"]["checked_at"] = max(filter(None, [bb.get("fetched_at"), os.environ.get("BB_CHECKED")]), default=None)
    sections = bb.get("sections") or []
    for c in data["courses"]:
        sec = next((s for s in sections if same_course(c["name"], s["name"])), None)
        c["official"] = sec
    data["unmatched_sections"] = [s for s in sections if not any(c.get("official") is s for c in data["courses"])]

    canvas_open = [i for i in data["items"] if i["status"] in ("missing", "overdue")]
    merged = []
    for i in canvas_open:
        course = next((c for c in data["courses"] if c["id"] == i["course_id"]), None)
        # A 0-point Canvas item can't move a grade; in classes graded in Blackbaud it's a
        # placeholder (e.g. Spanish quizzes taken in class and graded in the gradebook).
        if course and course.get("official") and not i.get("points"):
            continue
        merged.append({**i, "source": "canvas", "if_done": None if course and course.get("official") else i.get("if_done")})
    for s in sections:
        for a in s["assignments"]:
            if not a["missing"] or a["exempt"]:
                continue
            match = next((m for m in merged if same_course(m["course"], s["name"]) and same_assignment(m["name"], a["name"])), None)
            if_done = section_grade(s, (a["id"], a["max"])) if a.get("max") and a["counts"] else None
            if match:
                match["source"] = "both"
                match["if_done"] = if_done if if_done is not None else match.get("if_done")
                match["bb_comment"] = a["comment"]
            else:
                course = next((c for c in data["courses"] if c.get("official") is s), None)
                merged.append({
                    "id": f"bb{a['id']}", "course": course["name"] if course else s["name"],
                    "course_id": course["id"] if course else None, "name": a["name"],
                    "due": a["due"] + ":00" if a["due"] else None, "points": a["max"], "score": a["points"], "pct": a["pct"],
                    "status": "missing", "source": "gradebook", "if_done": if_done, "bb_comment": a["comment"],
                    "url": course["url"] if course else None, "comments": [], "desc": "", "offline": True,
                    "assessment": bool(ASSESSMENT.search(f"{a['name']} {a['type']}")), "recovery": False,
                })
    for m in merged:
        if m["source"] == "gradebook":
            twin = next((i for i in data["items"] if i["course_id"] == m["course_id"] and same_assignment(i["name"], m["name"])), None)
            if twin:
                m.update(url=twin["url"], canvas_id=twin["id"], tool=twin.get("tool"), desc=twin.get("desc", ""), linked=True)
    data["missing"] = merged
    for c in data["courses"]:
        sec = c.get("official")
        if not sec:
            continue
        fixes = [a for a in sec["assignments"] if a["missing"] and not a["exempt"] and a["counts"] and a.get("max")]
        if fixes:
            fixed = {**sec, "assignments": [{**a, "points": a["max"]} if a in fixes else a for a in sec["assignments"]]}
            c["if_all_done"] = section_grade(fixed)


def add_locations(cv, data):
    """Which Canvas module each missing assignment sits in, so it can actually be found."""
    for m in data.get("missing", []):
        aid = m.get("canvas_id") or (m["id"] if isinstance(m["id"], int) else None)
        if not aid or not m.get("course_id"):
            continue
        try:
            seq = cv.get(f"/api/v1/courses/{m['course_id']}/module_item_sequence", {"asset_type": "Assignment", "asset_id": aid})
            m["modules"] = [mod.get("name") for s in seq for mod in s.get("modules", []) if mod.get("name")]
        except requests.HTTPError:
            pass


# ---------------------------------------------------------------- history + alerts
def snapshot(data):
    return {
        "missing": len(data["missing"]),
        "courses": {str(c["id"]): c["pct"] for c in data["courses"] if c["pct"] is not None},
        "official": {c["name"]: c["official"]["grade"] for c in data["courses"] if c.get("official") and c["official"]["grade"] is not None},
    }


def alerts(prev_state, data):
    """Compare against the last run: newly missing work and newly posted grades."""
    msgs, state = [], {}
    for i in data["items"]:
        state[str(i["id"])] = [i["status"], i["score"]]
        old = prev_state.get(str(i["id"]))
        if old is None:
            continue
        if i["status"] in ("missing", "overdue") and old[0] not in ("missing", "overdue"):
            msgs.append(f"⚠️ {i['course']}: \"{i['name']}\" is now missing ({i['points'] or 0:g} pts)")
        elif i["score"] is not None and old[1] != i["score"]:
            mark = "🔻" if (i["pct"] or 100) < LOW_SCORE else "✅"
            msgs.append(f"{mark} {i['course']}: \"{i['name']}\" graded {i['score']:g}/{i['points'] or 0:g}"
                        + (f" ({i['pct']:.0f}%)" if i["pct"] is not None else ""))
    for c in data["courses"]:
        sec = c.get("official")
        if not sec:
            continue
        key = f"sec:{sec['id']}"
        state[key] = sec["grade"]
        old = prev_state.get(key)
        if old is not None and sec["grade"] is not None and abs(sec["grade"] - old) >= 1.0:
            arrow = "📈" if sec["grade"] > old else "📉"
            msgs.append(f"{arrow} {c['name']} official grade {old:.1f}% → {sec['grade']:.1f}%")
        for a in sec["assignments"]:
            key = f"bb:{a['id']}"
            state[key] = [a["missing"], a["points"]]
            old = prev_state.get(key)
            if old is None:
                continue
            if a["missing"] and not old[0]:
                msgs.append(f"⚠️ {c['name']}: \"{a['name']}\" marked missing in the gradebook")
            elif a["points"] is not None and old[1] != a["points"] and not a["missing"]:
                mark = "🔻" if (a["pct"] or 100) < LOW_SCORE else "✅"
                msgs.append(f"{mark} {c['name']}: \"{a['name']}\" {a['points']:g}/{a['max']:g} ({a['pct']:.0f}%)")
    return msgs, state


def main():
    load_env()
    password = os.environ["PAGE_PASSWORD"]
    now = datetime.now(timezone.utc)
    cv = Canvas(os.environ["CANVAS_BASE_URL"], os.environ["CANVAS_TOKEN"])
    data = build(cv, now)
    merge_official(data, decrypt(BLACKBAUD.read_text(), password) if BLACKBAUD.exists() else {})
    add_locations(cv, data)
    cal_id, cal_ics = os.environ.get("TYLER_CAL_ID"), os.environ.get("TYLER_CAL_ICS")
    if cal_id:
        from urllib.parse import quote
        data["calendar"] = {"name": "Tyler Schedule", "google": f"https://calendar.google.com/calendar/u/0/r?cid={quote(cal_id)}",
                            "ics": cal_ics or None}

    history = decrypt(HISTORY.read_text(), password) if HISTORY.exists() else {"days": {}, "state": None}
    msgs, state = alerts(history.get("state") or {}, data)
    first_run = history.get("state") is None
    history["state"] = state
    history["days"][now.astimezone(LOCAL_TZ).date().isoformat()] = snapshot(data)
    history["days"] = dict(sorted(history["days"].items())[-400:])
    data["history"] = history["days"]

    SITE.mkdir(exist_ok=True)
    (SITE / "data.enc").write_text(encrypt(data, password))
    HISTORY.write_text(encrypt(history, password))

    topic = os.environ.get("NTFY_TOPIC")
    if topic and msgs and not first_run:
        body = "\n".join(msgs[:15]) + (f"\n…and {len(msgs) - 15} more" if len(msgs) > 15 else "")
        requests.post(f"https://ntfy.sh/{topic}", data=body.encode(), timeout=15,
                      headers={"Title": "Homework HQ update", "Tags": "books",
                               "Click": os.environ.get("SITE_URL", "")})

    print(f"courses={len(data['courses'])} items={len(data['items'])} "
          f"missing={snapshot(data)['missing']} alerts={len(msgs)} first_run={first_run}")


if __name__ == "__main__":
    main()
