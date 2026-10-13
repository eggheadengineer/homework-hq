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

    feedback.sort(key=lambda f: f["at"] or "", reverse=True)
    return {
        "generated_at": iso(now),
        "quarter": {"title": quarter["title"], "start": iso(quarter["start"]), "end": iso(quarter["end"])} if quarter else None,
        "next_quarter": next(({"title": g["title"], "start": iso(g["start"])} for g in periods if g["start"] > now), None),
        "courses": sorted(courses, key=lambda c: (c["pct"] is None, c["pct"] or 0)),
        "items": items, "feedback": feedback[:60], "inbox": inbox,
    }


# ---------------------------------------------------------------- history + alerts
def snapshot(data):
    open_items = [i for i in data["items"] if i["status"] in ("missing", "overdue")]
    return {
        "missing": len(open_items),
        "courses": {str(c["id"]): c["pct"] for c in data["courses"] if c["pct"] is not None},
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
    return msgs, state


def main():
    load_env()
    password = os.environ["PAGE_PASSWORD"]
    now = datetime.now(timezone.utc)
    data = build(Canvas(os.environ["CANVAS_BASE_URL"], os.environ["CANVAS_TOKEN"]), now)

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
