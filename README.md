# Homework HQ

A password-locked page that shows one student's Canvas work: what's missing, what's due,
grades, and teacher comments. GitHub Actions rebuilds it every 30 minutes.

**Privacy:** the repo and site are public, but the student's data never is. `build.py` encrypts
it (AES-256-GCM, key from PBKDF2-SHA256 with 600k iterations) before it's written, and the page
decrypts it in the browser. `history.enc` (daily snapshots for the trend chart) is encrypted
the same way. Actions logs print counts only.

## Secrets (Settings → Secrets → Actions)
| Name | What |
|---|---|
| `CANVAS_BASE_URL` | e.g. `https://school.instructure.com` |
| `CANVAS_TOKEN` | Canvas → Account → Settings → New Access Token (student account) |
| `PAGE_PASSWORD` | the page password (changing it re-encrypts everything on the next run, but `history.enc` must be deleted first) |
| `NTFY_TOPIC` | optional; push alerts for newly missing work and new grades via ntfy.sh |

## Local run
```
uv venv .venv && uv pip install -p .venv -r requirements.txt
.venv/bin/python build.py      # reads .env
cd site && python3 -m http.server
```
