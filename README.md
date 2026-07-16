# Web Sentinel — Website Defacement & Vulnerability Assessment Platform

Built for System Siege (PS-005, Cyber Security & Web Mining domain).

## What it does
Monitors registered websites, detects content/defacement changes between scans,
runs a deterministic HTTP/TLS security check (headers, CORS, cookies, SSL expiry),
computes a transparent 0–100 security score, and (optionally) asks an LLM to turn
that real scan data into a plain-language executive/technical summary.

## AI disclosure (BYOK)
- **Provider:** Google Gemini
- **Model:** `gemini-2.0-flash` (configurable via `AI_MODEL` env var)
- **What it's used for:** ONLY summarizing/prioritizing findings already produced
  by the deterministic scanner (`backend/app/services/scanner.py`). It never
  invents vulnerabilities and never executes code.
- Set your own key in `backend/.env` as `AI_API_KEY`. Without a key set, the
  summary endpoint returns a clear "not configured" message rather than faking output.

## Stack
- Frontend: Next.js (JavaScript)
- Backend: FastAPI (Python)
- DB: PostgreSQL
- Auth: JWT (access + refresh), bcrypt password hashing, RBAC (Owner/Admin/Analyst/Viewer)

## Roles
| Role | Can view | Can add/scan sites | Can delete sites | Can view audit log |
|---|---|---|---|---|
| Viewer | ✅ | ❌ | ❌ | ❌ |
| Analyst | ✅ | ✅ | ❌ | ❌ |
| Admin | ✅ | ✅ | ✅ | ✅ |
| Owner | ✅ | ✅ | ✅ | ✅ |

RBAC is enforced **server-side on every route** (`require_role` dependency in
`app/core/security.py`), not just hidden in the UI — a Viewer's JWT cannot reach
Admin-only endpoints by calling the API directly. Cross-tenant access is blocked
via explicit `require_same_org` checks on every resource fetch by ID.

## Local setup
```bash
cp backend/.env.example backend/.env
# edit backend/.env and set AI_API_KEY, JWT_SECRET

docker compose up --build
```
- Backend: http://localhost:8000/docs (Swagger UI)
- Frontend: http://localhost:3000

## Known limitations (honest, not hidden)
- Screenshot/visual diffing (Playwright-based pixel comparison) is not yet wired
  in — current defacement detection is HTML-hash-based only. This is the first
  thing to add with remaining build time.
- No rate limiting / account lockout implemented yet on `/api/auth/login` —
  should be added before the live game window (e.g. `slowapi`).
- No email verification / password reset flow yet.
- Migrations use `Base.metadata.create_all` for speed; swap to Alembic for
  real schema evolution.
- No automated test suite included yet.

## Security notes for the attack/defend phase
Things we already checked ourselves (self-attack before submission):
- Viewer JWT cannot call POST /api/sites or DELETE /api/sites/{id} (403)
- Site/alert fetch-by-ID checks org ownership, not just existence (404 on cross-org access)
- CORS is restricted to `ALLOWED_ORIGINS`, never `*`
- Login returns identical error for "no such user" and "wrong password" (no user enumeration)
- No secrets committed — `.env` is gitignored, `.env.example` has placeholders only
