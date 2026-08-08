# AGENTS.md — RiskSense

CVE triage service: `backend/` (FastAPI, stateless) + `frontend/` (Next.js 14 App Router).
Two independent deployables joined by one endpoint: `POST /api/score`.
Deep design docs already exist — read `ARCHITECTURE.md` before changing scoring or enrichment.

## Commands

```bash
# Backend (a venv already exists at backend/venv, Python 3.14 — CI uses 3.12)
cd backend && ./venv/bin/pytest -q          # 23 tests, offline, ~0.2s
./venv/bin/pytest tests/test_scoring.py::test_name -q   # single test
./venv/bin/uvicorn app.main:app --reload    # :8000, /docs for Swagger

cd frontend && npm run build                # this IS the typecheck (tsc strict, noEmit)
npm run dev                                 # :3000

docker compose up --build                   # both
```

- **`npm run lint` is unusable** — ESLint was never initialized, so `next lint` drops into an
  interactive setup prompt and hangs. Do not run it; verify the frontend with `npm run build`.
- There is no Python linter/formatter configured. CI (`.github/workflows/ci.yml`) runs exactly
  `pytest -q` and `npm run build`. Match that before declaring done.
- `backend/venv` is gitignored but present; use it rather than installing globally.

## Architecture invariants

- `app/scoring.py` is **pure and network-free** — all business logic lives here so it is testable
  with literal numbers and zero mocks. `app/enrich.py` is the only impure/network module.
  Keep that split; do not import httpx or read config in `scoring.py`.
- Every enrichment leg is **best-effort**: NVD/EPSS/KEV failures return `None`/`{}` and scoring
  continues. Never let a feed error turn into a 5xx.
- Tuning constants are module-level in `scoring.py` (`LIKELIHOOD_FLOOR`, `KEV_FLOOR`,
  `KEV_RANSOMWARE_FLOOR`, `EPSS_POC`, `SSVC_WEIGHT`). Change these, not inline literals.
- `rank()` orders by SSVC action tier → days overdue → score. Score alone never decides order.
- NVD has no batch endpoint: `all_cvss()` is deliberately **sequential** with `NVD_DELAY`
  spacing (6.0s no key / 0.6s with key). Do not "optimize" it into `asyncio.gather` — it
  triggers 403s that silently blank CVSS.
- `main.py` strips `kev_due_date` from signals before calling `score_cve()` (display-only field,
  not a `score_cve` kwarg). Adding a signal means updating `enrich()`, `score_cve()`, that filter,
  `models.RiskItem`, and `frontend/lib/api.ts`'s `RiskItem` interface — the TS type is hand-written,
  not generated, so it silently drifts.

## Testing

- `tests/test_api.py` monkeypatches `enrich_mod.enrich` — patch the **module attribute**
  (`app.enrich.enrich`), not the name imported into `main.py`, or the stub won't apply.
- Tests must stay offline and deterministic; no test may touch NVD/FIRST/CISA.
- `enrich._kev_cache` is process-global with a 6h TTL — reset it if a test ever exercises it.

## Config

`config.py` reads env via plain `os.getenv` at import time after `load_dotenv()`, so
`backend/.env` is picked up automatically by uvicorn and pytest. Changing env requires a restart.
Vars: `NVD_API_KEY`, `NVD_DELAY`, `CORS_ORIGINS`, `NEXT_PUBLIC_API_URL` (see `.env.example`).
