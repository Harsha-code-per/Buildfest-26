# RiskSense — Architecture & Data Flow

RiskSense turns a raw list of CVE IDs into a **prioritised risk ranking**. It answers
the one question a vulnerability-management team actually has: *"I have 200 open CVEs
and time to patch 10 — which 10?"*

It does this by blending three independent, real-world signals into a single
explainable 0–100 score:

| Signal | Source | Question it answers |
|---|---|---|
| **CVSS** base score | NVD (NIST) | How severe is it *in theory*? |
| **EPSS** probability | FIRST.org | How likely is it to be exploited in the next 30 days? |
| **CISA KEV** membership | CISA | Is it *actually being exploited right now* (incl. ransomware)? |

The insight baked into the scoring: **a moderate-severity CVE that is actively
exploited outranks a "critical" CVE that nobody is attacking.** Theory loses to
evidence.

---

## 1. High-level architecture

```
┌────────────────────────────┐         ┌──────────────────────────────────────┐
│  Frontend (Next.js 14)     │         │  Backend (FastAPI, Python 3.12)       │
│  app/page.tsx              │         │                                        │
│   • textarea of CVE IDs    │  POST   │  main.py      /api/score  /health      │
│   • "Prioritize" button    │ ───────►│    │                                   │
│   • Export CSV             │ /api/   │    ├─ normalize_cves()  (enrich.py)    │
│  components/RiskTable.tsx  │  score  │    ├─ enrich()          (enrich.py) ───┼──► NVD  (CVSS)
│  lib/api.ts (fetch client) │ ◄────── │    │                                   ├──► FIRST (EPSS)
│                            │  JSON   │    ├─ score_cve()       (scoring.py)   └──► CISA (KEV)
└────────────────────────────┘         │    └─ rank()            (scoring.py)   │
                                        └──────────────────────────────────────┘
```

Two independently deployable pieces, talking over one JSON HTTP endpoint. No
database, no auth, no session state — the backend is a **pure function of its input
plus three public feeds**. That is a deliberate design choice: it makes the whole
thing trivially testable and horizontally scalable.

### Repository layout

```
RiskSense/
├── backend/
│   ├── app/
│   │   ├── main.py       # FastAPI app + routes (the HTTP boundary)
│   │   ├── models.py     # Pydantic request/response schemas
│   │   ├── enrich.py     # I/O layer: fetch CVSS/EPSS/KEV (impure, network)
│   │   ├── scoring.py    # scoring engine (pure, deterministic, no network)
│   │   └── config.py     # env-driven settings (12-factor)
│   ├── tests/            # pytest — scoring unit tests + API tests (network stubbed)
│   ├── requirements.txt
│   └── Dockerfile
├── frontend/
│   ├── app/page.tsx      # single-page UI (client component)
│   ├── components/RiskTable.tsx
│   └── lib/api.ts        # typed fetch wrapper
├── docker-compose.yml    # runs both together
└── .github/workflows/ci.yml   # pytest + next build on every push/PR
```

The backend's most important structural decision is the **split between `enrich.py`
(impure, does network I/O) and `scoring.py` (pure, no I/O).** All the interesting
business logic lives in the pure half, so it can be unit-tested offline with zero
mocks. The impure half is thin and best-effort.

---

## 2. End-to-end data flow

Follow a single request from keystroke to ranked table.

### Step 1 — User input (browser)
`frontend/app/page.tsx` holds a `<textarea>` pre-filled with four famous CVEs
(Log4Shell, Heartbleed, BlueKeep, EternalBlue). On **Prioritize**, it splits the
text on whitespace/commas into a `string[]` and calls `scoreCves(cves)`.

### Step 2 — HTTP request
`frontend/lib/api.ts` `POST`s to `${NEXT_PUBLIC_API_URL}/api/score` with body
`{ "cves": [...] }`. On a non-2xx it reads `detail` and throws — the UI catches it
and shows a red error banner.

### Step 3 — Validation (backend boundary)
`main.py::score()` receives the request. Pydantic (`models.ScoreRequest`) enforces
`1–100` CVE IDs before the handler even runs. Then `enrich.normalize_cves()`:
- upper-cases and trims each ID,
- validates it against `^CVE-\d{4}-\d{4,7}$`,
- de-duplicates while **preserving order**.

If nothing survives normalization → `HTTP 400` with a helpful message. Garbage in
does **not** get an empty 200.

### Step 4 — Enrichment (`enrich.enrich()`) — the I/O fan-out
This is where the three feeds are gathered **concurrently** under one shared
`httpx.AsyncClient`, via `asyncio.gather`:

1. **EPSS** (`fetch_epss`) — one *batched* request to FIRST for all CVEs at once →
   `{cve: (epss, percentile)}`. Parsed row-by-row so a single malformed row can't
   drop the whole batch.
2. **KEV** (`fetch_kev`) — the full CISA catalog (~1.6k entries), **cached in-process
   for 6 hours** (`_kev_cache`) because it changes at most daily. Returns
   `{cveID: is_ransomware}`.
3. **CVSS** (`all_cvss`) — NVD has **no batch endpoint**, so this is one request per
   CVE, issued **sequentially with a delay** (`NVD_DELAY`: 6s without an API key,
   0.6s with one) to stay under NVD's published rate limit. This is the slowest leg
   at volume; an `NVD_API_KEY` cuts the spacing 10×.

**Every leg is best-effort.** If a source times out, rate-limits, or 500s, that
signal simply becomes `None`/absent and scoring degrades gracefully — a request
never fails just because NVD is having a bad day.

The result is merged into `{cve: {cvss, epss, percentile, in_kev, kev_ransomware}}`.

### Step 5 — Scoring (`scoring.score_cve()`) — the pure core
For each CVE, deterministically:

```
severity   = (cvss or 0) * 10                              # 0–100
likelihood = epss or 0                                     # 0–1
multiplier = 0.4 + 0.6 * likelihood                        # LIKELIHOOD_FLOOR = 0.4
score      = severity * multiplier
if in_kev:          score = max(score, 90)                 # KEV_FLOOR
if kev_ransomware:  score = max(score, 95)                 # KEV_RANSOMWARE_FLOOR
score      = clamp(round(score, 1), 0, 100)
```

What the numbers *mean*:
- **`multiplier`** scales severity by exploit likelihood, but never below `0.4` — a
  severe-but-unproven CVE keeps 40% of its severity (`LIKELIHOOD_FLOOR`). Real-world
  exploit probability "unlocks" the remaining 60%.
- **KEV floors** are the key idea: anything on CISA's actively-exploited list is
  forced to *at least* 90 (Critical), and known-ransomware CVEs to *at least* 95 —
  no matter how weak their CVSS. Evidence beats theory.
- Each result carries an **explainable `breakdown`** (`severity_component`,
  `likelihood_multiplier`, `kev_floor_applied`) so the score is never a black box.

`priority_band()` maps the score to Critical (≥90) / High (≥70) / Medium (≥40) / Low.

### Step 6 — Ranking & response
`scoring.rank()` sorts results **highest-risk first** (the entire point of the tool).
`main.py` wraps them in `ScoreResponse{ results, count }` and returns JSON.

### Step 7 — Render (browser)
`RiskTable.tsx` renders the ranked rows: a score bar, colour-coded priority badge,
CVSS, EPSS as a percentage, and a KEV/Ransomware indicator. Each CVE links out to
its NVD detail page. **Export CSV** serialises the current results client-side (no
server round-trip) via a Blob download.

---

## 3. Why it's shaped this way (design rationale)

- **Pure scoring / impure enrichment split** → the business logic is testable with
  no network and no mocks. `test_scoring.py` calls `score_cve()` with literal
  numbers and asserts exact bands; `test_api.py` monkeypatches `enrich()` so the HTTP
  layer is tested deterministically.
- **Best-effort enrichment** → partial data is normal (a brand-new CVE may have EPSS
  but no CVSS yet). Missing signals degrade the score, they don't crash the request.
- **Stateless backend** → no DB to run, no migrations, no auth surface. Scales by
  running more copies. All "state" is the 6-hour in-process KEV cache, which is just
  an optimisation.
- **Concurrency shape** → EPSS (1 batched call) and KEV (1 cached call) are cheap and
  run in parallel with the expensive NVD leg; only NVD is throttled, because only NVD
  forces per-CVE calls with a strict rate limit.
- **`config.py` uses plain `os.getenv`** → three optional settings don't justify a
  settings framework.

---

## 4. External dependencies

| Feed | Endpoint | Auth | Notes |
|---|---|---|---|
| NVD (CVSS) | `services.nvd.nist.gov/rest/json/cves/2.0` | optional key | per-CVE; rate-limited; slowest leg |
| FIRST (EPSS) | `api.first.org/data/v1/epss` | none | batched; fast |
| CISA (KEV) | `cisa.gov/.../known_exploited_vulnerabilities.json` | none | full catalog; cached 6h |

All three are free and public. Only NVD benefits from a key.

---

## 5. Resilience & failure modes

| Failure | Behaviour |
|---|---|
| Invalid/garbage CVE IDs | `HTTP 400` before any network call |
| One feed down / rate-limited | That signal → `None`; scoring continues on the rest |
| One malformed EPSS row | Only that row dropped; batch survives |
| NVD throttling at volume | Absorbed by `NVD_DELAY` spacing; a key removes the pain |
| KEV feed unreachable | Falls back to the last cached copy (or empty) |

---

## 6. Configuration

| Variable | Default | Purpose |
|---|---|---|
| `NVD_API_KEY` | *(none)* | Optional NVD key; raises rate limit 5 → 50 req/30s |
| `NVD_DELAY` | `6.0` / `0.6` | Seconds between NVD calls (default depends on whether a key is set) |
| `CORS_ORIGINS` | `*` | Comma-separated allowed origins |
| `NEXT_PUBLIC_API_URL` | `http://localhost:8000` | Backend URL the frontend calls |

---

## 7. Running & testing

```bash
# Everything at once
docker-compose up

# Backend only
cd backend && pip install -r requirements.txt && uvicorn app.main:app --reload

# Frontend only
cd frontend && npm install && npm run dev

# Tests (offline, deterministic)
cd backend && pytest -q
```

CI (`.github/workflows/ci.yml`) runs `pytest -q` and `next build` on every push and
PR to `main`.

---

## 8. TL;DR data flow

```
CVE IDs (textarea)
   → POST /api/score
   → normalize + validate  (reject garbage → 400)
   → enrich  (NVD CVSS ‖ FIRST EPSS ‖ CISA KEV, concurrent, best-effort)
   → score   (severity × likelihood, floored by active-exploitation evidence)
   → rank    (highest risk first)
   → JSON    → RiskTable + CSV export
```
