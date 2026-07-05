<div align="center">

# RiskSense

**CVE risk prioritization that reflects real-world exploitation — not just severity.**

Blends **CVSS** (severity), **EPSS** (exploit probability), and the **CISA KEV** catalog
(confirmed active exploitation) into a single, explainable 0–100 score, so you patch what
actually matters first.

![Python](https://img.shields.io/badge/Python-3776AB?style=flat&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-009688?style=flat&logo=fastapi&logoColor=white)
![Next.js](https://img.shields.io/badge/Next.js-000000?style=flat&logo=nextdotjs&logoColor=white)
![TypeScript](https://img.shields.io/badge/TypeScript-3178C6?style=flat&logo=typescript&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-2496ED?style=flat&logo=docker&logoColor=white)
![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)

</div>

---

## Why RiskSense

A CVSS 9.8 that nobody is exploiting is often *less* urgent than a CVSS 7.5 that's in every
ransomware playbook. Severity alone over-alerts. RiskSense triages the way a SOC or
vulnerability-management team actually does — by combining severity with **likelihood** and
**evidence of active exploitation**:

| Signal | Source | What it tells you |
|---|---|---|
| **CVSS base score** | [NVD](https://nvd.nist.gov/) | How bad is it *if* exploited? |
| **EPSS** | [FIRST](https://www.first.org/epss/) | Probability it's exploited in the next 30 days |
| **CISA KEV** | [CISA](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Is it *already* being exploited in the wild? |

## Scoring methodology

```
severity   = cvss × 10                                   # 0–100
likelihood = epss                                        # 0–1 (EPSS)
score      = severity × (0.4 + 0.6 × likelihood)         # severity modulated by real-world likelihood
if in CISA KEV:              score = max(score, 90)       # actively exploited → at least Critical
if KEV + ransomware use:     score = max(score, 95)       # top of the queue
```

**Priority bands:** `Critical ≥ 90 · High ≥ 70 · Medium ≥ 40 · Low < 40`

Missing signals degrade gracefully — an unknown CVSS never blanks out an otherwise scorable
CVE. Every response includes a `breakdown` so the score is explainable, not a black box.

Example (live data):

| CVE | Score | Priority | Why |
|---|---|---|---|
| CVE-2021-44228 (Log4Shell) | 100 | Critical | CVSS 10 · EPSS ~1.0 · KEV + ransomware |
| CVE-2019-0708 (BlueKeep) | 98 | Critical | CVSS 9.8 · high EPSS · KEV |
| CVE-2014-0160 (Heartbleed) | 90 | Critical | KEV floor applied |

## Architecture

```
┌──────────────┐     POST /api/score      ┌─────────────────────┐
│  Next.js UI  │ ───────────────────────► │     FastAPI          │
│ (dashboard)  │ ◄─────────────────────── │  scoring + enrich    │
└──────────────┘   ranked risk results    └─────────┬───────────┘
                                                     │  (best-effort, cached)
                                    ┌────────────────┼────────────────┐
                                    ▼                ▼                ▼
                                 NVD API        FIRST EPSS        CISA KEV
```

## Quick start

### Docker (recommended)
```bash
git clone https://github.com/AtharvS7/RiskSense.git
cd RiskSense
docker compose up --build
# Frontend → http://localhost:3000   API docs → http://localhost:8000/docs
```

### Local dev
```bash
# Backend
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload            # http://localhost:8000

# Frontend (new terminal)
cd frontend
npm install
npm run dev                              # http://localhost:3000
```

## API

`POST /api/score`
```json
{ "cves": ["CVE-2021-44228", "CVE-2014-0160"] }
```
Response (ranked highest-risk first):
```json
{
  "count": 2,
  "results": [
    {
      "cve": "CVE-2021-44228", "score": 100.0, "priority": "Critical",
      "cvss": 10.0, "epss": 0.99999, "in_kev": true, "kev_ransomware": true,
      "breakdown": { "severity_component": 100.0, "likelihood_multiplier": 1.0, "kev_floor_applied": true }
    }
  ]
}
```
Interactive docs at `/docs` (Swagger UI). `GET /health` for liveness.

## Configuration

| Variable | Default | Notes |
|---|---|---|
| `NVD_API_KEY` | *(none)* | Optional [free key](https://nvd.nist.gov/developers/request-an-api-key) — raises rate limit 5 → 50 req/30s |
| `NVD_CONCURRENCY` | `3` | Parallel NVD lookups |
| `CORS_ORIGINS` | `*` | Comma-separated allowed origins |
| `NEXT_PUBLIC_API_URL` | `http://localhost:8000` | Backend URL for the frontend |

## Testing

```bash
cd backend && pytest        # scoring engine + API (offline, deterministic)
```
The scoring engine is pure and fully unit-tested; API tests stub enrichment so CI needs no
network. Frontend is type-checked via `npm run build` in CI.

## Roadmap

- [ ] Bulk CVE import from `pip`/`npm`/OS package manifests
- [ ] Configurable scoring weights per organization risk appetite
- [ ] Historical EPSS trend sparklines
- [ ] Auth + saved scans (currently stateless by design)
- [ ] Live deployment (Render + Vercel)

## Acknowledgements

Data courtesy of [NVD](https://nvd.nist.gov/), [FIRST EPSS](https://www.first.org/epss/), and
[CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog). Built by
[Atharv Sawane](https://github.com/AtharvS7).

## License

[MIT](./LICENSE)
