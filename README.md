<div align="center">

# RiskSense — AI Vulnerability Patch Prioritizer

**Built for Buildfest'26 · AI Vulnerability Patch Prioritizer for Lean IT Teams**

Most security tools hand you an opaque 0–100 risk score. RiskSense outputs a transparent **SSVC decision — Act / Attend / Track** — enhanced by **GPT-4o-mini AI Triage & Patch Remediation Guidance** specifically for resource-constrained IT teams.

![Built for Buildfest'26](https://img.shields.io/badge/Built_for-Buildfest'26-009688?style=flat)
![Python](https://img.shields.io/badge/Python-3776AB?style=flat&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-009688?style=flat&logo=fastapi&logoColor=white)
![Next.js](https://img.shields.io/badge/Next.js-000000?style=flat&logo=nextdotjs&logoColor=white)
![TypeScript](https://img.shields.io/badge/TypeScript-3178C6?style=flat&logo=typescript&logoColor=white)
![OpenAI GPT-4o-mini](https://img.shields.io/badge/AI-GPT--4o--mini-purple?style=flat&logo=openai&logoColor=white)
![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)

</div>

---

## Why RiskSense (Buildfest'26)

Small IT teams can't patch every CVE immediately and need to know **which vulnerabilities are actually being exploited in the wild**. A theoretical CVSS 9.8 that nobody is exploiting is often *less* urgent than a CVSS 7.5 that's in every active ransomware playbook.

RiskSense triages the way a SOC or vulnerability-management team actually does — by combining theoretical severity with **likelihood**, **evidence of active exploitation**, and **GPT-4o-mini AI guidance**:

| Signal | Source | What it tells you |
|---|---|---|
| **CVSS base score** | [NVD](https://nvd.nist.gov/) | How bad is it *if* exploited? |
| **EPSS** | [FIRST](https://www.first.org/epss/) | Probability it's exploited in the next 30 days |
| **CISA KEV** | [CISA](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Is it *already* being exploited in the wild (including ransomware)? |
| **AI Remediation Advisor** | **OpenAI GPT-4o-mini** | Executive summary & actionable sysadmin patch steps |

---

## AI Vulnerability Patch Prioritizer (GPT-4o-mini)

RiskSense incorporates an **AI Triage & Remediation Advisor**:
1. **Executive AI Briefing**: GPT-4o-mini analyzes the prioritized threat list and generates a 2-3 sentence top-level briefing on what action to take today.
2. **Per-CVE Actionable Remediation**: Generates direct, practical mitigation steps for every single vulnerability (workarounds, patch versions, firewall rules).
3. **Resilient Best-Effort Execution**: Asynchronous `httpx` API integration that gracefully degrades if an API key is missing.

---

## Scoring methodology

```
severity   = cvss × 10                                   # 0–100
likelihood = epss                                        # 0–1 (EPSS)
score      = severity × (0.4 + 0.6 × likelihood)         # severity modulated by real-world likelihood
if in CISA KEV:              score = max(score, 90)       # actively exploited → at least Critical
if KEV + ransomware use:     score = max(score, 95)       # top of the queue
```

**Priority bands:** `Critical ≥ 90 · High ≥ 70 · Medium ≥ 40 · Low < 40`

---

## SSVC decision — the differentiator

The 0–100 score ranks; the **SSVC action tells you what to do** (CISA / CMU-SEI methodology):

| Decision point | Derived from | Values |
|---|---|---|
| **Exploitation** | CISA KEV / EPSS | `active` (KEV) · `poc` (EPSS ≥ 0.1) · `none` |
| **Automatable** | CVSS vector | `yes` if network-reachable **and** no auth **and** no user interaction |
| **Technical impact** | CVSS base | `total` (≥ 9.0) · `partial` |

```
active   + (total OR automatable)   → Act       # exploited now, high impact — patch first
active   + partial (not automatable)→ Attend
poc      + (total OR automatable)   → Attend     # exploit code likely exists
none/low                            → Track      # routine patch cycle
```

---

## CISA deadline clock — SLA clock

Every KEV entry carries a **binding remediation deadline** (CISA BOD 22-01, `dueDate`). Within an action tier, **overdue CVEs outrank on-time ones** — the fire you're already late on gets triaged first.

---

## Quick start

### Docker (recommended)
```bash
git clone https://github.com/Harsha-code-per/Buildfest-26.git
cd Buildfest-26
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

---

## Configuration

| Variable | Default | Notes |
|---|---|---|
| `OPENAI_API_KEY` | *(none)* | Optional OpenAI key for AI-driven triage summaries & patch advice |
| `OPENAI_MODEL` | `gpt-4o-mini` | OpenAI GPT model selection |
| `NVD_API_KEY` | *(none)* | Optional free NVD key — raises rate limit 5 → 50 req/30s |
| `NVD_DELAY` | `6.0` / `0.6` | Seconds between NVD calls; default depends on whether a key is set |
| `CORS_ORIGINS` | `*` | Comma-separated allowed origins |
| `NEXT_PUBLIC_API_URL` | `http://localhost:8000` | Backend URL for the frontend |

---

## Acknowledgements

* **Built for Buildfest'26** by Team **Hakelize Techworks**.
* Enhanced with **GPT-4o-mini AI vulnerability patch prioritization**.
* Data courtesy of [NVD](https://nvd.nist.gov/), [FIRST EPSS](https://www.first.org/epss/), and [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).
