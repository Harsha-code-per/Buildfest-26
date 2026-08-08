"""RiskSense API — turn a list of CVE IDs into a prioritised risk ranking."""
from __future__ import annotations

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from . import ai as ai_mod
from . import enrich as enrich_mod
from .config import settings
from .models import RiskItem, ScoreRequest, ScoreResponse
from .scoring import rank, score_cve

app = FastAPI(
    title="RiskSense API",
    version="1.0.0",
    description="CVE risk prioritisation: CVSS (NVD) + EPSS (FIRST) + CISA KEV -> one score.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in settings.cors_origins.split(",")],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/api/score", response_model=ScoreResponse)
async def score(req: ScoreRequest) -> ScoreResponse:
    cves = enrich_mod.normalize_cves(req.cves)
    if not cves:
        raise HTTPException(400, "No valid CVE IDs (expected format: CVE-YYYY-NNNN).")
    signals = await enrich_mod.enrich(cves)
    # kev_due_date is display-only metadata; days_overdue is the scored signal.
    results = rank([
        score_cve(c, **{k: v for k, v in signals[c].items() if k != "kev_due_date"})
        for c in cves
    ])
    raw_dicts = [r.to_dict() for r in results]
    ai_summary, ai_remediations = await ai_mod.generate_ai_triage(raw_dicts)
    if ai_remediations:
        norm_map = {str(k).strip().upper(): str(v) for k, v in ai_remediations.items()}
        for d in raw_dicts:
            cve_id = str(d.get("cve", "")).strip().upper()
            if cve_id in norm_map:
                d["ai_remediation"] = norm_map[cve_id]

    return ScoreResponse(
        results=[RiskItem(**d) for d in raw_dicts],
        count=len(raw_dicts),
        ai_summary=ai_summary,
    )


