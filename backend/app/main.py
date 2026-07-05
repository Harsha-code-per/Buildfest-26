"""RiskSense API — turn a list of CVE IDs into a prioritised risk ranking."""
from __future__ import annotations

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

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
    results = rank([score_cve(c, **signals[c]) for c in cves])
    return ScoreResponse(results=[RiskItem(**r.to_dict()) for r in results], count=len(results))
