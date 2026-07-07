"""Pydantic request/response schemas for the RiskSense API."""
from __future__ import annotations

from pydantic import BaseModel, Field


class ScoreRequest(BaseModel):
    cves: list[str] = Field(..., min_length=1, max_length=100,
                            description="CVE IDs, e.g. ['CVE-2021-44228'].")


class RiskItem(BaseModel):
    cve: str
    score: float
    priority: str
    cvss: float | None = None
    epss: float | None = None
    percentile: float | None = None
    in_kev: bool = False
    kev_ransomware: bool = False
    days_overdue: int | None = None
    breakdown: dict = {}
    ssvc: dict = {}
    sla: dict = {}


class ScoreResponse(BaseModel):
    results: list[RiskItem]
    count: int
