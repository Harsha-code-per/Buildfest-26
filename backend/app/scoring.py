"""RiskSense composite risk scoring engine.

Combines three real-world signals to prioritise CVEs the way vulnerability
management teams actually triage them:

  * CVSS base score  (NVD)   -> intrinsic severity
  * EPSS probability (FIRST) -> likelihood of exploitation in the next 30 days
  * CISA KEV membership      -> confirmed active exploitation in the wild

Output is a single 0-100 RiskSense score plus an explainable breakdown.
Pure and deterministic (no network), so it is trivially unit-tested.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field

# A max-severity CVE with ~0 EPSS still keeps this fraction of its severity;
# the rest is unlocked by real-world exploit likelihood.
LIKELIHOOD_FLOOR = 0.4
KEV_FLOOR = 90.0             # any KEV CVE is at least Critical-adjacent
KEV_RANSOMWARE_FLOOR = 95.0  # KEV + known ransomware use = top of the queue

CRITICAL, HIGH, MEDIUM = 90.0, 70.0, 40.0


def _clamp(x: float, lo: float = 0.0, hi: float = 100.0) -> float:
    return max(lo, min(hi, x))


def priority_band(score: float) -> str:
    if score >= CRITICAL:
        return "Critical"
    if score >= HIGH:
        return "High"
    if score >= MEDIUM:
        return "Medium"
    return "Low"


@dataclass
class RiskResult:
    cve: str
    score: float
    priority: str
    cvss: float | None
    epss: float | None
    percentile: float | None
    in_kev: bool
    kev_ransomware: bool
    breakdown: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


def score_cve(
    cve: str,
    cvss: float | None = None,
    epss: float | None = None,
    percentile: float | None = None,
    in_kev: bool = False,
    kev_ransomware: bool = False,
) -> RiskResult:
    """Compute the composite RiskSense score for a single CVE.

    Missing signals degrade gracefully (treated as 0 / absent) rather than
    raising — an unknown CVSS should not blank out an otherwise scorable CVE.
    """
    severity = (cvss or 0.0) * 10.0            # 0-100
    likelihood = epss or 0.0                   # 0-1
    multiplier = LIKELIHOOD_FLOOR + (1 - LIKELIHOOD_FLOOR) * likelihood
    score = severity * multiplier

    if in_kev:
        score = max(score, KEV_FLOOR)
    if kev_ransomware:
        score = max(score, KEV_RANSOMWARE_FLOOR)
    score = round(_clamp(score), 1)

    breakdown = {
        "severity_component": round(severity, 1),
        "likelihood_multiplier": round(multiplier, 3),
        "kev_floor_applied": in_kev or kev_ransomware,
    }
    return RiskResult(
        cve=cve, score=score, priority=priority_band(score),
        cvss=cvss, epss=epss, percentile=percentile,
        in_kev=in_kev, kev_ransomware=kev_ransomware, breakdown=breakdown,
    )


def rank(results: list[RiskResult]) -> list[RiskResult]:
    """Sort results highest-risk first (the whole point of the tool)."""
    return sorted(results, key=lambda r: r.score, reverse=True)
