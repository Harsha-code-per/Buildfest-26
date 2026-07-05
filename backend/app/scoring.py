"""RiskSense composite risk scoring engine.

Combines three real-world signals to prioritise CVEs the way vulnerability
management teams actually triage them:

  * CVSS base score  (NVD)   -> intrinsic severity
  * EPSS probability (FIRST) -> likelihood of exploitation in the next 30 days
  * CISA KEV membership      -> confirmed active exploitation in the wild

Output is a single 0-100 RiskSense score, an explainable breakdown, AND — the
part that sets RiskSense apart from an opaque risk number — a transparent
**SSVC decision** (Act / Attend / Track) derived from the same signals, with the
reasoning shown. SSVC (Stakeholder-Specific Vulnerability Categorization,
CISA / CMU-SEI) prioritises by *what to do*, not just *how bad it is*.

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

# EPSS at/above this implies exploit code is likely public -> SSVC "poc".
# Calibration knob: raise to be stricter about what counts as proof-of-concept.
EPSS_POC = 0.1
# Action ranking weight (higher = triage first). Used to order the table so
# every "Act" sits above every "Attend", above every "Track".
SSVC_WEIGHT = {"Act": 3, "Attend": 2, "Track": 1}


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


def ssvc(
    cvss: float | None,
    epss: float | None,
    in_kev: bool,
    attack_vector: str | None = None,
    user_interaction: str | None = None,
    privileges_required: str | None = None,
) -> dict:
    """Map the raw signals onto a simplified CISA SSVC decision.

    Three intrinsic decision points (the environmental/mission dimension needs
    asset context RiskSense doesn't have, so it is intentionally omitted and the
    result is conservative):

      * exploitation: active (KEV) / poc (high EPSS) / none
      * automatable:  network-reachable AND no auth AND no user interaction
                      -> steps 1-4 of the kill chain can be mass-automated
      * technical:    total (CVSS >= 9) / partial

    Returns the outcome plus every input, so the UI can show *why*.
    """
    if in_kev:
        exploitation = "active"
    elif (epss or 0.0) >= EPSS_POC:
        exploitation = "poc"
    else:
        exploitation = "none"

    # Only assert "automatable" when we positively know all three are permissive
    # (v2-only CVEs lack these fields -> stays False, never guessed).
    automatable = (
        attack_vector == "NETWORK"
        and user_interaction == "NONE"
        and privileges_required == "NONE"
    )

    technical = "total" if (cvss or 0.0) >= 9.0 else "partial"

    if exploitation == "active":
        action = "Act" if (technical == "total" or automatable) else "Attend"
    elif exploitation == "poc":
        action = "Attend" if (technical == "total" or automatable) else "Track"
    else:  # none observed
        action = "Attend" if (technical == "total" and automatable) else "Track"

    why = (
        f"exploitation={exploitation}, "
        f"automatable={'yes' if automatable else 'no'}, "
        f"technical impact={technical} → {action}"
    )
    return {
        "action": action,
        "exploitation": exploitation,
        "automatable": automatable,
        "technical_impact": technical,
        "why": why,
    }


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
    ssvc: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


def score_cve(
    cve: str,
    cvss: float | None = None,
    epss: float | None = None,
    percentile: float | None = None,
    in_kev: bool = False,
    kev_ransomware: bool = False,
    attack_vector: str | None = None,
    user_interaction: str | None = None,
    privileges_required: str | None = None,
) -> RiskResult:
    """Compute the composite RiskSense score + SSVC decision for a single CVE.

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
    decision = ssvc(cvss, epss, in_kev, attack_vector,
                    user_interaction, privileges_required)
    return RiskResult(
        cve=cve, score=score, priority=priority_band(score),
        cvss=cvss, epss=epss, percentile=percentile,
        in_kev=in_kev, kev_ransomware=kev_ransomware,
        breakdown=breakdown, ssvc=decision,
    )


def rank(results: list[RiskResult]) -> list[RiskResult]:
    """Sort by SSVC action first (Act > Attend > Track), then by score.

    The action tier is the decision that matters; the numeric score breaks ties
    *within* a tier so the ordering is total and stable.
    """
    return sorted(
        results,
        key=lambda r: (SSVC_WEIGHT.get(r.ssvc.get("action"), 0), r.score),
        reverse=True,
    )
