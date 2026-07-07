"""Enrichment clients for NVD (CVSS), FIRST (EPSS) and CISA KEV.

Every call is best-effort: if a source is down or rate-limits, that signal is
simply ``None``/absent and scoring degrades gracefully instead of failing.
"""
from __future__ import annotations

import asyncio
import re
import time
from datetime import date

import httpx

from .config import settings

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)

EPSS_URL = "https://api.first.org/data/v1/epss"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# KEV catalog changes at most daily; cache it so we fetch ~1.6k entries rarely.
_kev_cache: dict = {"data": None, "ts": 0.0}
KEV_TTL = 6 * 3600


def normalize_cves(cves: list[str]) -> list[str]:
    """Upper-case, validate format, and de-duplicate while preserving order."""
    seen: set[str] = set()
    out: list[str] = []
    for c in cves:
        c = c.strip().upper()
        if CVE_RE.match(c) and c not in seen:
            seen.add(c)
            out.append(c)
    return out


async def fetch_epss(client: httpx.AsyncClient, cves: list[str]) -> dict:
    """Batch EPSS lookup -> {cve: (epss, percentile)}."""
    if not cves:
        return {}
    try:
        r = await client.get(EPSS_URL, params={"cve": ",".join(cves)}, timeout=15)
        r.raise_for_status()
        out: dict = {}
        for d in r.json().get("data", []):
            # Guard per row: one malformed entry shouldn't drop the whole batch.
            try:
                out[d["cve"].upper()] = (float(d["epss"]), float(d["percentile"]))
            except (KeyError, TypeError, ValueError):
                continue
        return out
    except Exception:
        return {}


async def fetch_kev(client: httpx.AsyncClient) -> dict:
    """CISA KEV catalog, cached -> {cveID: {"ransomware": bool, "due_date": str|None}}.

    ``due_date`` is CISA's *binding* remediation deadline (BOD 22-01) — the field
    commercial scanners collect but rarely surface. RiskSense turns it into an
    overdue clock so an actively-exploited CVE reads "12 days past a federal
    deadline", not just "exploited".
    """
    now = time.time()
    if _kev_cache["data"] is not None and now - _kev_cache["ts"] < KEV_TTL:
        return _kev_cache["data"]
    try:
        r = await client.get(KEV_URL, timeout=30)
        r.raise_for_status()
        data = {
            v["cveID"].upper(): {
                "ransomware": v.get("knownRansomwareCampaignUse", "").lower() == "known",
                "due_date": v.get("dueDate") or None,
            }
            for v in r.json().get("vulnerabilities", [])
        }
        _kev_cache.update(data=data, ts=now)
        return data
    except Exception:
        return _kev_cache["data"] or {}


def _days_overdue(due_date: str | None) -> int | None:
    """Whole days past a CISA due date (YYYY-MM-DD). None if absent/unparseable.

    Negative means the deadline is still in the future (days remaining).
    """
    if not due_date:
        return None
    try:
        return (date.today() - date.fromisoformat(due_date)).days
    except ValueError:
        return None


_EMPTY_CVSS = {"cvss": None, "attack_vector": None,
               "user_interaction": None, "privileges_required": None}


async def fetch_cvss(client: httpx.AsyncClient, cve: str) -> dict:
    """NVD CVSS for one CVE -> {cvss, attack_vector, user_interaction, privileges_required}.

    The vector fields (from CVSS v3.x) feed the SSVC "Automatable" decision;
    all fields are ``None`` when unavailable so scoring degrades gracefully.
    """
    headers = {"apiKey": settings.nvd_api_key} if settings.nvd_api_key else {}
    try:
        r = await client.get(NVD_URL, params={"cveId": cve}, headers=headers, timeout=20)
        r.raise_for_status()
        vulns = r.json().get("vulnerabilities", [])
        if not vulns:
            return dict(_EMPTY_CVSS)
        metrics = vulns[0]["cve"].get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metrics.get(key):
                d = metrics[key][0]["cvssData"]
                return {
                    "cvss": float(d["baseScore"]),
                    # v3.x carries these; v2 doesn't -> stays None (not automatable-inferred).
                    "attack_vector": d.get("attackVector"),
                    "user_interaction": d.get("userInteraction"),
                    "privileges_required": d.get("privilegesRequired"),
                }
    except Exception:
        return dict(_EMPTY_CVSS)
    return dict(_EMPTY_CVSS)


async def enrich(cves: list[str]) -> dict:
    """Gather CVSS + EPSS + KEV for a list of CVEs -> {cve: signals}."""
    async with httpx.AsyncClient() as client:

        async def all_cvss() -> dict:
            # NVD is per-CVE and rate-limited: query sequentially, spacing each
            # call by nvd_delay so a large batch doesn't burst into 403s (which
            # would silently blank out CVSS for most CVEs). Runs concurrently
            # with the batched EPSS + cached KEV lookups.
            out: dict = {}
            for i, cve in enumerate(cves):
                if i:
                    await asyncio.sleep(settings.nvd_delay)
                out[cve] = await fetch_cvss(client, cve)
            return out

        epss_map, kev_map, cvss_map = await asyncio.gather(
            fetch_epss(client, cves),
            fetch_kev(client),
            all_cvss(),
        )

    out: dict = {}
    for c in cves:
        epss, pct = epss_map.get(c, (None, None))
        cvss_data = cvss_map.get(c) or _EMPTY_CVSS
        kev = kev_map.get(c)  # {"ransomware", "due_date"} or None
        due_date = kev["due_date"] if kev else None
        out[c] = {
            **cvss_data,  # cvss, attack_vector, user_interaction, privileges_required
            "epss": epss,
            "percentile": pct,
            "in_kev": kev is not None,
            "kev_ransomware": bool(kev and kev["ransomware"]),
            "kev_due_date": due_date,
            "days_overdue": _days_overdue(due_date),
        }
    return out
