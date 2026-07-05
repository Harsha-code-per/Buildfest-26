"""Enrichment clients for NVD (CVSS), FIRST (EPSS) and CISA KEV.

Every call is best-effort: if a source is down or rate-limits, that signal is
simply ``None``/absent and scoring degrades gracefully instead of failing.
"""
from __future__ import annotations

import asyncio
import re
import time

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
        return {
            d["cve"].upper(): (float(d["epss"]), float(d["percentile"]))
            for d in r.json().get("data", [])
        }
    except Exception:
        return {}


async def fetch_kev(client: httpx.AsyncClient) -> dict:
    """CISA KEV catalog, cached -> {cveID: is_ransomware(bool)}."""
    now = time.time()
    if _kev_cache["data"] is not None and now - _kev_cache["ts"] < KEV_TTL:
        return _kev_cache["data"]
    try:
        r = await client.get(KEV_URL, timeout=30)
        r.raise_for_status()
        data = {
            v["cveID"].upper(): (v.get("knownRansomwareCampaignUse", "").lower() == "known")
            for v in r.json().get("vulnerabilities", [])
        }
        _kev_cache.update(data=data, ts=now)
        return data
    except Exception:
        return _kev_cache["data"] or {}


async def fetch_cvss(client: httpx.AsyncClient, cve: str) -> float | None:
    """NVD CVSS base score for one CVE -> float or None."""
    headers = {"apiKey": settings.nvd_api_key} if settings.nvd_api_key else {}
    try:
        r = await client.get(NVD_URL, params={"cveId": cve}, headers=headers, timeout=20)
        r.raise_for_status()
        vulns = r.json().get("vulnerabilities", [])
        if not vulns:
            return None
        metrics = vulns[0]["cve"].get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metrics.get(key):
                return float(metrics[key][0]["cvssData"]["baseScore"])
    except Exception:
        return None
    return None


async def enrich(cves: list[str]) -> dict:
    """Gather CVSS + EPSS + KEV for a list of CVEs -> {cve: signals}."""
    async with httpx.AsyncClient() as client:
        sem = asyncio.Semaphore(settings.nvd_concurrency)

        async def one_cvss(cve: str):
            async with sem:  # NVD is per-CVE and rate-limited
                return cve, await fetch_cvss(client, cve)

        epss_map, kev_map, cvss_pairs = await asyncio.gather(
            fetch_epss(client, cves),
            fetch_kev(client),
            asyncio.gather(*(one_cvss(c) for c in cves)),
        )

    cvss_map = dict(cvss_pairs)
    out: dict = {}
    for c in cves:
        epss, pct = epss_map.get(c, (None, None))
        out[c] = {
            "cvss": cvss_map.get(c),
            "epss": epss,
            "percentile": pct,
            "in_kev": c in kev_map,
            "kev_ransomware": kev_map.get(c, False),
        }
    return out
