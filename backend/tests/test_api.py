"""API tests with enrichment stubbed out — no network, fully deterministic."""
from fastapi.testclient import TestClient

from app import enrich as enrich_mod
from app.main import app

client = TestClient(app)


def test_score_endpoint_ranks_kev_first(monkeypatch):
    async def fake_enrich(cves):
        return {
            c: {
                "cvss": 9.8, "epss": 0.5, "percentile": 0.9,
                "in_kev": c.endswith("44228"), "kev_ransomware": False,
            }
            for c in cves
        }

    monkeypatch.setattr(enrich_mod, "enrich", fake_enrich)
    resp = client.post("/api/score", json={"cves": ["CVE-2020-1234", "CVE-2021-44228"]})
    assert resp.status_code == 200
    body = resp.json()
    assert body["count"] == 2
    assert body["results"][0]["cve"] == "CVE-2021-44228"  # KEV floored to top


def test_rejects_garbage_input():
    resp = client.post("/api/score", json={"cves": ["not-a-cve", "also bad"]})
    assert resp.status_code == 400


def test_health():
    assert client.get("/health").json() == {"status": "ok"}


def test_normalize_cves_dedupes_and_validates():
    out = enrich_mod.normalize_cves(
        [" cve-2021-44228 ", "CVE-2021-44228", "not-a-cve", "CVE-2014-0160"]
    )
    # Upper-cased + trimmed, order-preserving dedup, garbage dropped.
    assert out == ["CVE-2021-44228", "CVE-2014-0160"]


def test_score_endpoint_includes_ai_triage(monkeypatch):
    from app import ai as ai_mod

    async def fake_enrich(cves):
        return {
            c: {
                "cvss": 9.8, "epss": 0.5, "percentile": 0.9,
                "in_kev": False, "kev_ransomware": False,
            }
            for c in cves
        }

    async def fake_ai(results):
        return (
            "Focus on patching high-impact network vulnerabilities first.",
            {"CVE-2021-44228": "Upgrade Log4j2 to >=2.17.1 immediately."},
        )

    monkeypatch.setattr(enrich_mod, "enrich", fake_enrich)
    monkeypatch.setattr(ai_mod, "generate_ai_triage", fake_ai)

    resp = client.post("/api/score", json={"cves": ["CVE-2021-44228"]})
    assert resp.status_code == 200
    body = resp.json()
    assert body["ai_summary"] == "Focus on patching high-impact network vulnerabilities first."
    assert body["results"][0]["ai_remediation"] == "Upgrade Log4j2 to >=2.17.1 immediately."

