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
