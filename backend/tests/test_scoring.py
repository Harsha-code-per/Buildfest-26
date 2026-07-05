"""Deterministic, offline tests for the scoring engine — the core logic gate."""
from app.scoring import priority_band, rank, score_cve


def test_log4shell_is_critical():
    r = score_cve("CVE-2021-44228", cvss=10.0, epss=0.97, percentile=1.0,
                  in_kev=True, kev_ransomware=True)
    assert r.priority == "Critical"
    assert r.score >= 95


def test_low_signal_is_low():
    r = score_cve("CVE-2020-0001", cvss=3.1, epss=0.001, in_kev=False)
    assert r.priority == "Low"
    assert r.score < 40


def test_kev_floors_weak_cvss():
    # Weak CVSS but actively exploited must never be triaged as low priority.
    r = score_cve("CVE-2000-0000", cvss=4.0, epss=0.01, in_kev=True)
    assert r.score >= 90
    assert r.priority == "Critical"


def test_ransomware_outranks_plain_kev():
    plain = score_cve("A", cvss=5.0, epss=0.1, in_kev=True)
    ranso = score_cve("B", cvss=5.0, epss=0.1, in_kev=True, kev_ransomware=True)
    assert ranso.score > plain.score


def test_ranking_is_descending():
    a = score_cve("A", cvss=9.8, epss=0.9)
    b = score_cve("B", cvss=5.0, epss=0.1)
    c = score_cve("C", cvss=2.0, epss=0.01)
    assert [x.cve for x in rank([b, c, a])] == ["A", "B", "C"]


def test_missing_signals_dont_crash():
    r = score_cve("CVE-2021-0000")  # every signal absent
    assert r.score == 0.0
    assert r.priority == "Low"


def test_bands():
    assert priority_band(90) == "Critical"
    assert priority_band(70) == "High"
    assert priority_band(40) == "Medium"
    assert priority_band(39.9) == "Low"
