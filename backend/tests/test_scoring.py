"""Deterministic, offline tests for the scoring engine — the core logic gate."""
from app.scoring import priority_band, rank, score_cve, sla_status


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


# --- SSVC decision (the differentiator) -------------------------------------

def test_ssvc_active_total_is_act():
    d = score_cve("X", cvss=10.0, epss=0.9, in_kev=True).ssvc
    assert d["exploitation"] == "active"
    assert d["technical_impact"] == "total"
    assert d["action"] == "Act"


def test_ssvc_active_partial_not_automatable_is_attend():
    # KEV but weak, unknown vector -> not escalated to Act.
    d = score_cve("X", cvss=5.0, epss=0.1, in_kev=True).ssvc
    assert d["action"] == "Attend"


def test_ssvc_automatable_escalates():
    base = score_cve("X", cvss=5.0, epss=0.1, in_kev=True).ssvc
    auto = score_cve("X", cvss=5.0, epss=0.1, in_kev=True,
                     attack_vector="NETWORK", user_interaction="NONE",
                     privileges_required="NONE").ssvc
    assert base["automatable"] is False and base["action"] == "Attend"
    assert auto["automatable"] is True and auto["action"] == "Act"


def test_ssvc_poc_high_severity_is_attend():
    d = score_cve("X", cvss=9.8, epss=0.9).ssvc  # no KEV -> poc, total
    assert d["exploitation"] == "poc" and d["action"] == "Attend"


def test_ssvc_quiet_low_signal_is_track():
    d = score_cve("X", cvss=4.0, epss=0.01).ssvc
    assert d["exploitation"] == "none" and d["action"] == "Track"


def test_rank_puts_action_tier_above_raw_score():
    # Attend item scores LOWER than a Track item; action tier must still win.
    attend = score_cve("ATTEND", cvss=5.0, epss=0.1, attack_vector="NETWORK",
                       user_interaction="NONE", privileges_required="NONE")
    track = score_cve("TRACK", cvss=8.0, epss=0.05)
    assert attend.score < track.score          # raw score would rank track first
    assert [r.cve for r in rank([track, attend])] == ["ATTEND", "TRACK"]


# --- SLA / CISA binding-deadline clock (the market differentiator) ----------

def test_sla_none_without_kev():
    d = sla_status(in_kev=False, days_overdue=None)
    assert d["state"] == "none" and d["days_overdue"] is None


def test_sla_overdue_label():
    d = sla_status(in_kev=True, days_overdue=12)
    assert d["state"] == "overdue" and d["days_overdue"] == 12
    assert "past" in d["label"].lower()


def test_sla_due_in_future():
    d = sla_status(in_kev=True, days_overdue=-5)  # deadline 5 days away
    assert d["state"] == "due" and "until" in d["label"].lower()


def test_kev_without_due_date_is_none():
    # KEV membership but no parseable due date -> no false deadline claimed.
    assert sla_status(in_kev=True, days_overdue=None)["state"] == "none"


def test_score_cve_carries_sla():
    r = score_cve("X", cvss=9.8, epss=0.9, in_kev=True, days_overdue=30)
    assert r.days_overdue == 30 and r.sla["state"] == "overdue"


def test_overdue_breaks_ties_within_action_tier():
    # Two Act items, same score; the overdue one must rank first.
    fresh = score_cve("FRESH", cvss=10.0, epss=0.9, in_kev=True, days_overdue=-3)
    late = score_cve("LATE", cvss=10.0, epss=0.9, in_kev=True, days_overdue=40)
    assert fresh.ssvc["action"] == late.ssvc["action"] == "Act"
    assert [r.cve for r in rank([fresh, late])] == ["LATE", "FRESH"]
