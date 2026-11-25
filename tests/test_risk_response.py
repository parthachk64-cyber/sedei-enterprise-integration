from __future__ import annotations

import numpy as np
import pytest

from sedei import audit
from sedei.config import load_detection
from sedei.detectors.rules import RuleFinding
from sedei.events import EventEnvelope, to_dt
from sedei.response import ActionType, Decision, decide_contextual, decide_static, tier_thresholds
from sedei.risk import RiskAssessment, RiskModel, rank, select_threshold

CFG = load_detection()
RM = RiskModel(CFG["risk"])


def finding(sev, code="X", rid="R"):
    return RuleFinding(rid, sev, 1.0, "fv1", ("e1",), (code,))


def test_noisy_or_and_components_sum_to_risk():
    a = RM.assess("r", [finding(0.5), finding(0.5)], 0.0, "standard")
    assert a.components["rule"] == pytest.approx(0.75)
    assert a.risk == pytest.approx(0.55 * 0.75) and sum(a.contributions.values()) == pytest.approx(a.risk)


def test_identity_context_only_amplifies_existing_evidence():
    assert RM.assess("r", [], 0.0, "elevated").risk == 0.0
    assert RM.assess("r", [finding(0.5)], 0.0, "elevated").risk > RM.assess("r", [finding(0.5)], 0.0, "standard").risk


def test_criticality_scales_and_is_bounded():
    base = RM.assess("r", [finding(0.8)], 0.5, "standard", 1.0).risk
    assert RM.assess("r", [finding(0.8)], 0.5, "standard", 1.25).risk == pytest.approx(base * 1.25)
    assert RM.assess("r", [finding(0.8)], 0.5, "standard", 9.0).components["criticality"] == 1.25
    assert RM.assess("r", [finding(1.0)], 1.0, "elevated", 1.25).risk <= 1.0


def test_missing_anomaly_degrades_and_renormalises():
    a = RM.assess("r", [finding(0.9)], None, "standard")
    assert a.degraded and a.contributions["anomaly"] == 0.0
    assert a.risk == pytest.approx(0.9 * CFG["risk"]["w_rule"] / (CFG["risk"]["w_rule"] + CFG["risk"]["w_identity"]))


def test_ties_are_broken_deterministically():
    mk = lambda i, r: RiskAssessment(i, r, {}, {}, False, "v")  # noqa: E731
    xs = [mk("b", 0.5), mk("a", 0.5), mk("c", 0.9)]
    assert [x.record_id for x in rank(xs)] == ["c", "a", "b"] == [x.record_id for x in rank(xs[::-1])]


def test_threshold_selection_and_boundary_semantics():
    y = np.array([0, 0, 1, 1, 0, 1])
    s = np.array([0.1, 0.2, 0.7, 0.9, 0.3, 0.7])
    t = select_threshold(y, s)
    assert t == 0.7 and ((s >= t).astype(int) == y).all()  # score == threshold alerts
    assert select_threshold(np.zeros(4), np.arange(4.0)) == float("inf")


def test_static_ladder_boundaries():
    t = 0.45
    th = tier_thresholds(t)
    a = lambda r: RiskAssessment("r", r, {}, {}, False, "v", ("DENIAL_STORM",))  # noqa: E731
    assert decide_static(a(t - 1e-9), t, "p", "ev") is None
    assert decide_static(a(th[0]), t, "p", "ev").action_type is ActionType.AUTH_CHALLENGE
    assert decide_static(a(th[1]), t, "p", "ev").action_type is ActionType.RATE_LIMIT
    assert decide_static(a(th[2]), t, "p", "ev").action_type is ActionType.EVENT_QUARANTINE
    assert decide_static(a(th[2]), t, "p", None).action_type is ActionType.RATE_LIMIT
    assert decide_static(a(th[3]), t, "p", "ev").action_type is ActionType.ACCESS_BLOCK
    assert decide_static(a(1.0), t, "p", "ev").action_type is ActionType.CREDENTIAL_REVOCATION


@pytest.mark.parametrize("reasons,priv,expect", [
    (("UNEXPECTED_SERVICE_EDGE",), "standard", ActionType.SERVICE_ISOLATION),
    (("UNEXPECTED_SERVICE_EDGE", "SCOPE_PROBING"), "elevated", ActionType.CREDENTIAL_REVOCATION),
    (("CROSS_TENANT",), "standard", ActionType.ACCESS_BLOCK),
    (("CROSS_TENANT",), "elevated", ActionType.CREDENTIAL_REVOCATION),
    (("REPLAY_INCONSISTENT",), "standard", ActionType.EVENT_QUARANTINE),
    (("REPLAY_INCONSISTENT", "DENIAL_STORM"), "elevated", ActionType.ACCESS_BLOCK),
    (("DENIAL_STORM",), "standard", ActionType.RATE_LIMIT),
    ((), "standard", ActionType.AUTH_CHALLENGE)])
def test_contextual_mapping(reasons, priv, expect):
    a = RiskAssessment("r", 0.9, {}, {}, False, "v", reasons)
    assert decide_contextual(a, 0.5, "p", priv, "ev1", "admin-svc").action_type is expect
    assert decide_contextual(RiskAssessment("r", 0.1, {}, {}, False, "v", reasons), 0.5, "p", priv, "e", "s") is None


# ---- response engine ------------------------------------------------------------------------------
def engine(sys_):
    return sys_.response


def commit(sys_, d, key="inc-1", tenant="tenant-a", now=1000.0, principal="svc-07"):
    return sys_.response.commit(d, incident_key=key, tenant=tenant, principal=principal, risk=0.9,
                                evidence=["r1", "r2"], reasons=["X"], now_sim=now)


def test_each_of_the_six_responses_changes_state(sys_):
    s = sys_.store
    ev = EventEnvelope(event_id="ev1", tenant="tenant-a", emitter="g", type="T", event_time=to_dt(0),
                       ingest_time=to_dt(0), correlation_id="c", payload={})
    s.append_event(ev, ["inventory"], 0.0)
    cases = [
        (Decision(ActionType.AUTH_CHALLENGE, "principal", "svc-07", "t", "static"), lambda: s.get_control("challenge", "tenant-a", "svc-07")),
        (Decision(ActionType.RATE_LIMIT, "principal", "svc-07", "t", "static"), lambda: s.get_control("rate_limited", "tenant-a", "svc-07")),
        (Decision(ActionType.EVENT_QUARANTINE, "event", "ev1", "t", "static"),
         lambda: s.q1("SELECT state FROM deliveries WHERE event_id='ev1'")["state"] == "quarantined"),
        (Decision(ActionType.ACCESS_BLOCK, "principal", "svc-07", "t", "static"), lambda: s.get_control("blocked", "tenant-a", "svc-07")),
        (Decision(ActionType.CREDENTIAL_REVOCATION, "principal", "svc-07", "t", "static"), lambda: s.get_control("revoked", "tenant-a", "svc-07")),
        (Decision(ActionType.SERVICE_ISOLATION, "service", "admin-svc", "t", "static"), lambda: s.get_control("isolated", "tenant-a", "admin-svc")),
    ]
    for d, check in cases:
        r = commit(sys_, d)
        assert r.status == "committed" and not r.deduplicated and check(), d.action_type
    assert audit.verify_chain(s) and len(audit.entries(s)) == 6


def test_action_deduplication_and_decision_action_separation(sys_):
    d = Decision(ActionType.ACCESS_BLOCK, "principal", "svc-07", "t", "contextual")
    a, b = commit(sys_, d), commit(sys_, d, now=2000.0)
    assert b.deduplicated and a.action_id == b.action_id and b.committed_sim == a.committed_sim
    assert sys_.store.q1("SELECT COUNT(*) n FROM actions")["n"] == 1
    assert sys_.store.q1("SELECT COUNT(*) n FROM decisions")["n"] == 1
    assert len(audit.entries(sys_.store)) == 1
    c = commit(sys_, d, key="inc-2")  # different incident -> distinct action
    assert not c.deduplicated and sys_.store.q1("SELECT COUNT(*) n FROM actions")["n"] == 2


def test_expiry_and_recovery(sys_):
    d = Decision(ActionType.ACCESS_BLOCK, "principal", "svc-07", "t", "static")
    r = commit(sys_, d, now=1000.0)
    assert sys_.response.expire_due(1000.0 + 10) == 0
    assert sys_.store.get_control("blocked", "tenant-a", "svc-07")
    assert sys_.response.expire_due(1000.0 + CFG["response"]["durations_s"]["access_block"] + 1) == 1
    assert sys_.store.get_control("blocked", "tenant-a", "svc-07") is None
    assert sys_.store.q1("SELECT status FROM actions WHERE action_id=?", (r.action_id,))["status"] == "expired"
    rev = commit(sys_, Decision(ActionType.CREDENTIAL_REVOCATION, "principal", "svc-07", "t", "static"), now=1000.0)
    assert sys_.response.expire_due(10**9) == 0  # revocation never auto-expires
    assert sys_.response.recover(rev.action_id, "owner", 5000.0)
    assert sys_.store.get_control("revoked", "tenant-a", "svc-07") is None
    assert not sys_.response.recover(rev.action_id, "owner", 5001.0)
    assert audit.verify_chain(sys_.store)


def test_quarantine_release_on_expiry(sys_):
    ev = EventEnvelope(event_id="ev1", tenant="tenant-a", emitter="g", type="T", event_time=to_dt(0),
                       ingest_time=to_dt(0), correlation_id="c", payload={})
    sys_.store.append_event(ev, ["inventory"], 0.0)
    commit(sys_, Decision(ActionType.EVENT_QUARANTINE, "event", "ev1", "t", "static"), now=0.0)
    assert sys_.store.claim("inventory", 1.0, 30) == []
    sys_.response.expire_due(10**6)
    assert len(sys_.store.claim("inventory", 10**6, 30)) == 1


def test_revocation_and_isolation_restricted_to_fixtures(sys_):
    r1 = commit(sys_, Decision(ActionType.CREDENTIAL_REVOCATION, "principal", "svc-99", "t", "s"))
    r2 = commit(sys_, Decision(ActionType.SERVICE_ISOLATION, "service", "payments-prod", "t", "s"))
    assert (r1.status, r2.status) == ("refused", "refused")
    assert sys_.store.get_control("revoked", "tenant-a", "svc-99") is None
    assert sys_.store.get_control("isolated", "tenant-a", "payments-prod") is None
    again = commit(sys_, Decision(ActionType.CREDENTIAL_REVOCATION, "principal", "svc-99", "t", "s"))
    assert again.deduplicated


def test_audit_entries_carry_evidence_principal_policy_scope(sys_):
    commit(sys_, Decision(ActionType.RATE_LIMIT, "principal", "svc-07", "t", "static"))
    row = audit.entries(sys_.store)[0]
    assert row["principal"] == "svc-07" and row["policy_version"] == CFG["response"]["policy_version"]
    assert row["scope"] == "principal:svc-07" and "r1" in row["evidence_json"]


def test_audit_chain_detects_tampering(sys_):
    for i in range(3):
        commit(sys_, Decision(ActionType.RATE_LIMIT, "principal", f"p{i}", "t", "s"), key=f"k{i}")
    assert audit.verify_chain(sys_.store)
    sys_.store.q("SELECT 1")
    with sys_.store.txn() as c:
        c.execute("UPDATE audit SET principal='forged' WHERE id=2")
    assert not audit.verify_chain(sys_.store)
