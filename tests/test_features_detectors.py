from __future__ import annotations

import random

import numpy as np
import pytest

from sedei.config import load_detection
from sedei.detectors.anomaly import AnomalyDetector, ModelIntegrityError
from sedei.detectors.rules import RuleEngine
from sedei.features import FEATURE_NAMES, FEATURE_VERSION, build_features
from sedei.policy import load_policy
from sedei.store import Store
from sedei.telemetry import TelemetryIngestor, TelemetryRecord

POL = load_policy()
CFG = load_detection()
RULES = RuleEngine(CFG["rules"])


def rec(i, kind="gateway_decision", t=1000.0, delay=0.1, tenant="tenant-a", principal="svc-07", **kw):
    return TelemetryRecord(record_id=f"r{i}", kind=kind, tenant=tenant, principal=principal, event_time=t,
                           receipt_time=t + delay, **kw)


def deny(i, t, route="POST /v1/orders", reason="scope_missing", **kw):
    return rec(i, t=t, route=route, decision="deny", deny_reason=reason, **kw)


def feats(cur, hist):
    return build_features(cur, hist, POL, CFG["window_s"], CFG["late_after_s"])


def test_features_ignore_records_not_yet_received():
    cur = deny(1, 1000)
    future = deny(2, 1001, delay=500)  # event_time is before cur.receipt but it arrives much later
    fv = feats(cur, [cur, future])
    assert fv.values["n_deny"] == 1


def test_late_record_counts_only_after_receipt():
    cur = deny(1, 1100)
    late = deny(2, 1050, delay=40)  # received at 1090 <= 1100.1
    assert feats(cur, [cur, late]).values["n_deny"] == 2
    assert feats(cur, [cur, late]).values["late_ratio"] == 0.5


def test_out_of_order_and_duplicate_input_gives_identical_features():
    hist = [deny(i, 1000 + i * 5, route=f"GET /r{i % 3}") for i in range(6)]
    cur = hist[-1]
    a = feats(cur, hist)
    shuffled = hist[:] * 2
    random.Random(1).shuffle(shuffled)
    b = feats(cur, shuffled)
    assert a.values == b.values and a.evidence == b.evidence


def test_features_are_tenant_scoped_for_overlapping_ids():
    a = deny(1, 1000, tenant="tenant-a")
    b = deny(2, 1001, tenant="tenant-b")  # same principal id, other tenant
    assert feats(a, [a, b]).values["n_deny"] == 1


def delivery(i, t, attempt=1, redelivery=False, sha="h", emitter="gateway", event_id="ev1"):
    return rec(i, "event_delivery", t, event_id=event_id, emitter=emitter, payload_sha256=sha,
               delivery_attempt=attempt, transport_redelivery=redelivery)


def test_ordinary_redelivery_is_not_a_security_duplicate():
    first, again = delivery(1, 1000), delivery(2, 1010, 2, True)
    fv = feats(again, [first, again])
    assert (fv.values["n_benign_redelivery"], fv.values["n_security_dup"]) == (1, 0)
    assert RULES.evaluate(fv) == []


@pytest.mark.parametrize("bad", [dict(redelivery=False), dict(redelivery=True, sha="other"),
                                 dict(redelivery=True, emitter="partner-x")])
def test_inconsistent_replay_is_security_relevant(bad):
    first = delivery(1, 1000)
    kw = dict(attempt=2, **bad)
    replay = delivery(2, 1010, **kw)
    fv = feats(replay, [first, replay])
    assert fv.values["n_security_dup"] == 1 and fv.values["cur_is_security_dup"] == 1
    f = RULES.evaluate(fv)
    assert [x.rule_id for x in f] == ["R3_INCONSISTENT_REPLAY"] and f[0].evidence_ids == ("r2",)


def test_unexpected_service_edge_rule():
    ok = rec(1, "service_call", source_service="orchestrator", dest_service="inventory-svc")
    bad = rec(2, "service_call", t=1001, source_service="orchestrator", dest_service="admin-svc")
    assert RULES.evaluate(feats(ok, [ok])) == []
    f = RULES.evaluate(feats(bad, [ok, bad]))
    assert f[0].rule_id == "R4_UNEXPECTED_SERVICE_INTERACTION" and f[0].reason_codes == ("UNEXPECTED_SERVICE_EDGE",)


def test_rules_are_deterministic_and_carry_provenance():
    hist = [deny(i, 1000 + i, route=f"GET /r{i}") for i in range(4)]
    a = RULES.evaluate(feats(hist[-1], hist))
    b = RULES.evaluate(feats(hist[-1], list(reversed(hist))))
    assert a == b and {x.rule_id for x in a} == {"R1_REPEATED_DENIALS", "R2_SCOPE_PROBING"}
    for f in a:
        assert f.feature_version == FEATURE_VERSION and f.timestamp == hist[-1].receipt_time and f.evidence_ids


def test_tenant_mismatch_rule():
    c = deny(1, 1000, reason="tenant_mismatch")
    assert [f.rule_id for f in RULES.evaluate(feats(c, [c]))] == ["R5_CROSS_TENANT_ATTEMPT"]


def test_telemetry_ingest_dedup_and_late_flag():
    ing = TelemetryIngestor(Store(), late_after_s=30)
    r = rec(1, delay=60)
    assert ing.ingest(r).late and ing.ingest(r).status == "duplicate" and ing.duplicates_dropped == 1
    assert [x.record_id for x in ing.history("tenant-a", "svc-07", 1100, 300)] == ["r1"]
    assert ing.history("tenant-b", "svc-07", 1100, 300) == []


# ---- anomaly model --------------------------------------------------------------------------------
def toy_matrix(n=400, seed=0):
    rng = np.random.default_rng(seed)
    x = np.zeros((n, len(FEATURE_NAMES)))
    x[:, 0] = rng.integers(1, 6, n)
    x[:, 1] = rng.integers(1, 4, n)
    x[:, 11] = rng.uniform(0.2, 2.0, n)
    return x


def test_anomaly_score_direction_and_normalisation():
    x = toy_matrix()
    det = AnomalyDetector(50, 128, seed=3).fit(x)
    outlier = x[:5].copy()
    outlier[:, 2] = 30
    outlier[:, 9] = 8
    outlier[:, 11] = 60
    inl, out = det.score(x[:50]), det.score(outlier)
    assert out.min() > np.median(inl)  # higher == more anomalous
    n = det.normalize(np.concatenate([inl, out]))
    assert n.min() >= 0 and n.max() <= 1 and det.meta["orientation"] == "higher_is_more_anomalous"


def test_anomaly_fit_is_seeded_and_validates_input():
    x = toy_matrix()
    a, b = AnomalyDetector(40, 128, seed=1).fit(x), AnomalyDetector(40, 128, seed=1).fit(x)
    assert np.allclose(a.score(x[:20]), b.score(x[:20]))
    with pytest.raises(ValueError):
        AnomalyDetector().fit(np.zeros((5, 3)))
    with pytest.raises(RuntimeError):
        AnomalyDetector().score(x)


def test_anomaly_save_load_roundtrip_and_tamper_detection(tmp_path):
    x = toy_matrix()
    det = AnomalyDetector(40, 128, seed=2).fit(x)
    meta = det.save(tmp_path)
    loaded = AnomalyDetector.load(tmp_path)
    assert np.allclose(det.score(x[:30]), loaded.score(x[:30])) and meta["model_version"].startswith("if-fv1")
    p = tmp_path / "anomaly.joblib"
    p.write_bytes(p.read_bytes() + b"tamper")
    with pytest.raises(ModelIntegrityError):
        AnomalyDetector.load(tmp_path)
