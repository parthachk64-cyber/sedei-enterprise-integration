"""Three-trace walkthrough, executed against the real store, gateway, worker, detectors and response engine.

 1. authorized order completes, one trace across gateway decision / events / service calls
 2. ordinary transport redelivery after a worker crash: fulfillment once, identity stays active
 3. pre-authored incident fixture -> alert -> policy decision -> committed local quarantine; other
    tenant untouched; reprocessing yields no second action

Clock notes: `sim` timestamps come from the replayed data / SimClock; `ms` are monotonic wall-time.
"""

from __future__ import annotations

import json
from pathlib import Path

from sedei import audit
from sedei.config import DATA_DIR, RUNS_DIR, load_detection
from sedei.detectors.anomaly import AnomalyDetector
from sedei.detectors.rules import RuleEngine
from sedei.events import EventEnvelope, to_dt
from sedei.experiment import split_masks, train_model
from sedei.pipeline import DetectionPipeline, load_dataset
from sedei.risk import RiskModel
from sedei.system import SimClock, System, build_system
from sedei.telemetry import TelemetryRecord
from sedei.worker import SimulatedCrash

ORDER = {"sku": "SKU-1001", "quantity": 2}


_MODEL_CACHE: dict[str, AnomalyDetector] = {}


def _pipeline(sys_: System, model_dir: Path, mode: str = "contextual") -> DetectionPipeline:
    cfg = sys_.cfg
    key = str(model_dir)
    if key not in _MODEL_CACHE:
        _MODEL_CACHE[key] = AnomalyDetector.load(model_dir)
    det = _MODEL_CACHE[key]
    thr = json.loads((model_dir / "thresholds.json").read_text())["thresholds"]["hybrid"]
    return DetectionPipeline(sys_.ingestor, sys_.policy, RuleEngine(cfg["rules"]), det,
                             RiskModel(cfg["risk"]), thr, sys_.response, cfg, mode)


def trace_workflow(s: System, workflow_id: str) -> dict:
    wf = s.store.get_workflow(workflow_id)
    corr = wf["correlation_id"]
    tel = [json.loads(r["body_json"]) for r in s.store.q(
        "SELECT body_json FROM telemetry WHERE json_extract(body_json,'$.correlation_id')=? "
        "ORDER BY receipt_time, record_id", (corr,))]
    return {
        "workflow": {k: wf[k] for k in ("workflow_id", "tenant", "principal", "state", "correlation_id",
                                         "version")},
        "transitions": [dict(r) for r in s.store.q(
            "SELECT from_state,to_state,event_id,at,policy_version FROM transitions WHERE workflow_id=? "
            "ORDER BY id", (workflow_id,))],
        "deliveries": [dict(r) for r in s.store.q(
            "SELECT d.event_id,d.consumer,d.state,d.attempts FROM deliveries d JOIN events e ON "
            "e.tenant=d.tenant AND e.event_id=d.event_id WHERE e.correlation_id=? ORDER BY d.event_id,d.consumer",
            (corr,))],
        "telemetry": tel,
        "reservations": s.store.q1("SELECT COUNT(*) n FROM reservations WHERE tenant=? AND workflow_id=?",
                                   (wf["tenant"], workflow_id))["n"],
    }


def _tl(first: float | None, alert=None, decision=None, committed=None, note: str = "") -> dict:
    return {"first_eligible_evidence_sim": first, "alert_sim": alert, "policy_decision_sim": decision,
            "committed_sim": committed, "note": note}


def run_trace1(out: Path, model_dir: Path) -> dict:
    clock = SimClock()
    s = build_system(str(out / "trace1.sqlite"), clock, deterministic_ids=True)
    tok = s.issuer.issue("tenant-a", "svc-07", clock())
    r = s.gateway.handle("POST", "/v1/orders", tok, {"tenant": "tenant-a", **ORDER}, "demo-1")
    clock.advance(1)
    s.worker.drain()
    pipe = _pipeline(s, model_dir)
    alerts = [pipe.process(TelemetryRecord(**json.loads(x["body_json"]))) for x in s.store.q(
        "SELECT body_json FROM telemetry ORDER BY receipt_time, record_id")]
    tr = trace_workflow(s, r.workflow_id)
    tr.update(scenario="1_authorized_order_completes", gateway_result=r.__dict__,
              alerts=[a for a in alerts if a], timeline=_tl(
                  tr["telemetry"][0]["receipt_time"], note="no alert, no action (authorized completion)"))
    tr["assertions"] = {"workflow_completed": tr["workflow"]["state"] == "DISPATCH_AUTHORIZED",
                        "all_stages_share_correlation_id": len({t["correlation_id"] for t in tr["telemetry"]}) == 1,
                        "stage_kinds": sorted({t["kind"] for t in tr["telemetry"]}), "no_alert": not tr["alerts"]}
    return tr


def run_trace2(out: Path, model_dir: Path) -> dict:
    clock = SimClock()
    db = str(out / "trace2.sqlite")
    s = build_system(db, clock, deterministic_ids=True)
    tok = s.issuer.issue("tenant-a", "user-03", clock())
    r = s.gateway.handle("POST", "/v1/orders", tok, {"tenant": "tenant-a", **ORDER}, "demo-2")
    clock.advance(1)
    crashed = False
    try:
        s.worker.run_once("inventory", crash_before_ack=True)
    except SimulatedCrash:
        crashed = True
    s.store.close()
    # "restart": new process objects over the same durable file; lease expires, delivery returns
    clock.advance(31)
    s2 = build_system(db, clock, deterministic_ids=False)
    s2.worker.drain()
    clock.advance(1)
    s2.worker.drain()
    pipe = _pipeline(s2, model_dir)
    alerts = [pipe.process(TelemetryRecord(**json.loads(x["body_json"]))) for x in s2.store.q(
        "SELECT body_json FROM telemetry ORDER BY receipt_time, record_id")]
    tr = trace_workflow(s2, r.workflow_id)
    inv = [d for d in tr["deliveries"] if d["consumer"] == "inventory"][0]
    redeliveries = [t for t in tr["telemetry"] if t["kind"] == "event_delivery" and t["delivery_attempt"] > 1]
    tr.update(scenario="2_ordinary_redelivery_exactly_once", crash_injected=crashed,
              alerts=[a for a in alerts if a],
              timeline=_tl(tr["telemetry"][0]["receipt_time"],
                           note="redelivery classified benign (broker-asserted, same hash/emitter): no alert"))
    tr["assertions"] = {
        "crash_between_processing_and_ack": crashed, "inventory_delivery_attempts": inv["attempts"],
        "fulfillment_effects": tr["reservations"], "fulfillment_once": tr["reservations"] == 1,
        "workflow_completed": tr["workflow"]["state"] == "DISPATCH_AUTHORIZED",
        "redelivery_records_seen": len(redeliveries), "no_alert": not tr["alerts"],
        "identity_active": s2.store.get_control("revoked", "tenant-a", "user-03") is None
        and s2.store.get_control("blocked", "tenant-a", "user-03") is None}
    return tr


def pick_incident(ds, model_dir: Path, cfg: dict) -> tuple[dict, list[TelemetryRecord]]:
    """First held-in test-split replay incident whose contextual decision is an event quarantine."""
    masks = split_masks(ds, cfg)
    by_id = {r.record_id: r for r in ds.records}
    eps = {e["episode_id"]: e for e in ds.episodes}
    for inc in ds.incidents:
        if inc["scenario"] != "replay_injection" or inc["stealth"]:
            continue
        ep = eps[inc["episode_id"]]
        if masks[ep["record_ids"][0]] != "test":
            continue
        recs = sorted((by_id[i] for i in ep["record_ids"]), key=lambda r: (r.receipt_time, r.record_id))
        scratch = build_system(":memory:", SimClock(), deterministic_ids=True)
        pipe = _pipeline(scratch, model_dir)
        for r in recs:
            a = pipe.process(r)
            if a and a.decision and a.decision.action_type.value == "event_quarantine":
                return inc, recs
    raise RuntimeError("no suitable incident fixture found")


def run_trace3(out: Path, model_dir: Path, data_dir: Path) -> dict:
    ds = load_dataset(data_dir)
    cfg = load_detection()
    inc, recs = pick_incident(ds, model_dir, cfg)
    vt, vp = inc["tenant"], inc["principal"]
    bt = "tenant-b" if vt == "tenant-a" else "tenant-a"
    clock = SimClock(recs[0].receipt_time - 120)
    s = build_system(str(out / "trace3.sqlite"), clock, deterministic_ids=False)

    first_ev = next(r.event_id for r in recs if r.event_id)
    # live pending event for the incident principal (victim tenant) and a same-id event in the other tenant
    for tenant in (vt, bt):
        s.store.create_workflow(f"wf-{tenant}-fixture", tenant, "fixture", vp, f"c-{tenant}-fixture",
                                ORDER, "RECEIVED", clock())
        s.store.append_event(EventEnvelope(
            event_id=first_ev, tenant=tenant, emitter="gateway", type="OrderReceived",
            event_time=to_dt(clock()), ingest_time=to_dt(clock()), correlation_id=f"c-{tenant}-fixture",
            payload={"workflow_id": f"wf-{tenant}-fixture", "principal": vp, **ORDER}), ["inventory"], clock())
    # other tenant's own ordinary order through the gateway, same local principal id
    bsub = vp if s.issuer.is_fixture_identity(bt, vp) else "svc-07"
    btok = s.issuer.issue(bt, bsub, clock())
    bres = s.gateway.handle("POST", "/v1/orders", btok, {"tenant": bt, **ORDER}, "bystander-1")

    pipe = _pipeline(s, model_dir)
    results = []
    for r in recs:
        clock.set(max(clock(), r.receipt_time))
        a = pipe.process(r)
        if a:
            results.append(a)
    first = results[0]
    n_act = s.store.q1("SELECT COUNT(*) n FROM actions")["n"]
    n_aud = s.store.q1("SELECT COUNT(*) n FROM audit")["n"]
    again = pipe.process(next(r for r in recs if r.record_id == first.record_id))  # reprocess
    n_act2 = s.store.q1("SELECT COUNT(*) n FROM actions")["n"]
    n_aud2 = s.store.q1("SELECT COUNT(*) n FROM audit")["n"]
    clock.set(clock() + 1)
    s.worker.drain()
    quarantined = s.store.q1("SELECT state FROM deliveries WHERE tenant=? AND event_id=? AND consumer='inventory'",
                             (vt, first_ev))["state"]
    other = s.store.q1("SELECT state FROM deliveries WHERE tenant=? AND event_id=? AND consumer='inventory'",
                       (bt, first_ev))["state"]
    bwf = s.store.get_workflow(bres.workflow_id)["state"]
    act = s.store.q1("SELECT * FROM actions ORDER BY committed_sim LIMIT 1")
    findings = pipe.rules.evaluate(next(x for x in [pipe_features(pipe, recs, first.record_id)]))
    tl = dict(first.timeline, alert_record_id=first.record_id, incident_id=inc["incident_id"],
              first_eligible_evidence_sim=inc["first_evidence_receipt"])  # first labelled evidence in the fixture
    return {
        "scenario": "3_incident_fixture_quarantine", "incident": {k: inc[k] for k in (
            "incident_id", "scenario", "family", "tenant", "principal", "evidence_record_ids")},
        "timeline": tl,
        "rule_findings": [f.__dict__ for f in findings],
        "risk": first.risk, "reason_codes": list(first.reasons), "evidence_ids": list(first.evidence_ids),
        "decision": {"action": first.decision.action_type.value, "target": f"{first.decision.target_kind}:"
                     f"{first.decision.target_id}", "reason": first.decision.reason,
                     "policy": first.decision.policy},
        "action": {k: act[k] for k in ("action_id", "action_type", "status", "target_id", "committed_sim",
                                       "expires_at")},
        "audit_chain_valid": audit.verify_chain(s.store),
        "audit": [{"kind": r["kind"], "scope": r["scope"], "policy_version": r["policy_version"],
                   "evidence": json.loads(r["evidence_json"])} for r in audit.entries(s.store)],
        "assertions": {
            "victim_event_state": quarantined, "other_tenant_same_event_id_state": other,
            "other_tenant_workflow_state": bwf,
            "actions_before_reprocess": n_act, "actions_after_reprocess": n_act2,
            "audit_rows_before": n_aud, "audit_rows_after": n_aud2,
            "reprocess_reported_deduplicated": bool(again and again.action and again.action.deduplicated),
            "no_second_action": n_act == n_act2 and n_aud == n_aud2,
            "other_tenant_untouched": other != "quarantined" and bwf == "DISPATCH_AUTHORIZED"},
        "episode_timeline": [{"record_id": r.record_id, "kind": r.kind, "receipt_time": r.receipt_time,
                              "is_evidence": r.record_id in set(inc["evidence_record_ids"]),
                              "detail": r.event_id or r.deny_reason or r.dest_service or r.decision}
                             for r in recs],
        "fixture_note": "pre-authored telemetry replayed from data/; event ids re-keyed to the live pending event",
    }


def pipe_features(pipe: DetectionPipeline, recs: list[TelemetryRecord], record_id: str):
    from sedei.features import build_features
    cur = next(r for r in recs if r.record_id == record_id)
    return build_features(cur, [r for r in recs if r.receipt_time <= cur.receipt_time], pipe.policy,
                          pipe.window, pipe.cfg["late_after_s"])


def fmt_timeline(name: str, tl: dict) -> str:
    def f(x):
        return "-" if x is None else f"{x:.3f}"
    line = (f"{name:<38} first_evidence={f(tl['first_eligible_evidence_sim'])}  alert={f(tl['alert_sim'])}  "
            f"decision={f(tl['policy_decision_sim'])}  committed={f(tl['committed_sim'])}")
    extra = ""
    if "detect_ms" in tl:
        extra = (f"\n{'':<38} (monotonic wall ms: detect={tl['detect_ms']:.2f} decide={tl['decide_ms']:.2f} "
                 f"commit={tl['commit_ms']:.2f})")
    return line + extra


def ensure_model(data_dir: Path, runs_dir: Path) -> Path:
    from sedei.config import sha256_file
    cfg = load_detection()
    run = Path(runs_dir) / f"train-{sha256_file(Path(data_dir) / 'telemetry.jsonl')[:8]}-s{cfg['anomaly']['seed']}"
    if (run / "model" / "thresholds.json").exists() and (run / "model" / "anomaly.joblib").exists():
        return run
    return train_model(data_dir, runs_dir)


def run_demo(runs_dir: Path = RUNS_DIR, data_dir: Path = DATA_DIR) -> tuple[Path, list[dict]]:
    model_run = ensure_model(data_dir, runs_dir)
    out = Path(runs_dir) / "demo"
    out.mkdir(parents=True, exist_ok=True)
    for f in out.glob("*.sqlite*"):
        f.unlink()
    traces = [run_trace1(out, model_run / "model"), run_trace2(out, model_run / "model"),
              run_trace3(out, model_run / "model", Path(data_dir))]
    for i, t in enumerate(traces, 1):
        (out / f"trace_{i}.json").write_text(json.dumps(t, indent=1, sort_keys=True, default=str))
    return out, traces

