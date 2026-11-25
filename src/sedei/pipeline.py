"""Detection -> risk -> response pipeline: dataset loading, offline scoring and online replay."""

from __future__ import annotations

import bisect
import json
import time
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np

from sedei.detectors.anomaly import AnomalyDetector
from sedei.detectors.rules import RuleEngine, RuleFinding
from sedei.features import FeatureVector, build_features
from sedei.policy import RoutingPolicy
from sedei.response import ActionResult, Decision, ResponseEngine, decide_contextual, decide_static
from sedei.risk import RiskModel
from sedei.telemetry import SCORED_KINDS, TelemetryIngestor, TelemetryRecord


@dataclass
class Dataset:
    records: list[TelemetryRecord]
    labels: dict[str, bool]
    record_incident: dict[str, str | None]
    episodes: list[dict]
    incidents: list[dict]


def load_dataset(directory: Path | str) -> Dataset:
    d = Path(directory)

    def lines(n: str) -> list[dict]:
        return [json.loads(x) for x in (d / n).read_text(encoding="utf-8").splitlines() if x.strip()]

    recs = [TelemetryRecord(**r) for r in lines("telemetry.jsonl")]
    lab = lines("labels.jsonl")
    return Dataset(recs, {x["record_id"]: bool(x["is_evidence"]) for x in lab},
                   {x["record_id"]: x["incident_id"] for x in lab}, lines("episodes.jsonl"),
                   json.loads((d / "incidents.json").read_text(encoding="utf-8")))


@dataclass
class Scored:
    record: TelemetryRecord
    fv: FeatureVector
    findings: list[RuleFinding]
    rule_score: float


def rule_score(findings: list[RuleFinding]) -> float:
    return float(1.0 - np.prod([1.0 - f.severity for f in findings])) if findings else 0.0


def score_records(records: list[TelemetryRecord], policy: RoutingPolicy, rules: RuleEngine,
                  window_s: float, late_after_s: float) -> list[Scored]:
    """Offline equivalent of the online path. Each record sees only records received by its receipt time."""
    by_key: dict[tuple[str, str], list[TelemetryRecord]] = {}
    for r in sorted(records, key=lambda r: (r.receipt_time, r.record_id)):
        by_key.setdefault(r.key, []).append(r)
    out = []
    for lst in by_key.values():
        times = [r.receipt_time for r in lst]
        for r in lst:
            if r.kind not in SCORED_KINDS:
                continue
            lo = bisect.bisect_left(times, r.receipt_time - window_s)
            hi = bisect.bisect_right(times, r.receipt_time)
            fv = build_features(r, lst[lo:hi], policy, window_s, late_after_s)
            f = rules.evaluate(fv)
            out.append(Scored(r, fv, f, rule_score(f)))
    out.sort(key=lambda s: (s.record.receipt_time, s.record.record_id))
    return out


# ------------------------------------------------------------------------------------------------
@dataclass
class AlertResult:
    record_id: str
    tenant: str
    principal: str
    risk: float
    reasons: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    incident_key: str
    decision: Decision | None
    action: ActionResult | None
    timeline: dict = field(default_factory=dict)


class DetectionPipeline:
    """Online path against the real store: ingest -> features -> rules+anomaly -> risk -> decision -> action."""

    def __init__(self, ing: TelemetryIngestor, policy: RoutingPolicy, rules: RuleEngine,
                 detector: AnomalyDetector | None, risk: RiskModel, alert_t: float,
                 response: ResponseEngine, cfg: dict, mode: str = "contextual") -> None:
        self.ing, self.policy, self.rules, self.det, self.risk = ing, policy, rules, detector, risk
        self.alert_t, self.response, self.cfg, self.mode = alert_t, response, cfg, mode
        self.window = cfg["window_s"]

    def process(self, rec: TelemetryRecord) -> AlertResult | None:
        t_in = time.perf_counter()
        self.ing.ingest(rec)
        hist = self.ing.history(rec.tenant, rec.principal, rec.receipt_time, self.window)
        by_id = {r.record_id: r for r in hist}
        fv = build_features(rec, hist, self.policy, self.window, self.cfg["late_after_s"])
        findings = self.rules.evaluate(fv)
        a_norm = None
        if self.det is not None:
            a_norm = float(self.det.normalize(self.det.score(np.array([fv.as_list()])))[0])
        priv = next((r.privilege for r in reversed(hist) if r.privilege), "standard")
        crit = self.policy.criticality(rec.dest_service) if rec.kind == "service_call" else 1.0
        ass = self.risk.assess(rec.record_id, findings, a_norm, priv, crit)
        t_alert = time.perf_counter()
        if ass.risk < self.alert_t:
            return None
        ev_recs = [by_id[i] for i in ass.evidence_ids if i in by_id]
        event_ref = next((r.event_id for r in ev_recs if r.event_id), None)
        unexp = next((r.dest_service for r in ev_recs if r.kind == "service_call"), None)
        n = self.cfg["response"]["tier_count"]
        d = (decide_contextual(ass, self.alert_t, rec.principal, priv, event_ref, unexp)
             if self.mode == "contextual"
             else decide_static(ass, self.alert_t, rec.principal, event_ref, n))
        t_dec = time.perf_counter()
        key = f"{rec.tenant}:{rec.principal}:{int(rec.receipt_time // self.cfg['response']['incident_window_s'])}"
        act = None
        if d is not None:
            act = self.response.commit(d, incident_key=key, tenant=rec.tenant, principal=rec.principal,
                                       risk=ass.risk, evidence=list(ass.evidence_ids),
                                       reasons=list(ass.reason_codes), now_sim=rec.receipt_time)
        t_commit = time.perf_counter()
        first_ev = min((r.receipt_time for r in ev_recs), default=rec.receipt_time)
        tl = {
            "first_eligible_evidence_sim": first_ev, "alert_sim": rec.receipt_time,
            "policy_decision_sim": rec.receipt_time, "committed_sim": act.committed_sim if act else None,
            "clock_note": "sim = producer/receipt clock of the replayed data; ms fields = monotonic wall time",
            "detect_ms": (t_alert - t_in) * 1e3, "decide_ms": (t_dec - t_alert) * 1e3,
            "commit_ms": (t_commit - t_dec) * 1e3}
        return AlertResult(rec.record_id, rec.tenant, rec.principal, ass.risk, ass.reason_codes,
                           ass.evidence_ids, key, d, act, tl)
