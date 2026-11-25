"""Decision-time features. Only records *received* by the current record's receipt_time are visible."""

from __future__ import annotations

from dataclasses import dataclass, field

from sedei.policy import RoutingPolicy
from sedei.telemetry import TelemetryRecord

FEATURE_VERSION = "fv1"
FEATURE_NAMES = (
    "n_records", "n_decisions", "n_deny", "deny_ratio", "n_denied_routes", "n_scope_denies",
    "n_tenant_mismatch", "n_security_dup", "n_benign_redelivery", "n_unexpected_edges",
    "n_distinct_services", "rate_per_min", "late_ratio", "cur_is_deny", "cur_is_security_dup",
    "cur_is_unexpected_edge", "privilege_elevated",
)


@dataclass(frozen=True)
class FeatureVector:
    version: str
    as_of: float
    values: dict[str, float]
    evidence: dict[str, list[str]] = field(default_factory=dict)

    def as_list(self) -> list[float]:
        return [self.values[n] for n in FEATURE_NAMES]


def classify_deliveries(events: list[TelemetryRecord]) -> tuple[set[str], set[str]]:
    """Split repeat deliveries of one event_id into (benign_redelivery, security_duplicate) record ids.

    Trusted context: the broker sets transport_redelivery. A repeat is benign only if the broker
    asserts it AND emitter and payload hash match the first delivery. Anything else is security-relevant.
    """
    first: dict[tuple[str, str], TelemetryRecord] = {}
    benign: set[str] = set()
    sec: set[str] = set()
    for r in sorted(events, key=lambda x: (x.receipt_time, x.record_id)):
        if r.event_id is None:
            continue
        k = (r.tenant, r.event_id)
        f = first.get(k)
        if f is None:
            first[k] = r
        elif (r.transport_redelivery is True and r.payload_sha256 == f.payload_sha256
              and r.emitter == f.emitter):
            benign.add(r.record_id)
        else:
            sec.add(r.record_id)
    return benign, sec


def build_features(current: TelemetryRecord, history: list[TelemetryRecord], policy: RoutingPolicy,
                   window_s: float, late_after_s: float = 30.0) -> FeatureVector:
    """history may be unordered and may contain duplicates, late arrivals and future records."""
    as_of = current.receipt_time
    seen: dict[str, TelemetryRecord] = {}
    for r in history:
        if r.key != current.key or r.receipt_time > as_of or r.event_time < as_of - window_s:
            continue
        seen.setdefault(r.record_id, r)
    seen.setdefault(current.record_id, current)
    vis = sorted(seen.values(), key=lambda r: (r.receipt_time, r.record_id))

    decisions = [r for r in vis if r.kind == "gateway_decision"]
    denies = [r for r in decisions if r.decision == "deny"]
    deliveries = [r for r in vis if r.kind == "event_delivery"]
    calls = [r for r in vis if r.kind == "service_call"]
    benign, sec = classify_deliveries(deliveries)
    unexpected = [r for r in calls if not policy.edge_expected(r.source_service, r.dest_service)]
    mismatch = [r for r in denies if r.deny_reason == "tenant_mismatch"]
    scope = [r for r in denies if r.deny_reason == "scope_missing"]
    services = {s for r in calls for s in (r.source_service, r.dest_service) if s}
    late = sum(1 for r in vis if r.receipt_time - r.event_time > late_after_s)
    elevated = any(r.privilege == "elevated" for r in vis)

    values = {
        "n_records": float(len(vis)), "n_decisions": float(len(decisions)),
        "n_deny": float(len(denies)),
        "deny_ratio": len(denies) / len(decisions) if decisions else 0.0,
        "n_denied_routes": float(len({r.route for r in denies})),
        "n_scope_denies": float(len(scope)), "n_tenant_mismatch": float(len(mismatch)),
        "n_security_dup": float(len(sec)), "n_benign_redelivery": float(len(benign)),
        "n_unexpected_edges": float(len(unexpected)), "n_distinct_services": float(len(services)),
        "rate_per_min": len(decisions) / (window_s / 60.0),
        "late_ratio": late / len(vis),
        "cur_is_deny": float(current.decision == "deny" and current.kind == "gateway_decision"),
        "cur_is_security_dup": float(current.record_id in sec),
        "cur_is_unexpected_edge": float(any(r.record_id == current.record_id for r in unexpected)),
        "privilege_elevated": float(elevated),
    }
    evidence = {
        "denials": [r.record_id for r in denies], "tenant_mismatch": [r.record_id for r in mismatch],
        "security_dup": sorted(sec), "unexpected_edges": [r.record_id for r in unexpected],
    }
    return FeatureVector(FEATURE_VERSION, as_of, values, evidence)
