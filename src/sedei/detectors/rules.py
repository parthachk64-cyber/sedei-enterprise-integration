"""Transparent rules. Companion design choice: the paper's rule set is not available to this repo."""

from __future__ import annotations

from dataclasses import dataclass

from sedei.features import FeatureVector


@dataclass(frozen=True)
class RuleFinding:
    rule_id: str
    severity: float
    timestamp: float  # receipt time of the record that completed the pattern (simulated/producer clock)
    feature_version: str
    evidence_ids: tuple[str, ...]
    reason_codes: tuple[str, ...]


class RuleEngine:
    def __init__(self, rules_cfg: dict) -> None:
        self.cfg = rules_cfg

    def evaluate(self, fv: FeatureVector) -> list[RuleFinding]:
        v, ev, c = fv.values, fv.evidence, self.cfg
        out: list[RuleFinding] = []

        def add(rid: str, ids: list[str], reasons: tuple[str, ...]) -> None:
            out.append(RuleFinding(rid, float(c[rid]["severity"]), fv.as_of, fv.version,
                                   tuple(sorted(set(ids))), reasons))

        r = c["R1_REPEATED_DENIALS"]
        if v["n_deny"] >= r["min_denies"]:
            add("R1_REPEATED_DENIALS", ev["denials"], ("DENIAL_STORM",))
        r = c["R2_SCOPE_PROBING"]
        if v["n_deny"] >= r["min_denies"] and v["n_denied_routes"] >= r["min_distinct_routes"]:
            add("R2_SCOPE_PROBING", ev["denials"], ("SCOPE_PROBING",))
        if v["n_security_dup"] >= c["R3_INCONSISTENT_REPLAY"]["min_security_dup"]:
            add("R3_INCONSISTENT_REPLAY", ev["security_dup"], ("REPLAY_INCONSISTENT",))
        if v["n_unexpected_edges"] >= c["R4_UNEXPECTED_SERVICE_INTERACTION"]["min_unexpected_edges"]:
            add("R4_UNEXPECTED_SERVICE_INTERACTION", ev["unexpected_edges"], ("UNEXPECTED_SERVICE_EDGE",))
        if v["n_tenant_mismatch"] >= c["R5_CROSS_TENANT_ATTEMPT"]["min_tenant_mismatch"]:
            add("R5_CROSS_TENANT_ATTEMPT", ev["tenant_mismatch"], ("CROSS_TENANT",))
        return sorted(out, key=lambda f: f.rule_id)
