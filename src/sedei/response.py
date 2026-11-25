"""Adaptive response: decision (what policy says) and action (what was committed) are stored separately.

Six actions, each exercised through local state transitions in the `controls`/`deliveries` tables:
auth_challenge, rate_limit, event_quarantine, access_block, credential_revocation, service_isolation.
Credential revocation and service isolation are restricted to fixture identities/services declared in
configs/identities.yaml. Actions are deduplicated by (type, tenant, target, incident_key), bounded
where appropriate (auth_challenge, rate_limit, event_quarantine, access_block expire; revocation and
isolation require explicit recover()), and every change is written to the hash-chained audit log.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from enum import Enum

from sedei import audit
from sedei.identity import TestIssuer
from sedei.risk import RiskAssessment
from sedei.store import Store


class ActionType(str, Enum):
    AUTH_CHALLENGE = "auth_challenge"
    RATE_LIMIT = "rate_limit"
    EVENT_QUARANTINE = "event_quarantine"
    ACCESS_BLOCK = "access_block"
    CREDENTIAL_REVOCATION = "credential_revocation"
    SERVICE_ISOLATION = "service_isolation"


TIER_ORDER = (ActionType.AUTH_CHALLENGE, ActionType.RATE_LIMIT, ActionType.EVENT_QUARANTINE,
              ActionType.ACCESS_BLOCK, ActionType.CREDENTIAL_REVOCATION)
SEVERE = frozenset({ActionType.ACCESS_BLOCK, ActionType.CREDENTIAL_REVOCATION,
                    ActionType.SERVICE_ISOLATION})
EXPLICIT_RECOVERY = frozenset({ActionType.CREDENTIAL_REVOCATION, ActionType.SERVICE_ISOLATION})


@dataclass(frozen=True)
class Decision:
    action_type: ActionType
    target_kind: str  # principal | event | service
    target_id: str
    reason: str
    policy: str  # static | contextual


def tier_thresholds(alert_t: float, n: int = 5) -> list[float]:
    return [alert_t + k * (1.0 - alert_t) / n for k in range(n)]


def _tier(risk: float, alert_t: float, n: int) -> int:
    return max(k for k, t in enumerate(tier_thresholds(alert_t, n)) if risk >= t - 1e-12)


def decide_static(a: RiskAssessment, alert_t: float, principal: str, event_ref: str | None,
                  n_tiers: int = 5) -> Decision | None:
    """Risk-only ladder. Ignores identity, service and evidence context."""
    if not (a.risk >= alert_t):
        return None
    act = TIER_ORDER[_tier(a.risk, alert_t, n_tiers)]
    if act is ActionType.EVENT_QUARANTINE:
        if event_ref is None:
            return Decision(ActionType.RATE_LIMIT, "principal", principal,
                            "static: quarantine tier without event reference", "static")
        return Decision(act, "event", event_ref, "static: risk tier", "static")
    return Decision(act, "principal", principal, "static: risk tier", "static")


def decide_contextual(a: RiskAssessment, alert_t: float, principal: str, privilege: str,
                      event_ref: str | None, unexpected_dest: str | None) -> Decision | None:
    """Evidence- and context-aware mapping with the same alert gate as the static policy."""
    if not (a.risk >= alert_t):
        return None
    reasons = set(a.reason_codes)
    multi = len(reasons) >= 2
    elevated = privilege == "elevated"
    if "UNEXPECTED_SERVICE_EDGE" in reasons and unexpected_dest:
        if multi and elevated:
            return Decision(ActionType.CREDENTIAL_REVOCATION, "principal", principal,
                            "multi-stage evidence incl. unexpected service edge, elevated identity", "contextual")
        return Decision(ActionType.SERVICE_ISOLATION, "service", unexpected_dest,
                        "unexpected service interaction", "contextual")
    if "CROSS_TENANT" in reasons:
        act = ActionType.CREDENTIAL_REVOCATION if (multi or elevated) else ActionType.ACCESS_BLOCK
        return Decision(act, "principal", principal, "tenant-boundary violation", "contextual")
    if "REPLAY_INCONSISTENT" in reasons and event_ref:
        if multi and elevated:
            return Decision(ActionType.ACCESS_BLOCK, "principal", principal,
                            "replay plus further evidence, elevated identity", "contextual")
        return Decision(ActionType.EVENT_QUARANTINE, "event", event_ref,
                        "inconsistent replayed event", "contextual")
    if reasons & {"DENIAL_STORM", "SCOPE_PROBING"}:
        act = ActionType.ACCESS_BLOCK if (multi and elevated) else ActionType.RATE_LIMIT
        return Decision(act, "principal", principal, "denial pattern", "contextual")
    return Decision(ActionType.AUTH_CHALLENGE, "principal", principal,
                    "anomaly without rule evidence: low-confidence step-up", "contextual")


@dataclass(frozen=True)
class ActionResult:
    action_id: str
    status: str  # committed | refused | expired | recovered
    deduplicated: bool
    committed_sim: float | None
    committed_wall: float | None
    decision_id: str


class ResponseEngine:
    def __init__(self, store: Store, issuer: TestIssuer, policy_version: str, durations_s: dict[str, float]):
        self.store, self.issuer = store, issuer
        self.policy_version, self.durations = policy_version, durations_s

    def commit(self, d: Decision, *, incident_key: str, tenant: str, principal: str, risk: float,
               evidence: list[str], reasons: list[str], now_sim: float) -> ActionResult:
        dedup_key = f"{d.action_type.value}|{tenant}|{d.target_kind}|{d.target_id}|{incident_key}"
        h = hashlib.sha256(dedup_key.encode()).hexdigest()
        decision_id, action_id = f"dec-{h[:16]}", f"act-{h[:16]}"
        with self.store.txn() as c:
            row = c.execute("SELECT * FROM actions WHERE dedup_key=?", (dedup_key,)).fetchone()
            if row is not None:
                return ActionResult(row["action_id"], row["status"], True, row["committed_sim"],
                                    row["committed_wall"], row["decision_id"])
            c.execute("INSERT OR IGNORE INTO decisions VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                      (decision_id, incident_key, tenant, d.action_type.value, d.target_kind, d.target_id,
                       risk, self.policy_version, json.dumps(sorted(evidence)), json.dumps(reasons),
                       now_sim, time.time()))
            refusal = self._restriction(d, tenant)
            if refusal:
                c.execute("INSERT INTO actions VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                          (action_id, dedup_key, decision_id, d.action_type.value, tenant, d.target_kind,
                           d.target_id, "refused", None, None, None, refusal))
                audit.append(self.store, at=now_sim, kind="action_refused", actor="response-engine",
                             principal=principal, tenant=tenant, policy_version=self.policy_version,
                             scope=f"{d.target_kind}:{d.target_id}", evidence=sorted(evidence),
                             detail={"action": d.action_type.value, "why": refusal})
                return ActionResult(action_id, "refused", False, None, None, decision_id)
            note = self._apply(d, tenant, action_id)
            dur = None if d.action_type in EXPLICIT_RECOVERY else self.durations.get(d.action_type.value)
            expires = None if dur is None else now_sim + dur
            wall = time.time()
            c.execute("INSERT INTO actions VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                      (action_id, dedup_key, decision_id, d.action_type.value, tenant, d.target_kind,
                       d.target_id, "committed", now_sim, wall, expires, note))
            audit.append(self.store, at=now_sim, kind="action_committed", actor="response-engine",
                         principal=principal, tenant=tenant, policy_version=self.policy_version,
                         scope=f"{d.target_kind}:{d.target_id}", evidence=sorted(evidence),
                         detail={"action": d.action_type.value, "reason": d.reason, "risk": round(risk, 4),
                                 "expires_at": expires, "note": note})
            return ActionResult(action_id, "committed", False, now_sim, wall, decision_id)

    def _restriction(self, d: Decision, tenant: str) -> str | None:
        if d.action_type is ActionType.CREDENTIAL_REVOCATION and not self.issuer.is_fixture_identity(
                tenant, d.target_id):
            return "revocation restricted to fixture identities"
        if d.action_type is ActionType.SERVICE_ISOLATION and d.target_id not in self.issuer.fixture_services:
            return "isolation restricted to fixture services"
        return None

    def _apply(self, d: Decision, tenant: str, action_id: str) -> str:
        s, t = self.store, d.action_type
        if t is ActionType.AUTH_CHALLENGE:
            s.set_control("challenge", tenant, d.target_id, action_id)
        elif t is ActionType.RATE_LIMIT:
            s.set_control("rate_limited", tenant, d.target_id, action_id,
                          {"max_per_window": 5, "window_s": 60})
        elif t is ActionType.EVENT_QUARANTINE:
            n = s.quarantine_event(tenant, d.target_id)
            return f"deliveries_quarantined={n}"
        elif t is ActionType.ACCESS_BLOCK:
            s.set_control("blocked", tenant, d.target_id, action_id)
        elif t is ActionType.CREDENTIAL_REVOCATION:
            s.set_control("revoked", tenant, d.target_id, action_id)
        elif t is ActionType.SERVICE_ISOLATION:
            s.set_control("isolated", tenant, d.target_id, action_id)
        return ""

    _CONTROL = {"auth_challenge": "challenge", "rate_limit": "rate_limited", "access_block": "blocked",
                "credential_revocation": "revoked", "service_isolation": "isolated"}

    def _undo(self, row, new_status: str, actor: str, now: float) -> None:
        with self.store.txn():
            if row["action_type"] == "event_quarantine":
                self.store.release_quarantine(row["tenant"], row["target_id"], now)
            else:
                self.store.clear_control(self._CONTROL[row["action_type"]], row["tenant"], row["target_id"])
            self.store.set_action_status(row["action_id"], new_status)
            audit.append(self.store, at=now, kind=f"action_{new_status}", actor=actor, principal=None,
                         tenant=row["tenant"], policy_version=self.policy_version,
                         scope=f"{row['target_kind']}:{row['target_id']}", evidence=[],
                         detail={"action": row["action_type"], "action_id": row["action_id"]})

    def expire_due(self, now: float) -> int:
        rows = self.store.q("SELECT * FROM actions WHERE status='committed' AND expires_at IS NOT NULL "
                            "AND expires_at<=?", (now,))
        for r in rows:
            self._undo(r, "expired", "system", now)
        return len(rows)

    def recover(self, action_id: str, approver: str, now: float) -> bool:
        r = self.store.q1("SELECT * FROM actions WHERE action_id=? AND status='committed'", (action_id,))
        if r is None:
            return False
        self._undo(r, "recovered", approver, now)
        return True
