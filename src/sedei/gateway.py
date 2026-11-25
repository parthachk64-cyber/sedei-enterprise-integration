"""Security-aware gateway: authenticate -> controls -> authorize -> validate -> (only then) start workflow.

A denied request never starts a business workflow. Every outcome is recorded as a redacted
gateway_decision telemetry record (no token, no request body) carrying a correlation ID.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from sedei.identity import AuthError, Principal, TestIssuer
from sedei.orchestration import IdFactory, Orchestrator
from sedei.policy import RoutingPolicy
from sedei.store import Store
from sedei.telemetry import TelemetryIngestor, TelemetryRecord

log = logging.getLogger("sedei.gateway")


class OrderRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tenant: str = Field(pattern=r"^[a-z0-9\-]{1,40}$")
    sku: str = Field(pattern=r"^[A-Z0-9\-]{3,20}$")
    quantity: int = Field(ge=1, le=100)


@dataclass(frozen=True)
class GatewayResult:
    status: int
    decision: str  # allow | deny
    reason: str
    correlation_id: str
    workflow_id: str | None = None
    created: bool | None = None


class Gateway:
    def __init__(self, store: Store, policy: RoutingPolicy, issuer: TestIssuer, orch: Orchestrator,
                 ingestor: TelemetryIngestor, clock: Callable[[], float], ids: IdFactory) -> None:
        self.store, self.policy, self.issuer, self.orch = store, policy, issuer, orch
        self.ing, self.clock, self.ids = ingestor, clock, ids

    def _record(self, corr: str, tenant: str, principal: str, route: str, decision: str,
                reason: str | None, privilege: str | None, wf: str | None = None) -> None:
        now = self.clock()
        self.ing.ingest(TelemetryRecord(
            record_id=self.ids.next("tel"), kind="gateway_decision", tenant=tenant, principal=principal,
            event_time=now, receipt_time=now, correlation_id=corr, workflow_id=wf, route=route,
            decision=decision, deny_reason=reason, privilege=privilege))  # type: ignore[arg-type]
        log.info("gateway decision corr=%s tenant=%s principal=%s route=%s decision=%s reason=%s",
                 corr, tenant, principal, route, decision, reason)  # never logs token or body

    def _deny(self, status: int, reason: str, corr: str, tenant: str, principal: str, route: str,
              privilege: str | None) -> GatewayResult:
        self._record(corr, tenant, principal, route, "deny", reason, privilege)
        return GatewayResult(status, "deny", reason, corr)

    def _rate_limited(self, p: Principal, ctl: dict) -> bool:
        win, mx = ctl["params"]["window_s"], ctl["params"]["max_per_window"]
        now = self.clock()
        n = self.store.q1(
            "SELECT COUNT(*) n FROM telemetry WHERE tenant=? AND principal=? AND kind='gateway_decision' "
            "AND json_extract(body_json,'$.decision')='allow' AND receipt_time>?",
            (p.tenant, p.subject, now - win))["n"]
        return n >= mx

    def handle(self, method: str, path: str, token: str | None, body: dict,
               idempotency_key: str | None = None) -> GatewayResult:
        corr = self.ids.next("corr")
        route = f"{method.upper()} {path}"
        now = self.clock()
        try:
            p = self.issuer.verify(token or "", now)
        except AuthError as e:
            return self._deny(401, e.reason, corr, "-", "anonymous", route, None)
        t, s = p.tenant, p.subject

        def deny(code: int, reason: str) -> GatewayResult:
            return self._deny(code, reason, corr, t, s, route, p.privilege)

        if self.store.get_control("revoked", t, s):
            return deny(403, "credential_revoked")
        if self.store.get_control("blocked", t, s):
            return deny(403, "access_blocked")
        if self.store.get_control("challenge", t, s) and not p.stepup:
            return deny(401, "step_up_required")
        rl = self.store.get_control("rate_limited", t, s)
        if rl and self._rate_limited(p, rl):
            return deny(429, "rate_limited")
        rp = self.policy.route_for(method, path)
        if rp is None:
            return deny(404, "route_not_found")
        if any(str(k).startswith("_") for k in body):  # transport-level marker for oversize/unparseable bodies
            return deny(422, "invalid_input")
        if rp.scope not in p.scopes:
            return deny(403, "scope_missing")
        if body.get("tenant") != p.tenant:
            return deny(403, "tenant_mismatch")
        try:
            order = OrderRequest(**body)
        except (ValidationError, TypeError):
            return deny(422, "invalid_input")
        idem = idempotency_key or self.ids.next("idem")
        wf, created = self.orch.start(t, s, order.model_dump(exclude={"tenant"}), idem, corr)
        self._record(corr, t, s, route, "allow", None, p.privilege, wf)
        return GatewayResult(202 if created else 200, "allow", "accepted", corr, wf, created)
