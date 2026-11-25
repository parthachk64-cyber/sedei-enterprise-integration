"""Policy-driven orchestration: order receipt -> inventory reservation -> dispatch authorization.

Each consumer step is ONE transaction: mark-processed + business effect + state transition (checked
against the versioned policy) + outgoing event + telemetry. A crash anywhere inside rolls the whole
step back; a crash after commit but before acknowledgement yields a redelivery that is recognised by
the `processed` table and acknowledged without repeating the effect.
"""

from __future__ import annotations

import hashlib
import itertools
import uuid
from collections.abc import Callable

from sedei.events import EventEnvelope, to_dt
from sedei.policy import RoutingPolicy
from sedei.store import Store
from sedei.telemetry import TelemetryIngestor, TelemetryRecord

CONSUMERS = ("inventory", "dispatch")


class ServiceIsolated(RuntimeError):
    """Raised when the target service is isolated by an active response action."""


class InvalidTransition(RuntimeError):
    pass


class IdFactory:
    def __init__(self, deterministic: bool = False) -> None:
        self._n = itertools.count(1) if deterministic else None

    def next(self, prefix: str) -> str:
        if self._n is None:
            return f"{prefix}-{uuid.uuid4().hex[:16]}"
        return f"{prefix}-{next(self._n):06d}"


class Orchestrator:
    def __init__(self, store: Store, policy: RoutingPolicy, ingestor: TelemetryIngestor,
                 clock: Callable[[], float], ids: IdFactory) -> None:
        self.store, self.policy, self.ing, self.clock, self.ids = store, policy, ingestor, clock, ids

    # ---- telemetry helper ---------------------------------------------------------------------
    def _call(self, tenant: str, principal: str, corr: str, wf: str, src: str, dst: str) -> None:
        now = self.clock()
        self.ing.ingest(TelemetryRecord(
            record_id=self.ids.next("tel"), kind="service_call", tenant=tenant, principal=principal,
            event_time=now, receipt_time=now, correlation_id=corr, workflow_id=wf,
            source_service=src, dest_service=dst))

    # ---- workflow start (called only after the gateway allowed the request) ---------------------
    def start(self, tenant: str, principal: str, order: dict, idem_key: str,
              correlation_id: str) -> tuple[str, bool]:
        wf_id = "wf-" + hashlib.sha256(f"{tenant}|{idem_key}".encode()).hexdigest()[:16]
        now = self.clock()
        with self.store.txn():
            wf, created = self.store.create_workflow(wf_id, tenant, idem_key, principal, correlation_id,
                                                     order, self.policy.initial_state, now)
            if created:
                env = EventEnvelope(
                    event_id=f"ev-{wf}-received", tenant=tenant, emitter="gateway", type="OrderReceived",
                    event_time=to_dt(now), ingest_time=to_dt(now), correlation_id=correlation_id,
                    payload={"workflow_id": wf, "principal": principal, **order})
                self.store.append_event(env, ["inventory"], now)
                self._call(tenant, principal, correlation_id, wf, "gateway", "orchestrator")
        return wf, created

    # ---- consumers ------------------------------------------------------------------------------
    def _step(self, consumer: str, env: EventEnvelope, service: str, frm: str, to: str,
              out_type: str, out_consumers: list[str], effect: Callable[[float], None] | None) -> str:
        if self.store.get_control("isolated", env.tenant, service):
            raise ServiceIsolated(f"{service} isolated for {env.tenant}")
        if not self.policy.transition_allowed(frm, to):
            raise InvalidTransition(f"{frm}->{to} not allowed by {self.policy.version}")
        now = self.clock()
        wf, principal = env.payload["workflow_id"], env.payload["principal"]
        with self.store.txn():
            if not self.store.mark_processed(consumer, env.tenant, env.event_id, now):
                return "duplicate"
            if effect:
                effect(now)
            self.store.transition(wf, frm, to, env.event_id, now, self.policy.version)
            out = EventEnvelope(
                event_id=f"ev-{wf}-{out_type.lower()}", tenant=env.tenant, emitter="orchestrator",
                type=out_type, event_time=to_dt(now), ingest_time=to_dt(now),
                correlation_id=env.correlation_id, causation_id=env.event_id,
                payload={"workflow_id": wf, "principal": principal})
            self.store.append_event(out, out_consumers, now)
            self._call(env.tenant, principal, env.correlation_id, wf, "orchestrator", service)
        return "processed"

    def handle_inventory(self, env: EventEnvelope, attempt: int = 1) -> str:
        def reserve(now: float) -> None:
            with self.store.txn() as c:
                c.execute("INSERT OR IGNORE INTO reservations VALUES(?,?,?,?,?)",
                          (env.tenant, env.payload["workflow_id"], env.payload.get("sku"),
                           env.payload.get("quantity"), now))
        return self._step("inventory", env, "inventory-svc", "RECEIVED", "RESERVED",
                          "InventoryReserved", ["dispatch"], reserve)

    def handle_dispatch(self, env: EventEnvelope, attempt: int = 1) -> str:
        return self._step("dispatch", env, "dispatch-svc", "RESERVED", "DISPATCH_AUTHORIZED",
                          "DispatchAuthorized", [], None)

    def handlers(self) -> dict[str, Callable[[EventEnvelope, int], str]]:
        return {"inventory": self.handle_inventory, "dispatch": self.handle_dispatch}
