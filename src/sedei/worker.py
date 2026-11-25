"""Recoverable worker: claim -> telemetry -> handle -> ack, with bounded retry and dead-lettering."""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable

from sedei.events import EventEnvelope, to_epoch
from sedei.orchestration import IdFactory
from sedei.store import Store
from sedei.telemetry import TelemetryIngestor, TelemetryRecord


class SimulatedCrash(RuntimeError):
    """Fault injection: process dies after the handler committed but before the ack."""


class Worker:
    def __init__(self, store: Store, handlers: dict[str, Callable[[EventEnvelope, int], str]],
                 ingestor: TelemetryIngestor, clock: Callable[[], float], ids: IdFactory,
                 lease_s: float = 30.0, max_attempts: int = 3, backoff_base_s: float = 1.0) -> None:
        self.store, self.handlers, self.ing, self.clock, self.ids = store, handlers, ingestor, clock, ids
        self.lease_s, self.max_attempts, self.backoff = lease_s, max_attempts, backoff_base_s
        self.stats: Counter[str] = Counter()

    def _delivery_telemetry(self, env: EventEnvelope, attempt: int) -> None:
        now = self.clock()
        self.ing.ingest(TelemetryRecord(
            record_id=self.ids.next("tel"), kind="event_delivery", tenant=env.tenant,
            principal=env.payload.get("principal", env.emitter), event_time=to_epoch(env.event_time),
            receipt_time=now, correlation_id=env.correlation_id, workflow_id=env.payload.get("workflow_id"),
            event_id=env.event_id, event_type=env.type, emitter=env.emitter,
            payload_sha256=env.payload_sha256(), delivery_attempt=attempt,
            transport_redelivery=attempt > 1))

    def run_once(self, consumer: str, *, crash_before_ack: bool = False, limit: int = 10) -> int:
        claimed = self.store.claim(consumer, self.clock(), self.lease_s, limit)
        for c in claimed:
            env = self.store.get_event(c["tenant"], c["event_id"])
            if env is None:  # pragma: no cover - events are never deleted
                continue
            self._delivery_telemetry(env, c["attempt"])
            try:
                result = self.handlers[consumer](env, c["attempt"])
            except Exception as exc:  # noqa: BLE001 - any handler failure takes the retry path
                verdict = self.store.nack(consumer, env.tenant, env.event_id, repr(exc), self.clock(),
                                          self.max_attempts, self.backoff)
                self.stats[verdict] += 1
                continue
            if crash_before_ack:
                raise SimulatedCrash(f"crash after processing {env.event_id}, before ack")
            self.store.ack(consumer, env.tenant, env.event_id, self.clock())
            self.stats[result] += 1
            self.stats["acked"] += 1
        return len(claimed)

    def drain(self, max_rounds: int = 20) -> int:
        total = 0
        for _ in range(max_rounds):
            n = sum(self.run_once(c) for c in self.handlers)
            total += n
            if n == 0:
                break
        return total
