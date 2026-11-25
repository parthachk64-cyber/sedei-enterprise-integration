"""Unified security telemetry: typed records, tenant-scoped ingest, duplicate and late handling.

Clock conventions (see docs/architecture.md):
  event_time    when the thing happened, producer clock (simulated epoch seconds in the synthetic data)
  receipt_time  when telemetry reached the collector; the only time a detector may rely on
Processing time is measured separately with a monotonic clock and never mixed into these.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from sedei.store import Store

Kind = Literal["gateway_decision", "identity_context", "service_call", "event_delivery"]
SCORED_KINDS = ("gateway_decision", "service_call", "event_delivery")
ID = r"^[A-Za-z0-9_.:\-/ ]{1,120}$"


class TelemetryRecord(BaseModel):
    """Observable fields only. Labels, scenario names and response decisions do not exist here."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    record_id: str = Field(pattern=ID)
    kind: Kind
    tenant: str = Field(pattern=ID)
    principal: str = Field(pattern=ID)  # local identifier: unique only within a tenant
    event_time: float
    receipt_time: float
    correlation_id: str | None = None
    workflow_id: str | None = None
    route: str | None = None
    decision: Literal["allow", "deny"] | None = None
    deny_reason: str | None = None
    privilege: Literal["standard", "elevated"] | None = None
    source_service: str | None = None
    dest_service: str | None = None
    event_id: str | None = None
    event_type: str | None = None
    emitter: str | None = None
    payload_sha256: str | None = None
    delivery_attempt: int | None = None
    transport_redelivery: bool | None = None  # asserted by the trusted broker, not the producer

    @property
    def key(self) -> tuple[str, str]:
        return (self.tenant, self.principal)


class IngestResult(BaseModel):
    status: Literal["accepted", "duplicate"]
    late: bool


class TelemetryIngestor:
    """Writes records to the store. Duplicate record_ids are dropped (counted), late ones flagged."""

    def __init__(self, store: Store, late_after_s: float = 30.0) -> None:
        self.store = store
        self.late_after_s = late_after_s
        self.duplicates_dropped = 0

    def ingest(self, rec: TelemetryRecord) -> IngestResult:
        late = (rec.receipt_time - rec.event_time) > self.late_after_s
        ok = self.store.insert_telemetry(
            rec.record_id, rec.tenant, rec.principal, rec.kind, rec.event_time,
            rec.receipt_time, late, rec.model_dump(mode="json"))
        if not ok:
            self.duplicates_dropped += 1
        return IngestResult(status="accepted" if ok else "duplicate", late=late)

    def history(self, tenant: str, principal: str, as_of: float, window_s: float) -> list[TelemetryRecord]:
        """Records for this tenant+principal that were *received* by as_of (so available at decision time)."""
        import json
        rows = self.store.q(
            "SELECT body_json FROM telemetry WHERE tenant=? AND principal=? AND receipt_time<=? "
            "AND event_time>=? ORDER BY receipt_time, record_id",
            (tenant, principal, as_of, as_of - window_s))
        return [TelemetryRecord(**json.loads(r["body_json"])) for r in rows]
