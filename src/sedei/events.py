"""Versioned event envelope. Validation happens at every boundary that accepts one."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

SCHEMA_VERSION = "1.0"
SUPPORTED_MAJOR = "1"
MAX_PAYLOAD_BYTES = 16 * 1024
ID_PATTERN = r"^[A-Za-z0-9_.:\-]{1,80}$"
TYPE_PATTERN = r"^[A-Za-z][A-Za-z0-9_.]{0,63}$"


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


class EventEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    event_id: str = Field(pattern=ID_PATTERN)
    tenant: str = Field(pattern=ID_PATTERN)
    emitter: str = Field(pattern=ID_PATTERN)
    type: str = Field(pattern=TYPE_PATTERN)
    event_time: datetime
    ingest_time: datetime
    correlation_id: str = Field(pattern=ID_PATTERN)
    causation_id: str | None = Field(default=None, pattern=ID_PATTERN)
    schema_version: str = SCHEMA_VERSION
    payload: dict[str, Any] = Field(default_factory=dict)

    @field_validator("event_time", "ingest_time")
    @classmethod
    def _tz_aware(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            raise ValueError("timestamps must be timezone-aware")
        return v.astimezone(timezone.utc)

    @field_validator("schema_version")
    @classmethod
    def _supported(cls, v: str) -> str:
        if v.split(".")[0] != SUPPORTED_MAJOR:
            raise ValueError(f"unsupported schema_version {v!r}")
        return v

    @field_validator("payload")
    @classmethod
    def _bounded(cls, v: dict[str, Any]) -> dict[str, Any]:
        if len(canonical_json(v).encode()) > MAX_PAYLOAD_BYTES:
            raise ValueError("payload exceeds size limit")
        return v

    def payload_sha256(self) -> str:
        return hashlib.sha256(canonical_json(self.payload).encode()).hexdigest()


def to_dt(epoch: float) -> datetime:
    return datetime.fromtimestamp(epoch, tz=timezone.utc)


def to_epoch(dt: datetime) -> float:
    return dt.timestamp()
