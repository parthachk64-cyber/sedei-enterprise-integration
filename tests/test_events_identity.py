from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from sedei.events import SCHEMA_VERSION, EventEnvelope, to_dt
from sedei.identity import AuthError, TestIssuer

NOW = datetime(2026, 9, 16, tzinfo=timezone.utc)


def env(**kw):
    base = dict(event_id="e1", tenant="tenant-a", emitter="gateway", type="OrderReceived", event_time=NOW,
                ingest_time=NOW, correlation_id="c1", payload={"a": 1})
    return EventEnvelope(**{**base, **kw})


def test_envelope_valid_and_hash_is_stable():
    assert env().payload_sha256() == env(event_id="e2").payload_sha256()
    assert env().schema_version == SCHEMA_VERSION


@pytest.mark.parametrize("kw", [
    {"event_time": datetime(2026, 1, 1)}, {"event_id": "bad id!"}, {"schema_version": "2.0"},
    {"payload": {"x": "y" * 20000}}, {"tenant": ""}, {"unknown_field": 1}])
def test_envelope_rejects_invalid(kw):
    with pytest.raises(ValidationError):
        env(**kw)


def test_envelope_is_immutable():
    with pytest.raises(ValidationError):
        env().event_id = "other"


def test_to_dt_roundtrip():
    assert to_dt(0).year == 1970


def test_token_roundtrip_and_failures():
    iss = TestIssuer()
    tok = iss.issue("tenant-a", "svc-07", 100.0, ttl_s=10)
    p = iss.verify(tok, 105.0)
    assert (p.tenant, p.subject) == ("tenant-a", "svc-07") and "orders:create" in p.scopes
    with pytest.raises(AuthError, match="token_expired"):
        iss.verify(tok, 111.0)
    with pytest.raises(AuthError, match="bad_signature"):
        iss.verify(tok[:-2] + "xx", 105.0)
    with pytest.raises(AuthError, match="malformed_token"):
        iss.verify("garbage", 105.0)
    with pytest.raises(AuthError, match="bad_signature"):
        TestIssuer(key=b"other-key").verify(tok, 105.0)
    with pytest.raises(AuthError, match="not_a_fixture_identity"):
        iss.issue("tenant-a", "nobody", 0.0)
