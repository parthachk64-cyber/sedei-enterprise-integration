from __future__ import annotations

import json

from conftest import order
from fastapi.testclient import TestClient

from sedei.api import create_app


def n_workflows(s):
    return s.store.q1("SELECT COUNT(*) n FROM workflows")["n"]


def test_authorized_order_accepted_and_traced(sys_, token):
    r = sys_.gateway.handle("POST", "/v1/orders", token(), order(), "k1")
    assert (r.status, r.decision) == (202, "allow") and r.correlation_id and r.workflow_id
    sys_.worker.drain()
    assert sys_.store.get_workflow(r.workflow_id)["state"] == "DISPATCH_AUTHORIZED"
    rows = sys_.store.q("SELECT body_json FROM telemetry WHERE json_extract(body_json,'$.correlation_id')=?",
                        (r.correlation_id,))
    kinds = {json.loads(x["body_json"])["kind"] for x in rows}
    assert {"gateway_decision", "service_call", "event_delivery"} <= kinds


def test_idempotent_submission_returns_same_workflow(sys_, token):
    a = sys_.gateway.handle("POST", "/v1/orders", token(), order(), "same")
    b = sys_.gateway.handle("POST", "/v1/orders", token(), order(), "same")
    assert a.workflow_id == b.workflow_id and (a.created, b.created) == (True, False)
    assert n_workflows(sys_) == 1


def test_denials_never_start_a_workflow(sys_, token):
    cases = [
        (None, order(), "malformed_token"),
        (token(subject="user-03", tenant="tenant-b"), order("tenant-b"), "scope_missing"),
        (token(), order("tenant-b"), "tenant_mismatch"),
        (token(), order(sku="bad sku"), "invalid_input"),
        (token(), order(quantity=0), "invalid_input"),
        (token(), {"tenant": "tenant-a", "sku": "SKU-1", "quantity": 1, "extra": 1}, "invalid_input"),
        (token(), {"_invalid": True}, "invalid_input"),
    ]
    for tok, body, reason in cases:
        r = sys_.gateway.handle("POST", "/v1/orders", tok, body, "k")
        assert (r.decision, r.reason) == ("deny", reason), reason
    assert sys_.gateway.handle("POST", "/v1/nope", token(), order(), "k").reason == "route_not_found"
    assert n_workflows(sys_) == 0
    assert sys_.store.q1("SELECT COUNT(*) n FROM events")["n"] == 0


def test_expired_token_denied(sys_, token, clock):
    tok = token()
    clock.advance(10_000)
    assert sys_.gateway.handle("POST", "/v1/orders", tok, order(), "k").reason == "token_expired"


def test_decision_records_are_redacted(sys_, token):
    tok = token()
    sys_.gateway.handle("POST", "/v1/orders", tok, order(sku="SECRET-SKU-9"), "k")
    sys_.gateway.handle("POST", "/v1/orders", tok, order("tenant-b"), "k2")
    blob = " ".join(r["body_json"] for r in sys_.store.q("SELECT body_json FROM telemetry"))
    assert tok not in blob and "SECRET-SKU-9" not in blob and tok.split(".")[1] not in blob


def test_cross_tenant_isolation_same_local_id(sys_, token):
    a = sys_.gateway.handle("POST", "/v1/orders", token("tenant-a"), order("tenant-a"), "same-key")
    b = sys_.gateway.handle("POST", "/v1/orders", token("tenant-b"), order("tenant-b"), "same-key")
    assert a.workflow_id != b.workflow_id and b.created


def test_controls_enforced_by_gateway(sys_, token):
    sys_.store.set_control("revoked", "tenant-a", "svc-07", "x")
    assert sys_.gateway.handle("POST", "/v1/orders", token(), order(), "k").reason == "credential_revoked"
    sys_.store.clear_control("revoked", "tenant-a", "svc-07")
    sys_.store.set_control("blocked", "tenant-a", "svc-07", "x")
    assert sys_.gateway.handle("POST", "/v1/orders", token(), order(), "k").reason == "access_blocked"
    sys_.store.clear_control("blocked", "tenant-a", "svc-07")
    sys_.store.set_control("challenge", "tenant-a", "svc-07", "x")
    assert sys_.gateway.handle("POST", "/v1/orders", token(), order(), "k").reason == "step_up_required"
    assert sys_.gateway.handle("POST", "/v1/orders", token(stepup=True), order(), "k3").decision == "allow"


def test_rate_limit_control(sys_, token):
    sys_.store.set_control("rate_limited", "tenant-a", "svc-07", "x", {"max_per_window": 2, "window_s": 60})
    out = [sys_.gateway.handle("POST", "/v1/orders", token(), order(), f"k{i}") for i in range(4)]
    assert [o.decision for o in out] == ["allow", "allow", "deny", "deny"] and out[2].status == 429


def test_http_surface(sys_, token):
    c = TestClient(create_app(sys_))
    assert c.get("/healthz").json()["status"] == "ok"
    h = {"Authorization": f"Bearer {token()}", "Idempotency-Key": "http-1"}
    r = c.post("/v1/orders", json=order(), headers=h)
    assert r.status_code == 202 and r.json()["decision"] == "allow"
    assert c.post("/v1/orders", json=order()).status_code == 401
    assert c.post("/v1/orders", content=b"not json", headers=h).status_code == 422
    assert c.post("/v1/orders", content=b"[]", headers=h).status_code == 422
    assert c.post("/v1/orders", content=b"x" * 9000, headers=h).status_code == 422
