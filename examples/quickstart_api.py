"""In-process tour of the gateway: one allowed order, three denials. No network, no credentials.

    python examples/quickstart_api.py
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from sedei.api import create_app
from sedei.system import SimClock, build_system

clock = SimClock()
system = build_system(":memory:", clock, deterministic_ids=True)
client = TestClient(create_app(system))
issuer = system.issuer
order = {"tenant": "tenant-a", "sku": "SKU-1001", "quantity": 2}


def call(label: str, token: str | None, body: dict, key: str) -> None:
    headers = {"Idempotency-Key": key}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    r = client.post("/v1/orders", json=body, headers=headers)
    print(f"{label:<28} -> {r.status_code} {r.json()['decision']:<5} {r.json()['reason']}")


call("authorized order", issuer.issue("tenant-a", "svc-07", clock()), order, "k1")
call("no token", None, order, "k2")
call("claims another tenant", issuer.issue("tenant-a", "svc-07", clock()), {**order, "tenant": "tenant-b"}, "k3")
call("token lacks scope", issuer.issue("tenant-b", "user-03", clock()), {**order, "tenant": "tenant-b"}, "k4")
system.worker.drain()
print("workflows started:", system.store.q1("SELECT COUNT(*) n FROM workflows")["n"], "(denials start none)")
