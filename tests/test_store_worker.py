from __future__ import annotations

import threading

import pytest
from conftest import order

from sedei.events import EventEnvelope, to_dt
from sedei.orchestration import InvalidTransition, ServiceIsolated
from sedei.store import ConflictError, Store
from sedei.system import build_system
from sedei.worker import SimulatedCrash


def mk(eid="e1", tenant="tenant-a"):
    return EventEnvelope(event_id=eid, tenant=tenant, emitter="x", type="T", event_time=to_dt(0),
                         ingest_time=to_dt(0), correlation_id="c", payload={"workflow_id": "w", "principal": "p"})


def test_publish_claim_ack():
    s = Store()
    assert s.append_event(mk(), ["c1"], 0.0) and not s.append_event(mk(), ["c1"], 0.0)
    got = s.claim("c1", 0.0, 30)
    assert got[0]["attempt"] == 1 and s.claim("c1", 0.0, 30) == []
    s.ack("c1", "tenant-a", "e1", 1.0)
    assert s.backlog() == 0


def test_event_id_scoped_per_tenant():
    s = Store()
    assert s.append_event(mk(tenant="tenant-a"), ["c"], 0) and s.append_event(mk(tenant="tenant-b"), ["c"], 0)


def test_bounded_retry_then_dead_letter():
    s = Store()
    s.append_event(mk(), ["c"], 0.0)
    now, verdicts = 0.0, []
    for _ in range(3):
        s.claim("c", now, 30)
        verdicts.append(s.nack("c", "tenant-a", "e1", "boom", now, max_attempts=3, backoff_base_s=1.0))
        now += 10
    assert verdicts == ["retry", "retry", "dead"]
    assert s.q1("SELECT COUNT(*) n FROM dead_letters")["n"] == 1 and s.claim("c", now + 100, 30) == []


def test_backoff_delays_redelivery():
    s = Store()
    s.append_event(mk(), ["c"], 0.0)
    s.claim("c", 0.0, 30)
    s.nack("c", "tenant-a", "e1", "x", 0.0, 5, backoff_base_s=4.0)
    assert s.claim("c", 3.0, 30) == [] and len(s.claim("c", 4.0, 30)) == 1


def test_transaction_rolls_back_transition_and_event_together():
    s = Store()
    s.create_workflow("w", "tenant-a", "i", "p", "c", {}, "RECEIVED", 0.0)
    with pytest.raises(RuntimeError):
        with s.txn():
            s.transition("w", "RECEIVED", "RESERVED", "e1", 1.0, "v")
            s.append_event(mk(), ["c"], 1.0)
            raise RuntimeError("crash mid-step")
    assert s.get_workflow("w")["state"] == "RECEIVED"
    assert s.q1("SELECT COUNT(*) n FROM events")["n"] == 0


def test_concurrent_updates_only_one_wins(tmp_path):
    db = str(tmp_path / "c.sqlite")
    seed = Store(db)
    seed.create_workflow("w", "tenant-a", "i", "p", "c", {}, "RECEIVED", 0.0)
    seed.close()
    results = []

    def go():
        st = Store(db)
        try:
            st.transition("w", "RECEIVED", "RESERVED", None, 1.0, "v")
            results.append("ok")
        except ConflictError:
            results.append("conflict")
        finally:
            st.close()

    ts = [threading.Thread(target=go) for _ in range(6)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert sorted(results) == ["conflict"] * 5 + ["ok"]


def test_restart_between_processing_and_ack_is_exactly_once(tmp_path, clock):
    db = str(tmp_path / "r.sqlite")
    s1 = build_system(db, clock, deterministic_ids=True)
    tok = s1.issuer.issue("tenant-a", "svc-07", clock())
    r = s1.gateway.handle("POST", "/v1/orders", tok, order(), "k")
    with pytest.raises(SimulatedCrash):
        s1.worker.run_once("inventory", crash_before_ack=True)
    s1.store.close()
    clock.advance(31)  # lease expires
    s2 = build_system(db, clock, deterministic_ids=False)
    s2.worker.drain()
    s2.worker.drain()
    assert s2.store.get_workflow(r.workflow_id)["state"] == "DISPATCH_AUTHORIZED"
    assert s2.store.q1("SELECT COUNT(*) n FROM reservations")["n"] == 1
    assert s2.worker.stats["duplicate"] == 1
    inv = s2.store.q1("SELECT attempts,state FROM deliveries WHERE consumer='inventory'")
    assert (inv["attempts"], inv["state"]) == (2, "acked")


def test_worker_retries_then_dead_letters_on_isolated_service(sys_, token, clock):
    sys_.gateway.handle("POST", "/v1/orders", token(), order(), "k")
    sys_.store.set_control("isolated", "tenant-a", "inventory-svc", "a")
    for _ in range(4):
        sys_.worker.run_once("inventory")
        clock.advance(60)
    assert sys_.store.q1("SELECT COUNT(*) n FROM dead_letters")["n"] == 1
    assert sys_.worker.stats["retry"] == 2 and sys_.worker.stats["dead"] == 1


def test_isolated_service_raises(sys_, token):
    sys_.gateway.handle("POST", "/v1/orders", token(), order(), "k")
    sys_.store.set_control("isolated", "tenant-a", "inventory-svc", "a")
    env = sys_.store.get_event("tenant-a", sys_.store.q1("SELECT event_id FROM events")["event_id"])
    with pytest.raises(ServiceIsolated):
        sys_.orchestrator.handle_inventory(env)


def test_transition_policy_enforced(sys_, token):
    sys_.gateway.handle("POST", "/v1/orders", token(), order(), "k")
    env = sys_.store.get_event("tenant-a", sys_.store.q1("SELECT event_id FROM events")["event_id"])
    with pytest.raises(InvalidTransition):
        sys_.orchestrator._step("inventory", env, "inventory-svc", "RECEIVED", "DISPATCH_AUTHORIZED", "X",
                                [], None)
