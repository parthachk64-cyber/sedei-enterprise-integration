"""Bounded local throughput/latency benchmark of the real store + worker path (SQLite, single machine).

This measures the companion implementation on THIS machine. It cannot substantiate enterprise scale.
Latency per event = monotonic time from publish() commit start to ack() commit end (end-to-end through
two consumers), measured with time.perf_counter(). Event-time delays in the synthetic data are a
different clock and are not used here.
"""

from __future__ import annotations

import json
import platform
import statistics
import tempfile
import threading
import time
from pathlib import Path

import numpy as np

from sedei.config import RUNS_DIR
from sedei.events import EventEnvelope, to_dt
from sedei.orchestration import IdFactory, Orchestrator
from sedei.policy import load_policy
from sedei.store import Store
from sedei.telemetry import TelemetryIngestor
from sedei.worker import Worker

DEFAULT_PLAN = {"events": 600, "warmup_events": 100, "repeats": 3, "queue_capacity": 200,
                "event_sizes_bytes": [256, 4096], "worker_threads": [1, 2, 4],
                "duplicate_fraction": 0.05, "storage": "tempdir SQLite file, WAL, synchronous=NORMAL"}


def _env(i: int, size: int, tag: str) -> EventEnvelope:
    now = time.time()
    return EventEnvelope(event_id=f"b-{tag}-{i}", tenant="tenant-a", emitter="bench", type="OrderReceived",
                         event_time=to_dt(now), ingest_time=to_dt(now), correlation_id=f"c-{tag}-{i}",
                         payload={"workflow_id": f"wf-{tag}-{i}", "principal": "svc-07",
                                  "sku": "SKU-1001", "quantity": 1, "pad": "x" * max(0, size - 120)})


def one_run(n_events: int, size: int, threads: int, capacity: int, dup_frac: float, tag: str) -> dict:
    with tempfile.TemporaryDirectory() as td:
        db = str(Path(td) / "b.sqlite")
        store = Store(db)
        policy = load_policy()
        ing = TelemetryIngestor(store)
        orch = Orchestrator(store, policy, ing, time.time, IdFactory(False))
        t_pub: dict[str, float] = {}
        t_done: dict[str, float] = {}
        dropped = 0
        duplicates_injected = 0

        orig_ack = store.ack

        def timed_ack(consumer: str, tenant: str, event_id: str, now: float) -> None:
            orig_ack(consumer, tenant, event_id, now)
            t_done.setdefault(event_id, time.perf_counter())

        store.ack = timed_ack  # type: ignore[method-assign]
        stop = threading.Event()
        max_backlog = 0

        def work() -> None:
            w = Worker(store, {"inventory": orch.handle_inventory}, ing, time.time, IdFactory(False), lease_s=30)
            while not stop.is_set() or store.backlog("inventory") > 0:
                if not w.run_once("inventory", limit=20):
                    time.sleep(0.001)

        ths = [threading.Thread(target=work, daemon=True) for _ in range(threads)]
        t0 = time.perf_counter()
        for t in ths:
            t.start()
        for i in range(n_events):
            wait_start = time.perf_counter()
            while store.backlog("inventory") >= capacity and time.perf_counter() - wait_start < 2.0:
                time.sleep(0.0005)
            if store.backlog("inventory") >= capacity:  # bounded queue: shed after a 2 s wait
                dropped += 1
                continue
            env = _env(i, size, tag)
            store.create_workflow(env.payload["workflow_id"], "tenant-a", f"i{i}", "svc-07", env.correlation_id,
                                  {}, "RECEIVED", time.time())
            t_pub[env.event_id] = time.perf_counter()
            store.append_event(env, ["inventory"], time.time())
            if dup_frac > 0 and i % int(1 / dup_frac) == 0:  # producer retry of the same event id
                duplicates_injected += 1
                store.append_event(env, ["inventory"], time.time())  # must be rejected by the event log
            max_backlog = max(max_backlog, store.backlog("inventory"))
        stop.set()
        for t in ths:
            t.join(timeout=120)
        elapsed = time.perf_counter() - t0
        lat = np.array([(t_done[e] - t_pub[e]) * 1e3 for e in t_pub if e in t_done])
        done_states = store.q1("SELECT COUNT(*) n FROM deliveries WHERE state='acked'")["n"]
        dup_effects = store.q1("SELECT COUNT(*) n FROM (SELECT workflow_id FROM reservations "
                               "GROUP BY workflow_id HAVING COUNT(*)>1)")["n"]
        res = {"events_offered": n_events, "completed": int(done_states), "dropped": dropped,
               "duplicate_publishes_injected": duplicates_injected,
               "duplicate_effects_observed": int(dup_effects), "max_backlog": max_backlog,
               "elapsed_s": elapsed, "throughput_events_per_s": done_states / elapsed,
               "latency_ms": ({"p50": float(np.percentile(lat, 50)), "p95": float(np.percentile(lat, 95)),
                               "p99": float(np.percentile(lat, 99)), "n": int(len(lat))} if len(lat) else None),
               "latencies_ms": lat.tolist()}
        store.close()
        return res


def run_benchmark(runs_dir: Path = RUNS_DIR, plan: dict | None = None) -> Path:
    plan = dict(DEFAULT_PLAN, **(plan or {}))
    out = Path(runs_dir) / "benchmark"
    out.mkdir(parents=True, exist_ok=True)
    rows, raw = [], {}
    for size in plan["event_sizes_bytes"]:
        for th in plan["worker_threads"]:
            one_run(plan["warmup_events"], size, th, plan["queue_capacity"], 0.0, "warm")  # warm-up, discarded
            reps = [one_run(plan["events"], size, th, plan["queue_capacity"], plan["duplicate_fraction"],
                            f"r{k}") for k in range(plan["repeats"])]
            tp = [r["throughput_events_per_s"] for r in reps]
            lat = [x for r in reps for x in r["latencies_ms"]]
            rows.append({
                "event_size_bytes": size, "worker_threads": th, "queue_capacity": plan["queue_capacity"],
                "events_per_run": plan["events"], "repeats": plan["repeats"],
                "throughput_mean_eps": statistics.mean(tp), "throughput_sd_eps": statistics.pstdev(tp),
                "p50_ms": float(np.percentile(lat, 50)), "p95_ms": float(np.percentile(lat, 95)),
                "p99_ms": float(np.percentile(lat, 99)),
                "completed_total": sum(r["completed"] for r in reps), "dropped_total": sum(r["dropped"] for r in reps),
                "duplicate_publishes_injected": sum(r["duplicate_publishes_injected"] for r in reps),
                "duplicate_effects_observed": sum(r["duplicate_effects_observed"] for r in reps),
                "max_backlog": max(r["max_backlog"] for r in reps)})
            raw[f"{size}B_{th}t"] = [{k: v for k, v in r.items() if k != "latencies_ms"} for r in reps]
            raw[f"{size}B_{th}t_latencies_ms"] = lat
    meta = {"label": "Local measurement of the companion implementation; not enterprise-scale evidence",
            "plan": plan, "hardware": {"platform": platform.platform(), "machine": platform.machine(),
                                       "processor": platform.processor(), "python": platform.python_version()},
            "timing": "time.perf_counter() monotonic; publish->ack per event; warm-up runs discarded"}
    (out / "benchmark.json").write_text(json.dumps({"meta": meta, "summary": rows, "runs": raw}, indent=1))
    from sedei.experiment import write_csv
    write_csv(out / "benchmark_summary.csv", rows)
    return out
