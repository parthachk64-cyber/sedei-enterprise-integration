"""Wires the components into one local system. Transport and model boundaries stay replaceable."""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass

from sedei.config import load_detection
from sedei.gateway import Gateway
from sedei.identity import TestIssuer
from sedei.orchestration import IdFactory, Orchestrator
from sedei.policy import RoutingPolicy, load_policy
from sedei.response import ResponseEngine
from sedei.store import Store
from sedei.telemetry import TelemetryIngestor
from sedei.worker import Worker


class SimClock:
    """Settable clock for deterministic replay. Distinct from the monotonic clock used for timing."""

    def __init__(self, t0: float = 1_790_000_000.0) -> None:
        self.t = t0

    def __call__(self) -> float:
        return self.t

    def advance(self, dt: float) -> float:
        self.t += dt
        return self.t

    def set(self, t: float) -> None:
        self.t = t


@dataclass
class System:
    store: Store
    policy: RoutingPolicy
    issuer: TestIssuer
    ingestor: TelemetryIngestor
    orchestrator: Orchestrator
    gateway: Gateway
    worker: Worker
    response: ResponseEngine
    clock: Callable[[], float]
    cfg: dict


def build_system(db_path: str = ":memory:", clock: Callable[[], float] | None = None,
                 deterministic_ids: bool = False, max_attempts: int = 3) -> System:
    cfg = load_detection()
    clock = clock or time.time
    ids = IdFactory(deterministic_ids)
    store = Store(db_path)
    policy = load_policy()
    issuer = TestIssuer()
    ing = TelemetryIngestor(store, cfg["late_after_s"])
    orch = Orchestrator(store, policy, ing, clock, ids)
    gw = Gateway(store, policy, issuer, orch, ing, clock, ids)
    worker = Worker(store, orch.handlers(), ing, clock, ids, max_attempts=max_attempts)
    resp = ResponseEngine(store, issuer, cfg["response"]["policy_version"], cfg["response"]["durations_s"])
    return System(store, policy, issuer, ing, orch, gw, worker, resp, clock, cfg)
