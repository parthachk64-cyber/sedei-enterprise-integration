"""Versioned routing/orchestration policy (companion design choice, see configs/routing_policy.yaml)."""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, ConfigDict

from sedei.config import CONFIG_DIR, load_yaml


class RoutePolicy(BaseModel):
    model_config = ConfigDict(frozen=True)
    scope: str
    workflow: str


class RoutingPolicy(BaseModel):
    model_config = ConfigDict(frozen=True)
    version: str
    routes: dict[str, RoutePolicy]
    initial_state: str
    transitions: dict[str, tuple[str, ...]]
    terminal: tuple[str, ...]
    required_telemetry_stages: tuple[str, ...]
    service_graph: frozenset[tuple[str, str]]
    service_criticality: dict[str, float]

    def route_for(self, method: str, path: str) -> RoutePolicy | None:
        return self.routes.get(f"{method.upper()} {path}")

    def transition_allowed(self, current: str, new: str) -> bool:
        return new in self.transitions.get(current, ())

    def edge_expected(self, src: str | None, dst: str | None) -> bool:
        return (src, dst) in self.service_graph

    def criticality(self, service: str | None) -> float:
        return self.service_criticality.get(service or "", 1.0)


def load_policy(path: Path | None = None) -> RoutingPolicy:
    d = load_yaml(path or CONFIG_DIR / "routing_policy.yaml")
    wf = d["workflow"]
    return RoutingPolicy(
        version=d["version"],
        routes={k: RoutePolicy(**v) for k, v in d["routes"].items()},
        initial_state=wf["initial"],
        transitions={k: tuple(v) for k, v in wf["transitions"].items()},
        terminal=tuple(wf["terminal"]),
        required_telemetry_stages=tuple(d["required_telemetry_stages"]),
        service_graph=frozenset((a, b) for a, b in d["service_graph"]),
        service_criticality={k: float(v) for k, v in d["service_criticality"].items()},
    )
