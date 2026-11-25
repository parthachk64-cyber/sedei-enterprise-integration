"""Deterministic synthetic telemetry generator (companion data; NOT the paper's data).

Sampling unit: the *episode* (one workflow, retry, burst, or incident). Splits are made by episode
and time. Records contain observable fields only; labels, scenario names and episode ids live in
separate files (episodes.jsonl, labels.jsonl, incidents.json) and never reach the features.
All identifiers are fictitious. Two tenants deliberately reuse the same local principal ids.
"""

from __future__ import annotations

import hashlib
import json
import random
from dataclasses import dataclass, field
from pathlib import Path

T0 = 1_790_000_000.0
SPAN_S = 14 * 86_400
DEFAULT_SEED = 20260916
TENANTS = ("tenant-a", "tenant-b")
POOL = [f"svc-{i:02d}" for i in range(1, 25)] + [f"user-{i:02d}" for i in range(1, 17)]
ORDER_ROUTE = "POST /v1/orders"
ODD_ROUTES = ["GET /v1/admin", "POST /v1/refunds", "GET /v1/orders", "DELETE /v1/orders",
              "GET /v1/customers"]
UNEXPECTED_EDGES = [("orchestrator", "admin-svc"), ("inventory-svc", "identity-svc"),
                    ("gateway", "billing-svc"), ("dispatch-svc", "admin-svc")]

MIX = {  # scenario -> (count, family, is_incident)
    "normal_workflow": (500, "normal", False),
    "normal_retry": (70, "normal", False),
    "healthy_burst": (30, "normal", False),
    "scope_probe": (30, "access_misuse", True),
    "credential_misuse_chain": (30, "multi_stage", True),
    "replay_injection": (30, "message_integrity", True),
    "lateral_movement": (30, "lateral_movement", True),
    "cross_tenant_attempt": (20, "tenant_boundary", True),
}
FORBIDDEN_RECORD_KEYS = {"label", "is_evidence", "incident_id", "episode_id", "scenario", "family", "split",
                         "response", "action"}


def _h(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


@dataclass
class _State:
    rng: random.Random
    n_rec: int = 0
    records: list[dict] = field(default_factory=list)
    episodes: list[dict] = field(default_factory=list)
    labels: dict[str, tuple[bool, str | None]] = field(default_factory=dict)
    incidents: list[dict] = field(default_factory=list)
    busy: dict[tuple[str, str], list[tuple[float, float]]] = field(default_factory=dict)
    priv: dict[tuple[str, str], str] = field(default_factory=dict)


class Generator:
    def __init__(self, seed: int = DEFAULT_SEED, scale: float = 1.0) -> None:
        self.seed, self.scale = seed, scale
        self.s = _State(random.Random(seed))
        for t in TENANTS:
            for p in POOL:
                self.s.priv[(t, p)] = "elevated" if self.s.rng.random() < 0.2 else "standard"

    # ---- primitives ---------------------------------------------------------------------------
    def _pick(self, start: float, dur: float) -> tuple[str, str]:
        rng = self.s.rng
        for _ in range(200):
            t, p = rng.choice(TENANTS), rng.choice(POOL)
            if all(start - 600 > e or start + dur + 600 < b for b, e in self.s.busy.get((t, p), [])):
                self.s.busy.setdefault((t, p), []).append((start, start + dur))
                return t, p
        raise RuntimeError("principal pool exhausted; lower the episode counts")

    def _rec(self, ep: list[dict], kind: str, tenant: str, pid: str, t: float, delay: float, **kw) -> dict:
        self.s.n_rec += 1
        r = {"record_id": f"R{self.s.n_rec:06d}", "kind": kind, "tenant": tenant, "principal": pid,
             "event_time": round(t, 3), "receipt_time": round(t + delay, 3)}
        if kind in ("gateway_decision", "identity_context"):
            r["privilege"] = self.s.priv[(tenant, pid)]
        r.update({k: v for k, v in kw.items() if v is not None})
        ep.append(r)
        return r

    def _nd(self) -> float:
        return round(self.s.rng.uniform(0.05, 0.5), 3)

    # ---- episode builders: return (records, evidence_record_ids) --------------------------------
    def _workflow(self, ep, tenant, pid, t, eid, delayed=False, benign_deny=False, gap=None):
        rng = self.s.rng
        corr, wf, ev = f"c-{eid}", f"wf-{eid}", f"ev-{eid}"
        dd = (lambda: round(rng.uniform(40, 240), 3)) if delayed else self._nd
        if benign_deny:
            self._rec(ep, "gateway_decision", tenant, pid, t - 20, self._nd(), route=ORDER_ROUTE,
                      decision="deny", deny_reason="scope_missing", correlation_id=f"{corr}-d")
        self._rec(ep, "identity_context", tenant, pid, t, self._nd(), correlation_id=corr)
        self._rec(ep, "gateway_decision", tenant, pid, t + .05, self._nd(), route=ORDER_ROUTE,
                  decision="allow", correlation_id=corr, workflow_id=wf)
        if gap != "service_call":
            self._rec(ep, "service_call", tenant, pid, t + .1, dd(), correlation_id=corr, workflow_id=wf,
                      source_service="gateway", dest_service="orchestrator")
        if gap != "event_delivery":
            self._rec(ep, "event_delivery", tenant, pid, t + .3, dd(), correlation_id=corr, workflow_id=wf,
                      event_id=ev, event_type="OrderReceived", emitter="gateway", payload_sha256=_h(ev),
                      delivery_attempt=1, transport_redelivery=False)
        if gap != "service_call":
            self._rec(ep, "service_call", tenant, pid, t + .5, dd(), correlation_id=corr, workflow_id=wf,
                      source_service="orchestrator", dest_service="inventory-svc")
            self._rec(ep, "service_call", tenant, pid, t + .9, dd(), correlation_id=corr, workflow_id=wf,
                      source_service="orchestrator", dest_service="dispatch-svc")
        return ev

    def _normal(self, scen, tenant, pid, t, eid):
        rng, ep = self.s.rng, []
        gap = rng.choice(["service_call", "event_delivery"]) if (scen == "normal_workflow"
                                                                 and rng.random() < 0.03) else None
        ev = self._workflow(ep, tenant, pid, t, eid, delayed=(scen == "normal_workflow"
                                                              and rng.random() < 0.08),
                            benign_deny=rng.random() < 0.08, gap=gap)
        if scen == "normal_retry" and gap is None:
            self._rec(ep, "event_delivery", tenant, pid, t + rng.uniform(2, 8), self._nd(),
                      correlation_id=f"c-{eid}", workflow_id=f"wf-{eid}", event_id=ev,
                      event_type="OrderReceived", emitter="gateway", payload_sha256=_h(ev),
                      delivery_attempt=2, transport_redelivery=True)
        return ep, set()

    def _burst(self, tenant, pid, t, eid):
        rng, ep = self.s.rng, []
        t_cur = t
        for i in range(rng.randint(12, 30)):
            t_cur += rng.uniform(1, 4)
            c, wf, ev = f"c-{eid}-{i}", f"wf-{eid}-{i}", f"ev-{eid}-{i}"
            self._rec(ep, "gateway_decision", tenant, pid, t_cur, self._nd(), route=ORDER_ROUTE,
                      decision="allow", correlation_id=c, workflow_id=wf)
            self._rec(ep, "service_call", tenant, pid, t_cur + .1, self._nd(), correlation_id=c,
                      workflow_id=wf, source_service="gateway", dest_service="orchestrator")
            self._rec(ep, "event_delivery", tenant, pid, t_cur + .3, self._nd(), correlation_id=c,
                      workflow_id=wf, event_id=ev, event_type="OrderReceived", emitter="gateway",
                      payload_sha256=_h(ev), delivery_attempt=1, transport_redelivery=False)
        for _ in range(rng.choice([0, 0, 1, 2])):  # benign repeated denial on the same route
            self._rec(ep, "gateway_decision", tenant, pid, t + rng.uniform(5, 40), self._nd(),
                      route=ORDER_ROUTE, decision="deny", deny_reason="scope_missing")
        return ep, set()

    def _deny(self, ep, ev, tenant, pid, t, route, reason="scope_missing"):
        r = self._rec(ep, "gateway_decision", tenant, pid, t, self._nd(), route=route, decision="deny",
                      deny_reason=reason)
        ev.add(r["record_id"])

    def _scope_probe(self, tenant, pid, t, eid, stealth):
        rng, ep, ev = self.s.rng, [], set()
        if stealth:  # two denials on one route: below every rule threshold
            for i in range(2):
                self._deny(ep, ev, tenant, pid, t + i * 20, ORDER_ROUTE)
        else:
            routes = rng.sample(ODD_ROUTES, rng.randint(2, 4))
            for i in range(rng.randint(4, 9)):
                self._deny(ep, ev, tenant, pid, t + i * rng.uniform(8, 20), routes[i % len(routes)])
        return ep, ev

    def _chain(self, tenant, pid, t, eid, stealth):
        rng, ep, ev = self.s.rng, [], set()
        first = f"ev-{eid}"
        d_n = 1 if stealth else rng.randint(2, 4)
        routes = rng.sample(ODD_ROUTES, 2)
        for i in range(d_n):
            self._deny(ep, ev, tenant, pid, t + i * 12, routes[i % 2])
        t1 = t + d_n * 12 + 10
        self._rec(ep, "gateway_decision", tenant, pid, t1, self._nd(), route=ORDER_ROUTE, decision="allow",
                  correlation_id=f"c-{eid}", workflow_id=f"wf-{eid}")
        self._rec(ep, "event_delivery", tenant, pid, t1 + .3, self._nd(), correlation_id=f"c-{eid}",
                  event_id=first, event_type="OrderReceived", emitter="gateway",
                  payload_sha256=_h(first), delivery_attempt=1, transport_redelivery=False)
        for j in range(1 if stealth else rng.randint(1, 2)):
            src, dst = rng.choice(UNEXPECTED_EDGES)
            r = self._rec(ep, "service_call", tenant, pid, t1 + 10 + j * 15, self._nd(),
                          correlation_id=f"c-{eid}", source_service=src, dest_service=dst)
            ev.add(r["record_id"])
        if not stealth:
            r = self._rec(ep, "event_delivery", tenant, pid, t1 + 60, self._nd(), correlation_id=f"c-{eid}",
                          event_id=first, event_type="OrderReceived", emitter="gateway",
                          payload_sha256=_h(first + "tampered"), delivery_attempt=2,
                          transport_redelivery=False)
            ev.add(r["record_id"])
        return ep, ev

    def _replay(self, tenant, pid, t, eid, stealth):
        rng, ep, ev = self.s.rng, [], set()
        e = f"ev-{eid}"
        self._rec(ep, "event_delivery", tenant, pid, t, self._nd(), correlation_id=f"c-{eid}",
                  event_id=e, event_type="OrderReceived", emitter="gateway", payload_sha256=_h(e),
                  delivery_attempt=1, transport_redelivery=False)
        for k in range(rng.randint(1, 3)):
            gap = rng.uniform(320, 500) if stealth else rng.uniform(15, 120)
            mode = rng.choice(["no_broker_flag", "hash_differs", "emitter_differs"])
            r = self._rec(ep, "event_delivery", tenant, pid, t + gap + k * 7, self._nd(),
                          correlation_id=f"c-{eid}", event_id=e, event_type="OrderReceived",
                          emitter="partner-x" if mode == "emitter_differs" else "gateway",
                          payload_sha256=_h(e + "x") if mode == "hash_differs" else _h(e),
                          delivery_attempt=2 + k, transport_redelivery=(mode != "no_broker_flag"))
            ev.add(r["record_id"])
        return ep, ev

    def _lateral(self, tenant, pid, t, eid, stealth):
        rng, ep, ev = self.s.rng, [], set()
        self._rec(ep, "gateway_decision", tenant, pid, t, self._nd(), route=ORDER_ROUTE, decision="allow",
                  correlation_id=f"c-{eid}", workflow_id=f"wf-{eid}")
        for j in range(1 if stealth else rng.randint(2, 4)):
            src, dst = rng.choice(UNEXPECTED_EDGES)
            r = self._rec(ep, "service_call", tenant, pid, t + 5 + j * rng.uniform(10, 25), self._nd(),
                          correlation_id=f"c-{eid}", source_service=src, dest_service=dst)
            ev.add(r["record_id"])
        return ep, ev

    def _cross_tenant(self, tenant, pid, t, eid, stealth):
        ep, ev = [], set()
        for i in range(self.s.rng.randint(1, 3)):
            self._deny(ep, ev, tenant, pid, t + i * 15, ORDER_ROUTE, reason="tenant_mismatch")
        return ep, ev

    # ---- assembly -----------------------------------------------------------------------------
    def build(self) -> dict:
        rng, s = self.s.rng, self.s
        plan = [(scen, fam, inc) for scen, (n, fam, inc) in MIX.items() for _ in range(max(3, int(n * self.scale)))]
        rng.shuffle(plan)
        n_ep = 0
        for scen, fam, inc in plan:
            n_ep += 1
            eid = f"E{n_ep:05d}"
            start = T0 + rng.uniform(0, SPAN_S)
            dur = 900.0 if scen != "healthy_burst" else 200.0
            tenant, pid = self._pick(start, dur)
            stealth = inc and rng.random() < 0.2
            if scen in ("normal_workflow", "normal_retry"):
                recs, ev = self._normal(scen, tenant, pid, start, eid)
            elif scen == "healthy_burst":
                recs, ev = self._burst(tenant, pid, start, eid)
            else:
                fn = {"scope_probe": self._scope_probe, "credential_misuse_chain": self._chain,
                      "replay_injection": self._replay, "lateral_movement": self._lateral,
                      "cross_tenant_attempt": self._cross_tenant}[scen]
                recs, ev = fn(tenant, pid, start, eid, stealth)
            s.records.extend(recs)
            ids = [r["record_id"] for r in recs]
            inc_id = f"INC{len(s.incidents) + 1:04d}" if inc else None
            for r in recs:
                s.labels[r["record_id"]] = (r["record_id"] in ev, inc_id if r["record_id"] in ev else None)
            s.episodes.append({"episode_id": eid, "scenario": scen, "family": fam, "incident": inc,
                               "tenant": tenant, "principal": pid, "start": round(start, 3),
                               "end": round(max(r["receipt_time"] for r in recs), 3), "record_ids": ids,
                               "stealth": bool(stealth)})
            if inc:
                evr = [r for r in recs if r["record_id"] in ev]
                s.incidents.append({
                    "incident_id": inc_id, "episode_id": eid, "scenario": scen, "family": fam,
                    "tenant": tenant, "principal": pid, "stealth": bool(stealth),
                    "evidence_record_ids": sorted(ev),
                    "first_evidence_receipt": min(r["receipt_time"] for r in evr),
                    "last_evidence_receipt": max(r["receipt_time"] for r in evr),
                    "first_evidence_event_time": min(r["event_time"] for r in evr)})
        return self._finalize()

    def _finalize(self) -> dict:
        s = self.s
        s.records.sort(key=lambda r: (r["receipt_time"], r["record_id"]))
        return {"records": s.records, "episodes": s.episodes, "incidents": s.incidents,
                "labels": [{"record_id": k, "is_evidence": v[0], "incident_id": v[1]}
                           for k, v in sorted(s.labels.items())]}


def assign_splits(episodes: list[dict], fractions: dict[str, float], holdout_family: str) -> dict[str, str]:
    """episode_id -> split. Holdout family never enters train/val; the rest split by episode start time."""
    rest = sorted((e for e in episodes if e["family"] != holdout_family), key=lambda e: e["start"])
    n = len(rest)
    n_tr, n_va = int(n * fractions["train"]), int(n * fractions["val"])
    out = {e["episode_id"]: "holdout" for e in episodes if e["family"] == holdout_family}
    for i, e in enumerate(rest):
        out[e["episode_id"]] = "train" if i < n_tr else ("val" if i < n_tr + n_va else "test")
    return out


def write_dataset(out_dir: Path | str, seed: int = DEFAULT_SEED, scale: float = 1.0) -> dict[str, str]:
    d = Path(out_dir)
    d.mkdir(parents=True, exist_ok=True)
    data = Generator(seed, scale).build()
    for r in data["records"]:
        assert not (set(r) & FORBIDDEN_RECORD_KEYS), "label leakage into telemetry record"

    def dump_lines(name: str, rows: list[dict]) -> None:
        (d / name).write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in rows), encoding="utf-8",
                              newline="\n")

    dump_lines("telemetry.jsonl", data["records"])
    dump_lines("labels.jsonl", data["labels"])
    dump_lines("episodes.jsonl", data["episodes"])
    (d / "incidents.json").write_text(json.dumps(data["incidents"], indent=1, sort_keys=True) + "\n",
                                      encoding="utf-8", newline="\n")
    sums = {n: hashlib.sha256((d / n).read_bytes()).hexdigest()
            for n in ("telemetry.jsonl", "labels.jsonl", "episodes.jsonl", "incidents.json")}
    (d / "CHECKSUMS.json").write_text(json.dumps({"seed": seed, "sha256": sums}, indent=1, sort_keys=True) + "\n",
                                      encoding="utf-8", newline="\n")
    return sums
