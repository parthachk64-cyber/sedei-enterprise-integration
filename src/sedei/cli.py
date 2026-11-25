"""Command line: demo | generate-data | validate-data | train | replay | evaluate | benchmark | report | reproduce | serve."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from sedei.config import DATA_DIR, RUNS_DIR


def _p(s: str) -> Path:
    return Path(s)


def cmd_demo(a: argparse.Namespace) -> int:
    from sedei.demo import fmt_timeline, run_demo
    out, traces = run_demo(a.runs, a.data)
    print("SEDEI walkthrough (three contrasting local traces)\n")
    for t in traces:
        print(fmt_timeline(t["scenario"], t["timeline"]))
        print("   checks:", json.dumps(t["assertions"], sort_keys=True))
    t3 = traces[2]
    print(f"\nIncident {t3['incident']['incident_id']}: risk={t3['risk']:.3f} reasons={t3['reason_codes']}")
    print(f"decision: {t3['decision']['action']} -> {t3['decision']['target']} ({t3['decision']['policy']} policy, "
          f"{t3['decision']['reason']})")
    print(f"audit chain valid: {t3['audit_chain_valid']}")
    print(f"\ntrace JSON written to {out}/trace_1.json, trace_2.json, trace_3.json")
    ok = all(v is not False for t in traces for k, v in t["assertions"].items()
             if k in ("workflow_completed", "fulfillment_once", "no_alert", "no_second_action",
                      "other_tenant_untouched", "identity_active", "all_stages_share_correlation_id"))
    return 0 if ok else 1


def cmd_generate(a: argparse.Namespace) -> int:
    from sedei.datagen import write_dataset
    sums = write_dataset(a.out, a.seed, a.scale)
    print(json.dumps(sums, indent=1))
    return 0


def cmd_validate(a: argparse.Namespace) -> int:
    from sedei.validate import validate_dataset
    issues = validate_dataset(a.path, require_labels=not a.no_labels)
    for i in issues[:50]:
        print("ISSUE:", i)
    print(f"{len(issues)} issue(s)" if issues else "dataset OK")
    return 1 if issues else 0


def cmd_train(a: argparse.Namespace) -> int:
    from sedei.experiment import train_model
    out = train_model(a.data, a.runs, a.seed)
    print(f"model written to {out}/model")
    return 0


def cmd_replay(a: argparse.Namespace) -> int:
    from sedei.demo import _pipeline, ensure_model
    from sedei.pipeline import load_dataset
    from sedei.system import SimClock, build_system
    model = (a.model or ensure_model(a.data, a.runs) / "model")
    ds = load_dataset(a.data)
    clock = SimClock()
    s = build_system(":memory:", clock, deterministic_ids=True)
    pipe = _pipeline(s, Path(model), a.policy)
    recs = ds.records[: a.limit] if a.limit else ds.records
    alerts = []
    for r in recs:
        clock.set(max(clock(), r.receipt_time))
        res = pipe.process(r)
        if res:
            alerts.append(res)
    out = a.runs / "replay"
    out.mkdir(parents=True, exist_ok=True)
    (out / "alerts.jsonl").write_text("".join(json.dumps({
        "record_id": x.record_id, "tenant": x.tenant, "principal": x.principal, "risk": round(x.risk, 4),
        "reasons": list(x.reasons), "decision": x.decision.action_type.value if x.decision else None,
        "action_status": x.action.status if x.action else None, "deduplicated": x.action.deduplicated if x.action else None,
        "timeline": x.timeline} , sort_keys=True) + "\n" for x in alerts))
    n_act = s.store.q1("SELECT COUNT(*) n FROM actions")["n"]
    print(f"replayed {len(recs)} records: {len(alerts)} alert records, {n_act} distinct committed actions -> {out}")
    return 0


def cmd_evaluate(a: argparse.Namespace) -> int:
    from sedei.experiment import run_evaluation
    out = run_evaluation(a.data, a.runs, a.seed)
    print(f"evaluation artifacts in {out}")
    return 0


def cmd_benchmark(a: argparse.Namespace) -> int:
    from sedei.benchmark import run_benchmark
    plan = {"events": a.events, "repeats": a.repeats} if a.events else None
    out = run_benchmark(a.runs, plan)
    print(f"benchmark artifacts in {out}")
    return 0


def cmd_report(a: argparse.Namespace) -> int:
    from sedei.report import generate_report
    for n in generate_report(a.runs):
        print("NOTE:", n)
    print("docs/results.md and docs/figures/ updated")
    return 0


def cmd_reproduce(a: argparse.Namespace) -> int:
    """Validate data -> evaluate -> demo -> benchmark -> report. The whole research run."""
    steps = [("validate-data", lambda: cmd_validate(argparse.Namespace(path=a.data, no_labels=False))),
             ("evaluate", lambda: cmd_evaluate(argparse.Namespace(data=a.data, runs=a.runs, seed=None))),
             ("demo", lambda: cmd_demo(argparse.Namespace(data=a.data, runs=a.runs))),
             ("benchmark", lambda: cmd_benchmark(argparse.Namespace(runs=a.runs, events=None, repeats=None))),
             ("report", lambda: cmd_report(argparse.Namespace(runs=a.runs)))]
    for name, fn in steps:
        print(f"\n=== {name} ===")
        if fn() != 0:
            print(f"step {name} failed")
            return 1
    return 0


def cmd_serve(a: argparse.Namespace) -> int:  # pragma: no cover - interactive
    import uvicorn

    from sedei.api import create_app
    from sedei.system import build_system
    uvicorn.run(create_app(build_system(a.db)), host=a.host, port=a.port)
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="sedei", description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    def add(name, fn, **kw):
        sp = sub.add_parser(name, **kw)
        sp.set_defaults(fn=fn)
        return sp

    for name, fn in (("demo", cmd_demo), ("evaluate", cmd_evaluate), ("train", cmd_train),
                     ("replay", cmd_replay), ("reproduce", cmd_reproduce)):
        sp = add(name, fn)
        sp.add_argument("--data", type=_p, default=DATA_DIR)
        sp.add_argument("--runs", type=_p, default=RUNS_DIR)
        if name in ("evaluate", "train"):
            sp.add_argument("--seed", type=int, default=None)
        if name == "replay":
            sp.add_argument("--model", type=_p, default=None)
            sp.add_argument("--policy", choices=["contextual", "static"], default="contextual")
            sp.add_argument("--limit", type=int, default=0)
    sp = add("generate-data", cmd_generate)
    sp.add_argument("--out", type=_p, default=DATA_DIR)
    sp.add_argument("--seed", type=int, default=20260916)
    sp.add_argument("--scale", type=float, default=1.0, help="scale episode counts (tests use <1)")
    sp = add("validate-data", cmd_validate)
    sp.add_argument("--path", type=_p, default=DATA_DIR)
    sp.add_argument("--no-labels", action="store_true", help="user-supplied records without labels")
    sp = add("benchmark", cmd_benchmark)
    sp.add_argument("--runs", type=_p, default=RUNS_DIR)
    sp.add_argument("--events", type=int, default=0)
    sp.add_argument("--repeats", type=int, default=3)
    sp = add("report", cmd_report)
    sp.add_argument("--runs", type=_p, default=RUNS_DIR)
    sp = add("serve", cmd_serve)
    sp.add_argument("--host", default="127.0.0.1")
    sp.add_argument("--port", type=int, default=8080)
    sp.add_argument("--db", default=":memory:")
    a = ap.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
