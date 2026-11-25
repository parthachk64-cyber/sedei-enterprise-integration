"""Figures and docs/results.md, generated only from artifacts under runs/. Missing inputs -> figure skipped with reason."""

from __future__ import annotations

import csv
import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
from sklearn.metrics import precision_recall_curve  # noqa: E402

from sedei.config import REPO_ROOT, RUNS_DIR  # noqa: E402

DOCS = REPO_ROOT / "docs"
COLORS = {"rules_only": "#1b6ca8", "anomaly_only": "#c4511d", "hybrid": "#2a7f3f"}


def _latest(runs: Path, prefix: str) -> Path | None:
    c = sorted(runs.glob(f"{prefix}*"), key=lambda p: p.stat().st_mtime)
    return c[-1] if c else None


def _read(path: Path) -> list[dict]:
    with open(path, encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def fig_pr(run: Path, out: Path) -> str | None:
    rows = [r for r in _read(run / "scores.csv") if r["split"] == "test"]
    y = np.array([int(r["label_is_evidence"]) for r in rows])
    if y.sum() == 0 or y.sum() == len(y):
        return "skipped fig_pr: test split lacks both classes"
    fig, ax = plt.subplots(figsize=(5.2, 4))
    for key, col in (("rules_only", "rule_score"), ("anomaly_only", "anomaly_raw"), ("hybrid", "risk")):
        s = np.array([float(r[col]) for r in rows])
        p, r_, _ = precision_recall_curve(y, s)
        ax.step(r_, p, where="post", label=key.replace("_", " "), color=COLORS[key])
    ax.set(xlabel="recall (evidence records)", ylabel="precision", xlim=(0, 1), ylim=(0, 1.02),
           title="Synthetic companion evaluation: test split")
    ax.legend(loc="lower left")
    fig.tight_layout()
    fig.savefig(out / "fig_pr_curves.png", dpi=150)
    plt.close(fig)
    return None


def fig_latency(run: Path, out: Path) -> str | None:
    p = run / "detection_latency.csv"
    rows = [r for r in _read(p) if r["split"] == "test"] if p.exists() else []
    if not rows:
        return "skipped fig_latency: no detected incidents with latency"
    fig, ax = plt.subplots(figsize=(5.2, 4))
    for det in ("rules_only", "anomaly_only", "hybrid"):
        v = np.sort([float(r["latency_s_sim_receipt_clock"]) for r in rows if r["detector"] == det])
        if len(v):
            ax.step(v, np.arange(1, len(v) + 1) / len(v), where="post", color=COLORS[det],
                    label=f"{det.replace('_', ' ')} (n={len(v)} detected)")
    ax.set(xlabel="first evidence -> first qualifying alert (s, simulated receipt clock)",
           ylabel="fraction of DETECTED incidents", title="Detection latency (misses excluded; see results.md)")
    ax.legend(loc="lower right", fontsize=8)
    fig.tight_layout()
    fig.savefig(out / "fig_detection_latency.png", dpi=150)
    plt.close(fig)
    return None


def fig_throughput(runs: Path, out: Path) -> str | None:
    p = runs / "benchmark" / "benchmark_summary.csv"
    if not p.exists():
        return "skipped fig_throughput: run `sedei benchmark` first"
    rows = _read(p)
    fig, ax = plt.subplots(figsize=(5.2, 4))
    for size in sorted({int(r["event_size_bytes"]) for r in rows}):
        sub = [r for r in rows if int(r["event_size_bytes"]) == size]
        ax.errorbar([int(r["worker_threads"]) for r in sub], [float(r["throughput_mean_eps"]) for r in sub],
                    yerr=[float(r["throughput_sd_eps"]) for r in sub], marker="o", capsize=3,
                    label=f"{size} B payload")
    ax.set(xlabel="worker threads (shared SQLite connection)", ylabel="events/s (local, mean±sd of repeats)",
           title="Local throughput vs concurrency", ylim=(0, None))
    ax.legend()
    fig.tight_layout()
    fig.savefig(out / "fig_throughput_vs_load.png", dpi=150)
    plt.close(fig)
    return None


def fig_trace(runs: Path, out: Path) -> str | None:
    p = runs / "demo" / "trace_3.json"
    if not p.exists():
        return "skipped fig_trace: run `sedei demo` first"
    t = json.loads(p.read_text())
    ev = t["episode_timeline"]
    t0 = ev[0]["receipt_time"]
    fig, ax = plt.subplots(figsize=(7, 3.2))
    for e in ev:
        ax.scatter(e["receipt_time"] - t0, 0, c="#c4511d" if e["is_evidence"] else "#888", s=40, zorder=3)
    tl = t["timeline"]
    for key, y, col in (("alert_sim", 0.5, "#c4511d"), ("policy_decision_sim", 1.0, "#1b6ca8"),
                        ("committed_sim", 1.5, "#2a7f3f")):
        ax.scatter(tl[key] - t0, y, marker="D", c=col, s=60, zorder=3)
        ax.annotate(f"{key.replace('_sim','').replace('_',' ')} (+{tl[key]-t0:.1f}s sim)", (tl[key] - t0, y),
                    textcoords="offset points", xytext=(6, 4), fontsize=8)
    ax.set(yticks=[0, 0.5, 1.0, 1.5], yticklabels=["telemetry\n(red = evidence)", "alert", "policy decision",
                                                    "committed action"], xlabel="seconds since first record (simulated receipt clock)",
           title=f"{t['incident']['incident_id']}: {t['decision']['action']} -> {t['decision']['target']}")
    ax.set_ylim(-0.4, 2.0)
    fig.tight_layout()
    fig.savefig(out / "fig_trace_policy_action.png", dpi=150)
    plt.close(fig)
    return None


def _f(x, n=3) -> str:
    return "undefined" if x is None else f"{x:.{n}f}"


def results_md(run: Path, runs: Path) -> str:
    m = json.loads((run / "metrics.json").read_text())
    man = json.loads((run / "manifest.json").read_text())
    L = ["# Results: Synthetic companion evaluation\n",
         "> **Label: Synthetic companion evaluation.** Every number below was measured on the checked-in "
         "synthetic dataset (`data/`) with the companion detectors in this repository. **No value in this file "
         "is a result reported by the SEDEI paper**; the paper's own result fields are unverified "
         "(see the last section and `references/reported/`).\n",
         f"Run `{m['run_id']}` · seed {man['seed']} · commit `{man['git_commit'][:12]}` · dataset "
         f"telemetry sha256 `{man['dataset']['sha256']['telemetry.jsonl'][:16]}…` · model `{man['model_version']}`\n",
         "Origins: configuration = *companion design choice*; values = *measured output*; "
         "published specification = *unverified*.\n"]
    sz, pos = m["split_sizes"], m["positives_by_split"]
    L.append("## Units and splits\n")
    L.append("Primary unit for event classification: one scored telemetry record (gateway decision, service call or "
             "event delivery); positive = the record is an evidence step of a labelled incident. Splits are by "
             "episode and time (60/20/20), the `lateral_movement` family is held out of training and threshold "
             "selection. Incident unit: one incident counted once; an alert matches if it is on the same "
             "tenant+principal between first evidence and last evidence + 300 s.\n")
    L.append("| split | scored records | positive records |\n|---|---|---|")
    for s in ("train", "val", "test", "holdout"):
        L.append(f"| {s} | {sz[s]} | {pos[s]} |")
    for split, title in (("test", "Test split (in-distribution families)"),
                         ("holdout", "Held-out scenario family (`lateral_movement`), synthetic holdout performance")):
        L.append(f"\n## Event classification: {title}\n")
        L.append("| detector | threshold (val-selected) | TP | FP | FN | TN | precision | recall | F1 | FPR | PR-AUC |")
        L.append("|---|---|---|---|---|---|---|---|---|---|---|")
        for k, r in m[f"event_classification_{split}"].items():
            L.append(f"| {k.replace('_',' ')} | {_f(r['threshold'])} | {r['tp']} | {r['fp']} | {r['fn']} | {r['tn']} | "
                     f"{_f(r['precision'])} ({r['tp']}/{r['predicted_positive']}) | {_f(r['recall'])} "
                     f"({r['tp']}/{r['positives']}) | {_f(r['f1'])} | {_f(r['false_positive_rate'])} "
                     f"({r['fp']}/{r['fpr_denominator_negatives']}) | {_f(r['pr_auc'])} |")
    L.append("\n`undefined` = zero denominator (e.g. precision with no predicted positives). PR-AUC is average "
             "precision, computed only when both classes and more than one distinct score exist. The holdout "
             "split contains only incident episodes, so its negative count is small and FPR there is weak evidence.\n")
    L.append("## Incident evaluation (each incident counted once)\n")
    L.append("| split | detector | incidents | detected | missed | alert records | spurious alert records | spurious groups | detection latency p50 / p95 / max (s, simulated) |")
    L.append("|---|---|---|---|---|---|---|---|---|")
    for sp, dd in m["incident_evaluation"].items():
        for k, r in dd.items():
            ls = r["detection_latency_summary"]
            lat = "n/a (none detected)" if not ls else f"{ls['p50']:.1f} / {ls['p95']:.1f} / {ls['max']:.1f} (n={ls['n']})"
            L.append(f"| {sp} | {k.replace('_',' ')} | {r['incidents']} | {r['detected']} | {r['missed']} | "
                     f"{r['alerts_total']} | {r['spurious_alert_records']} | {r['spurious_alert_groups']} | {lat} |")
    miss = m["incident_evaluation"]["test"]["hybrid"]["missed_incidents"]
    L.append("\nLatency is computed over **detected** incidents only; misses are listed separately so a fast-looking "
             "detector cannot hide hard cases. Hybrid misses on test: " +
             (", ".join(f"{x['incident_id']} ({x['scenario']}{', stealth' if x['stealth'] else ''})" for x in miss) or "none") + ".\n")
    L.append("### Recall of evidence records by incident family (test + holdout)\n")
    fam = m["recall_by_family_test_and_holdout"]
    fams = sorted({f for d in fam.values() for f in d})
    L.append("| family | " + " | ".join(k.replace('_', ' ') for k in fam) + " |\n|---|" + "---|" * len(fam))
    for f in fams:
        L.append(f"| {f} | " + " | ".join(
            f"{fam[k][f]['detected_evidence_records']}/{fam[k][f]['evidence_records']}" if f in fam[k] else "n/a" for k in fam) + " |")
    L.append("\nThe held-out family is caught by the rule that compares service calls to the trusted service "
             "graph (R4), by construction of that rule, not because a model generalised. The anomaly baseline alone "
             "detects none of it. Treat the holdout row as a check that the pipeline does not rely on training "
             "exposure, not as evidence of novel-attack detection.\n")
    L.append("## Static vs contextual response (detector outputs held fixed)\n")
    L.append("| split | policy | alert groups on incident episodes | alert groups on benign episodes | severe actions on incident groups | severe actions on benign groups | action mix |\n|---|---|---|---|---|---|---|")
    for sp, rc in m["response_policy_comparison"].items():
        for pol in ("static", "contextual"):
            r = rc[pol]
            L.append(f"| {sp} | {pol} | {r['alert_groups_on_incident_episodes']} | {r['alert_groups_on_benign_episodes']} | "
                     f"{r['severe_actions_on_incident_groups']} | {r['severe_actions_on_benign_groups']} | "
                     f"{json.dumps(r['actions_by_type'])} |")
    L.append("\n*Severe* = access block, credential revocation, service isolation. " +
             m["response_policy_comparison"]["test"]["note"] + "\n")
    v = m["visibility"]
    L.append("## Telemetry visibility\n")
    L.append(f"{v['fully_linked']}/{v['eligible_workflows']} eligible workflows fully linked = **{_f(v['fraction'], 4)}**. "
             f"{v['definition']}. The synthetic generator deliberately drops one stage in ~3% of ordinary workflows.\n")
    sp = m["seed_spread_test"]
    L.append("## Sensitivity to the isolation-forest seed (test split)\n")
    L.append("| metric | mean | sd | min | max |\n|---|---|---|---|---|")
    for k, a in sp["aggregate"].items():
        if a:
            L.append(f"| {k} | {a['mean']:.3f} | {a['sd']:.3f} | {a['min']:.3f} | {a['max']:.3f} |")
    L.append(f"\nSeeds {sp['seeds']}. {sp['note']}\n")
    b = runs / "benchmark" / "benchmark.json"
    L.append("## Local throughput and latency\n")
    if b.exists():
        bj = json.loads(b.read_text())
        L.append(f"*{bj['meta']['label']}.* Hardware: {bj['meta']['hardware']['platform']}, "
                 f"{bj['meta']['hardware']['processor']}, Python {bj['meta']['hardware']['python']}. "
                 f"Plan: {json.dumps(bj['meta']['plan'])}. Timing: {bj['meta']['timing']}.\n")
        L.append("| payload B | threads | events/run | repeats | events/s mean±sd | p50 ms | p95 ms | p99 ms | completed | dropped | dup publishes injected | dup effects | max backlog |\n|---|---|---|---|---|---|---|---|---|---|---|---|---|")
        for r in bj["summary"]:
            L.append(f"| {r['event_size_bytes']} | {r['worker_threads']} | {r['events_per_run']} | {r['repeats']} | "
                     f"{r['throughput_mean_eps']:.0f}±{r['throughput_sd_eps']:.0f} | {r['p50_ms']:.1f} | {r['p95_ms']:.1f} | "
                     f"{r['p99_ms']:.1f} | {r['completed_total']} | {r['dropped_total']} | {r['duplicate_publishes_injected']} | "
                     f"{r['duplicate_effects_observed']} | {r['max_backlog']} |")
        L.append("\nOne SQLite connection is shared by the worker threads, so extra threads measure contention, not "
                 "parallel scaling. Where `max backlog` equals the queue capacity the producer outran the consumer, so "
                 "p50/p95/p99 there are dominated by queue wait under saturation, not service time. Repeat-to-repeat "
                 "variance is large on this shared Windows host (see sd). This is a local single-machine measurement "
                 "of the companion code; it cannot substantiate enterprise-scale throughput or compare against the "
                 "paper.\n")
    else:
        L.append("Benchmark not run yet (`sedei benchmark`).\n")
    L.append("## Original paper results\n")
    L.append("| quantity | value | unit | denominator | source | run |\n|---|---|---|---|---|---|")
    for q in ("detection accuracy / F1", "false-positive rate", "API latency reduction", "throughput",
              "response time", "dataset / sample counts"):
        L.append(f"| {q} | **unverified** | n/a | n/a | full text not accessible to this build | n/a |")
    L.append("\nSee `references/reported/reported_values.yaml` and `docs/paper-map.md` for what was and was not verified.")
    return "\n".join(L) + "\n"


def generate_report(runs_dir: Path = RUNS_DIR, docs_dir: Path = DOCS) -> list[str]:
    run = _latest(runs_dir, "eval-")
    if run is None:
        return ["no evaluation run found: run `sedei evaluate` first"]
    figs = Path(docs_dir) / "figures"
    figs.mkdir(parents=True, exist_ok=True)
    notes = [x for x in (fig_pr(run, figs), fig_latency(run, figs), fig_throughput(runs_dir, figs),
                         fig_trace(runs_dir, figs)) if x]
    (Path(docs_dir) / "results.md").write_text(results_md(run, runs_dir), encoding="utf-8")
    return notes
