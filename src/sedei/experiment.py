"""Experiment runner: rules-only vs anomaly-only vs hybrid, incident metrics, response-policy comparison.

Origins are kept explicit in every output: `configuration` = companion design choice,
`values` = measured on the synthetic dataset. No published SEDEI result is reproduced here.
"""

from __future__ import annotations

import csv
import json
import platform
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np
import sklearn
from sklearn.metrics import average_precision_score

from sedei import __version__
from sedei.config import CONFIG_DIR, DATA_DIR, RUNS_DIR, load_detection, sha256_file, sha256_json
from sedei.datagen import assign_splits
from sedei.detectors.anomaly import AnomalyDetector
from sedei.detectors.rules import RuleEngine
from sedei.features import FEATURE_NAMES
from sedei.pipeline import Dataset, Scored, load_dataset, score_records
from sedei.policy import RoutingPolicy, load_policy
from sedei.response import SEVERE, decide_contextual, decide_static
from sedei.risk import RiskModel, select_threshold

ORIGIN = {"configuration": "companion_design_choice", "values": "measured_on_synthetic_dataset",
          "published_specification": "unverified (full text not accessible to the build)"}


def git_commit() -> str:
    try:
        out = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, timeout=10,
                             cwd=Path(__file__).resolve().parents[2])
        return out.stdout.strip() if out.returncode == 0 else "uncommitted"
    except (OSError, subprocess.SubprocessError):
        return "uncommitted"


def split_masks(ds: Dataset, cfg: dict) -> dict[str, str]:
    ep_split = assign_splits(ds.episodes, cfg["splits"], cfg["holdout_family"])
    rec_split: dict[str, str] = {}
    for e in ds.episodes:
        for rid in e["record_ids"]:
            rec_split[rid] = ep_split[e["episode_id"]]
    return rec_split


class Prepared:
    """Scored stream plus aligned arrays, built once and reused by every comparison."""

    def __init__(self, ds: Dataset, policy: RoutingPolicy, cfg: dict) -> None:
        self.ds, self.policy, self.cfg = ds, policy, cfg
        self.rules = RuleEngine(cfg["rules"])
        self.scored: list[Scored] = score_records(ds.records, policy, self.rules, cfg["window_s"],
                                                  cfg["late_after_s"])
        self.split = split_masks(ds, cfg)
        ep_inc = {rid: e["incident"] for e in ds.episodes for rid in e["record_ids"]}
        self.in_incident_ep = np.array([ep_inc[s.record.record_id] for s in self.scored])
        self.sp = np.array([self.split[s.record.record_id] for s in self.scored])
        self.y = np.array([ds.labels[s.record.record_id] for s in self.scored], dtype=int)
        self.X = np.array([s.fv.as_list() for s in self.scored])
        self.rule = np.array([s.rule_score for s in self.scored])
        self.priv = [s.record.privilege or "standard" for s in self.scored]
        self.crit = np.array([policy.criticality(s.record.dest_service) if s.record.kind == "service_call"
                              else 1.0 for s in self.scored])


def fit_models(p: Prepared, seed: int) -> tuple[AnomalyDetector, dict]:
    a = p.cfg["anomaly"]
    base = (p.sp == "train") & (~p.in_incident_ep.astype(bool))  # clean baseline-period behaviour
    det = AnomalyDetector(a["n_estimators"], a["max_samples"], seed).fit(
        p.X[base], p.cfg["risk"]["anomaly_floor_percentile"], p.cfg["risk"]["anomaly_ceiling_percentile"])
    raw = det.score(p.X)
    norm = det.normalize(raw)
    rm = RiskModel(p.cfg["risk"])
    risk = np.array([rm.assess(s.record.record_id, s.findings, float(norm[i]), p.priv[i],
                               float(p.crit[i])).risk for i, s in enumerate(p.scored)])
    val = p.sp == "val"
    thr = {"rules_only": select_threshold(p.y[val], p.rule[val]),
           "anomaly_only": select_threshold(p.y[val], raw[val]),
           "hybrid": select_threshold(p.y[val], risk[val])}
    scores = {"rules_only": p.rule, "anomaly_only": raw, "hybrid": risk}
    return det, {"raw": raw, "norm": norm, "risk": risk, "thr": thr, "scores": scores}


def confusion(y: np.ndarray, pred: np.ndarray) -> dict:
    tp, fp = int(((pred == 1) & (y == 1)).sum()), int(((pred == 1) & (y == 0)).sum())
    fn, tn = int(((pred == 0) & (y == 1)).sum()), int(((pred == 0) & (y == 0)).sum())
    prec = tp / (tp + fp) if (tp + fp) else None
    rec = tp / (tp + fn) if (tp + fn) else None
    f1 = 2 * prec * rec / (prec + rec) if prec and rec else (0.0 if (tp + fp) and (tp + fn) else None)
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "n": int(len(y)), "positives": tp + fn,
            "predicted_positive": tp + fp, "precision": prec, "recall": rec, "f1": f1,
            "false_positive_rate": fp / (fp + tn) if (fp + tn) else None,
            "fpr_denominator_negatives": fp + tn}


def evaluate_split(p: Prepared, m: dict, split: str) -> dict:
    sel = p.sp == split
    out = {}
    for name, sc in m["scores"].items():
        t = m["thr"][name]
        pred = (sc[sel] >= t).astype(int)
        r = confusion(p.y[sel], pred)
        y = p.y[sel]
        r["threshold"] = None if np.isinf(t) else float(t)
        r["pr_auc"] = (float(average_precision_score(y, sc[sel]))
                       if 0 < y.sum() < len(y) and len(np.unique(sc[sel])) > 1 else None)
        out[name] = r
    return out


def alert_groups(p: Prepared, sc: np.ndarray, t: float, sel: np.ndarray) -> dict:
    """Alert records in the selection -> groups keyed (tenant, principal, window bucket)."""
    w = p.cfg["response"]["incident_window_s"]
    g: dict[tuple, list[int]] = defaultdict(list)
    for i in np.where(sel & (sc >= t))[0]:
        r = p.scored[i].record
        g[(r.tenant, r.principal, int(r.receipt_time // w))].append(int(i))
    return g


def incident_eval(p: Prepared, sc: np.ndarray, t: float, split: str) -> dict:
    sel = p.sp == split
    eps = {e["episode_id"] for e in p.ds.episodes if p.split[e["record_ids"][0]] == split}
    incs = [i for i in p.ds.incidents if i["episode_id"] in eps]
    win = p.cfg["alert_match_window_s"]
    alert_idx = np.where(sel & (sc >= t))[0]
    used: set[int] = set()
    detected, missed, lat = [], [], []
    for inc in incs:
        lo, hi = inc["first_evidence_receipt"], inc["last_evidence_receipt"] + win
        hits = [int(i) for i in alert_idx
                if p.scored[i].record.tenant == inc["tenant"] and p.scored[i].record.principal == inc["principal"]
                and lo <= p.scored[i].record.receipt_time <= hi]
        if hits:
            used.update(hits)
            first = min(hits, key=lambda i: (p.scored[i].record.receipt_time, p.scored[i].record.record_id))
            lat.append(p.scored[first].record.receipt_time - inc["first_evidence_receipt"])
            detected.append(inc["incident_id"])
        else:
            missed.append({"incident_id": inc["incident_id"], "scenario": inc["scenario"],
                           "stealth": inc["stealth"]})
    spurious = [i for i in alert_idx if int(i) not in used]
    return {"incidents": len(incs), "detected": len(detected), "missed": len(missed),
            "incident_recall": len(detected) / len(incs) if incs else None,
            "alerts_total": int(len(alert_idx)), "spurious_alert_records": len(spurious),
            "spurious_alert_groups": len({(p.scored[i].record.tenant, p.scored[i].record.principal,
                                           int(p.scored[i].record.receipt_time //
                                               p.cfg["response"]["incident_window_s"])) for i in spurious}),
            "detection_latency_s_simulated_receipt_clock": lat,
            "detection_latency_summary": ({"p50": float(np.percentile(lat, 50)), "p95": float(np.percentile(lat, 95)),
                                           "max": float(np.max(lat)), "n": len(lat)} if lat else None),
            "missed_incidents": missed, "detected_ids": detected}


def response_comparison(p: Prepared, m: dict, split: str, rm_cfg: dict) -> dict:
    """Detector outputs held fixed (hybrid risk, same alert gate); only the response policy differs."""
    sel = p.sp == split
    t = m["thr"]["hybrid"]
    rm = RiskModel(p.cfg["risk"])
    n = p.cfg["response"]["tier_count"]
    res = {}
    for mode in ("static", "contextual"):
        types, severe_benign, severe_inc, groups_inc, groups_ben = Counter(), 0, 0, 0, 0
        for key, idxs in sorted(alert_groups(p, m["risk"], t, sel).items()):
            i = idxs[0]
            s = p.scored[i]
            hist_ids = {x for j in idxs for x in rm.assess(s.record.record_id, p.scored[j].findings,
                        float(m["norm"][j]), p.priv[j], float(p.crit[j])).evidence_ids}
            a = rm.assess(s.record.record_id, p.scored[idxs[-1]].findings, float(m["norm"][idxs[-1]]),
                          p.priv[idxs[-1]], float(p.crit[idxs[-1]]))
            ev = [x for x in p.scored if x.record.record_id in hist_ids]
            event_ref = next((x.record.event_id for x in ev if x.record.event_id), None)
            unexp = next((x.record.dest_service for x in ev if x.record.kind == "service_call"), None)
            principal = key[1]
            d = (decide_static(a, t, principal, event_ref, n) if mode == "static"
                 else decide_contextual(a, t, principal, p.priv[idxs[-1]], event_ref, unexp))
            is_inc = any(p.in_incident_ep[j] for j in idxs)
            if d is None:
                continue
            types[d.action_type.value] += 1
            sev = d.action_type in SEVERE
            if is_inc:
                groups_inc += 1
                severe_inc += sev
            else:
                groups_ben += 1
                severe_benign += sev
        res[mode] = {"actions_by_type": dict(types), "alert_groups_on_incident_episodes": groups_inc,
                     "alert_groups_on_benign_episodes": groups_ben,
                     "severe_actions_on_incident_groups": severe_inc,
                     "severe_actions_on_benign_groups": severe_benign}
    res["note"] = ("Collateral (severe action on a benign episode) and action mix only. There is no ground-truth "
                   "'correct action', so this does NOT establish that contextual response is more effective.")
    return res


def visibility(p: Prepared) -> dict:
    need = set(p.policy.required_telemetry_stages)
    inc_eps = {e["episode_id"] for e in p.ds.episodes if e["incident"]}
    ep_of = {rid: e["episode_id"] for e in p.ds.episodes for rid in e["record_ids"]}
    by_corr: dict[str, list] = defaultdict(list)
    for r in p.ds.records:
        if r.correlation_id and ep_of[r.record_id] not in inc_eps:
            by_corr[r.correlation_id].append(r)
    eligible = {c: rs for c, rs in by_corr.items()
                if any(r.kind == "gateway_decision" and r.decision == "allow" for r in rs)}
    linked = [c for c, rs in eligible.items() if need <= {r.kind for r in rs}]
    return {"eligible_workflows": len(eligible), "fully_linked": len(linked),
            "fraction": len(linked) / len(eligible) if eligible else None,
            "required_stages": sorted(need),
            "definition": "allow-decision workflows (non-incident episodes) whose correlation_id has every "
                          "required stage kind in the telemetry received by end of data"}


def seed_spread(p: Prepared, seeds: list[int]) -> dict:
    rows = []
    for sd in seeds:
        _, m = fit_models(p, sd)
        ev = evaluate_split(p, m, "test")
        rows.append({"seed": sd, "anomaly_f1": ev["anomaly_only"]["f1"], "hybrid_f1": ev["hybrid"]["f1"],
                     "anomaly_pr_auc": ev["anomaly_only"]["pr_auc"], "hybrid_pr_auc": ev["hybrid"]["pr_auc"]})
    agg = {}
    for k in ("anomaly_f1", "hybrid_f1", "anomaly_pr_auc", "hybrid_pr_auc"):
        v = [r[k] for r in rows if r[k] is not None]
        agg[k] = {"mean": float(np.mean(v)), "sd": float(np.std(v)), "min": float(np.min(v)),
                  "max": float(np.max(v))} if v else None
    return {"seeds": seeds, "per_seed": rows, "aggregate": agg,
            "note": "Isolation-forest seed only; dataset and splits fixed. Not a significance test."}


def write_csv(path: Path, rows: list[dict]) -> None:
    if not rows:
        return
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)


def run_evaluation(data_dir: Path = DATA_DIR, runs_dir: Path = RUNS_DIR, seed: int | None = None) -> Path:
    cfg = load_detection()
    seed = cfg["anomaly"]["seed"] if seed is None else seed
    ds = load_dataset(data_dir)
    policy = load_policy()
    p = Prepared(ds, policy, cfg)
    det, m = fit_models(p, seed)
    ds_sha = sha256_file(Path(data_dir) / "telemetry.jsonl")
    run_id = f"eval-{ds_sha[:8]}-s{seed}"
    out = Path(runs_dir) / run_id
    (out / "model").mkdir(parents=True, exist_ok=True)
    meta = det.save(out / "model")
    thresholds = {k: (None if np.isinf(v) else float(v)) for k, v in m["thr"].items()}
    (out / "model" / "thresholds.json").write_text(json.dumps(
        {"selected_on": "validation split, max F1, smallest maximiser", "thresholds": thresholds}, indent=1))

    metrics = {"origin": ORIGIN, "label": "Synthetic companion evaluation", "run_id": run_id}
    for split in ("val", "test", "holdout"):
        metrics[f"event_classification_{split}"] = evaluate_split(p, m, split)
    metrics["incident_evaluation"] = {
        sp: {name: incident_eval(p, m["scores"][name], m["thr"][name], sp)
             for name in ("rules_only", "anomaly_only", "hybrid")} for sp in ("test", "holdout")}
    metrics["response_policy_comparison"] = {sp: response_comparison(p, m, sp, cfg["risk"])
                                             for sp in ("test", "holdout")}
    metrics["visibility"] = visibility(p)
    metrics["seed_spread_test"] = seed_spread(p, [0, 1, 2, 3, 4])
    metrics["split_sizes"] = {s: int((p.sp == s).sum()) for s in ("train", "val", "test", "holdout")}
    metrics["positives_by_split"] = {s: int(p.y[p.sp == s].sum()) for s in ("train", "val", "test", "holdout")}
    # per-record recall by incident family on test (detector diagnostics)
    fam_of = {i["incident_id"]: i["family"] for i in ds.incidents}
    fam: dict[str, dict] = {}
    for name in ("rules_only", "anomaly_only", "hybrid"):
        c: dict[str, list[int]] = defaultdict(lambda: [0, 0])
        for i, s in enumerate(p.scored):
            if p.y[i] == 1 and p.sp[i] in ("test", "holdout"):
                f = fam_of[ds.record_incident[s.record.record_id]]
                c[f][1] += 1
                c[f][0] += int(m["scores"][name][i] >= m["thr"][name])
        fam[name] = {f: {"detected_evidence_records": a, "evidence_records": b, "recall": a / b}
                     for f, (a, b) in sorted(c.items())}
    metrics["recall_by_family_test_and_holdout"] = fam
    (out / "metrics.json").write_text(json.dumps(metrics, indent=1, sort_keys=True, default=str))

    flat = []
    for split in ("val", "test", "holdout"):
        for name, r in metrics[f"event_classification_{split}"].items():
            flat.append({"split": split, "detector": name, **{k: r[k] for k in (
                "n", "positives", "predicted_positive", "tp", "fp", "fn", "tn", "precision", "recall", "f1",
                "false_positive_rate", "pr_auc", "threshold")}})
    write_csv(out / "metrics.csv", flat)
    write_csv(out / "scores.csv", [
        {"record_id": s.record.record_id, "split": p.sp[i], "label_is_evidence": int(p.y[i]),
         "rule_score": round(float(p.rule[i]), 6), "anomaly_raw": round(float(m["raw"][i]), 6),
         "anomaly_norm": round(float(m["norm"][i]), 6), "risk": round(float(m["risk"][i]), 6)}
        for i, s in enumerate(p.scored)])
    write_csv(out / "split_mask.csv", [{"record_id": r.record_id, "split": p.split[r.record_id]}
                                       for r in ds.records])
    lat_rows = [{"split": sp, "detector": d, "latency_s_sim_receipt_clock": v}
                for sp, dd in metrics["incident_evaluation"].items() for d, r in dd.items()
                for v in r["detection_latency_s_simulated_receipt_clock"]]
    write_csv(out / "detection_latency.csv", lat_rows)
    (out / "manifest.json").write_text(json.dumps(manifest(data_dir, seed, meta), indent=1, sort_keys=True))
    return out


def manifest(data_dir: Path, seed: int, model_meta: dict | None) -> dict:
    import fastapi
    import pydantic
    return {
        "sedei_version": __version__, "git_commit": git_commit(), "seed": seed,
        "dataset": {"dir": str(Path(data_dir).name), "sha256": json.loads(
            (Path(data_dir) / "CHECKSUMS.json").read_text())["sha256"]},
        "config_sha256": {n: sha256_file(CONFIG_DIR / n) for n in
                          ("detection.yaml", "routing_policy.yaml", "identities.yaml")},
        "model_version": (model_meta or {}).get("model_version"),
        "model_sha256": (model_meta or {}).get("sha256"),
        "feature_names": list(FEATURE_NAMES),
        "packages": {"python": sys.version.split()[0], "numpy": np.__version__,
                     "scikit-learn": sklearn.__version__, "pydantic": pydantic.__version__,
                     "fastapi": fastapi.__version__},
        "platform": platform.platform(), "machine": platform.machine(),
        "clock_conventions": {
            "event_time_receipt_time": "synthetic/producer epoch seconds; simulated, never compared to wall time",
            "processing_time": "time.perf_counter() monotonic, reported in ms, only for benchmark/replay timing",
            "detection_latency": "receipt_time(first qualifying alert) - receipt_time(first evidence), simulated",
        },
        "origin": ORIGIN, "config_hash": sha256_json({"detection": load_detection()}),
    }


def train_model(data_dir: Path = DATA_DIR, runs_dir: Path = RUNS_DIR, seed: int | None = None) -> Path:
    """Fit the baseline anomaly detector on the training split and calibrate thresholds on validation."""
    cfg = load_detection()
    seed = cfg["anomaly"]["seed"] if seed is None else seed
    p = Prepared(load_dataset(data_dir), load_policy(), cfg)
    det, m = fit_models(p, seed)
    out = Path(runs_dir) / f"train-{sha256_file(Path(data_dir) / 'telemetry.jsonl')[:8]}-s{seed}"
    meta = det.save(out / "model")
    (out / "model" / "thresholds.json").write_text(json.dumps(
        {"selected_on": "validation split, max F1, smallest maximiser",
         "thresholds": {k: (None if np.isinf(v) else float(v)) for k, v in m["thr"].items()}}, indent=1))
    (out / "manifest.json").write_text(json.dumps(manifest(data_dir, seed, meta), indent=1, sort_keys=True))
    return out
