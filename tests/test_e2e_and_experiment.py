"""End-to-end: the three walkthrough traces on the shipped data, the experiment runner, benchmark, report, CLI."""

from __future__ import annotations

import json

import pytest

from sedei import cli
from sedei.benchmark import run_benchmark
from sedei.demo import run_trace1, run_trace2, run_trace3
from sedei.experiment import run_evaluation
from sedei.report import generate_report
from sedei.validate import validate_dataset


@pytest.fixture(scope="module")
def traces(trained_model, shipped_data, tmp_path_factory):
    _, run = trained_model
    out = tmp_path_factory.mktemp("demo")
    m = run / "model"
    return run_trace1(out, m), run_trace2(out, m), run_trace3(out, m, shipped_data)


def test_trace1_authorized_order_completes_with_shared_trace(traces):
    t = traces[0]
    a = t["assertions"]
    assert a["workflow_completed"] and a["all_stages_share_correlation_id"] and a["no_alert"]
    assert {"gateway_decision", "service_call", "event_delivery"} <= set(a["stage_kinds"])
    assert [x["to_state"] for x in t["transitions"]] == ["RECEIVED", "RESERVED", "DISPATCH_AUTHORIZED"]


def test_trace2_redelivery_fulfils_once_and_identity_stays_active(traces):
    a = traces[1]["assertions"]
    assert a["crash_between_processing_and_ack"] and a["inventory_delivery_attempts"] == 2
    assert a["fulfillment_once"] and a["workflow_completed"] and a["no_alert"] and a["identity_active"]
    assert a["redelivery_records_seen"] == 1 and traces[1]["alerts"] == []


def test_trace3_incident_quarantines_event_and_leaves_other_tenant_alone(traces):
    t = traces[2]
    a = t["assertions"]
    assert t["decision"]["action"] == "event_quarantine" and t["action"]["status"] == "committed"
    assert a["victim_event_state"] == "quarantined"
    assert a["other_tenant_same_event_id_state"] == "acked" and a["other_tenant_workflow_state"] == "DISPATCH_AUTHORIZED"
    assert a["no_second_action"] and a["reprocess_reported_deduplicated"] and a["other_tenant_untouched"]
    assert t["audit_chain_valid"] and t["evidence_ids"] and t["reason_codes"] == ["REPLAY_INCONSISTENT"]
    tl = t["timeline"]
    assert tl["first_eligible_evidence_sim"] <= tl["alert_sim"] <= tl["policy_decision_sim"] <= tl["committed_sim"]
    assert {"detect_ms", "decide_ms", "commit_ms"} <= set(tl)
    json.dumps(t, default=str)  # trace is a self-contained JSON document


def test_experiment_runner_on_small_data(small_data, tmp_path):
    run = run_evaluation(small_data, tmp_path)
    m = json.loads((run / "metrics.json").read_text())
    assert m["label"] == "Synthetic companion evaluation" and "unverified" in m["origin"]["published_specification"]
    for split in ("val", "test", "holdout"):
        assert set(m[f"event_classification_{split}"]) == {"rules_only", "anomaly_only", "hybrid"}
    t = m["event_classification_test"]["hybrid"]
    assert t["tp"] + t["fn"] == t["positives"] and t["fp"] + t["tn"] == t["fpr_denominator_negatives"]
    assert 0.0 <= m["visibility"]["fraction"] <= 1.0
    man = json.loads((run / "manifest.json").read_text())
    assert man["seed"] == 42 and man["packages"]["scikit-learn"] and "clock_conventions" in man
    for f in ("scores.csv", "split_mask.csv", "metrics.csv", "model/anomaly.joblib", "detection_latency.csv"):
        assert (run / f).exists()
    notes = generate_report(tmp_path, tmp_path / "docs")
    assert (tmp_path / "docs" / "results.md").exists() and (tmp_path / "docs" / "figures" / "fig_pr_curves.png").exists()
    assert any("throughput" in n or "demo" in n for n in notes)  # missing inputs are reported, not faked
    assert "Synthetic companion evaluation" in (tmp_path / "docs" / "results.md").read_text()


def test_benchmark_tiny_plan(tmp_path):
    out = run_benchmark(tmp_path, {"events": 40, "warmup_events": 10, "repeats": 1, "event_sizes_bytes": [256],
                                   "worker_threads": [1, 2], "queue_capacity": 25})
    j = json.loads((out / "benchmark.json").read_text())
    assert len(j["summary"]) == 2
    for r in j["summary"]:
        assert r["completed_total"] == 40 and r["dropped_total"] == 0 and r["duplicate_effects_observed"] == 0
        assert r["duplicate_publishes_injected"] >= 1 and r["p50_ms"] <= r["p95_ms"] <= r["p99_ms"]
    assert "not enterprise-scale" in j["meta"]["label"]


def test_cli_validate_generate_and_errors(tmp_path, capsys):
    d = tmp_path / "d"
    assert cli.main(["generate-data", "--out", str(d), "--seed", "5", "--scale", "0.1"]) == 0
    assert cli.main(["validate-data", "--path", str(d)]) == 0
    assert validate_dataset(d) == []
    (d / "telemetry.jsonl").write_text("not json\n")
    assert cli.main(["validate-data", "--path", str(d)]) == 1
    with pytest.raises(SystemExit):
        cli.main(["nonsense"])


def test_cli_replay_commits_each_action_once(trained_model, shipped_data, tmp_path, capsys):
    runs, run = trained_model
    rc = cli.main(["replay", "--data", str(shipped_data), "--runs", str(tmp_path), "--model",
                   str(run / "model"), "--limit", "700"])
    assert rc == 0
    alerts = [json.loads(x) for x in (tmp_path / "replay" / "alerts.jsonl").read_text().splitlines()]
    assert alerts and all(a["action_status"] in ("committed", "refused") for a in alerts)
    # repeated alerts for one incident reuse the same committed action
    assert any(a["deduplicated"] for a in alerts) or len(alerts) == len({a["record_id"] for a in alerts})
