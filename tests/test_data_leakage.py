from __future__ import annotations

import json
from pathlib import Path

from sedei.config import load_detection, sha256_file
from sedei.datagen import FORBIDDEN_RECORD_KEYS, Generator, assign_splits, write_dataset
from sedei.experiment import Prepared
from sedei.features import FEATURE_NAMES
from sedei.pipeline import load_dataset
from sedei.policy import load_policy
from sedei.validate import validate_dataset

CFG = load_detection()


def test_shipped_dataset_validates_and_matches_checksums(shipped_data):
    assert validate_dataset(shipped_data) == []


def test_generator_is_deterministic(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    assert write_dataset(a, seed=11, scale=0.1) == write_dataset(b, seed=11, scale=0.1)
    assert write_dataset(tmp_path / "c", seed=12, scale=0.1) != write_dataset(a, seed=11, scale=0.1)


def test_shipped_data_regenerates_identically(shipped_data, tmp_path):
    meta = json.loads((Path(shipped_data) / "CHECKSUMS.json").read_text())
    sums = write_dataset(tmp_path, seed=meta["seed"])
    assert sums == meta["sha256"]


def test_no_label_like_fields_reach_telemetry_or_features(small_data):
    for line in (small_data / "telemetry.jsonl").read_text().splitlines():
        assert not (FORBIDDEN_RECORD_KEYS & set(json.loads(line)))
    assert not any(k in n for n in FEATURE_NAMES for k in ("label", "scenario", "episode", "incident", "action"))


def test_features_do_not_depend_on_label_files(small_data, tmp_path):
    ds = load_dataset(small_data)
    p1 = Prepared(ds, load_policy(), CFG)
    ds.labels = {k: not v for k, v in ds.labels.items()}  # flip every label
    p2 = Prepared(ds, load_policy(), CFG)
    assert (p1.X == p2.X).all() and (p1.rule == p2.rule).all()


def test_splits_by_episode_time_and_holdout_family(small_data):
    ds = load_dataset(small_data)
    sp = assign_splits(ds.episodes, CFG["splits"], CFG["holdout_family"])
    fams = {s: {e["family"] for e in ds.episodes if sp[e["episode_id"]] == s} for s in set(sp.values())}
    assert CFG["holdout_family"] not in fams["train"] | fams["val"] | fams["test"]
    assert fams["holdout"] == {CFG["holdout_family"]}
    start = lambda s: [e["start"] for e in ds.episodes if sp[e["episode_id"]] == s]  # noqa: E731
    assert max(start("train")) <= min(start("val")) and max(start("val")) <= min(start("test"))
    seen = set()
    for e in ds.episodes:  # every record belongs to exactly one episode, hence one split
        assert not (seen & set(e["record_ids"]))
        seen |= set(e["record_ids"])


def test_two_tenants_overlap_local_identifiers_and_cover_scenarios(small_data):
    ds = load_dataset(small_data)
    by_principal = {}
    for r in ds.records:
        by_principal.setdefault(r.principal, set()).add(r.tenant)
    assert any(len(t) == 2 for t in by_principal.values())
    scen = {e["scenario"] for e in ds.episodes}
    assert {"normal_workflow", "normal_retry", "healthy_burst", "scope_probe", "replay_injection",
            "lateral_movement"} <= scen
    assert any(r.transport_redelivery for r in ds.records) and any(r.receipt_time - r.event_time > 30
                                                                    for r in ds.records)


def test_healthy_bursts_do_not_define_positives(small_data):
    ds = load_dataset(small_data)
    burst = {rid for e in ds.episodes if e["scenario"] == "healthy_burst" for rid in e["record_ids"]}
    assert burst and not any(ds.labels[r] for r in burst)
    n_dec = max(sum(1 for r in ds.records if r.record_id in burst and r.kind == "gateway_decision"), 1)
    assert n_dec >= 12


def test_validator_flags_problems(tmp_path):
    d = tmp_path / "bad"
    write_dataset(d, seed=3, scale=0.1)
    lines = (d / "telemetry.jsonl").read_text().splitlines()
    rec = json.loads(lines[0])
    rec["label"] = 1
    lines[0] = json.dumps(rec)
    lines.append(lines[1])  # duplicate id
    (d / "telemetry.jsonl").write_text("\n".join(lines) + "\n")
    issues = validate_dataset(d)
    assert any("label-like" in i for i in issues) and any("duplicate" in i for i in issues)
    assert any("checksum" in i for i in issues)
    assert validate_dataset(tmp_path / "missing")[0].startswith("missing")


def test_label_free_user_data_validates(tmp_path):
    d = tmp_path / "u"
    write_dataset(d, seed=3, scale=0.1)
    for n in ("labels.jsonl", "episodes.jsonl", "CHECKSUMS.json", "incidents.json"):
        (d / n).unlink()
    assert validate_dataset(d, require_labels=False) == []
    assert validate_dataset(d)[0].startswith("labels.jsonl missing")


def test_checksum_helper(shipped_data):
    assert len(sha256_file(Path(shipped_data) / "telemetry.jsonl")) == 64
    assert Generator(1, 0.05).build()["records"]
