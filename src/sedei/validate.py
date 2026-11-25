"""Dataset validator. Works on the shipped synthetic data and on authorized user-supplied records."""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import ValidationError

from sedei.config import sha256_file
from sedei.datagen import FORBIDDEN_RECORD_KEYS
from sedei.telemetry import TelemetryRecord


def validate_dataset(directory: Path | str, require_labels: bool = True) -> list[str]:
    d = Path(directory)
    issues: list[str] = []
    tp = d / "telemetry.jsonl"
    if not tp.exists():
        return [f"missing {tp}"]
    ids: set[str] = set()
    recs: list[TelemetryRecord] = []
    for n, line in enumerate(tp.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            raw = json.loads(line)
        except json.JSONDecodeError:
            issues.append(f"telemetry line {n}: not valid JSON")
            continue
        leaked = FORBIDDEN_RECORD_KEYS & set(raw)
        if leaked:
            issues.append(f"telemetry line {n}: label-like keys present {sorted(leaked)}")
        try:
            r = TelemetryRecord(**raw)
        except ValidationError as e:
            issues.append(f"telemetry line {n}: {e.errors()[0]['msg']}")
            continue
        if r.record_id in ids:
            issues.append(f"duplicate record_id {r.record_id}")
        ids.add(r.record_id)
        if r.receipt_time < r.event_time:
            issues.append(f"{r.record_id}: receipt_time precedes event_time")
        recs.append(r)
    lp, ep = d / "labels.jsonl", d / "episodes.jsonl"
    if lp.exists():
        lab = {json.loads(x)["record_id"] for x in lp.read_text(encoding="utf-8").splitlines() if x.strip()}
        if lab != ids:
            issues.append(f"labels cover {len(lab)} records but telemetry has {len(ids)}")
    elif require_labels:
        issues.append("labels.jsonl missing (needed for training/evaluation)")
    if ep.exists():
        seen: dict[str, str] = {}
        for x in ep.read_text(encoding="utf-8").splitlines():
            e = json.loads(x)
            for rid in e["record_ids"]:
                if rid not in ids:
                    issues.append(f"episode {e['episode_id']} references unknown record {rid}")
                if rid in seen:
                    issues.append(f"record {rid} appears in two episodes")
                seen[rid] = e["episode_id"]
    cs = d / "CHECKSUMS.json"
    if cs.exists():
        for name, want in json.loads(cs.read_text())["sha256"].items():
            if (d / name).exists() and sha256_file(d / name) != want:
                issues.append(f"checksum mismatch: {name}")
    return issues
