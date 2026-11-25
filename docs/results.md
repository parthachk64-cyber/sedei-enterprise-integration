# Results: Synthetic companion evaluation

> **Label: Synthetic companion evaluation.** Every number below was measured on the checked-in synthetic dataset (`data/`) with the companion detectors in this repository. **No value in this file is a result reported by the SEDEI paper**; the paper's own result fields are unverified (see the last section and `references/reported/`).

Run `eval-c00cb09d-s42` · seed 42 · commit `a2285e14ed21` · dataset telemetry sha256 `c00cb09d619c7eeb…` · model `if-fv1-s42`

Origins: configuration = *companion design choice*; values = *measured output*; published specification = *unverified*.

## Units and splits

Primary unit for event classification: one scored telemetry record (gateway decision, service call or event delivery); positive = the record is an evidence step of a labelled incident. Splits are by episode and time (60/20/20), the `lateral_movement` family is held out of training and threshold selection. Incident unit: one incident counted once; an alert matches if it is on the same tenant+principal between first evidence and last evidence + 300 s.

| split | scored records | positive records |
|---|---|---|
| train | 3296 | 299 |
| val | 1049 | 60 |
| test | 972 | 67 |
| holdout | 99 | 69 |

## Event classification: Test split (in-distribution families)

| detector | threshold (val-selected) | TP | FP | FN | TN | precision | recall | F1 | FPR | PR-AUC |
|---|---|---|---|---|---|---|---|---|---|---|
| anomaly only | 0.610 | 54 | 22 | 13 | 883 | 0.711 (54/76) | 0.806 (54/67) | 0.755 | 0.024 (22/905) | 0.752 |
| hybrid | 0.450 | 52 | 9 | 15 | 896 | 0.852 (52/61) | 0.776 (52/67) | 0.812 | 0.010 (9/905) | 0.895 |
| rules only | 0.600 | 49 | 8 | 18 | 897 | 0.860 (49/57) | 0.731 (49/67) | 0.790 | 0.009 (8/905) | 0.702 |

## Event classification: Held-out scenario family (`lateral_movement`), synthetic holdout performance

| detector | threshold (val-selected) | TP | FP | FN | TN | precision | recall | F1 | FPR | PR-AUC |
|---|---|---|---|---|---|---|---|---|---|---|
| anomaly only | 0.610 | 0 | 0 | 69 | 30 | undefined (0/0) | 0.000 (0/69) | undefined | 0.000 (0/30) | 0.567 |
| hybrid | 0.450 | 69 | 0 | 0 | 30 | 1.000 (69/69) | 1.000 (69/69) | 1.000 | 0.000 (0/30) | 1.000 |
| rules only | 0.600 | 69 | 0 | 0 | 30 | 1.000 (69/69) | 1.000 (69/69) | 1.000 | 0.000 (0/30) | 1.000 |

`undefined` = zero denominator (e.g. precision with no predicted positives). PR-AUC is average precision, computed only when both classes and more than one distinct score exist. The holdout split contains only incident episodes, so its negative count is small and FPR there is weak evidence.

## Incident evaluation (each incident counted once)

| split | detector | incidents | detected | missed | alert records | spurious alert records | spurious groups | detection latency p50 / p95 / max (s, simulated) |
|---|---|---|---|---|---|---|---|---|
| holdout | anomaly only | 30 | 0 | 30 | 0 | 0 | 0 | n/a (none detected) |
| holdout | hybrid | 30 | 30 | 0 | 69 | 0 | 0 | 0.0 / 0.0 / 0.0 (n=30) |
| holdout | rules only | 30 | 30 | 0 | 69 | 0 | 0 | 0.0 / 0.0 / 0.0 (n=30) |
| test | anomaly only | 20 | 16 | 4 | 76 | 14 | 10 | 0.0 / 0.0 / 0.0 (n=16) |
| test | hybrid | 20 | 17 | 3 | 61 | 1 | 1 | 11.9 / 48.1 / 112.1 (n=17) |
| test | rules only | 20 | 16 | 4 | 57 | 0 | 0 | 12.1 / 52.1 / 112.1 (n=16) |

Latency is computed over **detected** incidents only; misses are listed separately so a fast-looking detector cannot hide hard cases. Hybrid misses on test: INC0054 (scope_probe, stealth), INC0076 (scope_probe, stealth), INC0080 (scope_probe, stealth).

### Recall of evidence records by incident family (test + holdout)

| family | anomaly only | hybrid | rules only |
|---|---|---|---|
| access_misuse | 23/23 | 15/23 | 13/23 |
| lateral_movement | 0/69 | 69/69 | 69/69 |
| message_integrity | 0/10 | 9/10 | 9/10 |
| multi_stage | 25/28 | 22/28 | 21/28 |
| tenant_boundary | 6/6 | 6/6 | 6/6 |

The held-out family is caught by the rule that compares service calls to the trusted service graph (R4), by construction of that rule, not because a model generalised. The anomaly baseline alone detects none of it. Treat the holdout row as a check that the pipeline does not rely on training exposure, not as evidence of novel-attack detection.

## Static vs contextual response (detector outputs held fixed)

| split | policy | alert groups on incident episodes | alert groups on benign episodes | severe actions on incident groups | severe actions on benign groups | action mix |
|---|---|---|---|---|---|---|
| holdout | static | 33 | 0 | 0 | 0 | {"auth_challenge": 33} |
| holdout | contextual | 33 | 0 | 33 | 0 | {"service_isolation": 33} |
| test | static | 19 | 1 | 4 | 0 | {"access_block": 3, "auth_challenge": 6, "credential_revocation": 1, "event_quarantine": 2, "rate_limit": 8} |
| test | contextual | 19 | 1 | 11 | 0 | {"access_block": 2, "auth_challenge": 2, "credential_revocation": 1, "event_quarantine": 4, "rate_limit": 3, "service_isolation": 8} |

*Severe* = access block, credential revocation, service isolation. Collateral (severe action on a benign episode) and action mix only. There is no ground-truth 'correct action', so this does NOT establish that contextual response is more effective.

## Telemetry visibility

1171/1188 eligible workflows fully linked = **0.9857**. allow-decision workflows (non-incident episodes) whose correlation_id has every required stage kind in the telemetry received by end of data. The synthetic generator deliberately drops one stage in ~3% of ordinary workflows.

## Sensitivity to the isolation-forest seed (test split)

| metric | mean | sd | min | max |
|---|---|---|---|---|
| anomaly_f1 | 0.762 | 0.017 | 0.729 | 0.777 |
| anomaly_pr_auc | 0.753 | 0.006 | 0.742 | 0.758 |
| hybrid_f1 | 0.812 | 0.000 | 0.812 | 0.812 |
| hybrid_pr_auc | 0.892 | 0.001 | 0.890 | 0.893 |

Seeds [0, 1, 2, 3, 4]. Isolation-forest seed only; dataset and splits fixed. Not a significance test.

## Local throughput and latency

*Local measurement of the companion implementation; not enterprise-scale evidence.* Hardware: Windows-10-10.0.26300-SP0, Intel64 Family 6 Model 186 Stepping 2, GenuineIntel, Python 3.10.11. Plan: {"events": 600, "warmup_events": 100, "repeats": 3, "queue_capacity": 200, "event_sizes_bytes": [256, 4096], "worker_threads": [1, 2, 4], "duplicate_fraction": 0.05, "storage": "tempdir SQLite file, WAL, synchronous=NORMAL"}. Timing: time.perf_counter() monotonic; publish->ack per event; warm-up runs discarded.

| payload B | threads | events/run | repeats | events/s mean±sd | p50 ms | p95 ms | p99 ms | completed | dropped | dup publishes injected | dup effects | max backlog |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 256 | 1 | 600 | 3 | 221±16 | 406.8 | 809.9 | 865.9 | 1800 | 0 | 90 | 0 | 199 |
| 256 | 2 | 600 | 3 | 231±3 | 47.5 | 157.9 | 227.3 | 1800 | 0 | 90 | 0 | 38 |
| 256 | 4 | 600 | 3 | 250±11 | 18.5 | 70.4 | 100.8 | 1800 | 0 | 90 | 0 | 23 |
| 4096 | 1 | 600 | 3 | 231±22 | 476.7 | 838.3 | 867.4 | 1800 | 0 | 90 | 0 | 200 |
| 4096 | 2 | 600 | 3 | 204±30 | 16.6 | 59.5 | 91.3 | 1800 | 0 | 90 | 0 | 18 |
| 4096 | 4 | 600 | 3 | 211±14 | 19.7 | 68.8 | 101.9 | 1800 | 0 | 90 | 0 | 20 |

One SQLite connection is shared by the worker threads, so extra threads measure contention, not parallel scaling. Where `max backlog` equals the queue capacity the producer outran the consumer, so p50/p95/p99 there are dominated by queue wait under saturation, not service time. Repeat-to-repeat variance is large on this shared Windows host (see sd). This is a local single-machine measurement of the companion code; it cannot substantiate enterprise-scale throughput or compare against the paper.

## Original paper results

| quantity | value | unit | denominator | source | run |
|---|---|---|---|---|---|
| detection accuracy / F1 | **unverified** | n/a | n/a | full text not accessible to this build | n/a |
| false-positive rate | **unverified** | n/a | n/a | full text not accessible to this build | n/a |
| API latency reduction | **unverified** | n/a | n/a | full text not accessible to this build | n/a |
| throughput | **unverified** | n/a | n/a | full text not accessible to this build | n/a |
| response time | **unverified** | n/a | n/a | full text not accessible to this build | n/a |
| dataset / sample counts | **unverified** | n/a | n/a | full text not accessible to this build | n/a |

See `references/reported/reported_values.yaml` and `docs/paper-map.md` for what was and was not verified.
