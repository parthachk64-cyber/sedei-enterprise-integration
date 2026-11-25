# SEDEI companion: secure event-driven enterprise integration

**Paper.** K. K. Duggineni, P. Chakraborty, R. Velu, M. S. Prashanth, R. Rajendran and B. K. Garimalla,
"Secure Event-Driven Enterprise Integration an Intelligent Architecture for API Orchestration, Real-Time Messaging,
and Adaptive Threat Detection," *2026 10th International Conference on I-SMAC (IoT in Social, Mobile, Analytics and
Cloud)*, Kirtipur, Nepal, 16–18 Sep 2026, pp. 2064–2072. DOI
[10.1109/I-SMAC70384.2026.11747907](https://doi.org/10.1109/I-SMAC70384.2026.11747907) ·
[IEEE record](https://ieeexplore.ieee.org/abstract/document/11747907/).

> **What this is, and is not.** A runnable *companion implementation* of the architecture named in the paper's
> abstract, maintained by Partha Chakraborty. It is **not** the authors' code and **does not reproduce the paper's
> experiments**: at build time the full text was not accessible (IEEE returned a sign-in page), so the paper's
> estimator, risk formula, datasets, baselines and numbers are **unverified** (`docs/paper-map.md`,
> `references/reported/`). Three origins stay separate everywhere: *published specification* (abstract only),
> *companion design choice* (every config), *measured output* (every number in `docs/results.md`, labelled
> "Synthetic companion evaluation").

Start from an API decision → follow its event through the workflow → inspect the evidence behind a threat score →
see whether the policy action was applied exactly once. One command shows all of it:

```bash
git clone https://github.com/parthachk64-cyber/sedei-enterprise-integration && cd sedei-enterprise-integration
python -m pip install -e ".[dev]"      # editable install: configs/ and data/ are read from the checkout
sedei demo                              # ~1-2 min first time (trains the baseline model once)
```

Real output (from this repository, `sedei demo`):

```text
SEDEI walkthrough (three contrasting local traces)

1_authorized_order_completes           first_evidence=1790000000.000  alert=-  decision=-  committed=-
   checks: {"all_stages_share_correlation_id": true, "no_alert": true, "workflow_completed": true, ...}
2_ordinary_redelivery_exactly_once     first_evidence=1790000000.000  alert=-  decision=-  committed=-
   checks: {"crash_between_processing_and_ack": true, "fulfillment_once": true, "identity_active": true,
            "inventory_delivery_attempts": 2, "no_alert": true, "workflow_completed": true, ...}
3_incident_fixture_quarantine          first_evidence=1791162269.673  alert=1791162269.673  decision=1791162269.673  committed=1791162269.673
                                       (monotonic wall ms: detect=31.71 decide=0.03 commit=2.48)
   checks: {"no_second_action": true, "other_tenant_untouched": true, "other_tenant_same_event_id_state": "acked",
            "victim_event_state": "quarantined", "reprocess_reported_deduplicated": true, ...}

Incident INC0015: risk=0.498 reasons=['REPLAY_INCONSISTENT']
decision: event_quarantine -> event:ev-E00085 (contextual policy, inconsistent replayed event)
audit chain valid: True
```

Trace 3, abridged (`runs/demo/trace_3.json` is the full JSON; the sequence can be rebuilt from it alone):

```json
{"incident": {"incident_id": "INC0015", "scenario": "replay_injection", "tenant": "tenant-a", "principal": "svc-06"},
 "rule_findings": [{"rule_id": "R3_INCONSISTENT_REPLAY", "severity": 0.8, "evidence_ids": ["R000619"],
                    "reason_codes": ["REPLAY_INCONSISTENT"], "feature_version": "fv1"}],
 "risk": 0.498, "decision": {"action": "event_quarantine", "target": "event:ev-E00085", "policy": "contextual"},
 "action": {"action_id": "act-d4c2a43c06fc0a02", "status": "committed", "expires_at": 1791165869.673},
 "audit": [{"kind": "action_committed", "scope": "event:ev-E00085", "policy_version": "resp-1.0.0", "evidence": ["R000619"]}],
 "assertions": {"actions_before_reprocess": 1, "actions_after_reprocess": 1, "audit_rows_before": 1, "audit_rows_after": 1}}
```

The three timestamps `alert / policy_decision / committed` are equal in simulated time because the replay commits at
the alert instant; the monotonic `detect_ms / decide_ms / commit_ms` carry the real processing cost. Simulated and
wall clocks are never subtracted from each other (`docs/architecture.md`, "Clock conventions").

## Links

* [Architecture, trust boundaries, ack semantics, failure paths, sequence diagram](docs/architecture.md)
* [Data registry, synthetic dataset, leakage controls, replacing the data](docs/data.md)
* [Results: Synthetic companion evaluation](docs/results.md) · figures in `docs/figures/`
* [Paper map: what is verified, what is unresolved](docs/paper-map.md)
* [Reported values (all unverified)](references/reported/reported_values.yaml)

## Commands

| command | does |
|---|---|
| `sedei demo` | the three traces above; exit 1 if any check fails |
| `sedei generate-data --out data --seed 20260916` | regenerate the synthetic dataset (byte-identical, checksummed) |
| `sedei validate-data [--path DIR] [--no-labels]` | schema, duplicates, label-key leakage, checksums |
| `sedei train` | fit baseline anomaly model on the train split, calibrate thresholds on validation |
| `sedei replay [--limit N]` | stream telemetry through detect → risk → response against the real store |
| `sedei evaluate` | rules vs anomaly vs hybrid, incident metrics, static vs contextual response, visibility, seed spread |
| `sedei benchmark` | bounded local throughput/latency of the real store + worker path |
| `sedei report` | `docs/results.md` and `docs/figures/*.png` from `runs/` artifacts only |
| `sedei reproduce` | validate → evaluate → demo → benchmark → report |
| `sedei serve` | FastAPI gateway on `127.0.0.1:8080` (demo identities only) |

```bash
sedei reproduce        # the whole research run; or: python examples/quickstart_api.py for the gateway alone
```

Each run writes `runs/<id>/manifest.json`: package versions, seed, dataset checksums, config hashes, model version
and SHA-256, git commit, platform, clock conventions.

## What is implemented

| component | module | behaviour |
|---|---|---|
| security-aware API gateway | `gateway.py`, `identity.py`, `api.py` | HMAC test-issuer tokens; revoked/blocked/challenge/rate-limit controls; scope + tenant authorization; strict validation; redacted decision records with correlation IDs; a denied request never starts a workflow |
| policy-driven orchestration | `orchestration.py`, `policy.py` | versioned YAML policy, order → inventory reservation → dispatch authorization, enforced transitions, idempotency keys |
| event processing | `events.py`, `store.py`, `worker.py` | versioned envelope, SQLite WAL log, at-least-once delivery, bounded retry + dead letter, idempotent consumers, atomic transition+event, crash/restart recovery |
| unified telemetry | `telemetry.py`, `features.py` | typed records, tenant-scoped dedup, late flag, features built only from records received by decision time |
| hybrid detection | `detectors/rules.py`, `detectors/anomaly.py` | five transparent rules + seeded Isolation Forest (companion baseline; orientation recorded) |
| contextual risk | `risk.py` | inspectable formula with component contributions, degraded mode, deterministic ties; an ordinal index, **not** a calibrated probability |
| adaptive response + audit | `response.py`, `audit.py` | six actions through local state, decision/action stored separately, dedup, expiry/recovery, fixture-only revocation/isolation, hash-chained audit |

## Tested environment and measured status

* Developed and tested on **Python 3.10.11, Windows 11**; clean-venv install resolved numpy 2.2.6, scikit-learn 1.7.2,
  pydantic 2.14.4, fastapi 0.162.5. The brief suggested Python 3.11; `.github/workflows/ci.yml` runs 3.10/3.11/3.12 with
  read-only permissions, but **CI has not yet run** (the repository was not pushed from the build environment).
* `python -m pytest --cov=sedei` in a clean venv: **84 passed, 0 failed, 94 % line coverage** of `src/sedei`
  (2,077 statements, 118 missed). Weakest: `cli.py` 69 % (interactive `serve`, thin wrappers), `report.py` 78 %.
  `ruff check` is clean. `sedei reproduce` exited 0; its manifests record commit `a2285e1`.
* Measured results are on **synthetic data only** and are summarised, with their limits, in `docs/results.md`.
  Not evidence of real-world detection performance, enterprise-scale throughput, or any claim made by the paper.

## Replacing the synthetic data

See `docs/data.md`: export authorized records as JSONL matching `TelemetryRecord`, run
`sedei validate-data --path DIR --no-labels`, add labels if you have them, then `sedei evaluate --data DIR`.
Never commit authorized data here.

## Security notes

Local demo only. Gateway binds to `127.0.0.1`. Tokens come from a fixture issuer with a published demo key
(override with `SEDEI_DEMO_ISSUER_KEY`); it is not an identity provider. Parameterized SQL only, pydantic validation,
8 KiB request cap, no tokens or bodies in logs/telemetry (tested). Model files are joblib pickles: load only
artifacts you generated (SHA-256 verified on load). Detection and response are offline over pre-authored telemetry;
nothing here executes attacks, acquires credentials, scans networks, or targets systems. Revocation and isolation act
only on fixture identities and services listed in `configs/identities.yaml`.

## Maintainer, license, citation

Sole maintainer and code owner: Partha Chakraborty ([@parthachk64-cyber](https://github.com/parthachk64-cyber)),
see `.github/CODEOWNERS`. MIT license (`LICENSE`; confirm the copyright holder before release). Cite the software with
`CITATION.cff`, which also lists the paper's six authors in published order.
