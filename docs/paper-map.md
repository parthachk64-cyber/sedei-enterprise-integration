# Paper map

Paper: K. K. Duggineni, P. Chakraborty, R. Velu, M. S. Prashanth, R. Rajendran, B. K. Garimalla,
"Secure Event-Driven Enterprise Integration an Intelligent Architecture for API Orchestration, Real-Time
Messaging, and Adaptive Threat Detection," 2026 10th International Conference on I-SMAC, Kirtipur, Nepal,
16–18 Sep 2026, pp. 2064–2072. DOI [10.1109/I-SMAC70384.2026.11747907](https://doi.org/10.1109/I-SMAC70384.2026.11747907).

## What was and was not verified

| source | status |
|---|---|
| Crossref DOI record | **Verified**: title, six authors in order, venue, pages, event dates and location, 14 references. No abstract field. |
| Abstract (Google Scholar excerpt supplied by the owner, truncated at "hybrid rule-based and machine-learning threat detection …") | **Verified as an excerpt only.** Source of every "abstract" row below. |
| IEEE Xplore PDF (`…/iel8/11746888/11747126/11747907.pdf`) | **Not accessible.** The request returned IEEE's HTML sign-in page, not a PDF. |
| Owner-supplied PDF | **Not available** at build time. |
| Sections III, IV, V, figures, tables, equations, datasets, results, code links | **Unverified.** Nothing below claims their content. |

Consequence: this repository is a *companion implementation* of the architecture described in the abstract. It
is not a reproduction of the paper's experiments. If the owner supplies the PDF, every "Unresolved" row below
becomes checkable and `references/reported/reported_values.yaml` can be filled with page-cited values.

## Architecture elements (abstract) → code

| paper element (abstract wording) | origin | file / function | test | artifact |
|---|---|---|---|---|
| security-aware API gateway | abstract | `gateway.py` `Gateway.handle`, `identity.py` | `tests/test_gateway.py` | `runs/demo/trace_1.json` |
| policy-driven orchestration engine | abstract | `orchestration.py`, `policy.py`, `configs/routing_policy.yaml` | `test_store_worker.py::test_transition_policy_enforced` | `trace_1.json` transitions |
| event processing layer (real-time messaging) | abstract | `events.py`, `store.py`, `worker.py` | `test_store_worker.py` | `trace_2.json` |
| unified security telemetry | abstract | `telemetry.py`, `features.py` | `test_features_detectors.py` | `data/telemetry.jsonl` |
| hybrid rule-based and ML threat detection | abstract (ML estimator unspecified) | `detectors/rules.py`, `detectors/anomaly.py` | `test_features_detectors.py` | `runs/eval-*/metrics.json` |
| contextual risk assessment | brief | `risk.py` (companion formula) | `test_risk_response.py` | `scores.csv` |
| adaptive security response | brief | `response.py`, `audit.py` | `test_risk_response.py` | `trace_3.json` |
| continuous behavioral monitoring | abstract | `pipeline.py` `DetectionPipeline` | `test_e2e_and_experiment.py::test_cli_replay…` | `runs/replay/alerts.jsonl` |

## Threat categories (abstract) → modelled evidence

| category named in the abstract | companion model | rule | synthetic scenario |
|---|---|---|---|
| unauthorized API access | repeated scope denials, probing of unfamiliar routes | R1, R2 | `scope_probe` |
| credential misuse | denials followed by allow + unusual service calls | R1, R2, R4 | `credential_misuse_chain` |
| event injection | inconsistent producer metadata on a repeated event id | R3 | `replay_injection` |
| replay attacks | repeated event id without broker assertion / hash or emitter mismatch | R3 | `replay_injection` |
| abnormal service interactions | service call outside the trusted service graph | R4 | `lateral_movement` (held out) |
| multi-stage threats | several evidence types for one principal in a window; contextual escalation | risk + `decide_contextual` | `credential_misuse_chain` |
| cross-tenant access (design addition) | tenant claim ≠ token tenant | R5 | `cross_tenant_attempt` |

## Unresolved details (each needs the full text)

1. ML estimator for threat detection: unspecified in the accessible abstract. Companion baseline: seeded Isolation Forest.
2. Risk-scoring formula and thresholds: unspecified. Companion: `risk.py` noisy-or + weighted components.
3. Rule set and rule thresholds: unspecified. Companion: R1–R5 in `configs/detection.yaml`.
4. Feature set and window length: unspecified. Companion: `fv1`, 300 s.
5. Messaging technology (broker, delivery guarantee): unspecified. Companion: SQLite event log, at-least-once + idempotent consumers.
6. API gateway / orchestration product or policy language: unspecified. Companion: YAML routing policy.
7. Evaluation dataset, workload generator, sample counts: unspecified in the abstract. See `docs/data.md`.
8. Baselines compared against ("improvements" the abstract intends): unnamed. Static-vs-contextual and rule/model/hybrid comparisons here are companion experiments, not the paper's.
9. Reported numbers (accuracy, false-positive rate, latency, throughput): none verified.
10. Figures and tables of the paper: not inspected; none mapped.
11. Section III (architecture), IV (methodology), V (threat model and security requirements): not read; the
    security-requirement list above is derived from the abstract's threat names only.
12. Artifact/code links in the paper: none verified; this repository does not claim access to original code.
13. Of the 14 references in the Crossref record, none was inspected; a reference cited in related work does not
    establish that its dataset was used by the authors.
