# Data

## Source registry

| id | provider | exact URL | version / date accessed | license / access | fields used | units | preprocessing | checksum |
|---|---|---|---|---|---|---|---|---|
| **Original evaluation dataset** | **unverified** | n/a | n/a | n/a | n/a | n/a | n/a | n/a |
| S1 Crossref DOI record | Crossref | https://api.crossref.org/works/10.1109/I-SMAC70384.2026.11747907 | accessed 2026-11-25 | open metadata | title, authors, pages, event, reference list | n/a | none | n/a |
| S2 IEEE Xplore PDF | IEEE | https://ieeexplore.ieee.org/iel8/11746888/11747126/11747907.pdf | requested 2026-11-25 | subscription; returned HTML sign-in page | none obtained | n/a | n/a | n/a |
| S3 Companion synthetic telemetry | this repository | `data/telemetry.jsonl` (generator `src/sedei/datagen.py`) | seed 20260916 | MIT (same as code) | see schema below | seconds (epoch), counts | none (generated) | `data/CHECKSUMS.json` |

**Original evaluation dataset unverified.** Sources checked: the Crossref record (no dataset field, no abstract),
the IEEE PDF (not accessible), and the abstract excerpt supplied by the owner (names no dataset). The 14 cited
references were not used to infer a dataset: a reference in related work does not establish what the authors
evaluated on. No generic intrusion-detection corpus (CIC-IDS, UNSW-NB15, …) is substituted or presented as SEDEI's data.

## Synthetic companion dataset

Everything is fictitious (tenants `tenant-a`/`tenant-b`, principals `svc-NN`/`user-NN`, workflow/event ids derived
from episode numbers). Regenerate byte-identically with `sedei generate-data --out data --seed 20260916`
(verified by `tests/test_data_leakage.py::test_shipped_data_regenerates_identically`).

Files: `telemetry.jsonl` (observable records only), `labels.jsonl` (record_id → is_evidence, incident_id),
`episodes.jsonl` (episode → scenario, family, split-relevant start time, record ids), `incidents.json`
(incident → evidence record ids, first/last evidence receipt time, stealth flag), `CHECKSUMS.json`.

**Sampling unit** the *episode* (one workflow, retry, burst, or incident). **Scored unit** one telemetry record of
kind gateway_decision, service_call or event_delivery (`identity_context` records are context only).

**Scenario mix (seed 20260916)**

| scenario | family | episodes | role |
|---|---|---|---|
| normal_workflow (8% delayed events, 8% one benign denial, 3% a telemetry stage dropped) | normal | 500 | negatives |
| normal_retry (transport redelivery, same hash/emitter) | normal | 70 | negatives |
| healthy_burst (12–30 allowed orders in ~1 min, sometimes 1–2 benign repeated denials) | normal | 30 | negatives; a traffic spike alone is never positive |
| scope_probe (20% stealth: 2 denials on one route) | access_misuse | 30 | incident |
| credential_misuse_chain (20% stealth) | multi_stage | 30 | incident |
| replay_injection (20% stealth: replay beyond the 300 s window) | message_integrity | 30 | incident |
| cross_tenant_attempt | tenant_boundary | 20 | incident |
| lateral_movement (20% stealth: one unexpected edge) | lateral_movement | 30 | incident, **held out** |

**Splits** by episode and start time before any fitting: first 60% of non-holdout episodes → train, next 20% → validation,
last 20% → test. The `lateral_movement` family is excluded from training and threshold selection and reported
only as "synthetic holdout performance". Anomaly baseline is fitted on train-split records of non-incident episodes
(assumes a clean baseline period); scalers and percentile bounds are fitted on those rows only; thresholds are selected
on validation; test and holdout are untouched until reporting.

**Leakage controls** records contain no label, scenario, family, episode, incident or response fields (checked by the
generator, `sedei validate-data`, and tests); features are computed from records *received* by the current record's
receipt time; flipping every label leaves features and rule scores unchanged (`test_features_do_not_depend_on_label_files`).

**Clocks** `event_time` is the producer clock, `receipt_time` the collector clock, both simulated epoch seconds.
Delays of 40–240 s model delayed delivery. Simulated times are never subtracted from wall-clock measurements.

**Limitations** Labels and scenarios are authored by the same person who wrote the rules, so rule recall on in-family
incidents is partly circular. Positives are ~9% of scored records (495 of 5,416). There is no benign operational noise beyond the
healthy-burst, retry, delay and single-denial patterns above. Two tenants only. A single dataset seed. The holdout
family is detectable by rule R4 by construction (it reads the trusted service graph), so holdout results do not show
generalisation to unseen attack techniques. None of this characterises real enterprise traffic.

## Replacing the synthetic data with authorized records

1. Export your records as JSONL matching `TelemetryRecord` (`src/sedei/telemetry.py`): one object per line with
   `record_id, kind, tenant, principal, event_time, receipt_time` and the kind-specific fields. Redact tokens and
   payload bodies first. Keep `principal` as the tenant-local identifier.
2. `sedei validate-data --path <dir> --no-labels` checks schema, duplicate ids, receipt ≥ event time and absence of
   label-like keys.
3. Add `labels.jsonl`, `episodes.jsonl` and `incidents.json` in the same schema if you have analyst labels (otherwise only
   `replay` is meaningful). Then `sedei evaluate --data <dir>`.
4. Do not commit authorized data; `data/` in this repo is synthetic only.
