"""Contextual risk. Companion formula (the paper's formula is not available).

    R = noisy-or of rule severities                      in [0,1]
    A = anomaly score rescaled by baseline percentiles   in [0,1]
    I = identity privilege tier (0 standard, 1 elevated); counts ONLY when R>0 or A>=0.5
    base = w_rule*R + w_anomaly*A + w_identity*I_eff
    risk = clip(base * criticality, 0, 1)                criticality in [1.0, 1.25]

risk is an ordinal index, NOT a calibrated probability. Missing anomaly score: weights renormalise
over the available components and `degraded` is set.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np

from sedei.detectors.rules import RuleFinding


@dataclass(frozen=True)
class RiskAssessment:
    record_id: str
    risk: float
    components: dict[str, float]
    contributions: dict[str, float]
    degraded: bool
    version: str
    reason_codes: tuple[str, ...] = field(default_factory=tuple)
    evidence_ids: tuple[str, ...] = field(default_factory=tuple)


class RiskModel:
    def __init__(self, cfg: dict) -> None:
        self.cfg = cfg
        self.version = cfg["version"]

    def assess(self, record_id: str, findings: list[RuleFinding], anomaly_norm: float | None,
               privilege: str, criticality: float = 1.0) -> RiskAssessment:
        c = self.cfg
        r = 1.0 - float(np.prod([1.0 - f.severity for f in findings])) if findings else 0.0
        a = None if anomaly_norm is None else float(min(max(anomaly_norm, 0.0), 1.0))
        i_raw = float(c["identity_privilege"].get(privilege, 0.0))
        i_eff = i_raw if (r > 0.0 or (a is not None and a >= 0.5)) else 0.0
        w = {"rule": c["w_rule"], "anomaly": c["w_anomaly"], "identity": c["w_identity"]}
        degraded = a is None
        if degraded:
            total = w["rule"] + w["identity"]
            w = {"rule": w["rule"] / total, "anomaly": 0.0, "identity": w["identity"] / total}
        contrib = {"rule": w["rule"] * r, "anomaly": w["anomaly"] * (a or 0.0),
                   "identity": w["identity"] * i_eff}
        crit = min(max(criticality, 1.0), 1.25)
        risk = float(min(max(sum(contrib.values()) * crit, 0.0), 1.0))
        return RiskAssessment(
            record_id, risk, {"rule": r, "anomaly": a if a is not None else float("nan"),
                              "identity": i_eff, "criticality": crit},
            contrib, degraded, self.version,
            tuple(sorted({rc for f in findings for rc in f.reason_codes})),
            tuple(sorted({e for f in findings for e in f.evidence_ids})))


def rank(assessments: list[RiskAssessment]) -> list[RiskAssessment]:
    """Deterministic ordering: highest risk first; ties broken by record_id ascending."""
    return sorted(assessments, key=lambda a: (-round(a.risk, 12), a.record_id))


def select_threshold(y: np.ndarray, scores: np.ndarray) -> float:
    """Validation-set threshold maximising F1 (alert iff score >= threshold). Smallest maximiser wins.

    Returns +inf if the validation set has no positives (nothing can be calibrated).
    """
    y, s = np.asarray(y).astype(int), np.asarray(scores, dtype=float)
    if y.sum() == 0:
        return float("inf")
    best_f1, best_t = -1.0, float("inf")
    for t in np.unique(s):
        pred = s >= t
        tp = int((pred & (y == 1)).sum())
        fp = int((pred & (y == 0)).sum())
        fn = int(((~pred) & (y == 1)).sum())
        f1 = 2 * tp / (2 * tp + fp + fn) if (2 * tp + fp + fn) else 0.0
        if f1 > best_f1 + 1e-12:
            best_f1, best_t = f1, float(t)
    return best_t
