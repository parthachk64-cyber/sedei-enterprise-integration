"""Seeded Isolation Forest: explicitly a COMPANION BASELINE, not the paper's estimator (unspecified).

Score orientation: score = -sklearn.score_samples(x). HIGHER means MORE anomalous. Raw scores are
unbounded in principle; risk.py rescales with baseline percentiles stored in the model metadata.
Model files are joblib (pickle) -- load only artifacts you produced; load() verifies a SHA-256 sidecar.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import joblib
import numpy as np
import sklearn
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from sedei.features import FEATURE_NAMES, FEATURE_VERSION

ORIENTATION = "higher_is_more_anomalous"


class ModelIntegrityError(RuntimeError):
    pass


class AnomalyDetector:
    def __init__(self, n_estimators: int = 200, max_samples: int = 256, seed: int = 42) -> None:
        self.n_estimators, self.max_samples, self.seed = n_estimators, max_samples, seed
        self.scaler: StandardScaler | None = None
        self.model: IsolationForest | None = None
        self.meta: dict = {}

    def fit(self, x: np.ndarray, floor_pct: float = 50.0, ceil_pct: float = 99.5) -> AnomalyDetector:
        x = np.asarray(x, dtype=float)
        if x.ndim != 2 or x.shape[1] != len(FEATURE_NAMES) or len(x) < 10:
            raise ValueError("training matrix must be (n>=10, n_features)")
        self.scaler = StandardScaler().fit(x)  # fitted on the training baseline only
        xs = self.scaler.transform(x)
        self.model = IsolationForest(n_estimators=self.n_estimators,
                                     max_samples=min(self.max_samples, len(x)),
                                     contamination="auto", random_state=self.seed).fit(xs)
        base = -self.model.score_samples(xs)
        self.meta = {
            "feature_version": FEATURE_VERSION, "feature_names": list(FEATURE_NAMES),
            "orientation": ORIENTATION, "seed": self.seed, "n_train": int(len(x)),
            "n_estimators": self.n_estimators, "sklearn_version": sklearn.__version__,
            "baseline_floor": float(np.percentile(base, floor_pct)),
            "baseline_ceiling": float(np.percentile(base, ceil_pct)),
            "floor_percentile": floor_pct, "ceiling_percentile": ceil_pct,
        }
        return self

    def score(self, x: np.ndarray) -> np.ndarray:
        if self.model is None or self.scaler is None:
            raise RuntimeError("detector is not fitted")
        return -self.model.score_samples(self.scaler.transform(np.asarray(x, dtype=float)))

    def normalize(self, raw: np.ndarray) -> np.ndarray:
        lo, hi = self.meta["baseline_floor"], self.meta["baseline_ceiling"]
        return np.clip((np.asarray(raw) - lo) / max(hi - lo, 1e-9), 0.0, 1.0)

    def save(self, directory: Path | str) -> dict:
        d = Path(directory)
        d.mkdir(parents=True, exist_ok=True)
        mp = d / "anomaly.joblib"
        joblib.dump({"scaler": self.scaler, "model": self.model}, mp)
        meta = dict(self.meta, sha256=hashlib.sha256(mp.read_bytes()).hexdigest(),
                    model_version=f"if-{FEATURE_VERSION}-s{self.seed}")
        (d / "anomaly.meta.json").write_text(json.dumps(meta, indent=2, sort_keys=True), encoding="utf-8")
        return meta

    @classmethod
    def load(cls, directory: Path | str) -> AnomalyDetector:
        d = Path(directory)
        meta = json.loads((d / "anomaly.meta.json").read_text(encoding="utf-8"))
        mp = d / "anomaly.joblib"
        if hashlib.sha256(mp.read_bytes()).hexdigest() != meta["sha256"]:
            raise ModelIntegrityError("model file does not match recorded SHA-256")
        if meta["feature_names"] != list(FEATURE_NAMES):
            raise ModelIntegrityError("feature set differs from the one the model was trained on")
        blob = joblib.load(mp)
        det = cls(meta["n_estimators"], seed=meta["seed"])
        det.scaler, det.model, det.meta = blob["scaler"], blob["model"], meta
        return det
