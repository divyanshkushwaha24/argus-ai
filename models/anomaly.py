"""
Argus AI — Isolation Forest anomaly baseline.

Unsupervised anomaly detector trained on benign traffic features.
Its score becomes the A_anomaly signal fed into risk fusion.

Rare/weird flows get isolated in very few splits → high anomaly score.
"""

from __future__ import annotations

import os
from typing import Dict, List

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

import config


# Features used by the anomaly model — general flow characteristics
# that should differ between normal and anomalous traffic regardless
# of the specific threat type.
ANOMALY_FEATURE_COLS = [
    "total_packets",
    "total_bytes",
    "packet_rate",
    "byte_rate",
    "average_packet_size",
    "upload_download_ratio",
    "source_flow_count",
    "unique_destination_ips",
    "unique_destination_ports",
    "flow_duration",
]


class AnomalyModel:
    """Isolation Forest trained on benign traffic."""

    def __init__(self):
        self.model: IsolationForest = None
        self.feature_cols = ANOMALY_FEATURE_COLS
        self._model_path = os.path.join(config.MODEL_SAVE_DIR, "anomaly_iforest.joblib")

    def train(self, X_train: pd.DataFrame) -> Dict:
        """Train on benign-only traffic features.

        Isolation Forest uses contamination='auto' so it adapts to the
        data distribution without requiring a fixed anomaly ratio.
        """
        self.model = IsolationForest(
            n_estimators=200,
            contamination="auto",
            random_state=42,
        )
        self.model.fit(X_train)

        os.makedirs(config.MODEL_SAVE_DIR, exist_ok=True)
        joblib.dump(self.model, self._model_path)

        # Report average anomaly score on training data (should be near 0)
        scores = self.model.decision_function(X_train)
        return {
            "mean_score": float(scores.mean()),
            "std_score": float(scores.std()),
            "n_samples": len(X_train),
        }

    def load(self):
        """Load trained model from disk."""
        if os.path.exists(self._model_path):
            self.model = joblib.load(self._model_path)

    def score(self, row: pd.Series) -> float:
        """Return anomaly score ∈ [0, 1] for one flow record.

        Isolation Forest's decision_function returns negative values for
        anomalies and positive for normal points.  We invert and clamp
        to [0, 1]:  anomaly_score = max(0, min(1, -decision / 0.5))

        This gives:
          - Normal traffic → ~0.0
          - Mildly unusual  → 0.3–0.6
          - Strong anomaly  → 0.8–1.0
        """
        if self.model is None:
            self.load()
        if self.model is None:
            return 0.0

        features = {}
        for col in self.feature_cols:
            val = row.get(col, 0)
            features[col] = float(val) if pd.notna(val) else 0.0

        X = pd.DataFrame([features])[self.feature_cols]
        decision = self.model.decision_function(X)[0]

        # Invert: more negative → more anomalous → higher score
        anomaly_score = max(0.0, min(1.0, -decision / 0.5))
        return round(anomaly_score, 4)
