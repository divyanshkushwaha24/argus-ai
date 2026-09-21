"""
Argus AI — DGA / DNS-tunnelling detector (ML-trained).

Model: XGBoost binary classifier on DNS lexical features.
       Calibrated with CalibratedClassifierCV so confidence ≈ true probability.
       SHAP TreeExplainer for per-prediction explanations.

Features (from dataset + engineered):
  dns_entropy, dns_query_length, dns_digit_ratio, dns_label_count,
  dns_longest_label, dns_unique_bigram_count, dns_unique_trigram_count,
  dns_event_count, dns_unique_domain_count_per_flow,
  dns_max_query_length_per_flow, ngram_score (English-likeness)
"""

from __future__ import annotations

import os
from typing import Dict, Optional, Tuple

import joblib
import numpy as np
import pandas as pd

try:
    import shap
except ImportError:
    shap = None

import config
from features.dns_features import DGA_FEATURE_COLS, extract_dga_features
from models.alert_schema import Detection


class DGAModel:
    """XGBoost-based DGA / DNS-tunnel classifier."""

    def __init__(self):
        self.model = None           # CalibratedClassifierCV wrapping XGBoost
        self.raw_model = None       # Unwrapped XGBoost (for SHAP)
        self.explainer = None       # SHAP TreeExplainer
        self.feature_cols = DGA_FEATURE_COLS
        self._model_path = os.path.join(config.MODEL_SAVE_DIR, "dga_xgboost.joblib")
        self._raw_model_path = os.path.join(config.MODEL_SAVE_DIR, "dga_xgboost_raw.joblib")

    # ── Training ─────────────────────────────────────────────────────
    def train(self, X_train: pd.DataFrame, y_train: pd.Series) -> Dict:
        """Train XGBoost + calibrate.  Returns training metrics."""
        from xgboost import XGBClassifier
        from sklearn.calibration import CalibratedClassifierCV
        from sklearn.metrics import classification_report, roc_auc_score

        # Raw XGBoost
        xgb = XGBClassifier(
            n_estimators=200,
            max_depth=6,
            learning_rate=0.1,
            scale_pos_weight=max(1, (y_train == 0).sum() / max(1, (y_train == 1).sum())),
            use_label_encoder=False,
            eval_metric="logloss",
            random_state=42,
        )
        xgb.fit(X_train, y_train)
        self.raw_model = xgb

        # Calibrated wrapper (Platt scaling via logistic sigmoid)
        # cv=3 because we have limited positive samples
        calibrated = CalibratedClassifierCV(xgb, cv=3, method="sigmoid")
        calibrated.fit(X_train, y_train)
        self.model = calibrated

        # Save both
        os.makedirs(config.MODEL_SAVE_DIR, exist_ok=True)
        joblib.dump(calibrated, self._model_path)
        joblib.dump(xgb, self._raw_model_path)

        # Training metrics
        y_pred = calibrated.predict(X_train)
        y_proba = calibrated.predict_proba(X_train)[:, 1]
        report = classification_report(y_train, y_pred, output_dict=True)
        auc = roc_auc_score(y_train, y_proba) if len(set(y_train)) > 1 else 0.0

        return {"classification_report": report, "roc_auc": auc}

    # ── Loading ──────────────────────────────────────────────────────
    def load(self):
        """Load trained model from disk."""
        if os.path.exists(self._model_path):
            self.model = joblib.load(self._model_path)
        if os.path.exists(self._raw_model_path):
            self.raw_model = joblib.load(self._raw_model_path)
            if shap is not None:
                try:
                    self.explainer = shap.TreeExplainer(self.raw_model)
                except Exception:
                    self.explainer = None

    # ── Inference ────────────────────────────────────────────────────
    def predict(self, row: Union[pd.Series, dict]) -> Optional[Detection]:
        """Run inference on one flow record.  Returns Detection or None."""
        if self.model is None:
            self.load()
        if self.model is None:
            return None

        if isinstance(row, dict):
            row = dict(row)
            if "dest_ip" not in row and "dst_ip" in row:
                row["dest_ip"] = row["dst_ip"]
            if "dest_port" not in row and "dst_port" in row:
                row["dest_port"] = row["dst_port"]
            if "timestamp" not in row and "ts" in row:
                row["timestamp"] = str(row["ts"])
            if "dns_query" not in row and "query" in row:
                row["dns_query"] = row["query"]
            if "dns_event_count" not in row:
                row["dns_event_count"] = 1 if (row.get("dns_query") or row.get("event_type") == "dns") else 0

        # Only run on rows that have DNS data
        dns_event_count = row.get("dns_event_count", 0)
        if pd.isna(dns_event_count) or int(dns_event_count) == 0:
            return None

        features = extract_dga_features(row)
        X = pd.DataFrame([features])[self.feature_cols]
        X = X.fillna(0)

        proba = self.model.predict_proba(X)[0, 1]

        if proba < 0.5:
            return None

        # ── SHAP explanation ─────────────────────────────────────────
        shap_explanation = {}
        if self.explainer is not None:
            try:
                shap_values = self.explainer.shap_values(X)
                if isinstance(shap_values, list):
                    sv = shap_values[1][0]  # class-1 SHAP values
                else:
                    sv = shap_values[0]
                # Top-3 features by absolute SHAP value
                top_idx = np.argsort(np.abs(sv))[-3:][::-1]
                for idx in top_idx:
                    feat_name = self.feature_cols[idx]
                    shap_explanation[feat_name] = {
                        "value": float(X.iloc[0, idx]),
                        "shap": round(float(sv[idx]), 4),
                    }
            except Exception:
                pass

        return Detection(
            timestamp=str(row.get("timestamp", "")),
            flow_id=str(row.get("flow_id", "")),
            src_ip=str(row.get("src_ip", "")),
            src_port=int(row.get("src_port", 0)),
            dest_ip=str(row.get("dest_ip", "")),
            dest_port=int(row.get("dest_port", 0)),
            threat_class="dns_tunnel",
            confidence=round(float(proba), 4),
            evidence={
                "model_probability": round(float(proba), 4),
                "dns_query": str(row.get("dns_query", ""))[:80],
                "shap_top_features": shap_explanation,
                "reason": self._build_reason(features, proba),
            },
            raw_features=features,
        )

    def get_shap_explanation(self, features: Dict) -> Dict:
        """Get SHAP values for a single prediction (used by explain.py)."""
        if self.explainer is None:
            return {}
        X = pd.DataFrame([features])[self.feature_cols].fillna(0)
        try:
            shap_values = self.explainer.shap_values(X)
            if isinstance(shap_values, list):
                sv = shap_values[1][0]
            else:
                sv = shap_values[0]
            return {self.feature_cols[i]: float(sv[i]) for i in range(len(sv))}
        except Exception:
            return {}

    @staticmethod
    def _build_reason(features: Dict, proba: float) -> str:
        parts = [f"DGA/tunnel probability {proba:.2f}"]
        ent = features.get("dns_entropy", 0)
        if ent > config.DGA_ENTROPY_BENIGN_MAX:
            parts.append(f"domain entropy {ent:.2f} (typical benign < {config.DGA_ENTROPY_BENIGN_MAX})")
        qlen = features.get("dns_query_length", 0)
        if qlen > 30:
            parts.append(f"query length {int(qlen)}")
        ngram = features.get("ngram_score", 0)
        if ngram < -5:
            parts.append(f"n-gram score {ngram:.1f} (not English-like)")
        return "; ".join(parts)


_dga_instance: Optional[DGAModel] = None


def build_detector() -> DGAModel:
    global _dga_instance
    if _dga_instance is None:
        _dga_instance = DGAModel()
        _dga_instance.load()
    return _dga_instance


def evaluate(event: Union[dict, pd.Series], r: Any = None) -> Optional[List[dict]]:
    """Contract 2 evaluation function for Cherenkov streaming pipeline."""
    det = build_detector().predict(event)
    if not det:
        return None
    ev = det.evidence
    ev_list = [f"{k}: {v}" for k, v in ev.items()] if isinstance(ev, dict) else (ev if isinstance(ev, list) else [str(ev)])
    return [{
        "threat_class": det.threat_class,
        "confidence": float(det.confidence),
        "evidence": ev_list,
        "flow_id": str(det.flow_id),
        "src_ip": str(det.src_ip),
        "dst_ip": str(getattr(det, "dest_ip", "") or getattr(det, "dst_ip", "") or (event.get("dst_ip") if isinstance(event, dict) else "")),
        "event_time": float(event.get("ts", time.time()) if isinstance(event, dict) else getattr(det, "timestamp_epoch", time.time())),
    }]

