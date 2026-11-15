"""
ml_detector.py
---------------
Machine-learning threat detection module.

Trains a RandomForestClassifier on network-traffic features to classify
each connection/record as:
    normal | dos | probe | r2l_u2r

Exposes:
    train_and_save_model()  -> trains, evaluates, and persists the model
    load_model()             -> loads the persisted model + encoders
    predict_traffic(record)  -> returns (label, confidence, per-class probabilities)
"""

import os
import json
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix

MODEL_DIR = "model"
MODEL_PATH = os.path.join(MODEL_DIR, "threat_model.joblib")
ENCODERS_PATH = os.path.join(MODEL_DIR, "encoders.joblib")
METRICS_PATH = os.path.join(MODEL_DIR, "metrics.json")
DATA_PATH = os.path.join("data", "network_traffic.csv")

CATEGORICAL_COLS = ["protocol_type", "service", "flag"]
NUMERIC_COLS = [
    "duration", "src_bytes", "dst_bytes", "count", "srv_count",
    "serror_rate", "rerror_rate", "same_srv_rate", "diff_srv_rate",
    "num_failed_logins",
]
FEATURE_COLS = CATEGORICAL_COLS + NUMERIC_COLS


def train_and_save_model():
    if not os.path.exists(DATA_PATH):
        from generate_dataset import build_dataset
        os.makedirs("data", exist_ok=True)
        build_dataset().to_csv(DATA_PATH, index=False)

    df = pd.read_csv(DATA_PATH)

    encoders = {}
    for col in CATEGORICAL_COLS:
        le = LabelEncoder()
        df[col] = le.fit_transform(df[col])
        encoders[col] = le

    label_encoder = LabelEncoder()
    y = label_encoder.fit_transform(df["label"])
    encoders["label"] = label_encoder

    X = df[FEATURE_COLS]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    clf = RandomForestClassifier(
        n_estimators=200,
        max_depth=14,
        random_state=42,
        n_jobs=-1,
        class_weight="balanced",
    )
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    report = classification_report(
        y_test, y_pred, target_names=label_encoder.classes_, output_dict=True
    )
    cm = confusion_matrix(y_test, y_pred).tolist()

    os.makedirs(MODEL_DIR, exist_ok=True)
    joblib.dump(clf, MODEL_PATH)
    joblib.dump(encoders, ENCODERS_PATH)

    metrics = {
        "accuracy": acc,
        "classification_report": report,
        "confusion_matrix": cm,
        "classes": label_encoder.classes_.tolist(),
        "feature_importances": dict(zip(FEATURE_COLS, clf.feature_importances_.tolist())),
        "n_train": len(X_train),
        "n_test": len(X_test),
    }
    with open(METRICS_PATH, "w") as f:
        json.dump(metrics, f, indent=2)

    print(f"Model trained. Test accuracy: {acc:.4f}")
    return metrics


def load_model():
    if not (os.path.exists(MODEL_PATH) and os.path.exists(ENCODERS_PATH)):
        train_and_save_model()
    clf = joblib.load(MODEL_PATH)
    encoders = joblib.load(ENCODERS_PATH)
    return clf, encoders


_clf_cache = None
_encoders_cache = None


def _get_cached_model():
    global _clf_cache, _encoders_cache
    if _clf_cache is None:
        _clf_cache, _encoders_cache = load_model()
    return _clf_cache, _encoders_cache


def predict_traffic(record: dict):
    """
    record: dict with keys matching FEATURE_COLS, e.g.
        {
          "duration": 0.5, "protocol_type": "tcp", "service": "http", "flag": "SF",
          "src_bytes": 300, "dst_bytes": 500, "count": 4, "srv_count": 4,
          "serror_rate": 0.0, "rerror_rate": 0.0, "same_srv_rate": 0.9,
          "diff_srv_rate": 0.05, "num_failed_logins": 0
        }
    Returns: (predicted_label: str, confidence: float, probabilities: dict)
    """
    clf, encoders = _get_cached_model()

    row = {}
    for col in CATEGORICAL_COLS:
        le = encoders[col]
        val = record.get(col, le.classes_[0])
        if val not in le.classes_:
            val = le.classes_[0]  # unseen category fallback
        row[col] = le.transform([val])[0]
    for col in NUMERIC_COLS:
        row[col] = float(record.get(col, 0.0))

    X = pd.DataFrame([row])[FEATURE_COLS]
    proba = clf.predict_proba(X)[0]
    label_encoder = encoders["label"]
    pred_idx = int(np.argmax(proba))
    pred_label = label_encoder.inverse_transform([pred_idx])[0]
    confidence = float(proba[pred_idx])
    probabilities = {
        cls: float(p) for cls, p in zip(label_encoder.classes_, proba)
    }
    return pred_label, confidence, probabilities


if __name__ == "__main__":
    train_and_save_model()
