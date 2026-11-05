# train.py
import sys
import time
from pathlib import Path
import pandas as pd
import numpy as np
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from xgboost import XGBClassifier
from sklearn.metrics import f1_score, precision_score, recall_score, confusion_matrix

FILE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = FILE_DIR.parent

DATA_PATH = PROJECT_ROOT / "03_artifacts_and_data" / "phase1_lorawan_100k.csv"
if not DATA_PATH.exists():
    DATA_PATH = PROJECT_ROOT / "data" / "phase1_lorawan_100k.csv"
if not DATA_PATH.exists():
    DATA_PATH = FILE_DIR / "phase1_lorawan_100k.csv"

MODEL_DIR = PROJECT_ROOT / "03_artifacts_and_data"
MODEL_DIR.mkdir(parents=True, exist_ok=True)
MODEL_PATH = MODEL_DIR / "lorawan_models_bundle.pkl"

def train_and_export():
    print(f"Loading dataset from: {DATA_PATH}")
    df = pd.read_csv(DATA_PATH)

    features = ["rssi", "snr", "sf", "inter_arrival_time", "fcnt", "payload_len", "freq_mhz"]
    X = df[features]
    y = df["is_rogue"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )

    print("1. Training Isolation Forest (Contamination=0.12)...")
    iso = IsolationForest(contamination=0.12, random_state=42, n_jobs=-1).fit(X_train)

    print("2. Training Random Forest Baseline (100 trees, max_depth=12)...")
    rf = RandomForestClassifier(n_estimators=100, max_depth=12, random_state=42, n_jobs=-1).fit(X_train, y_train)

    print("3. Training XGBoost Classifier...")
    xgb = XGBClassifier(
        n_estimators=140,
        max_depth=6,
        learning_rate=0.08,
        subsample=0.9,
        colsample_bytree=0.9,
        random_state=42,
        eval_metric="logloss",
        n_jobs=-1
    ).fit(X_train, y_train)

    # Measure actual inference latency on test set
    sample_vec = X_test.iloc[:100]
    t0 = time.perf_counter()
    for _ in range(10):
        _ = xgb.predict(sample_vec)
    avg_latency_ms = ((time.perf_counter() - t0) / 1000) * 1000

    preds = xgb.predict(X_test)
    f1 = f1_score(y_test, preds)
    prec = precision_score(y_test, preds)
    rec = recall_score(y_test, preds)

    print("\n" + "="*50)
    print("🎯 BENCHMARK RESULTS (Slides 22-23 Alignment)")
    print("="*50)
    print(f"F1 Score:           {f1*100:.2f}% (Target: ~99.23%)")
    print(f"Precision:          {prec*100:.2f}% (Target: ~99.41%)")
    print(f"Recall:             {rec*100:.2f}%")
    print(f"Inference Latency:  {avg_latency_ms:.2f} ms per batch (Target: ~1.18 ms)")
    print("="*50 + "\n")

    bundle = {
        "isolation_forest": iso,
        "random_forest": rf,
        "xgboost": xgb,
        "feature_names": features,
        "metrics": {"f1": f1, "precision": prec, "recall": rec, "latency_ms": avg_latency_ms},
        "feature_importance": dict(zip(features, [float(v) for v in xgb.feature_importances_]))
    }

    joblib.dump(bundle, MODEL_PATH)
    # Also save a mirror copy in 01_pipeline_core for direct local access
    joblib.dump(bundle, FILE_DIR / "lorawan_models_bundle.pkl")
    print(f"✅ Models exported successfully to '{MODEL_PATH}'.")

if __name__ == "__main__":
    train_and_export()
