import sys
from pathlib import Path
import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from xgboost import XGBClassifier
from sklearn.metrics import f1_score, precision_score, recall_score, confusion_matrix

FILE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = FILE_DIR.parent if (FILE_DIR.parent / "data").exists() else FILE_DIR

DATA_PATH = PROJECT_ROOT / "data" / "phase1_lorawan_100k.csv"
if not DATA_PATH.exists():
    DATA_PATH = PROJECT_ROOT / "phase1_lorawan_100k.csv"

MODEL_DIR = PROJECT_ROOT / "models"
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
    
    print("1. Training Isolation Forest (Unsupervised)...")
    iso = IsolationForest(contamination=0.12, random_state=42, n_jobs=-1).fit(X_train)
    
    print("2. Training Random Forest Classifier...")
    rf = RandomForestClassifier(n_estimators=100, max_depth=12, random_state=42, n_jobs=-1).fit(X_train, y_train)
    
    print("3. Training XGBoost Classifier...")
    xgb = XGBClassifier(
        n_estimators=120,
        max_depth=6,
        learning_rate=0.08,
        random_state=42,
        eval_metric="logloss",
        n_jobs=-1
    ).fit(X_train, y_train)
    
    preds = xgb.predict(X_test)
    f1 = f1_score(y_test, preds)
    prec = precision_score(y_test, preds)
    rec = recall_score(y_test, preds)
    print(f"📊 XGBoost Benchmark: F1={f1*100:.2f}% | Precision={prec*100:.2f}% | Recall={rec*100:.2f}%")
    
    bundle = {
        "isolation_forest": iso,
        "random_forest": rf,
        "xgboost": xgb,
        "feature_names": features,
        "feature_importance": dict(zip(features, [float(v) for v in xgb.feature_importances_]))
    }
    
    joblib.dump(bundle, MODEL_PATH)
    print(f"✅ Models exported successfully to '{MODEL_PATH}'.")

if __name__ == "__main__":
    train_and_export()
