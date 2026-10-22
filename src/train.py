# train.py
import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from xgboost import XGBClassifier
from sklearn.metrics import classification_report, f1_score, precision_score, recall_score

def train_and_export():
    print("Loading upgraded local dataset...")
    df = pd.read_csv("../data/phase1_lorawan_100k.csv")
    
    features = ["rssi", "snr", "sf", "inter_arrival_time", "fcnt", "payload_len", "freq_mhz"]
    X = df[features]
    y = df["is_rogue"]
    
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )
    
    print("1. Training Isolation Forest (Unsupervised)...")
    iso = IsolationForest(contamination=0.12, random_state=42, n_jobs=-1).fit(X_train)
    
    print("2. Training Random Forest (Supervised)...")
    rf = RandomForestClassifier(n_estimators=100, max_depth=12, random_state=42, n_jobs=-1).fit(X_train, y_train)
    
    print("3. Training XGBoost Classifier (Supervised Fast-Path)...")
    xgb = XGBClassifier(
        n_estimators=120,
        max_depth=6,
        learning_rate=0.08,
        random_state=42,
        eval_metric="logloss",
        n_jobs=-1
    ).fit(X_train, y_train)
    
    # Validation evaluation
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
        "feature_importance": dict(zip(features, xgb.feature_importances_))
    }
    
    joblib.dump(bundle, "../models/lorawan_models_bundle.pkl")
    print("✅ Models and feature mappings exported to 'lorawan_models_bundle.pkl'.")

if __name__ == "__main__":
    train_and_export()
