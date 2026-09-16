import pandas as pd
import numpy as np
import joblib
import shap
from sklearn.model_selection import train_test_split
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from xgboost import XGBClassifier
import os

def train_and_export():
    data_path = "data/phase1_lorawan_100k.csv"
    if not os.path.exists(data_path):
        raise FileNotFoundError(f"{data_path} not found. Run generate_data.py first.")

    print("Loading local dataset...")
    df = pd.read_csv(data_path)

    features = ['rssi', 'snr', 'sf', 'inter_arrival_time', 'fcnt']
    X = df[features]
    y = df['label']

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, random_state=42, stratify=y
    )

    print("Training Isolation Forest (Unsupervised)...")
    iso = IsolationForest(contamination=0.15, random_state=42, n_jobs=-1).fit(X_train)

    print("Training Random Forest...")
    rf = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42, n_jobs=-1).fit(X_train, y_train)

    print("Training XGBoost (Supervised)...")
    xgb = XGBClassifier(n_estimators=100, max_depth=6, learning_rate=0.1, random_state=42, eval_metric="logloss", n_jobs=-1).fit(X_train, y_train)

    print("Initializing SHAP Explainer Engine...")
    background_sample = X_train.sample(n=100, random_state=42)
    explainer = shap.TreeExplainer(xgb, background_sample)

    bundle = {
        "isolation_forest": iso,
        "random_forest": rf,
        "xgboost": xgb,
        "shap_explainer": explainer,
        "feature_names": features
    }

    os.makedirs("models", exist_ok=True)
    joblib.dump(bundle, "models/lorawan_models_bundle.pkl")
    print("Models and SHAP Explainer successfully saved to 'models/lorawan_models_bundle.pkl'.")

if __name__ == "__main__":
    train_and_export()