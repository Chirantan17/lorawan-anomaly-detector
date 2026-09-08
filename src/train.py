import pandas as pd
import joblib
import os
from sklearn.model_selection import train_test_split
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from xgboost import XGBClassifier

def train_and_export():
    os.makedirs("models", exist_ok=True)
    print("Loading local dataset...")
    df = pd.read_csv("data/phase1_lorawan_100k.csv")
    
    features = ["rssi", "snr", "sf", "inter_arrival_time", "fcnt"]
    X = df[features]
    y = df["is_rogue"]
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42, stratify=y)
    
    print("Training Isolation Forest...")
    iso = IsolationForest(contamination=0.10, random_state=42, n_jobs=-1).fit(X_train)
    
    print("Training Random Forest...")
    rf = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42, n_jobs=-1).fit(X_train, y_train)
    
    print("Training XGBoost...")
    xgb = XGBClassifier(n_estimators=100, max_depth=6, learning_rate=0.1, random_state=42, eval_metric="logloss", n_jobs=-1).fit(X_train, y_train)
    
    bundle = {
        "isolation_forest": iso,
        "random_forest": rf,
        "xgboost": xgb,
        "feature_names": features
    }
    
    joblib.dump(bundle, "models/lorawan_models_bundle.pkl")
    print("Models successfully trained and exported to 'models/lorawan_models_bundle.pkl'.")

if __name__ == "__main__":
    train_and_export()