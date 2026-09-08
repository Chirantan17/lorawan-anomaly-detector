import numpy as np
import pandas as pd
import os

def generate_lorawan_dataset(records=100000, output_path="data/phase1_lorawan_100k.csv"):
    np.random.seed(42)
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    BENIGN_DEVICES = ["Dev_001", "Dev_002", "Dev_003", "Dev_004", "Dev_005"]
    ROGUE_DEVICE = "Rogue_X1"
    
    n_benign = int(records * 0.90)
    n_rogue = int(records * 0.10)
    
    # Benign traffic (90%)
    benign_data = {
        "device_id": np.random.choice(BENIGN_DEVICES, n_benign),
        "rssi": np.random.normal(loc=-85, scale=5, size=n_benign),
        "snr": np.random.normal(loc=8, scale=2, size=n_benign),
        "sf": np.random.choice([7, 8, 9, 10], size=n_benign, p=[0.4, 0.3, 0.2, 0.1]),
        "inter_arrival_time": np.random.exponential(scale=30.0, size=n_benign) + 5.0,
        "fcnt": np.tile(np.arange(1, 18001), 5)[:n_benign],
        "is_rogue": 0
    }
    
    # Rogue traffic (10%)
    rogue_data = {
        "device_id": [ROGUE_DEVICE] * n_rogue,
        "rssi": np.random.normal(loc=-115, scale=8, size=n_rogue),
        "snr": np.random.normal(loc=-8, scale=3, size=n_rogue),
        "sf": np.random.choice([11, 12], size=n_rogue, p=[0.3, 0.7]),
        "inter_arrival_time": np.random.uniform(low=0.01, high=0.5, size=n_rogue),
        "fcnt": np.random.choice([0, 1, 65535], size=n_rogue),
        "is_rogue": 1
    }
    
    df = pd.concat([pd.DataFrame(benign_data), pd.DataFrame(rogue_data)]).sample(frac=1.0, random_state=42).reset_index(drop=True)
    df.to_csv(output_path, index=False)
    print(f"Dataset successfully created at '{output_path}' ({len(df)} records).")

if __name__ == "__main__":
    generate_lorawan_dataset()