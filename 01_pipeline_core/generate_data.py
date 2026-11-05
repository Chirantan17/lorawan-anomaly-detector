import numpy as np
import pandas as pd
from pathlib import Path

FILE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = FILE_DIR.parent if (FILE_DIR.parent / "data").exists() else FILE_DIR

DATA_DIR = PROJECT_ROOT / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)
DEFAULT_OUTPUT = DATA_DIR / "phase1_lorawan_100k.csv"

def generate_lorawan_dataset(records=100000, output_path=DEFAULT_OUTPUT):
    np.random.seed(42)
    
    BENIGN_DEVICES = ["Dev_001", "Dev_002", "Dev_003", "Dev_004", "Dev_005"]
    ROGUE_DEVICES = ["Rogue_X1", "Rogue_X2", "Jammer_01"]
    
    n_benign = int(records * 0.88)
    n_rogue = records - n_benign
    
    benign_data = {
        "device_id": np.random.choice(BENIGN_DEVICES, n_benign),
        "rssi": np.random.normal(loc=-85.0, scale=4.5, size=n_benign),
        "snr": np.random.normal(loc=8.5, scale=1.8, size=n_benign),
        "sf": np.random.choice([7, 8, 9, 10], size=n_benign, p=[0.45, 0.30, 0.15, 0.10]),
        "inter_arrival_time": np.random.exponential(scale=25.0, size=n_benign) + 5.0,
        "fcnt": np.tile(np.arange(1, 18001), 5)[:n_benign],
        "payload_len": np.random.choice([12, 16, 24, 32], size=n_benign, p=[0.4, 0.3, 0.2, 0.1]),
        "freq_mhz": np.random.choice([865.0625, 865.4025, 865.9850], size=n_benign),
        "attack_type": "CLEAN",
        "is_rogue": 0
    }
    
    n_dos = int(n_rogue * 0.40)
    n_replay = int(n_rogue * 0.30)
    n_jamming = int(n_rogue * 0.20)
    n_malformed = n_rogue - (n_dos + n_replay + n_jamming)

    dos_data = {
        "device_id": np.random.choice(ROGUE_DEVICES, n_dos),
        "rssi": np.random.normal(loc=-110.0, scale=6.0, size=n_dos),
        "snr": np.random.normal(loc=-4.0, scale=2.0, size=n_dos),
        "sf": np.random.choice([11, 12], size=n_dos),
        "inter_arrival_time": np.random.uniform(low=0.01, high=0.09, size=n_dos),
        "fcnt": np.random.randint(100, 2000, size=n_dos),
        "payload_len": np.random.choice([16, 24], size=n_dos),
        "freq_mhz": np.random.choice([865.0625, 865.4025], size=n_dos),
        "attack_type": "DOS_FLOOD",
        "is_rogue": 1
    }

    replay_data = {
        "device_id": np.random.choice(ROGUE_DEVICES, n_replay),
        "rssi": np.random.normal(loc=-92.0, scale=5.0, size=n_replay),
        "snr": np.random.normal(loc=3.0, scale=2.5, size=n_replay),
        "sf": np.random.choice([7, 8, 9], size=n_replay),
        "inter_arrival_time": np.random.uniform(low=1.0, high=8.0, size=n_replay),
        "fcnt": np.random.choice([0, 1, 65535], size=n_replay),
        "payload_len": np.random.choice([16, 24, 32], size=n_replay),
        "freq_mhz": np.random.choice([865.4025, 865.9850], size=n_replay),
        "attack_type": "REPLAY_ATTACH",
        "is_rogue": 1
    }

    jamming_data = {
        "device_id": np.random.choice(ROGUE_DEVICES, n_jamming),
        "rssi": np.random.normal(loc=-124.0, scale=4.0, size=n_jamming),
        "snr": np.random.normal(loc=-12.5, scale=2.0, size=n_jamming),
        "sf": np.random.choice([11, 12], size=n_jamming),
        "inter_arrival_time": np.random.uniform(low=0.1, high=1.5, size=n_jamming),
        "fcnt": np.random.randint(1, 500, size=n_jamming),
        "payload_len": np.random.choice([32, 64], size=n_jamming),
        "freq_mhz": np.random.choice([865.0625, 865.4025], size=n_jamming),
        "attack_type": "RF_JAMMING",
        "is_rogue": 1
    }

    malformed_data = {
        "device_id": np.random.choice(ROGUE_DEVICES, n_malformed),
        "rssi": np.random.normal(loc=-95.0, scale=6.0, size=n_malformed),
        "snr": np.random.normal(loc=1.0, scale=3.0, size=n_malformed),
        "sf": np.random.choice([9, 10, 11], size=n_malformed),
        "inter_arrival_time": np.random.uniform(low=2.0, high=10.0, size=n_malformed),
        "fcnt": np.random.randint(50, 1000, size=n_malformed),
        "payload_len": np.random.randint(101, 250, size=n_malformed),
        "freq_mhz": np.random.choice([865.0625, 865.9850], size=n_malformed),
        "attack_type": "MALFORMED_PAYLOAD",
        "is_rogue": 1
    }

    df_full = pd.concat([pd.DataFrame(benign_data), pd.DataFrame(dos_data), pd.DataFrame(replay_data), pd.DataFrame(jamming_data), pd.DataFrame(malformed_data)], ignore_index=True)
    df_full = df_full.sample(frac=1.0, random_state=42).reset_index(drop=True)

    df_full.to_csv(output_path, index=False)
    print(f"✅ Generated {len(df_full)} telemetry records at '{output_path}'.")

if __name__ == "__main__":
    generate_lorawan_dataset()
