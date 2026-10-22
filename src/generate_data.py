# generate_data.py
import numpy as np
import pandas as pd
import os

def generate_lorawan_dataset(records=100000, output_path="phase1_lorawan_100k.csv"):
    """
    Synthesizes a realistic 100,000 LoRaWAN PHY/MAC telemetry dataset
    simulating authentic node distributions alongside 4 explicit cyberattack vectors.
    """
    np.random.seed(42)
    
    BENIGN_DEVICES = ["Dev_001", "Dev_002", "Dev_003", "Dev_004", "Dev_005"]
    ROGUE_DEVICES = ["Rogue_X1", "Rogue_X2", "Jammer_01"]
    
    n_benign = int(records * 0.88)
    n_rogue = records - n_benign
    
    # ---------------- 1. BENIGN TRANSMISSIONS (88%) ----------------
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
    
    # ---------------- 2. ROGUE ATTACK TRANSMISSIONS (12%) ----------------
    # Sub-divide into 4 concrete LoRaWAN attack profiles
    n_dos = int(n_rogue * 0.40)       # Gateway DoS Flooding
    n_replay = int(n_rogue * 0.30)    # Frame Replay & Sequence Reset
    n_jamming = int(n_rogue * 0.20)   # RF Fading / Signal Jamming
    n_malformed = n_rogue - (n_dos + n_replay + n_jamming) # Payload Anomaly

    # Attack Vector 1: Gateway DoS Burst
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

    # Attack Vector 2: Frame Counter Replay
    replay_data = {
        "device_id": np.random.choice(ROGUE_DEVICES, n_replay),
        "rssi": np.random.normal(loc=-92.0, scale=5.0, size=n_replay),
        "snr": np.random.normal(loc=3.0, scale=2.5, size=n_replay),
        "sf": np.random.choice([7, 8, 9], size=n_replay),
        "inter_arrival_time": np.random.uniform(low=1.0, high=8.0, size=n_replay),
        "fcnt": np.random.choice([0, 1, 65535], size=n_replay),
        "payload_len": np.random.choice([12, 16], size=n_replay),
        "freq_mhz": np.random.choice([865.0625, 865.9850], size=n_replay),
        "attack_type": "REPLAY_SPOOF",
        "is_rogue": 1
    }

    # Attack Vector 3: RF Physical Layer Jamming
    jamming_data = {
        "device_id": ["Jammer_01"] * n_jamming,
        "rssi": np.random.normal(loc=-124.0, scale=4.0, size=n_jamming),
        "snr": np.random.normal(loc=-12.5, scale=2.0, size=n_jamming),
        "sf": np.random.choice([11, 12], size=n_jamming),
        "inter_arrival_time": np.random.uniform(low=0.2, high=1.5, size=n_jamming),
        "fcnt": np.random.randint(1, 1000, size=n_jamming),
        "payload_len": np.random.choice([32, 64], size=n_jamming),
        "freq_mhz": [865.0625] * n_jamming,
        "attack_type": "JAMMING_RF",
        "is_rogue": 1
    }

    # Attack Vector 4: Oversized Payload Malformation
    malformed_data = {
        "device_id": np.random.choice(ROGUE_DEVICES, n_malformed),
        "rssi": np.random.normal(loc=-95.0, scale=6.0, size=n_malformed),
        "snr": np.random.normal(loc=1.0, scale=3.0, size=n_malformed),
        "sf": np.random.choice([10, 11, 12], size=n_malformed),
        "inter_arrival_time": np.random.uniform(low=0.5, high=15.0, size=n_malformed),
        "fcnt": np.random.randint(1, 500, size=n_malformed),
        "payload_len": np.random.choice([128, 222, 255], size=n_malformed),
        "freq_mhz": np.random.choice([865.4025, 865.9850], size=n_malformed),
        "attack_type": "MALFORMED_PAYLOAD",
        "is_rogue": 1
    }

    df_benign = pd.DataFrame(benign_data)
    df_dos = pd.DataFrame(dos_data)
    df_replay = pd.DataFrame(replay_data)
    df_jamming = pd.DataFrame(jamming_data)
    df_malformed = pd.DataFrame(malformed_data)

    df_total = pd.concat([df_benign, df_dos, df_replay, df_jamming, df_malformed])
    df_total = df_total.sample(frac=1.0, random_state=42).reset_index(drop=True)
    
    df_total.to_csv(output_path, index=False)
    print(f"✅ Enhanced LoRaWAN dataset saved to '{output_path}' ({len(df_total):,} rows).")
    print(f"📊 Attack Distribution:\n{df_total['attack_type'].value_counts()}")

if __name__ == "__main__":
    generate_lorawan_dataset()