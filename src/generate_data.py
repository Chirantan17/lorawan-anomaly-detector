import numpy as np
import pandas as pd
import os

def generate_lorawan_dataset(num_samples=100000, output_path="data/phase1_lorawan_100k.csv"):
    np.random.seed(42)
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    devices = [f"Dev_00{i}" for i in range(1, 6)]
    
    # 1. Generate Normal Traffic Base (85% of dataset)
    n_normal = int(num_samples * 0.85)
    
    dev_ids = np.random.choice(devices, n_normal)
    # Log-distance path loss correlation for normal nodes
    rssi_normal = np.random.normal(-90, 8, n_normal)
    snr_normal = 0.35 * rssi_normal + 38 + np.random.normal(0, 2, n_normal)
    sf_normal = np.random.choice([7, 8, 9, 10], n_normal, p=[0.4, 0.3, 0.2, 0.1])
    inter_arrival_normal = np.random.exponential(scale=30.0, size=n_normal) + 1.0
    fcnt_normal = np.sort(np.random.randint(1, 15000, n_normal))
    
    df_normal = pd.DataFrame({
        'device_id': dev_ids,
        'rssi': rssi_normal,
        'snr': snr_normal,
        'sf': sf_normal,
        'inter_arrival_time': inter_arrival_normal,
        'fcnt': fcnt_normal,
        'label': 0,
        'attack_type': 'Normal'
    })
    
    # 2. Attack Vector 1: RF / Distance Spoofing (5%)
    n_spoof = int(num_samples * 0.05)
    dev_spoof = np.random.choice(devices, n_spoof)
    # Physical violation: High RSSI with abnormally low SNR (channel mismatch)
    rssi_spoof = np.random.normal(-65, 5, n_spoof)
    snr_spoof = np.random.normal(-12, 3, n_spoof)
    sf_spoof = np.random.choice([11, 12], n_spoof)
    inter_arrival_spoof = np.random.exponential(scale=20.0, size=n_spoof) + 1.0
    fcnt_spoof = np.random.randint(100, 10000, n_spoof)
    
    df_spoof = pd.DataFrame({
        'device_id': dev_spoof,
        'rssi': rssi_spoof,
        'snr': snr_spoof,
        'sf': sf_spoof,
        'inter_arrival_time': inter_arrival_spoof,
        'fcnt': fcnt_spoof,
        'label': 1,
        'attack_type': 'Distance Spoofing'
    })
    
    # 3. Attack Vector 2: Replay Attack (5%)
    n_replay = int(num_samples * 0.05)
    dev_replay = np.random.choice(devices, n_replay)
    rssi_replay = np.random.normal(-90, 8, n_replay)
    snr_replay = 0.35 * rssi_replay + 38 + np.random.normal(0, 2, n_replay)
    sf_replay = np.random.choice([7, 8, 9, 10], n_replay)
    inter_arrival_replay = np.random.exponential(scale=15.0, size=n_replay) + 0.5
    # Stale / Duplicate FCnt values
    fcnt_replay = np.random.choice(fcnt_normal[:1000], n_replay)
    
    df_replay = pd.DataFrame({
        'device_id': dev_replay,
        'rssi': rssi_replay,
        'snr': snr_replay,
        'sf': sf_replay,
        'inter_arrival_time': inter_arrival_replay,
        'fcnt': fcnt_replay,
        'label': 1,
        'attack_type': 'Replay Attack'
    })

    # 4. Attack Vector 3: Jamming / DoS Flooding (5%)
    n_dos = num_samples - (n_normal + n_spoof + n_replay)
    dev_dos = np.random.choice(devices, n_dos)
    rssi_dos = np.random.normal(-115, 10, n_dos)
    snr_dos = np.random.normal(-18, 4, n_dos)
    sf_dos = np.random.choice([12], n_dos)
    # Burst inter-arrival times (< 0.05 seconds)
    inter_arrival_dos = np.random.uniform(0.001, 0.049, n_dos)
    fcnt_dos = np.random.randint(1, 50000, n_dos)
    
    df_dos = pd.DataFrame({
        'device_id': dev_dos,
        'rssi': rssi_dos,
        'snr': snr_dos,
        'sf': sf_dos,
        'inter_arrival_time': inter_arrival_dos,
        'fcnt': fcnt_dos,
        'label': 1,
        'attack_type': 'Jamming DoS'
    })
    
    # Combine and shuffle dataset
    df_full = pd.concat([df_normal, df_spoof, df_replay, df_dos], ignore_index=True)
    df_full = df_full.sample(frac=1.0, random_state=42).reset_index(drop=True)
    
    df_full.to_csv(output_path, index=False)
    print(f"Dataset successfully created at '{output_path}' ({len(df_full)} records).")

if __name__ == "__main__":
    generate_lorawan_dataset()