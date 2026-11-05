# database.py
import sqlite3
from datetime import datetime
from pathlib import Path

FILE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = FILE_DIR.parent
DB_PATH = FILE_DIR / "lorawan_security.db"
DB_NAME = str(DB_PATH)

def get_connection():
    conn = sqlite3.connect(DB_NAME, timeout=10)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    return conn

def init_db():
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS telemetry_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME,
            device_id TEXT,
            rssi REAL,
            snr REAL,
            sf INTEGER,
            inter_arrival_time REAL,
            fcnt INTEGER,
            payload_len INTEGER,
            freq_mhz REAL,
            is_anomaly INTEGER,
            threat_type TEXT
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS security_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME,
            device_id TEXT,
            threat_category TEXT,
            severity TEXT,
            recommendation TEXT,
            mitigation_status TEXT
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS blacklisted_devices (
            device_id TEXT PRIMARY KEY,
            blocked_at DATETIME,
            reason TEXT
        )
    ''')
    
    conn.commit()
    conn.close()

def log_telemetry(data: dict, is_anomaly: int, threat_type: str = "Normal"):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO telemetry_logs (
            timestamp, device_id, rssi, snr, sf, 
            inter_arrival_time, fcnt, payload_len, freq_mhz, 
            is_anomaly, threat_type
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        datetime.now().isoformat(),
        data.get("device_id", "Unknown"),
        float(data.get("rssi", -85.0)),
        float(data.get("snr", 8.0)),
        int(data.get("sf", 7)),
        float(data.get("inter_arrival_time", data.get("iat", 15.0))),
        int(data.get("fcnt", 0)),
        int(data.get("payload_len", 16)),
        float(data.get("freq_mhz", 865.0625)),
        int(is_anomaly),
        threat_type
    ))
    conn.commit()
    conn.close()

def log_alert(device_id: str, category: str, severity: str, recommendation: str, status: str = "Active"):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO security_alerts (timestamp, device_id, threat_category, severity, recommendation, mitigation_status)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (datetime.now().isoformat(), device_id, category, severity, recommendation, status))
    conn.commit()
    conn.close()

def get_blacklisted_devices() -> list[dict]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT device_id, blocked_at, reason FROM blacklisted_devices ORDER BY blocked_at DESC")
    rows = cursor.fetchall()
    conn.close()
    return [{"device_id": r[0], "blocked_at": r[1], "reason": r[2]} for r in rows]

def remove_blacklisted_device(device_id: str) -> bool:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM blacklisted_devices WHERE device_id = ?", (device_id,))
    deleted = cursor.rowcount > 0
    conn.commit()
    conn.close()
    return deleted

def get_recent_alerts(limit: int = 20) -> list[dict]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT id, timestamp, device_id, threat_category, severity, recommendation, mitigation_status
        FROM security_alerts
        ORDER BY id DESC LIMIT ?
    ''', (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [{
        "id": r[0],
        "timestamp": r[1],
        "device_id": r[2],
        "threat_category": r[3],
        "severity": r[4],
        "recommendation": r[5],
        "mitigation_status": r[6]
    } for r in rows]
