# test_server.py
import pytest
from fastapi.testclient import TestClient
from server import app

client = TestClient(app)

def test_evaluate_benign_traffic():
    payload = {
        "device_id": "Dev_001",
        "rssi": -85.0,
        "snr": 8.0,
        "sf": 7,
        "inter_arrival_time": 15.0,
        "fcnt": 100,
        "payload_len": 16,
        "freq_mhz": 865.0625,
        "model_type": "xgboost"
    }
    response = client.post("/api/evaluate", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["is_rogue_pred"] == 0
    assert data["soc_diagnostics"] is None

def test_evaluate_dos_attack():
    payload = {
        "device_id": "Rogue_X1",
        "rssi": -110.0,
        "snr": -4.0,
        "sf": 12,
        "inter_arrival_time": 0.02,
        "fcnt": 200,
        "payload_len": 24,
        "freq_mhz": 865.0625,
        "model_type": "xgboost"
    }
    response = client.post("/api/evaluate", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["is_rogue_pred"] == 1
    assert data["soc_diagnostics"] is not None
    assert "DoS" in data["soc_diagnostics"]["threat_category"]

def test_udp_simulation_trigger():
    response = client.post("/api/simulate_udp")
    assert response.status_code == 200
    assert response.json()["status"] == "dispatched"

def test_blacklist_lifecycle():
    dev = "Dev_Test_Quarantine_99"
    # 1. Add to blacklist via REST
    res = client.post("/api/blacklist", json={"device_id": dev, "reason": "Test Containment"})
    assert res.status_code == 200
    
    # 2. Query blacklist
    bl_res = client.get("/api/blacklist")
    assert bl_res.status_code == 200
    blocked_ids = [d["device_id"] for d in bl_res.json()]
    assert dev in blocked_ids
    
    # 3. Packet from blacklisted device must be rejected/quarantined
    eval_res = client.post("/api/evaluate", json={
        "device_id": dev,
        "rssi": -85.0,
        "snr": 8.0,
        "sf": 7,
        "inter_arrival_time": 15.0,
        "fcnt": 50,
        "payload_len": 16,
        "freq_mhz": 865.0625,
        "model_type": "xgboost"
    })
    assert eval_res.status_code == 200
    assert eval_res.json()["is_rogue_pred"] == 1
    assert eval_res.json().get("is_quarantined") is True
    
    # 4. Remove from blacklist
    del_res = client.delete(f"/api/blacklist/{dev}")
    assert del_res.status_code == 200
    
    # 5. Verify release
    bl_res2 = client.get("/api/blacklist")
    blocked_ids2 = [d["device_id"] for d in bl_res2.json()]
    assert dev not in blocked_ids2