# server.py
import json
import asyncio
import threading
import time
import sys
from pathlib import Path
import joblib
import pandas as pd
from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

FILE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = FILE_DIR.parent

if str(FILE_DIR) not in sys.path:
    sys.path.insert(0, str(FILE_DIR))

from gateway_socket import LoRaWANSocketGateway, simulate_udp_stream
from soc_copilot import generate_soc_analysis
from database import init_db, log_telemetry, get_blacklisted_devices, remove_blacklisted_device, get_recent_alerts
from mitigation import AutomatedMitigationEngine
from mqtt_listener import ChirpStackMQTTListener

init_db()
mitigation_engine = AutomatedMitigationEngine()

models = {}
feature_names = ["rssi", "snr", "sf", "inter_arrival_time", "fcnt", "payload_len", "freq_mhz"]
active_model_key = "xgboost"

MODEL_PATHS = [
    PROJECT_ROOT / "03_artifacts_and_data" / "lorawan_models_bundle.pkl",
    PROJECT_ROOT / "models" / "lorawan_models_bundle.pkl",
    FILE_DIR / "lorawan_models_bundle.pkl"
]

INDEX_PATHS = [
    FILE_DIR / "index.html",
    PROJECT_ROOT / "03_artifacts_and_data" / "index.html",
    PROJECT_ROOT / "index.html"
]

for p in MODEL_PATHS:
    if p.exists():
        try:
            bundle = joblib.load(p)
            models["xgboost"] = bundle.get("xgboost")
            models["random_forest"] = bundle.get("random_forest")
            models["isolation_forest"] = bundle.get("isolation_forest")
            feature_names = bundle.get("feature_names", feature_names)
            print(f" [Layer 2] ML Models loaded successfully from: {p}")
            break
        except Exception as e:
            print(f" Model load warning: {e}")

INDEX_FILE = next((p for p in INDEX_PATHS if p.exists()), None)

class TelemetryPayload(BaseModel):
    device_id: str = "Dev_001"
    rssi: float = -85.0
    snr: float = 8.0
    sf: int = 7
    inter_arrival_time: float = 15.0
    fcnt: int = 1
    payload_len: int = 16
    freq_mhz: float = 865.0625
    model_type: str = "xgboost"

class BlacklistRequest(BaseModel):
    device_id: str
    reason: str = "Manual Quarantine"

class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in list(self.active_connections):
            try:
                await connection.send_json(message)
            except Exception:
                self.disconnect(connection)

manager = ConnectionManager()
telemetry_queue: asyncio.Queue = asyncio.Queue(maxsize=2000)

def score_telemetry(telemetry: dict, requested_model: str = None) -> dict:
    device_id = telemetry.get("device_id", "Unknown")

    if mitigation_engine.is_blacklisted(device_id):
        telemetry["is_rogue_pred"] = 1
        telemetry["is_quarantined"] = True
        telemetry["soc_diagnostics"] = {
            "incident_id": f"INC-DROP-{int(time.time()) % 10000:04d}",
            "device_id": device_id,
            "threat_category": "Quarantined Node Frame Rejection",
            "severity": "CRITICAL",
            "root_cause_summary": f"Device '{device_id}' exists in SQLite blacklist. Packet discarded at socket boundary.",
            "recommended_iptables_rule": f"iptables -A INPUT -p udp --dport 9999 -m string --algo bm --string '{device_id}' -j DROP",
            "gateway_mac_command": f"LORA_MAC_REJECT_DEVICE --dev-eui {device_id}"
        }
        return telemetry

    model_key = requested_model or active_model_key
    selected_model = models.get(model_key) or models.get("xgboost")
    t0 = time.perf_counter()

    try:
        if selected_model is not None:
            features_df = pd.DataFrame([{
                "rssi": float(telemetry.get("rssi", -85.0)),
                "snr": float(telemetry.get("snr", 8.0)),
                "sf": int(telemetry.get("sf", 7)),
                "inter_arrival_time": float(telemetry.get("inter_arrival_time", 15.0)),
                "fcnt": int(telemetry.get("fcnt", 1)),
                "payload_len": int(telemetry.get("payload_len", 16)),
                "freq_mhz": float(telemetry.get("freq_mhz", 865.0625))
            }])
            raw_pred = int(selected_model.predict(features_df[feature_names])[0])
            pred = 1 if (model_key == "isolation_forest" and raw_pred == -1) else raw_pred
        else:
            raise ValueError("Model bundle unavailable")
    except Exception:
        iat = float(telemetry.get("inter_arrival_time", 15.0))
        fcnt = int(telemetry.get("fcnt", 1))
        rssi = float(telemetry.get("rssi", -85.0))
        snr = float(telemetry.get("snr", 8.0))
        plen = int(telemetry.get("payload_len", 16))
        pred = 1 if (iat < 0.10 or fcnt in [0, 1, 65535] or rssi < -108.0 or snr < -4.0 or plen > 100) else 0

    latency_ms = round((time.perf_counter() - t0) * 1000, 2)
    telemetry["is_rogue_pred"] = pred
    telemetry["inference_ms"] = latency_ms
    telemetry["model_used"] = model_key.upper()
    telemetry["is_quarantined"] = False

    if pred == 1:
        soc_diag = generate_soc_analysis(telemetry, model_name=model_key.upper())
        telemetry["soc_diagnostics"] = soc_diag
        mitigation_engine.evaluate_and_enforce(device_id, soc_diag)
        threat_label = soc_diag.get("threat_category", "Anomaly")
    else:
        telemetry["soc_diagnostics"] = None
        threat_label = "Normal"

    try:
        log_telemetry(telemetry, is_anomaly=pred, threat_type=threat_label)
    except Exception:
        pass

    return telemetry

async def queue_consumer():
    while True:
        packet = await telemetry_queue.get()
        try:
            scored = score_telemetry(packet)
            await manager.broadcast(scored)
        except Exception as err:
            print(f"Consumer error: {err}")
        finally:
            telemetry_queue.task_done()

@asynccontextmanager
async def lifespan(app: FastAPI):
    loop = asyncio.get_running_loop()

    def packet_callback(packet_dict: dict):
        if not telemetry_queue.full():
            loop.call_soon_threadsafe(telemetry_queue.put_nowait, packet_dict)

    gateway = LoRaWANSocketGateway(host="127.0.0.1", port=9999)
    gw_thread = threading.Thread(target=gateway.start_udp_server, args=(packet_callback,), daemon=True)
    gw_thread.start()

    mqtt_client = ChirpStackMQTTListener(
        broker="localhost",
        port=1883,
        topic="application/+/device/+/event/up",
        evaluation_callback=packet_callback
    )
    mqtt_client.start()

    worker_task = asyncio.create_task(queue_consumer())
    yield
    worker_task.cancel()

app = FastAPI(title="Real-Time Network Threat Intelligence Engine", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
async def serve_index():
    if INDEX_FILE and INDEX_FILE.exists():
        with open(INDEX_FILE, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return JSONResponse(content={
        "status": "online",
        "engine": "AI-Powered Real-Time Network Security & Packet Analytics Engine",
        "transport": "UDP:127.0.0.1:9999",
        "active_model": active_model_key,
        "websocket": "ws://127.0.0.1:8000/ws/telemetry"
    })

@app.post("/api/evaluate")
async def evaluate_packet(payload: TelemetryPayload):
    global active_model_key
    active_model_key = payload.model_type
    pkt = payload.model_dump()
    pkt["timestamp"] = time.time()
    return score_telemetry(pkt, requested_model=payload.model_type)

@app.post("/api/simulate_udp")
async def trigger_udp_burst():
    threading.Thread(target=simulate_udp_stream, daemon=True).start()
    return {"status": "dispatched", "packets": 15}

@app.get("/api/blacklist")
async def get_blacklist():
    return get_blacklisted_devices()

@app.post("/api/blacklist")
async def add_blacklist(req: BlacklistRequest):
    return {"status": "success", "message": mitigation_engine.blacklist_device(req.device_id, reason=req.reason)}

@app.delete("/api/blacklist/{device_id}")
async def remove_blacklist(device_id: str):
    return {"status": "success" if remove_blacklisted_device(device_id) else "not_found"}

@app.get("/api/alerts")
async def get_alerts():
    return get_recent_alerts(limit=25)

@app.websocket("/ws/telemetry")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="127.0.0.1", port=8000, reload=False)
