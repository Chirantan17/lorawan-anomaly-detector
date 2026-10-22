# server.py
import json
import asyncio
import threading
import time
import joblib
import pandas as pd
from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from gateway_socket import LoRaWANSocketGateway, simulate_udp_stream
from soc_copilot import generate_soc_analysis

models = {}
feature_names = ["rssi", "snr", "sf", "inter_arrival_time", "fcnt", "payload_len", "freq_mhz"]
active_model_key = "xgboost"

try:
    bundle = joblib.load("../models/lorawan_models_bundle.pkl")
    models["xgboost"] = bundle.get("xgboost")
    models["random_forest"] = bundle.get("random_forest")
    models["isolation_forest"] = bundle.get("isolation_forest")
    feature_names = bundle.get("feature_names", feature_names)
    print("✅ ML Models (XGBoost, Random Forest, Isolation Forest) loaded from lorawan_models_bundle.pkl")
except Exception as e:
    print(f"⚠️ Model load warning: {e}. Heuristic fallback rules active.")

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
telemetry_queue: asyncio.Queue = asyncio.Queue(maxsize=1000)

def score_telemetry(telemetry: dict, requested_model: str = None) -> dict:
    """Classifies telemetry via selected ML model; attaches XAI diagnostics on anomaly."""
    model_key = requested_model or active_model_key
    selected_model = models.get(model_key) or models.get("xgboost")
    t0 = time.perf_counter()

    try:
        if selected_model is not None:
            features_df = pd.DataFrame([{
                "rssi": float(telemetry.get("rssi", -85.0)),
                "snr": float(telemetry.get("snr", 8.0)),
                "sf": int(telemetry.get("sf", 7)),
                "inter_arrival_time": float(telemetry.get("inter_arrival_time", telemetry.get("iat", 15.0))),
                "fcnt": int(telemetry.get("fcnt", 1)),
                "payload_len": int(telemetry.get("payload_len", 16)),
                "freq_mhz": float(telemetry.get("freq_mhz", 865.0625))
            }])
            raw_pred = int(selected_model.predict(features_df[feature_names])[0])
            # Isolation Forest outputs -1 for anomaly and 1 for normal
            if model_key == "isolation_forest":
                pred = 1 if raw_pred == -1 else 0
            else:
                pred = raw_pred
        else:
            raise ValueError("No model loaded")
    except Exception:
        iat = float(telemetry.get("inter_arrival_time", telemetry.get("iat", 15.0)))
        fcnt = int(telemetry.get("fcnt", 1))
        rssi = float(telemetry.get("rssi", -85.0))
        snr = float(telemetry.get("snr", 8.0))
        plen = int(telemetry.get("payload_len", 16))
        pred = 1 if (iat < 0.10 or fcnt in [0, 1, 65535] or rssi < -108.0 or snr < -4.0 or plen > 100) else 0

    latency_ms = round((time.perf_counter() - t0) * 1000, 2)
    telemetry["is_rogue_pred"] = pred
    telemetry["inference_ms"] = latency_ms
    telemetry["model_used"] = model_key.upper()

    if pred == 1:
        telemetry["soc_diagnostics"] = generate_soc_analysis(telemetry, model_name=model_key.upper())
    else:
        telemetry["soc_diagnostics"] = None

    return telemetry

async def queue_consumer():
    """Reads packets from UDP ingest queue, evaluates them, and broadcasts to UI."""
    while True:
        packet = await telemetry_queue.get()
        try:
            scored = score_telemetry(packet)
            await manager.broadcast(scored)
        except Exception as err:
            print(f"Inference/broadcast error: {err}")
        finally:
            telemetry_queue.task_done()

@asynccontextmanager
async def lifespan(app: FastAPI):
    loop = asyncio.get_running_loop()

    def udp_callback(packet_dict: dict):
        if not telemetry_queue.full():
            loop.call_soon_threadsafe(telemetry_queue.put_nowait, packet_dict)

    gateway = LoRaWANSocketGateway(host="127.0.0.1", port=9999)
    gw_thread = threading.Thread(
        target=gateway.start_udp_server,
        args=(udp_callback,),
        daemon=True
    )
    gw_thread.start()

    worker_task = asyncio.create_task(queue_consumer())
    yield
    worker_task.cancel()

app = FastAPI(title="LoRaWAN Real-Time Security Engine", lifespan=lifespan)

@app.get("/")
async def get_dashboard():
    with open("../web/index.html", "r", encoding="utf-8") as f:
        return HTMLResponse(content=f.read())

@app.post("/api/evaluate")
async def evaluate_packet(payload: TelemetryPayload):
    """Direct REST evaluation endpoint for UI buttons and manual injector."""
    global active_model_key
    active_model_key = payload.model_type
    pkt = payload.model_dump()
    pkt["timestamp"] = time.time()
    scored = score_telemetry(pkt, requested_model=payload.model_type)
    return scored

@app.post("/api/simulate_udp")
async def trigger_udp_burst():
    """Triggers a 5-packet UDP burst into port 9999 on a background thread."""
    threading.Thread(target=simulate_udp_stream, daemon=True).start()
    return {"status": "dispatched", "packets": 5}

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
    uvicorn.run("server:app", host="127.0.0.1", port=8000, reload=True)
