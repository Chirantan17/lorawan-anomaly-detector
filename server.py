# server.py
import json
import asyncio
import threading
import joblib
import pandas as pd
import numpy as np
from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse

from gateway_socket import LoRaWANSocketGateway
from soc_copilot import generate_soc_analysis

xgboost_model = None
feature_names = ["rssi", "snr", "sf", "inter_arrival_time", "fcnt"]

try:
    bundle = joblib.load("lorawan_models_bundle.pkl")
    xgboost_model = bundle.get("xgboost")
    feature_names = bundle.get("feature_names", feature_names)
    print("✅ ML Models loaded successfully from lorawan_models_bundle.pkl")
except Exception as e:
    print(f"⚠️ Model load warning: {e}. Heuristic fallback rules active.")

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

def score_telemetry(telemetry: dict) -> dict:
    """Classifies telemetry via XGBoost; attaches XAI diagnostics on anomaly."""
    try:
        if xgboost_model is not None:
            features_df = pd.DataFrame([{
                "rssi": float(telemetry.get("rssi", -85.0)),
                "snr": float(telemetry.get("snr", 8.0)),
                "sf": int(telemetry.get("sf", 7)),
                "inter_arrival_time": float(telemetry.get("inter_arrival_time", 15.0)),
                "fcnt": int(telemetry.get("fcnt", 1))
            }])
            pred = int(xgboost_model.predict(features_df[feature_names])[0])
        else:
            raise ValueError("No model loaded")
    except Exception:
        iat = float(telemetry.get("inter_arrival_time", 15.0))
        fcnt = int(telemetry.get("fcnt", 1))
        rssi = float(telemetry.get("rssi", -85.0))
        snr = float(telemetry.get("snr", 8.0))
        pred = 1 if (iat < 0.1 and fcnt in [0, 1, 65535]) or (rssi < -105.0 or snr < -3.0) else 0

    telemetry["is_rogue_pred"] = pred

    if pred == 1:
        telemetry["soc_diagnostics"] = generate_soc_analysis(telemetry, model_name="XGBoost Engine")
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
    with open("index.html", "r", encoding="utf-8") as f:
        return HTMLResponse(content=f.read())

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