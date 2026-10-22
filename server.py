# server.py
import json
import asyncio
import joblib
import pandas as pd
import numpy as np
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from src.gateway_socket import LoRaWANSocketGateway
from src.soc_copilot import generate_soc_analysis

app = FastAPI(title="LoRaWAN Real-Time Security Engine")

# Load pre-trained models
try:
    bundle = joblib.load("models/lorawan_models_bundle.pkl")
    xgboost_model = bundle["xgboost"]
    feature_names = bundle["feature_names"]
    print("✅ ML Models loaded successfully.")
except Exception as e:
    print(f"⚠️ Model load warning: {e}. Ensure models/lorawan_models_bundle.pkl exists.")

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
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                pass

manager = ConnectionManager()

def run_ml_inference(telemetry: dict) -> dict:
    """Passes socket telemetry through XGBoost model & attaches GenAI diagnostics if anomalous."""
    try:
        # Build feature dataframe
        input_data = pd.DataFrame([{
            "rssi": telemetry.get("rssi", -85.0),
            "snr": telemetry.get("snr", 8.0),
            "sf": telemetry.get("sf", 7),
            "inter_arrival_time": telemetry.get("inter_arrival_time", 30.0),
            "fcnt": telemetry.get("fcnt", 1)
        }])
        
        # XGBoost Prediction (0 = Clean, 1 = Rogue)
        pred = int(xgboost_model.predict(input_data[feature_names])[0])
        telemetry["is_rogue_pred"] = pred
        
        # Generate SOC Copilot diagnostics if flagged as anomaly
        if pred == 1:
            soc_report = generate_soc_analysis(telemetry, model_name="XGBoost Engine")
            telemetry["soc_diagnostics"] = soc_report
        else:
            telemetry["soc_diagnostics"] = None
            
    except Exception as err:
        # Fallback heuristic if models are missing
        is_rogue = 1 if (telemetry.get("rssi", -85) < -105 or telemetry.get("inter_arrival_time", 1) < 0.1) else 0
        telemetry["is_rogue_pred"] = is_rogue
        if is_rogue:
            telemetry["soc_diagnostics"] = generate_soc_analysis(telemetry)
            
    return telemetry

@app.websocket("/ws/telemetry")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # Keep-alive loop
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

@app.get("/")
async def get_dashboard():
    with open("index.html", "r", encoding="utf-8") as f:
        return HTMLResponse(content=f.read())

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)