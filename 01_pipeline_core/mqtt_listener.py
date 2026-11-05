# mqtt_listener.py
import json
import time
import logging
from collections import defaultdict

logger = logging.getLogger("MQTTConnector")

try:
    import paho.mqtt.client as mqtt
    MQTT_AVAILABLE = True
except ImportError:
    MQTT_AVAILABLE = False
    logger.warning("⚠️ paho-mqtt not installed. MQTT listener will run in offline stub mode.")

class ChirpStackMQTTListener:
    def __init__(self, broker: str = "localhost", port: int = 1883, topic: str = "application/+/device/+/event/up", evaluation_callback=None):
        self.broker = broker
        self.port = port
        self.topic = topic
        self.callback = evaluation_callback
        self.device_state = defaultdict(lambda: {"last_time": None, "last_fcnt": 0})
        self.client = mqtt.Client() if MQTT_AVAILABLE else None

    def on_connect(self, client, userdata, flags, rc):
        logger.info(f"Connected to MQTT Broker {self.broker}:{self.port} with code {rc}")
        client.subscribe(self.topic)

    def on_message(self, client, userdata, msg):
        try:
            payload = json.loads(msg.payload.decode('utf-8'))
            rx_info = payload.get("rxInfo", [{}])[0]
            tx_info = payload.get("txInfo", {})
            dev_id = payload.get("deviceInfo", {}).get("devEui", "Unknown")
            
            now = time.time()
            state = self.device_state[dev_id]
            
            # Dynamically compute sliding IAT
            if state["last_time"] is not None:
                iat = max(0.001, round(now - state["last_time"], 4))
            else:
                iat = 15.0
                
            state["last_time"] = now
            curr_fcnt = int(payload.get("fCnt", 0))
            state["last_fcnt"] = curr_fcnt
            
            # Translate ChirpStack JSON payload into Security Engine 7-D format
            telemetry = {
                "device_id": dev_id,
                "rssi": float(rx_info.get("rssi", -85.0)),
                "snr": float(rx_info.get("snr", 8.0)),
                "sf": int(tx_info.get("loRaModulationInfo", {}).get("spreadingFactor", 7)),
                "inter_arrival_time": iat,
                "fcnt": curr_fcnt,
                "payload_len": int(len(payload.get("data", ""))),
                "freq_mhz": float(tx_info.get("frequency", 865062500) / 1000000.0),
                "timestamp": now
            }
            
            if self.callback:
                self.callback(telemetry)
        except Exception as e:
            logger.error(f"Failed to parse MQTT packet: {e}")

    def start(self):
        if not MQTT_AVAILABLE:
            return
        try:
            self.client.on_connect = self.on_connect
            self.client.on_message = self.on_message
            self.client.connect_async(self.broker, self.port, 60)
            self.client.loop_start()
            logger.info("📡 MQTT Listener running in background...")
        except Exception as e:
            logger.warning(f"Could not connect to MQTT broker ({e}). Gateway UDP socket remains primary.")