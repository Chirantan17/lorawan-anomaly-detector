# gateway_socket.py
import socket
import json
import time
from collections import defaultdict

class LoRaWANSocketGateway:
    def __init__(self, host="127.0.0.1", port=9999):
        self.host = host
        self.port = port
        self.device_state = defaultdict(lambda: {"last_time": None, "last_fcnt": 0})

    def process_packet(self, raw_data: bytes) -> dict:
        """Parses transport packet bytes and computes real-time sliding features."""
        now = time.time()
        payload = json.loads(raw_data.decode("utf-8"))
        dev_id = payload.get("device_id", "Unknown")
        
        state = self.device_state[dev_id]
        
        # Calculate Inter-Arrival Time (IAT) if not explicitly overridden by simulator
        if "inter_arrival_time" in payload:
            iat = float(payload["inter_arrival_time"])
        elif state["last_time"] is not None:
            iat = max(0.001, round(now - state["last_time"], 4))
        else:
            iat = 15.0  # Default nominal baseline
            
        # Calculate Frame Counter Delta (FCnt Jump)
        curr_fcnt = int(payload.get("fcnt", 0))
        fcnt_delta = curr_fcnt - state["last_fcnt"] if state["last_fcnt"] > 0 else 1
        
        # Update device state
        state["last_time"] = now
        state["last_fcnt"] = curr_fcnt
        
        return {
            "device_id": dev_id,
            "rssi": float(payload.get("rssi", -85.0)),
            "snr": float(payload.get("snr", 8.0)),
            "sf": int(payload.get("sf", 7)),
            "inter_arrival_time": iat,
            "fcnt": curr_fcnt,
            "fcnt_delta": fcnt_delta,
            "payload_len": int(payload.get("payload_len", 16)),
            "freq_mhz": float(payload.get("freq_mhz", 865.0625)),
            "timestamp": now
        }

    def start_udp_server(self, callback_fn=None):
        """Starts asynchronous UDP socket listener loop."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, self.port))
        print(f"📡 Gateway UDP Socket Listener live at {self.host}:{self.port}")
        
        try:
            while True:
                data, addr = sock.recvfrom(2048)
                parsed_telemetry = self.process_packet(data)
                print(
                    f"[UDP Ingest] Dev: {parsed_telemetry['device_id']} | "
                    f"IAT: {parsed_telemetry['inter_arrival_time']}s | "
                    f"RSSI: {parsed_telemetry['rssi']} dBm | "
                    f"Len: {parsed_telemetry['payload_len']}B"
                )
                if callback_fn:
                    callback_fn(parsed_telemetry)
        except KeyboardInterrupt:
            print("\nShutting down gateway socket listener.")
        finally:
            sock.close()

def simulate_udp_stream(host="127.0.0.1", port=9999):
    """Sends a mixed 5-packet burst (Benign + 4 Attack Vectors) over UDP port 9999."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sample_pkts = [
        {"device_id": "Dev_001", "rssi": -83.0, "snr": 9.1, "sf": 7, "inter_arrival_time": 14.2, "fcnt": 105, "payload_len": 16, "freq_mhz": 865.0625},
        {"device_id": "Rogue_X1", "rssi": -112.0, "snr": -4.8, "sf": 12, "inter_arrival_time": 0.025, "fcnt": 310, "payload_len": 24, "freq_mhz": 865.0625},
        {"device_id": "Dev_002", "rssi": -86.0, "snr": 8.0, "sf": 8, "inter_arrival_time": 18.5, "fcnt": 242, "payload_len": 24, "freq_mhz": 865.4025},
        {"device_id": "Rogue_X2", "rssi": -93.0, "snr": 2.5, "sf": 8, "inter_arrival_time": 2.1, "fcnt": 0, "payload_len": 16, "freq_mhz": 865.9850},
        {"device_id": "Jammer_01", "rssi": -125.0, "snr": -13.2, "sf": 12, "inter_arrival_time": 0.45, "fcnt": 19, "payload_len": 64, "freq_mhz": 865.0625},
    ]
    for pkt in sample_pkts:
        sock.sendto(json.dumps(pkt).encode("utf-8"), (host, port))
        time.sleep(0.15)
    sock.close()

if __name__ == "__main__":
    simulate_udp_stream()