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
        
        # Calculate Inter-Arrival Time (IAT)
        if state["last_time"] is not None:
            iat = max(0.001, round(now - state["last_time"], 4))
        else:
            iat = 15.0  # Default nominal baseline
            
        # Calculate Frame Counter Delta (FCnt Jump)
        curr_fcnt = payload.get("fcnt", 0)
        fcnt_delta = curr_fcnt - state["last_fcnt"] if state["last_fcnt"] > 0 else 1
        
        # Update device state
        state["last_time"] = now
        state["last_fcnt"] = curr_fcnt
        
        return {
            "device_id": dev_id,
            "rssi": payload.get("rssi", -85.0),
            "snr": payload.get("snr", 8.0),
            "sf": payload.get("sf", 7),
            "inter_arrival_time": iat,
            "fcnt": curr_fcnt,
            "fcnt_delta": fcnt_delta,
            "timestamp": now
        }

    def start_udp_server(self, callback_fn=None):
        """Starts asynchronous UDP socket listener loop."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((self.host, self.port))
        print(f"📡 Gateway UDP Socket Listener live at {self.host}:{self.port}")
        
        try:
            while True:
                data, addr = sock.recvfrom(1024)
                parsed_telemetry = self.process_packet(data)
                print(f"[UDP Ingest] Dev: {parsed_telemetry['device_id']} | IAT: {parsed_telemetry['inter_arrival_time']}s | RSSI: {parsed_telemetry['rssi']} dBm")
                if callback_fn:
                    callback_fn(parsed_telemetry)
        except KeyboardInterrupt:
            print("\nShutting down gateway socket listener.")
        finally:
            sock.close()

def simulate_udp_stream(host="127.0.0.1", port=9999, count=5):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sample_pkts = [
        {"device_id": "Dev_001", "rssi": -82, "snr": 9.1, "sf": 7, "fcnt": 101},
        {"device_id": "Rogue_X1", "rssi": -118, "snr": -9.2, "sf": 12, "fcnt": 0},
        {"device_id": "Dev_002", "rssi": -86, "snr": 8.0, "sf": 8, "fcnt": 204},
    ]
    for pkt in sample_pkts:
        sock.sendto(json.dumps(pkt).encode("utf-8"), (host, port))
        time.sleep(0.2)
    sock.close()

if __name__ == "__main__":
    gw = LoRaWANSocketGateway()
    gw.start_udp_server()