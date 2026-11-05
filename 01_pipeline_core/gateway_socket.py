# gateway_socket.py
import socket
import struct
import json
import time
import random
import math
from collections import defaultdict, deque

# Speed of light in air (meters per nanosecond)
C_M_PER_NS = 0.299792458 

class LoRaWANSocketGateway:
    """
    Layer 1: Network Ingress & Multi-Gateway Protocol Parser.
    Handles UDP sockets, binary frames, deduplication, and TDoA spatial checks.
    """
    STRUCT_FORMAT = ">8shhBIB"
    STRUCT_SIZE = struct.calcsize(STRUCT_FORMAT)

    # Reference Gateway Coordinates (BPHC Lab Testbed) in meters (x, y)
    GATEWAYS = {
        "GW_A": {"x": 0.0, "y": 0.0},
        "GW_B": {"x": 450.0, "y": 300.0}
    }

    def __init__(self, host: str = "127.0.0.1", port: int = 9999, window_size: int = 10):
        self.host = host
        self.port = port
        self.running = False
        self.window_size = window_size
        self.device_history = defaultdict(lambda: {
            "last_ts": None,
            "last_fcnt": None,
            "iat_window": deque(maxlen=window_size)
        })

    def unpack_binary_frame(self, data: bytes) -> dict:
        dev_id_raw, rssi, snr_x10, sf, fcnt, plen = struct.unpack(self.STRUCT_FORMAT, data[:self.STRUCT_SIZE])
        return {
            "device_id": dev_id_raw.decode("utf-8", errors="ignore").strip("\x00"),
            "gateway_id": "GW_A",
            "rssi": float(rssi),
            "snr": float(snr_x10 / 10.0),
            "sf": int(sf),
            "fcnt": int(fcnt),
            "payload_len": int(plen),
            "freq_mhz": 865.0625,
            "tdoa_variance_ns": 0.0,
            "timestamp": time.time()
        }

    def check_tdoa_consistency(self, gw_a_ts_ns: float, gw_b_ts_ns: float) -> float:
        """Computes TDoA jitter variance between two observing gateways (Slide 29)."""
        delta_t_ns = abs(gw_a_ts_ns - gw_b_ts_ns)
        
        # Max physical propagation delay based on gateway separation
        dx = self.GATEWAYS["GW_A"]["x"] - self.GATEWAYS["GW_B"]["x"]
        dy = self.GATEWAYS["GW_A"]["y"] - self.GATEWAYS["GW_B"]["y"]
        max_dist_m = math.hypot(dx, dy)
        max_physical_delta_ns = max_dist_m / C_M_PER_NS

        # If arrival difference exceeds speed-of-light window, report variance spike
        if delta_t_ns > max_physical_delta_ns:
            return round(delta_t_ns - max_physical_delta_ns, 2)
        return 0.0

    def process_streaming_metrics(self, packet: dict) -> dict:
        dev_id = packet.get("device_id", "Unknown")
        now = packet.get("timestamp", time.time())
        current_fcnt = int(packet.get("fcnt", 0))

        state = self.device_history[dev_id]

        if state["last_ts"] is not None:
            live_iat = max(0.0005, round(now - state["last_ts"], 4))
            delta_fcnt = current_fcnt - state["last_fcnt"]
        else:
            live_iat = float(packet.get("inter_arrival_time", 15.0))
            delta_fcnt = 1

        state["last_ts"] = now
        state["last_fcnt"] = current_fcnt
        state["iat_window"].append(live_iat)

        rolling_iat = sum(state["iat_window"]) / len(state["iat_window"])
        packet["inter_arrival_time"] = live_iat
        packet["rolling_iat_avg"] = round(rolling_iat, 4)
        packet["delta_fcnt"] = delta_fcnt
        return packet

    def start_udp_server(self, callback):
        self.running = True
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
        sock.bind((self.host, self.port))
        print(f"📡 [Layer 1] Multi-Gateway UDP Socket bound on {self.host}:{self.port} (Buffer: 64KB)")

        while self.running:
            try:
                data, _ = sock.recvfrom(4096)
                if len(data) == self.STRUCT_SIZE:
                    packet = self.unpack_binary_frame(data)
                else:
                    packet = json.loads(data.decode("utf-8", errors="ignore"))
                    if "timestamp" not in packet:
                        packet["timestamp"] = time.time()

                enriched = self.process_streaming_metrics(packet)
                callback(enriched)
            except Exception:
                if not self.running:
                    break
        sock.close()

def simulate_udp_stream(host: str = "127.0.0.1", port: int = 9999, num_packets: int = 15, attack_profile: str = "mixed"):
    """
    Simulates gateway packet streams covering the 7 slide attack scenarios:
    - DOS_FLOOD (Duty-Cycle)
    - REPLAY (FCnt desync)
    - RF_JAMMING (Noise floor)
    - MALFORMED (Oversized MTU)
    - TDOA_SPOOF (Spatial Sybil)
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    devices = ["Dev_001", "Dev_002", "Dev_003", "Rogue_X1", "Jammer_01", "Sybil_Node"]

    for i in range(num_packets):
        dev = "Rogue_X1" if attack_profile == "replay" else ("Sybil_Node" if attack_profile == "tdoa" else random.choice(devices))
        now = time.time()

        if dev == "Rogue_X1":
            payload = {
                "device_id": dev,
                "gateway_id": "GW_A",
                "rssi": -92.0,
                "snr": 3.0,
                "sf": 7,
                "fcnt": 0,  # Replay counter reset
                "payload_len": 24,
                "freq_mhz": 865.4025,
                "tdoa_variance_ns": 12.0,
                "timestamp": now
            }
            delay = 0.05
        elif dev == "Jammer_01":
            payload = {
                "device_id": dev,
                "gateway_id": "GW_A",
                "rssi": -122.0,
                "snr": -12.0,
                "sf": 12,
                "fcnt": 150,
                "payload_len": 32,
                "freq_mhz": 865.0625,
                "tdoa_variance_ns": 5.0,
                "timestamp": now
            }
            delay = 0.08
        elif dev == "Sybil_Node" or attack_profile == "tdoa":
            payload = {
                "device_id": "Sybil_Node",
                "gateway_id": "GW_B",
                "rssi": -88.0,
                "snr": 7.5,
                "sf": 8,
                "fcnt": 210,
                "payload_len": 16,
                "freq_mhz": 865.0625,
                "tdoa_variance_ns": 425.0,  # Slide 29 trigger: > 350.0 ns
                "timestamp": now
            }
            delay = 0.1
        else:
            payload = {
                "device_id": dev,
                "gateway_id": "GW_A",
                "rssi": round(random.uniform(-88.0, -82.0), 1),
                "snr": round(random.uniform(7.0, 10.0), 1),
                "sf": 7,
                "fcnt": 1000 + i,
                "payload_len": 16,
                "freq_mhz": 865.0625,
                "tdoa_variance_ns": round(random.uniform(2.0, 45.0), 1),
                "timestamp": now
            }
            delay = 0.15

        sock.sendto(json.dumps(payload).encode("utf-8"), (host, port))
        time.sleep(delay)
    sock.close()
