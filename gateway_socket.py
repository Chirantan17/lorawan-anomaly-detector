# gateway_socket.py
import socket
import json
import time
import random

class LoRaWANSocketGateway:
    def __init__(self, host: str = "127.0.0.1", port: int = 9999):
        self.host = host
        self.port = port
        self.running = False

    def start_udp_server(self, callback):
        self.running = True
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((self.host, self.port))
        print(f"📡 Gateway UDP Socket Listener active on {self.host}:{self.port}")
        
        while self.running:
            try:
                data, addr = sock.recvfrom(4096)
                packet_str = data.decode('utf-8', errors='ignore')
                packet_dict = json.loads(packet_str)
                if not packet_dict.get("timestamp"):
                    packet_dict["timestamp"] = time.time()
                callback(packet_dict)
            except Exception as e:
                if not self.running:
                    break

def simulate_udp_stream(host: str = "127.0.0.1", port: int = 9999, num_packets: int = 5):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    devices = ["Dev_001", "Dev_002", "Rogue_X1", "Rogue_X2", "Jammer_01"]
    
    for _ in range(num_packets):
        dev = random.choice(devices)
        if dev.startswith("Rogue") or dev.startswith("Jammer"):
            payload = {
                "device_id": dev,
                "rssi": round(random.uniform(-118.0, -105.0), 1),
                "snr": round(random.uniform(-10.0, -4.0), 1),
                "sf": random.choice([11, 12]),
                "inter_arrival_time": round(random.uniform(0.01, 0.08), 4),
                "fcnt": random.choice([0, 1, 65535, random.randint(100, 500)]),
                "payload_len": random.choice([16, 24, 150]),
                "freq_mhz": random.choice([865.0625, 865.4025]),
                "timestamp": time.time()
            }
        else:
            payload = {
                "device_id": dev,
                "rssi": round(random.uniform(-90.0, -80.0), 1),
                "snr": round(random.uniform(6.0, 10.0), 1),
                "sf": random.choice([7, 8, 9]),
                "inter_arrival_time": round(random.uniform(10.0, 25.0), 2),
                "fcnt": random.randint(1, 1000),
                "payload_len": random.choice([12, 16, 24]),
                "freq_mhz": 865.0625,
                "timestamp": time.time()
            }
        sock.sendto(json.dumps(payload).encode('utf-8'), (host, port))
        time.sleep(0.05)
    sock.close()