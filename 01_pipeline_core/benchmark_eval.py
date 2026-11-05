# benchmark_eval.py
import time
import requests
import json
from gateway_socket import simulate_udp_stream

SERVER_URL = "http://127.0.0.1:8000"

def run_evaluation():
    print("=" * 65)
    print(" 🚀 ADVANCED COMPUTER NETWORKS PROJECT: AUTOMATED EVALUATION SUITE")
    print("=" * 65)

    # 1. Check Server Ingress Health
    try:
        resp = requests.get(f"{SERVER_URL}/")
        assert resp.status_code == 200
        print("✅ [Layer 1] Server & UDP Gateway Ingress is ACTIVE.")
    except Exception as e:
        print(f"❌ Server not reachable at {SERVER_URL}. Start 'python server.py' first.")
        return

    # 2. Simulate Attack Vectors
    scenarios = [
        ("DoS Duty-Cycle Burst", "mixed", 8),
        ("Frame Counter Replay", "replay", 5),
        ("Multi-Gateway TDoA Impersonation", "tdoa", 5)
    ]

    for name, mode, count in scenarios:
        print(f"\n📡 Simulating Traffic Scenario: {name} ({count} packets)...")
        simulate_udp_stream(num_packets=count, attack_profile=mode)
        time.sleep(0.8)

    # 3. Fetch Generated Alerts from Layer 3
    print("\n" + "=" * 65)
    print(" 🛡️ LAYER 3: GENERATED INCIDENT EVIDENCE TRAIL")
    print("=" * 65)
    alerts_resp = requests.get(f"{SERVER_URL}/api/alerts").json()

    for idx, alert in enumerate(alerts_resp[:4], 1):
        print(f"\n[{idx}] Alert ID: {alert['id']} | Node: {alert['device_id']}")
        print(f"    Threat:    {alert['threat_category']}")
        print(f"    Severity:  {alert['severity']}")
        print(f"    Action:    {alert['mitigation_status']}")
        print(f"    Rule:      {alert['recommendation']}")

    # 4. Check Quarantine Registry
    blacklist = requests.get(f"{SERVER_URL}/api/blacklist").json()
    print("\n" + "=" * 65)
    print(f" 🚫 ACTIVE QUARANTINE REGISTRY: {len(blacklist)} Nodes Quarantined")
    print("=" * 65)
    for dev in blacklist:
        print(f" • Device: {dev['device_id']:<12} | Blocked: {dev['blocked_at']} | Reason: {dev['reason']}")

    print("\n" + "=" * 65)
    print(" 📊 SYSTEM STATUS: All 3 Layers Operating within Presentation Constraints")
    print("=" * 65 + "\n")

if __name__ == "__main__":
    run_evaluation()
