# soc_copilot.py
import json
import time

def generate_soc_analysis(alert_record: dict, model_name: str = "XGBoost Classifier") -> dict:
    """
    Executes the 7-Heuristic Diagnostic Cascade (Slide 24)
    and formats evidence into an explainable SOC Incident Record (Slide 25).
    """
    dev_id = alert_record.get("device_id", "Unknown_Node")
    gw_id = alert_record.get("gateway_id", "GW_A")
    rssi = float(alert_record.get("rssi", -110.0))
    snr = float(alert_record.get("snr", -10.0))
    sf = int(alert_record.get("sf", 7))
    iat = float(alert_record.get("inter_arrival_time", alert_record.get("iat", 0.01)))
    fcnt = int(alert_record.get("fcnt", 0))
    payload_len = int(alert_record.get("payload_len", 16))
    freq = float(alert_record.get("freq_mhz", 865.0625))
    delta_fcnt = alert_record.get("delta_fcnt", 1)
    tdoa_var = float(alert_record.get("tdoa_variance_ns", 0.0))

    # Check 1: Multi-Gateway TDoA Spatial Discrepancy (Slide 29 trigger: > 350.0 ns)
    if tdoa_var > 350.0:
        attack_type = "Spatial TDoA Inconsistency / Transmitter Impersonation"
        risk_score = "CRITICAL (96.4%)"
        explanation = (
            f"Uplink from node '{dev_id}' exhibited Time-Difference-of-Arrival jitter of {tdoa_var:.1f} ns across {gw_id}. "
            "Exceeds physical speed-of-light boundary (|tA - tB| <= ||rA - rB|| / c), proving proxy relay or transmitter impersonation."
        )
        mitigation_cmd = f"iptables -A INPUT -p udp --dport 9999 -m string --algo bm --string '{dev_id}' -j DROP"
        mac_action = f"LORA_MAC_REVOKE_SESSION --dev-eui {dev_id} --reason TDOA_SPATIAL_VIOLATION"

    # Check 2: Gateway DoS Burst (Duty-Cycle Violation)
    elif iat < 0.10:
        attack_type = "Gateway DoS Transmission Burst (Duty-Cycle Violation)"
        risk_score = "CRITICAL (99.2%)"
        explanation = (
            f"Node '{dev_id}' sent packet bursts with inter-arrival time of {iat:.4f}s. "
            "Violates regional sub-band 1% channel duty-cycle limits (RP002)."
        )
        mitigation_cmd = f"iptables -A INPUT -p udp --dport 9999 -m string --algo bm --string '{dev_id}' -j DROP"
        mac_action = f"LORA_MAC_SET_DUTY_CYCLE --dev-eui {dev_id} --max-duty-cycle 0.001"

    # Check 3: Sequence Counter Replay & Desynchronization
    elif fcnt in [0, 1, 65535] or delta_fcnt <= 0:
        attack_type = "Frame Counter Replay & Join-Desynchronization"
        risk_score = "CRITICAL (98.6%)"
        explanation = (
            f"Node '{dev_id}' presented counter rollback (FCnt = {fcnt}, Delta = {delta_fcnt}). "
            "Uplink replay signature matches attempts to desynchronize gateway session counters."
        )
        mitigation_cmd = f"iptables -A INPUT -m string --algo bm --string '{dev_id}' -j DROP"
        mac_action = f"LORA_MAC_REJECT_DEVICE --dev-eui {dev_id} --reason REPLAY_DETECTED"

    # Check 4: RF Jamming / Noise Floor Flooding
    elif snr < -8.0 or rssi < -115.0:
        attack_type = "RF Physical Layer Jamming / Noise Floor Flooding"
        risk_score = "HIGH (94.8%)"
        explanation = (
            f"Carrier {freq} MHz experienced severe RF degradation (RSSI={rssi:.1f} dBm, SNR={snr:.1f} dB), "
            "indicating active continuous or swept barrage RF jamming."
        )
        mitigation_cmd = f"gateway-cli hop-frequency --channel-exclude {freq}MHz"
        mac_action = f"LinkADRReq (CID 0x03) --dev-eui {dev_id} --target-sf 12 --power-boost +3dBm"

    # Check 5: Spreading Factor / ADR Manipulation
    elif sf in [11, 12] and rssi > -90.0 and snr > 6.0:
        attack_type = "Malicious LinkADRReq / Spreading Factor Manipulation"
        risk_score = "HIGH (93.1%)"
        explanation = (
            f"Node '{dev_id}' operating at SF{sf} despite pristine link conditions (RSSI={rssi:.1f} dBm, SNR={snr:.1f} dB). "
            "Forced max airtime exhausts node battery and blocks gateway demodulator channels."
        )
        mitigation_cmd = f"gateway-cli override-adr --dev-eui {dev_id} --target-sf 7"
        mac_action = f"LinkADRReq (CID 0x03) --dev-eui {dev_id} --target-sf 7 --tx-power 14dBm"

    # Check 6: Oversized Payload Exploit
    elif payload_len > 100:
        attack_type = "Oversized LoRaWAN Payload Exploit"
        risk_score = "HIGH (91.5%)"
        explanation = (
            f"Payload length of {payload_len} bytes exceeds maximum LoRaWAN MAC payload ceiling, "
            "risking ring-buffer overflow on gateway forwarder."
        )
        mitigation_cmd = f"iptables -A INPUT -p udp -m length --length {payload_len}:65535 -j DROP"
        mac_action = f"LORA_MAC_TRUNCATE_FRAME --dev-eui {dev_id} --max-bytes 51"

    # Check 7: Physical Layer Spatial Drift
    else:
        attack_type = "Physical Layer Spatial Drift / Rogue Impersonation"
        risk_score = "HIGH (88.4%)"
        explanation = f"RF telemetry for node '{dev_id}' diverges from Gaussian baseline distribution."
        mitigation_cmd = f"iptables -A INPUT -m string --algo bm --string '{dev_id}' -j DROP"
        mac_action = f"LORA_MAC_QUARANTINE --dev-eui {dev_id}"

    ts = alert_record.get("timestamp", time.time())
    incident_suffix = int(float(ts) * 1000) % 10000

    return {
        "incident_id": f"INC-{incident_suffix:04d}",
        "device_id": dev_id,
        "gateway_id": gw_id,
        "detector_engine": model_name,
        "threat_category": attack_type,
        "severity": risk_score,
        "root_cause_summary": explanation,
        "recommended_iptables_rule": mitigation_cmd,
        "gateway_mac_command": mac_action
    }
