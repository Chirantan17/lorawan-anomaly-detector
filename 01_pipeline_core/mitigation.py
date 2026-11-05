# mitigation.py
import logging
from database import (
    get_connection,
    log_alert,
    get_blacklisted_devices,
    remove_blacklisted_device
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("MitigationEngine")

class AutomatedMitigationEngine:
    def __init__(self):
        pass

    def evaluate_and_enforce(self, device_id: str, soc_diag: dict) -> str:
        """
        Evaluates diagnostic severity and applies automated quarantine policy
        for CRITICAL or HIGH risk categories.
        """
        if not soc_diag:
            return "No Anomaly"

        threat_category = soc_diag.get("threat_category", "Unknown Threat")
        severity_raw = str(soc_diag.get("severity", "LOW")).upper()
        action_taken = "Monitoring"

        # Build composite recommendation from generated rules
        iptables_cmd = soc_diag.get("recommended_iptables_rule", "")
        mac_cmd = soc_diag.get("gateway_mac_command", "")
        recommendation = f"{iptables_cmd} | {mac_cmd}".strip(" |")

        # Robust check against formatted severity strings (e.g. 'CRITICAL (99.2%)')
        if any(level in severity_raw for level in ["CRITICAL", "HIGH"]):
            action_taken = self.blacklist_device(device_id, reason=threat_category)
            
        log_alert(
            device_id=device_id,
            category=threat_category,
            severity=soc_diag.get("severity", "HIGH"),
            recommendation=recommendation,
            status=f"Mitigated: {action_taken}"
        )
        return action_taken

    def blacklist_device(self, device_id: str, reason: str) -> str:
        """Adds node to blacklisted_devices table and drops incoming socket frames."""
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT OR REPLACE INTO blacklisted_devices (device_id, blocked_at, reason) VALUES (?, datetime('now'), ?)",
            (device_id, reason)
        )
        conn.commit()
        conn.close()
        logger.warning(f"🚨 ACTIVE MITIGATION: Blacklisted Device '{device_id}' due to: {reason}")
        return "Device Blacklisted & Session Revoked"

    def is_blacklisted(self, device_id: str) -> bool:
        """Queries whether a device is currently quarantined."""
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM blacklisted_devices WHERE device_id = ?", (device_id,))
        result = cursor.fetchone()
        conn.close()
        return result is not None

    def unblacklist_device(self, device_id: str) -> bool:
        """Releases a device from quarantine."""
        return remove_blacklisted_device(device_id)

    def list_blacklisted(self) -> list[dict]:
        """Returns all quarantined nodes."""
        return get_blacklisted_devices()
