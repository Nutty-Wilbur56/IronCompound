import logging

from administration.logging.security_logs.legionnaire_logger import LegionnaireLogger
from security.session_tracking.sess_track import SessionTracker

class ViolationManager:
    # Violation thresholds before triggering disconnect
    VIOLATION_THRESHOLDS = {
        "Throttling Violation": 3,
        "Replay Violation": 2,
        "SYN Flood Violation": 1,
        "ICMP Flood Violation": 2,
        # Add more rules as needed
    }
    @ staticmethod
    def record_violation(rule_name, client_id):
        # beginning of code for dynamic violations
        if not client_id not in SessionTracker.client_sessions:
            LegionnaireLogger.log_legionnaire_activity(f"[ViolationManager] Unknown client ID: {client_id}")
            return
        SessionTracker.client_sessions[client_id].setdefault("violations", {})
        SessionTracker.client_sessions[client_id][rule_name] += 1
        violation_count = SessionTracker.client_sessions[client_id][rule_name]
        LegionnaireLogger.log_legionnaire_activity(
            f"[Client {client_id}] Rule violated: {rule_name} (#{violation_count})"
        )

        violation_threshold = ViolationManager.VIOLATION_THRESHOLDS.get(rule_name)
        if violation_count >= violation_threshold:
            SessionTracker.is_session_flagged(client_id)
            LegionnaireLogger.log_legionnaire_activity(
                f"[Client {client_id}] Exceeded {rule_name} threshold ({violation_count}/{violation_threshold}) — flagged for disconnect"
            )
