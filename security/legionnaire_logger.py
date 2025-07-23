import json
import os
import logging
from datetime import datetime
from threading import Lock

#thread safe lock for logging

log_lock = Lock()

class LegionnaireLogger:
    LOG_FILE = "legionniare_hit_list.json"
    ALERT_SERVER = True # enabling of terminal alerts

    @staticmethod
    def _ensure_log_directory():
        # ensuring the path to the log exists
        os.makedirs(os.path.dirname(LegionnaireLogger.LOG_FILE), exist_ok=True)

    @ staticmethod
    def log_violation(rule_name, client_id, action, session):
        # logging of client's violation against the server
        LegionnaireLogger._ensure_log_directory()

        hit_list_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "client_id": client_id,
            "ip": session.get('ip'),
            "rule": rule_name,
            "action": action,
            "fingerprint": session.get('fingerprint'),
            "bytes_sent": session.get('bytes_sent', 0),
            "bytes_received": session.get('bytes_received', 0),
            "violation_count": session.get('violation_count', 0),
        }
        with log_lock:
            try:
                with open(LegionnaireLogger.LOG_FILE, "a") as hit_list_file:
                    hit_list_file.write(json.dumps(hit_list_entry) + '\n')

            except Exception as e:
                logging.error(f"[Legionnaire's logger] failed to write log entry {e}")

        if LegionnaireLogger.ALERT_SERVER:
            print(
                f"\033[91m[IPS ALERT] Rule '{rule_name}' triggered for client {client_id} ({hit_list_entry['ip']}) → {action.upper()}\033[0m")

    """@staticmethod
    def log_custom(message: str):
    # ehh, might implement function later on, might not
        IPSLogger._ensure_log_dir()
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "message": message
        }

        with log_lock:
            try:
                with open(IPSLogger.LOG_FILE, "a") as f:
                    f.write(json.dumps(entry) + "\n")
            except Exception as e:
                logging.error(f"[IPSLogger] Failed to log custom message: {e}")"""
