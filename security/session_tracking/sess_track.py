import threading
from collections import defaultdict


class SessionTracker:
    client_sessions = {}
    client_ip_mapping = {}
    tracker_lock = threading.Lock()
    session_payloads = defaultdict(list)

    @staticmethod
    def session_creation(client_id, ip_address, connection_time, **kwargs):
        with SessionTracker.tracker_lock:
            SessionTracker.client_sessions[client_id] = {
                'ip_address': ip_address,
                "start_time": connection_time,
                'violations': {},
                **kwargs
            }
            SessionTracker.client_ip_mapping[ip_address] = client_id

    @staticmethod
    def get_client_id(client_ip):
        with SessionTracker.tracker_lock:
            return SessionTracker.client_ip_mapping[client_ip]

    @staticmethod
    def get_session_info(client_id):
        if client_id in SessionTracker.client_sessions:
            return SessionTracker.client_sessions[client_id]

    @staticmethod
    def add_payload(client_id, payload):
        if payload:
            SessionTracker.session_payloads[client_id].append(payload)

    @staticmethod
    def flag_session(client_id):
        if not SessionTracker.client_sessions[client_id]["flagged_for_disconnect"]:
            SessionTracker.client_sessions[client_id]["flagged_for_disconnect"] = True

    @staticmethod
    def flag_for_blacklist(client_id):
        if not SessionTracker.client_sessions[client_id]["flagged_for_blacklist"]:
            SessionTracker.client_sessions[client_id]["flagged_for_blacklist"] = True

    @staticmethod
    def end_session(client_id):
        with SessionTracker.tracker_lock:
            session = SessionTracker.client_sessions.pop(client_id, None)
            if session and "ip" in session:
                SessionTracker.client_ip_mapping.pop(session["ip"], None)

    @staticmethod
    def is_session_flagged(client_id):
        # centralized and off ramp way of checking session to see if it's flagged for disconnection
        if client_id in SessionTracker.client_sessions:
            if SessionTracker.client_sessions[client_id]['flagged_for_disconnect']:
                return True
            else:
                return False