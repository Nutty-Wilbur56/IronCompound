import threading

class SessionTracker:
    client_sessions = {}
    client_ip_mapping = {}
    tracker_lock = threading.Lock()

    @staticmethod
    def session_creation(client_id, ip_address, connection_time, **kwargs):
        with SessionTracker.tracker_lock:
            SessionTracker.client_sessions[client_id] = {
                'ip_address': ip_address,
                "start_time": connection_time,
                'violations': [],
                **kwargs
            }
            SessionTracker.client_ip_mapping[ip_address] = client_id

    @staticmethod
    def get_client_id(client_ip):
        with SessionTracker.tracker_lock:
            return SessionTracker.client_ip_mapping[client_ip]

    @staticmethod
    def record_violation(client_id, violation):
        with SessionTracker.tracker_lock:
            if client_id in SessionTracker.client_sessions:
                SessionTracker.client_sessions[client_id]["violations"].append(violation)

    @staticmethod
    def end_session(client_id):
        with SessionTracker.tracker_lock:
            session = SessionTracker.client_sessions.pop(client_id, None)
            if session and "ip" in session:
                SessionTracker.client_ip_mapping.pop(session["ip"], None)

    @staticmethod
    def get_session(client_id):
        with SessionTracker.tracker_lock:
            return SessionTracker.client_sessions.get(client_id)