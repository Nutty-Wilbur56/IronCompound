import time
from collections import defaultdict, deque

class ThrottleManager:
    window_seconds = 10
    max_bytes_per_second = 2500 # 2.5 KB/second threshold due to very limited resources
    cool_down_period = 10 # throttling activity must exceed rate for 10 continous seconds
    byte_history = defaultdict(lambda:deque())
    violation_timestamp = defaultdict(lambda:None)

    @classmethod
    def record_transfer(cls, client_id, client_byte_count):
        # recording packet transfer
        now = time.time()
        cls.byte_history[client_id].append((now, client_byte_count))

    @classmethod
    def rate_of_transfer(cls, client_id):
        # capturing
        now = time.time()
        window_start = now - cls.window_seconds
        recent_transfer = [(ts, bytes) for ts, bytes in cls.byte_history[client_id] if ts >= window_start]
        cls.byte_history[client_id] = deque(recent_transfer)
        total_bts = sum(bytes for _, bytes in recent_transfer)

        return total_bts / cls.window_seconds
    @classmethod
    def session_should_be_throttled(cls, session):
        # determining if session violated server through throttling network
        client_id = session.get('client_id')
        if client_id is None:
            return False
        now = time.time()
        rate = cls.rate_of_transfer(client_id)
        if rate > cls.max_bytes_per_second:
            if cls.violation_timestamp[client_id] is None:
                cls.violation_timestamp[client_id] = now

            elif now - cls.violation_timestamp[client_id] >= cls.cool_down_period:
                return True

        else:
            # violation time stamp will be reset if client drops below the threshold of throttling activity
            cls.violation_timestamp[client_id] = None

        return cls.rate_of_transfer(client_id) > cls.max_bytes_per_second