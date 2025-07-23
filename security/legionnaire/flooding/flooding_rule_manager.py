# flooding rule manager

import time
from collections import deque, defaultdict

class FloodingRuleManager:
    def __init__(self):
        self._packet_history = defaultdict(lambda: deque(maxlen=1000))
        self._window_size = 5 # seconds
        self._max_packet_rate = 100 # packets per second

    @classmethod
    def record_packet(self, client_id):
        # recording packet function
        now = time.time()
        self._packet_history[client_id].append(now)

    @classmethod
    def packet_rate(self, session):
        # tracking packet rate
        client_id = session.get('client_id')
        now = time.time()
        history = self._packet_history[client_id]
        # remove timestamps older than window
        packet_cutoff = now-self._window_size
        most_recent = [ts for ts in history if ts >= packet_cutoff]
        self._packet_history[client_id] = deque(most_recent, maxlen=1000)

        return len(most_recent)

    @classmethod
    def should_session_be_flagged(self, session):
        # function responsible for returning true value if a certain session should be flagged
        client_id = session.get('client_id')
        self.record_packet(client_id)
        return self.packet_rate(session) >= self._max_packet_rate