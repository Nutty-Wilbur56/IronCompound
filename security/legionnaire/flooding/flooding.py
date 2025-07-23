import time
from collections import deque
from ips_manager import SecurityRule

class FloodingRule(SecurityRule):
    """
    The class's purpose is for detecting if the client is sending too many packets per second
    will be implementing more specific rules against SYN and ICMP flooding attacks
    in the future
    """

    def __init__(self, max_packets_per_second=100, window_size=5):
        # allowing the maximum amount of packets to be sent to be 100
        self.max_packet_per_second = max_packets_per_second
        self.window_size = window_size
        self.packet_history = {}

    def check_user(self, session, client_id):
        # function checks to see if client (identified by client ID) is commencing a flooding attack
        now = time.time()

        if client_id not in self.packet_history:
            # initialization of client tracking window
            self.packet_history[client_id] = deque(maxlen=1000)

        # append the timestamp of when the client is being checked
        self.packet_history[client_id].append(now)

        # cleaning up of old entries ouside the window
        window_cutoff = now - self.window_size
        history = self.packet_history[client_id]
        recent_packets = [ts for ts in history if ts >= window_cutoff]

        self.packet_history[client_id] = deque(recent_packets, maxlen=1000)

        # computation of packet send rate
        rate = len(recent_packets) / self.window_size
        if rate > self.max_packet_per_second:
            session['flagged_for_disconnect'] = True
            session['reason_for_flag'] = f"Flooding: {rate:.2f} packets/sec"

            return True
            # rule against flooding attacks has been triggered
        return False
        # rule has not been triggered