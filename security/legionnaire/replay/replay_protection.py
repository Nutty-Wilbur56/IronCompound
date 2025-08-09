import time
from collections import deque

from administration.vpn_logging.security_logs.legionnaire_logger import LegionnaireLogger


class ReplayProtection:
    def __init__(self, max_nonces=1000, ttl=30):
        # initial creation of replay protector object, will accept 1000 nonces
        self.recent_nonces = {}
        self.queue = deque(maxlen=max_nonces)
        self.packet_ttl = ttl
        # giving packet 30 seconds to live

    def is_replay_attack(self, nonce: bytes) -> bool:
        # does the client's nonce exist in the nonce queue
        assert isinstance(nonce, bytes) and len(nonce) == 8
        return nonce in self.recent_nonces

    def check_and_register_nonce(self, nonce: bytes):
        # checking if nonce is in list of session nonces
        # if nonce is, returns true, else appends nonce to recent
        # nonces along with a time to live
        # also check to see if current length of queue is longer than it is supposed to be
        """if self.is_replay_attack(nonce):
            LegionnaireLogger.log_legionnaire_activity("Replay attack detected")
            return True

            look into modularizing code for replay attack, so that registration of packet nonce
            also checks if nonce is duplicate and can end loop for specific instance
            """

        current_time = time.time()
        if nonce in self.recent_nonces:
            return True
        self.queue.append((nonce, current_time))
        self.recent_nonces[nonce] = current_time

        while len(self.queue) > self.queue.maxlen:
            old_nonce, _ = self.queue.popleft()
            self.recent_nonces.pop(old_nonce, None)

    def check_ttl(self):
        # function designed for removing old nonces
        current_time = time.time()
        while self.queue:
            nonce, time_stamp = self.queue[0]
            if current_time - time_stamp > self.packet_ttl:
                self.queue.popleft()
                self.recent_nonces.pop(nonce, None)
            else:
                break
