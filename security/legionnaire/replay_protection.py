from collections import deque

class ReplayProtection:
    def __init__(self, max_nonces=1000):
        # initial creation of replay protector object, will accept 1000 nonces
        self.recent_nonces = set()
        self.queue = deque(maxlen=max_nonces)

    def existing_nonce(self, nonce: bytes) -> bool:
        # does the client's nonce exist in the nonce queue
        return nonce in self.recent_nonces

    def register_nonce(self, nonce: bytes):
        # register nonce
        if len(self.queue) == self.queue.maxlen:
            # check to see if the current nonce queue has reached its max length
            old = self.queue.popleft()
            self.recent_nonces.discard(old)

        self.queue.append(nonce)
        self.recent_nonces.add(nonce)