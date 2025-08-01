import numpy as np

MAX_PAYLOAD_SIZE = 512
# max bytes to embed

class IronPayloadEmbedder:
    @staticmethod
    def extract_embed_payload(packet):
        if hasattr(packet, 'payload') and hasattr(packet.payload, 'original'):
            payload_bytes = bytes(packet.payload.original)
        else:
            return np.zeros(MAX_PAYLOAD_SIZE)

        # truncate/pad payloads
        trimmed = payload_bytes[:MAX_PAYLOAD_SIZE]
        padded = trimmed + bytes(MAX_PAYLOAD_SIZE - len(trimmed))

        # converting to fload vector in [0,1]
        embedded = np.array([b/255.0 for b in padded], dtype=np.float32)
        return embedded