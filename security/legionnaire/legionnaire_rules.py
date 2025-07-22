import time
import logging
from ips_manager import SecurityRule

def get_legions_rules():
    return[
        SecurityRule(
            "Inactivity Timeout",
            lambda s: time.time() - s.get("last_activity", 0) > 600,
            lambda s, cid: s.update({"flagged_for_disconnect": True})
        ),

        SecurityRule(
            "Replay Violation",
            lambda s: s.get("replay_hits", 0) > 5,
            lambda s, cid: s.update({"flagged_for_blacklist": True})
        ),

        SecurityRule(
            "Excessive Bandwidth Use",
            lambda s: s.get("bytes_sent", 0) > 5_000_000 or s.get("bytes_received", 0) > 5_000_000,
            lambda s, cid: logging.warning(f"[IPS] Client {cid} exceeded bandwidth limit.")
        )

    ]