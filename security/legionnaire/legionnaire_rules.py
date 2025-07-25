import time
import logging
from ips_manager import SecurityRule
from security.legionnaire.flooding.flooding_rule_manager import SynFloodingRuleManager, ICMPFloodRuleManager
from security.legionnaire.throttling.throttling_manager import ThrottleManager
from security.legionnaire_logger import LegionnaireLogger
from security.violation_management import ViolationManager


def get_legions_rules():
    return[
        SecurityRule(
            "Inactivity Timeout",
            lambda s: time.time() - s.get("last_activity", 0) > 600,
            lambda s, cid: s.update({"flagged_for_disconnect": True}),

        ),

        SecurityRule(
            # security rule for replay violations
            "Replay Violation",
            lambda session: session.get("replay_hits", 0) > 5,
            lambda session, client_id: (
                ViolationManager.record_violation(session, 'Replay Violation', client_id)
            )
        ),

        SecurityRule(
            "Excessive Bandwidth Use",
            lambda s: s.get("bytes_sent", 0) > 5_000_000 or s.get("bytes_received", 0) > 5_000_000,
            lambda s, cid: logging.warning(f"[IPS] Client {cid} exceeded bandwidth limit."),
        ),

        SecurityRule(
            # security rule for flooding attacks
            "SYN Flooding Attack",
            lambda session: SynFloodingRuleManager.should_session_be_flagged(session),
            lambda session, client_id: (
                ViolationManager.record_violation(session, 'SYN Flooding Violation', client_id)
            )
        ),

        SecurityRule(
            # security rule for flooding attacks
            "ICMP Flooding Attack",
            lambda session: ICMPFloodRuleManager.should_session_be_flagged(session),
            lambda session, client_id: (
                ViolationManager.record_violation(session, 'ICMP Flooding Violation', client_id)
            )
        ),

        SecurityRule(
            # security rule for throttling violations
            "Throttling Violation",
            lambda session: ThrottleManager.session_should_be_throttled(session),
            lambda session, client_id: (
                ViolationManager.record_violation(session, 'Throttling Violation', client_id)
            )
        ),

        SecurityRule(
            # security rule that imposes an automatic blacklist threshold
            "Automatic Blacklist Threshold",
            lambda session: sum(session["violations"].values()) >= 6,
            lambda session, client_id: session.update({'flagged_for_blacklist': True})
        )
    ]