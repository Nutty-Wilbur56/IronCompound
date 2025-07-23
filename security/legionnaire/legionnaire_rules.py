import time
import logging
from ips_manager import SecurityRule
from security.legionnaire.flooding.flooding_rule_manager import FloodingRuleManager
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
            "Flooding Attack",
            lambda session: FloodingRuleManager.should_session_be_flagged(session),
            lambda session, client_id: (
                ViolationManager.record_violation(session, 'Flooding Violation', client_id)
            )
        ),

        SecurityRule(
            "Throttling Violation",
            lambda session: ThrottleManager.session_should_be_throttled(session),
            lambda session, client_id: (
                ViolationManager.record_violation(session, 'Throttling Violation', client_id)
            )
        )
    ]