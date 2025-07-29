import time

from administration.logging.security_logs.legionnaire_logger import LegionnaireLogger
from security.artificial_intelligence.initial_training.session_classifier import SessionClassifier
from security.legionnaire.flooding.flooding_rule_manager import SynFloodingRuleManager
from security.legionnaire.flooding.flooding_rule_manager import IcmpFloodingRuleManager
from security.legionnaire.ips_manager import SecurityRule
from security.legionnaire.throttling.throttling_manager import ThrottleManager
from security.legionnaire.violation_management import ViolationManager

"""Easy to add:

Zero-day detectors

Geo-blocking

Threat intelligence feeds"""


class IronPolicy:
    def __init__(self):
        self.active_compound_rules = []

    def register_initial_policies(self):
        self.active_compound_rules = [
            SecurityRule(
                "SYN Flood Detection",
                lambda session: SynFloodingRuleManager.should_session_be_flagged(session.client_id),
                lambda session, client_id: ViolationManager.record_violation(session, 'SYN Flood', client_id)
            ),
            SecurityRule(
                "ICMP Flood Detection",
                lambda session: IcmpFloodingRuleManager.should_session_be_flagged(session),
                lambda session, client_id: ViolationManager.record_violation(session, 'ICMP Flood', client_id)
            ),
            SecurityRule(
                "ML Session Classifier",
                lambda session: SessionClassifier.classify(session),
                lambda session, client_id: ViolationManager.record_violation(session, 'Model Classifier Flagged',
                                                                             client_id)
            ),
            SecurityRule(
                "Inactivity Timeout",
                lambda s: time.time() - s.get("last_activity", 0) > 600,
                lambda s, cid: s.update({"flagged_for_disconnect": True}),

            ),

            SecurityRule(
                "Excessive Bandwidth Use",
                lambda s: s.get("bytes_sent", 0) > 5_000_000 or s.get("bytes_received", 0) > 5_000_000,
                lambda s, cid: LegionnaireLogger.log_legionnaire_activity(f"[IPS] Client {cid} exceeded bandwidth limit."),
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

            # Add more rules here (e.g. model-based classifier)
        ]
        # left off, 7/25/2025
    def add_rule(self, rule: SecurityRule):
        if rule not in self.active_compound_rules:
            self.active_compound_rules.append(rule)

    def evaluate_session(self, session):
        for rule in self.active_compound_rules:
            if rule.evaluate_situation(session):
                print("hi")