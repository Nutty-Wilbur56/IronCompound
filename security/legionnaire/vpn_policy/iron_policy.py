from administration.logging.security_logs.legionnaire_logger import LegionnaireLogger
from security.artificial_intelligence.initial_training.session_classifier import SessionClassifier
from security.legionnaire.deep_packet_inspection.flooding.flooding_rule_manager import SynFloodingRuleManager
from security.legionnaire.ips_manager import SecurityRule, LegionnaireManager
from security.legionnaire.throttling.throttling_manager import ThrottleManager
from security.legionnaire.violation_management import ViolationManager
from security.session_tracking.sess_track import SessionTracker

"""Easy to add:

Zero-day detectors

Geo-blocking

Threat intelligence feeds"""
"""SecurityRule(
        "Inactivity Timeout",
        lambda s: time.time() - s.get("last_activity", 0) > 600,
        lambda s, cid: s.update({"flagged_for_disconnect": True}),
    ),
will be integrating security rule for inactivity timeout in the future            
"""

class IronPolicy:
    def __init__(self):
        self.active_compound_rules = []
        self.legionnaire = LegionnaireManager()

    def register_initial_policies(self):
        self.active_compound_rules = [
            SecurityRule(
                "SYN Flood Detection",
                lambda client_id: SynFloodingRuleManager.should_session_be_flagged(client_id),
                lambda client_id: (
                ViolationManager.record_violation('SYN Flooding Violations', client_id),
                SessionTracker.client_sessions[client_id].__setitem__('flagged_for_blacklist', True),
                self.legionnaire.blacklist_client_ip(client_id,
                                                     SessionTracker.client_sessions[client_id].get("initial_ip"))
                )
            ),

            SecurityRule(
                "ICMP Flood Detection",
                lambda client_id: SynFloodingRuleManager.should_session_be_flagged(client_id),
                lambda client_id: (
                    ViolationManager.record_violation('ICMP Flooding Violations', client_id),
                    SessionTracker.client_sessions[client_id].__setitem__('flagged_for_blacklist', True),
                    self.legionnaire.blacklist_client_ip(client_id, SessionTracker.client_sessions[client_id].get("initial_ip")),
                )
            ),
            SecurityRule(
                "Hybrid ML Session Classifier",
                lambda session: SessionClassifier.classify(session),
                lambda session, client_id: ViolationManager.record_violation('Hybrid Model Classifier Flagged',
                                                                             client_id)
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
                    ViolationManager.record_violation('Throttling Violation', client_id)
                )
            ),
            SecurityRule(
                # security rule that imposes an automatic blacklist threshold
                "Automatic Blacklist Threshold",
                lambda session, client_id: sum(session[client_id]["violations"].values()) >= 6,
                lambda session, client_id: session.update({'flagged_for_blacklist': True})
            )

            # Add more rules here (e.g. model-based classifier)
        ]
        # left off, 7/25/2025
    def add_rule(self, rule: SecurityRule):
        if rule not in self.active_compound_rules:
            self.active_compound_rules.append(rule)