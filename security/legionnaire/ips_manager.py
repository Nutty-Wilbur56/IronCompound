import json
import threading
from datetime import datetime

import joblib
import torch

from administration.vpn_logging.security_logs.legionnaire_logger import LegionnaireLogger
from security.legionnaire.deep_packet_inspection.flooding.flooding_rule_manager import IcmpFloodingRuleManager, SynFloodingRuleManager
from security.artificial_intelligence.initial_training.session_classifier import LegionnaireMLDecisionEngine, \
    SessionClassifier, SessionAutoEncoder
from security.session_tracking.sess_track import SessionTracker
from security.legionnaire.violation_management import ViolationManager
import os
from security.risk_management.risk_manager import AdaptableRiskMonitor, AdaptiveThresholdManager
from ..legionnaire.configuration.legionnaire_configuration import LegionnaireConfiguration

class SecurityRule:
    """
    Represents a security rule with a name, condition, and action.
    """

    def __init__(self, name, condition, action):
        self.name = name
        self.condition = condition
        self.action = action


class LegionnaireManager:
    """
    Legionnaire is the name of the Intrusion prevention system
    This class manages and evaluates security rules against client sessions
    """

    def __init__(self):
        from administration.vpn_policy.iron_policy import IronPolicy
        # The IPS rule set is controlled by the Iron policy
        self.policy_engine = IronPolicy()
        self.policy_engine.register_initial_policies()
        # registering policies on creation of IPS object
        self.enforcement = {}  # tracking of client actions
        self.interface = 'tun0'

        # loading configuration file
        LegionnaireConfiguration.load()

        # Load hybrid ML models
        clf = SessionClassifier()
        clf.load_state_dict(torch.load("classifier.pt"))
        clf.eval()

        ae = SessionAutoEncoder()
        ae.load_state_dict(torch.load("autoencoder.pt"))
        ae.eval()
        scaler = joblib.load("scaler.pkl")

        self.ml_engine = LegionnaireMLDecisionEngine()

    def start_packet_sniffers(self, client_id, pckt):
        # function sniffs packets in the background to monitor for flooding attacks (whether SYN or ICMP)
        threading.Thread(target=SynFloodingRuleManager.monitor, args=(self.interface,), daemon=True).start()
        # daemon thread for SYN flooding
        threading.Thread(target=IcmpFloodingRuleManager.monitor, args=(self.interface,), daemon=True).start()
        # daemon thread for ICMP flooding
        LegionnaireLogger.log_legionnaire_activity(f"[Legionnaire] Packet sniffers set active at {datetime.now()}"
                                                   f" on interface {self.interface}")

    def check_if_client_in_gulag(self, client_ip):
        # function for checking if client is in gulag, via client's external ip
        if os.path.getsize("gulag.json") == 0:
            pass
        else:
            with open("gulag.json", "r") as f:
                ip_data = json.load(f)
            if client_ip in ip_data["Blacklisted IPs"]:
                return True

    def blacklist_client_ip(self, client_id, client_ip):
        # function for blacklisting client public IPs
        if os.path.exists("security/gulag/gulag.json"):
            with open("security/gulag/gulag.json", "r") as f:
                ip_data = json.load(f)
        else:
            ip_data = {"Blacklisted IPs": []}

        if client_ip not in ip_data["Blacklisted IPs"]:
            # if statement checking if client public ip is not in blacklisted file
            ip_data["Blacklisted IPs"].append(str(client_ip))
            with open("security/gulag/gulag.json", "w") as gulag_file:
                json.dump(ip_data, gulag_file)

            LegionnaireLogger.log_legionnaire_activity(f"[Legionnaire] Client {client_id} flagged "
                                                       f"for blacklist session evaluation at {datetime.now()}."
                                                       f"will be ending session.")

            SessionTracker.end_session(client_id)

    def evaluate_session(self, client_id):
        session_info = SessionTracker.get_session_info(client_id)
        if not session_info:
            return False  # No active session found

        try:
            # variables for Hybrid ML Evaluation
            hybrid_result = self.ml_engine.evaluate(session_info)
            risk_score = hybrid_result["risk_score"]
            explanation = hybrid_result["explanation"]
            supervised_prob = hybrid_result["supervised_prob"]
            mse = hybrid_result["unsupervised_mse"]

            AdaptableRiskMonitor.update(risk_score)
            # calling adaptable risk monitor within evaluate session function

            if LegionnaireConfiguration.is_in_monitor_mode():
                # if legionnaire is in passive mode
                LegionnaireLogger.log_legionnaire_activity(
                    f"[MONITOR-ONLY] Client {client_id} - Risk: {hybrid_result['risk_score']:.2f}, Flag: {hybrid_result['final_flag']}"
                )
                # enforcement of suppression
                return False
            else:
                # logic if legionnaire is not in passive mode
                LegionnaireLogger.log_legionnaire_activity(
                    f"[IPS] Client {client_id} - Risk Score: {risk_score:.2f} | "
                    f"Supervised: {supervised_prob:.2f} | MSE: {mse:.4f} | Explanation: {explanation}"
                )

                """Beginning of rule fusion logic within IPS (Look into moving to violation management)"""
                if risk_score >= 0.75 and session_info.replay_violations >= 2:
                    ViolationManager.record_violation("Hybrid ML + Replay", client_id)
                    LegionnaireLogger.log_legionnaire_activity(
                        f"[IPS-FUSION] Client {client_id} flagged: High ML score + Replay violations."
                    )
                    return True

                if risk_score >= 0.65 and session_info.icmp_flood_violations >= 2:
                    ViolationManager.record_violation("Hybrid ML + ICMP Flood", client_id)
                    LegionnaireLogger.log_legionnaire_activity(
                        f"[IPS-FUSION] Client {client_id} flagged: ML score + ICMP flood."
                    )
                    return True

                if risk_score >= 0.6 and session_info.syn_flood_violations >= 1:
                    ViolationManager.record_violation("Hybrid ML + SYN Flood", client_id)
                    LegionnaireLogger.log_legionnaire_activity(
                        f"[IPS-FUSION] Client {client_id} flagged: ML score + SYN flood."
                    )
                    return True

                if hybrid_result["final_flag"]:
                    ViolationManager.record_violation("Hybrid ML Model Flagged", client_id)
                    LegionnaireLogger.log_legionnaire_activity(
                        f"[IPS-FUSION] Client {client_id} flagged: ML score alone."
                    )

                    rule_triggered = False
                    for rule in self.policy_engine.active_compound_rules:
                        # beginning of initial
                        # Continue to check static rules (if not flagged by ML)
                        try:
                            if rule.condition(session_info, client_id):
                                rule.action(session_info, client_id)
                                rule_triggered = True
                                break
                        except Exception as e:
                            LegionnaireLogger.log_legionnaire_activity(
                                f"[IPS ERROR] Rule '{rule.name}' failed: {e}"
                            )

                    # No policy rule triggered → possible false positive
                    if not rule_triggered:
                        AdaptiveThresholdManager.false_positive_feedback()
                        LegionnaireLogger.log_legionnaire_activity(
                            f"[IPS] False positive detected (ML-only flag with no rule match): {client_id}"
                        )

                    return True
                """Ending of logic for hybrid rule fusion"""

                return False  # Client session is clean

        except Exception as e:
            LegionnaireLogger.log_legionnaire_activity(
                f"[IPS ERROR] Hybrid ML evaluation failed for client {client_id} token {session_info.session_id}: {e}"
            )


    def check_if_flagged_for_disconnect(self, client_id):
        # checking to see if session is flagged for disconnection
        if SessionTracker.client_sessions[client_id].get("flagged_for_disconnect"):
            return True

    def reset(self):
        self.enforcement.clear()
