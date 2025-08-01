import json
import threading
import logging
from datetime import datetime

import joblib
import torch

from administration.gulag_manager import GulagManager
from administration.logging.security_logs.legionnaire_logger import LegionnaireLogger
from flooding.flooding_rule_manager import IcmpFloodingRuleManager, SynFloodingRuleManager
from iron_server import session_lock, client_socket_lock, client_sockets_dict
from security.artificial_intelligence.initial_training.session_classifier import LegionnaireMLDecisionEngine, \
    SessionClassifier, SessionAutoEncoder
from security.session_tracking.sess_track import SessionTracker
from security.legionnaire.violation_management import ViolationManager
from vpn_policy.iron_policy import IronPolicy
import os


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
        # The IPS rule set is controlled by the Iron policy
        self.policy_engine = IronPolicy()
        self.policy_engine.register_initial_policies()
        # registering policies on creation of IPS object
        self.enforcement = {}  # tracking of client actions
        self.interface = 'tun0'

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
        if os.path.getsize("gulag_rules.json") == 0:
            pass
        else:
            with open("gulag_rules.json", "r") as f:
                ip_data = json.load(f)
            if client_ip in ip_data["Blacklisted IPs"]:
                return True

    def blacklist_client_ip(self, client_id, client_ip):
        if os.path.exists("security/gulag/gulag.json"):
            with open("security/gulag/gulag.json", "r") as f:
                ip_data = json.load(f)
        else:
            ip_data = {"Blacklisted IPs": []}

        if client_ip not in ip_data["Blacklisted IPs"]:
            ip_data["Blacklisted IPs"].append(client_ip)
            with open("security/gulag/gulag.json", "w") as gulag_file:
                json.dump(ip_data, gulag_file)

            LegionnaireLogger.log_legionnaire_activity(f"[Legionnaire] Client {client_id} flagged "
                                                       f"for blacklist session evaluation at {datetime.now()}."
                                                       f"will be ending session.")

        SessionTracker.end_session(client_id)

    def evaluate_session(self, client_id):
        # evaluation of session and client against current policy engine

        """
        beginning of logic for comparing client against session rules
        """
        session_info = SessionTracker.get_session_info(client_id)

        """beginning of logic for flagging with machine learning models"""
        try:

            hybrid_result = self.ml_engine.evaluate(session_info)
            # integration of machine learning pipeline into the Legionnaire
            LegionnaireLogger.log_legionnaire_activity(
                f"[IPS] Risk Evaluation: Client {client_id} - Score: {hybrid_result['risk_score']:.2f}, "
                f"Level: {hybrid_result['risk_level']}, Details: {hybrid_result['explanation']}"
            )

            if hybrid_result["final_flag"]:
                ViolationManager.record_violation("Hybrid ML Model Flagged", client_id)
                return True

        except Exception as e:
            LegionnaireLogger.log_legionnaire_activity(
                f"[ML-IPS ERROR] Hybrid model failed for client {client_id}: {e}"
            )
        """ending of logic for flagging with machine learning models"""

        for rule in self.policy_engine.active_compound_rules:
            # Evaluation of all rules that exist in the rule engine
            try:
                # Support rules that expect either (session) or (session, client_id)
                if rule.condition.__code__.co_argcount == 1:
                    # checking to see if there's one argument in the Rule
                    triggered = rule.condition(client_id)
                    if triggered:
                        rule.action(client_id)
                        return True
                elif rule.condition.__code__.co_argcount == 2:
                    # checking to see if there's two arguments in the Rule
                    triggered = rule.condition(session_info, client_id)
                    if triggered:
                        rule.action(session_info, client_id)
                        return True

            except Exception as e:
                LegionnaireLogger.log_legionnaire_activity(
                    f"[IPS ERROR] Rule '{rule.name}' failed for client {client_id}: {e}"
                )
        return False

    def check_if_flagged_for_disconnect(self, client_id):
        # checking to see if session is flagged for disconnection
        if SessionTracker.client_sessions[client_id].get("flagged_for_disconnect"):
            return True

    def reset(self):
        self.enforcement.clear()
