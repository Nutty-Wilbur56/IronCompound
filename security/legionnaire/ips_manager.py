import json
import threading
import logging
from datetime import datetime

from administration.gulag_manager import GulagManager
from administration.logging.security_logs.legionnaire_logger import LegionnaireLogger
from flooding.flooding_rule_manager import IcmpFloodingRuleManager, SynFloodingRuleManager
from iron_server import session_lock, client_socket_lock, client_sockets_dict
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
        self.ips_rules = IronPolicy()
        self.enforcement = {} # tracking of client actions
        self.interface = 'tun0'

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
            if client_ip in ip_data:
                return True

    def evaluate_session(self, client_id):
        # evaluation of session
        # if session is flagged, end session command is called
        if SessionTracker.client_sessions[client_id].get("flagged_for_disconnect"):
            return True
        """
        beginning of logic for SYN and ICMP Flooding Detection
        """
        if SynFloodingRuleManager.should_session_be_flagged(client_id):
            SessionTracker.flag_session(client_id)
            ViolationManager.record_violation(
                rule_name="SYN Flood Detection",
                client_id=client_id
            )
            LegionnaireLogger.log_legionnaire_activity(
                f"[Legionnaire] Client {client_id} flagged for SYN Flood during session evaluation at {datetime.now()}."
            )
            return True

        if IcmpFloodingRuleManager.should_session_be_flagged(client_id):
            SessionTracker.flag_session(client_id)
            ViolationManager.record_violation(
                rule_name="ICMP Flood Detection",
                client_id=client_id
            )
            LegionnaireLogger.log_legionnaire_activity(
                f"[Legionnaire] Client {client_id} flagged for ICMP Echo Flood during session evaluation at {datetime.now()}."
            )
            return True
        return False
    def reset(self):
        self.enforcement.clear()
