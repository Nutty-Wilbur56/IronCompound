import threading
import time
import logging
import json
from administration.gulag_manager import GulagManager
from flooding.flooding_rule_manager import ICMPFloodRuleManager, SynFloodingRuleManager
from iron_server import session_lock, session_tokens, client_socket_lock, client_sockets_dict


class SecurityRule:
    """
    Represents a security rule with a name, condition, and action.
    """
    def __init__(self, name, condition, action):
        self.name = name
        self.condition = condition
        self.action = action

    def evaluate_situation(self, session, client_id):
        # evaluation of situation
        if self.condition(session):
            logging.info(f"[Legionnaire] triggered rule: {self.name} against client {client_id}")
            self.action(session, client_id)
            logging.info(f"[Legionnaire] took action: {self.action} against client {client_id}")

            return True
        return False


class LegionnaireRuleset:
    """
    holds IronCompound's list of security rules and applies them as needed.
    """
    def __init__(self):
        self.ruleset = [] # all active security rule objects

    def add_rule(self, rule: SecurityRule):
        # appending rules to ruleset
        self.ruleset.append(rule)

    def apply_all_rules(self, session, client_id):
        # applying established rules against each client that has an established session
        for rule in self.ruleset:
            rule.evaluate(session, client_id)


class LegionnaireManager:
    """
    Legionnaire is the name of the Intrusion prevention system
    This class manages and evaluates security rules against client sessions
    """
    def __init__(self):
        self.ips_rules = LegionnaireRuleset()
        self.enforcement = {} # tracking of client actions
        self.interface = 'tun0'
        self.start_packet_sniffers()

    def start_packet_sniffers(self, client_id, pckt):
        # function sniffs packets in the background to monitor for flooding attacks (whether SYN or ICMP)
        threading.Thread(target=SynFloodingRuleManager.register_packet, args=(self.interface,), daemon=True).start()
        # daemon thread for SYN flooding
        threading.Thread(target=ICMPFloodRuleManager.monitor, args=(self.interface,), daemon=True).start()
        # daemon thread for ICMP flooding
        logging.info(f"[Legionnaire] Packet sniffers active on interface {self.interface}")

    def add_rule(self, rule: SecurityRule):
        self.ips_rules.add_rule(rule)
        logging.info(f"[Legionnaire] Added {rule.name} rule")

    def evaluate_session(self, session_data, client_id):
        # evaluation of session against all IPS rules
        self.ips_rules.apply_all_rules(session_data, client_id)
        if session_data.get('flagged_for_blacklist'):
            logging.warning(f"[Legionnaire] Blacklisted client {client_id} due to violation of IPS rules")
            # send token to gulag
            GulagManager.send_to_gulag(session_data['token'])

            with session_lock:
                session_tokens.pop(client_id, None)

            with client_socket_lock:
                sock = client_sockets_dict.pop(client_id, None)
                if sock:
                    try:
                        sock.close()
                        logging.info(f"successfully closed {client_id}'s socket")
                    except Exception as e:
                        logging.error(f"Error closing socket for client {client_id}: {e}")
            return False
        return True

    def reset(self):
        self.enforcement.clear()