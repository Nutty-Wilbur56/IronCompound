import time
import logging
import json

class SecurityRule:
    """
    Represents a security rule with a name, condition, and action.
    """
    def __init__(self, name, condition, action):
        self.name = name
        self.condition = condition
        self.action = action

    def evaluate_situation(self, session, client_id):
        # evaulation
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

    def add_rule(self, rule: SecurityRule):
        self.ips_rules.add_rule(rule)
        logging.info(f"[Legionnaire] Added {rule.name} rule")

    def evaluate_session(self, session_data, client_id):
        # evaluation of session against all IPS rules
        self.ips_rules.apply_all_rules(session_data, client_id)

    """def log_enforced_actions(self):
        for client_id, actions in self.enforcement.items():
            logging.info(f"[Legionnaire] Enforced for client {client_id}: {actions}")"""

    def reset(self):
        self.enforcement.clear()