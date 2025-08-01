# flooding rule manager

from scapy.all import sniff, TCP, IP, ICMP
import logging
# syn_flood_rule.py
import time
from collections import defaultdict

from administration.logging.security_logs.legionnaire_logger import LegionnaireLogger
from administration.utils.packet_utils import extract_payload
from security.session_tracking.sess_track import SessionTracker
from security.legionnaire.violation_management import ViolationManager


class SynFloodingRuleManager:
    SYN_WINDOW = 10           # seconds
    SYN_THRESHOLD = 100       # per window
    COOLDOWN = 60             # seconds between flags

    syn_attempts = defaultdict(list)
    last_flagged = defaultdict(float)
    completed_handshakes = defaultdict(set)

    @staticmethod
    def monitor(interface):
        # function for monitoring tunnel that the server listens on
        def process_packet(packet):
            # processing packet function that is nested in monitor function
            payload = extract_payload(packet)
            if packet.haslayer(TCP) and packet.haslayer(IP):

                if packet[TCP].flags == 'S':  # Only track SYN packets
                    src_ip = packet[IP].src
                    client_id = SessionTracker.get_client_id(src_ip)

                    if client_id:
                        SessionTracker.add_payload(client_id, payload)
                        SynFloodingRuleManager.syn_attempts[client_id].append(time.time())

                        if SynFloodingRuleManager.should_session_be_flagged(client_id):
                            ViolationManager.record_violation("SYN Flood Violation", client_id)
                            LegionnaireLogger.log_legionnaire_activity(
                                f"[SYN Flood] Client {client_id} ({src_ip}) flagged."
                            )
                    else:
                        LegionnaireLogger.log_legionnaire_activity(
                            f"[SYN Flood] Untracked IP: {src_ip}"
                        )

        sniff(iface=interface, prn=process_packet, store=False)

    @staticmethod
    def should_session_be_flagged(client_id):
        now = time.time()

        # Drop old attempts
        SynFloodingRuleManager.syn_attempts[client_id] = [
            t for t in SynFloodingRuleManager.syn_attempts[client_id]
            if now - t <= SynFloodingRuleManager.SYN_WINDOW
        ]

        if now - SynFloodingRuleManager.last_flagged[client_id] < SynFloodingRuleManager.COOLDOWN:
            return False  # in cooldown

        syn_count = len(SynFloodingRuleManager.syn_attempts[client_id])
        if syn_count > SynFloodingRuleManager.SYN_THRESHOLD:
            SynFloodingRuleManager.last_flagged[client_id] = now
            return True
        return False


# icmp_flood_rule.py
class IcmpFloodingRuleManager:
    ICMP_WINDOW = 10           # seconds
    ICMP_THRESHOLD = 80        # per window
    COOLDOWN = 20              # seconds between flags

    icmp_attempts = defaultdict(list)
    last_flagged = defaultdict(float)

    @staticmethod
    def monitor(interface):
        # function for monitoring tunnel that the server listens on
        def process_packet(packet):
            if IP in packet and ICMP in packet and packet[ICMP].type == 8:
                # if statement based upon if packet is an IP ICMP packet and has type 8 for payload
                payload = extract_payload(packet)
                src_ip = packet[IP].src
                client_id = SessionTracker.get_client_id(src_ip)
                # check to see if client id exists within session tracker
                if client_id:
                    SessionTracker.add_payload(client_id, payload)
                    if IcmpFloodingRuleManager.should_session_be_flagged(client_id):
                        ViolationManager.record_violation(
                            rule_name="ICMP Flood Violation",
                            client_id=client_id
                        )
                        LegionnaireLogger.log_legionnaire_activity(f"[ICMP Flood] Client {client_id} ({src_ip}) flagged.")
                else:
                    # logs unknown IP
                    LegionnaireLogger.log_legionnaire_activity(f"[ICMP Flood] Untracked IP: {src_ip}")

        sniff(iface=interface, prn=process_packet, store=False)

    @staticmethod
    def register_packet(packet, client_id):
        # registering packet if packet is an ICMP packet
        if packet.haslayer('ICMP'):
            now = time.time()
            IcmpFloodingRuleManager.icmp_attempts[client_id].append(now)

    @staticmethod
    def should_session_be_flagged(session):
        # function for determining if session should be flagged for an ICMP echo request attack
        client_id = session.client_id
        now = time.time()

        IcmpFloodingRuleManager.icmp_attempts[client_id] = [
            # logging icmp echo request attempts
            t for t in IcmpFloodingRuleManager.icmp_attempts[client_id]
            if now - t <= IcmpFloodingRuleManager.ICMP_WINDOW
        ]

        if now - IcmpFloodingRuleManager.last_flagged[client_id] < IcmpFloodingRuleManager.COOLDOWN:
            # checking to see if latest icmp packet exists outside of cooldown period
            return False

        icmp_count = len(IcmpFloodingRuleManager.icmp_attempts[client_id])
        if icmp_count > IcmpFloodingRuleManager.ICMP_THRESHOLD:
            IcmpFloodingRuleManager.last_flagged[client_id] = now
            return True
        return False
