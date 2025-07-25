# flooding rule manager

import time
from collections import defaultdict, deque
from scapy.all import sniff, TCP, IP, ICMP
import logging
# syn_flood_rule.py
import time
from collections import defaultdict

class SynFloodingRuleManager:
    SYN_WINDOW = 10           # seconds
    SYN_THRESHOLD = 100       # per window
    COOLDOWN = 60             # seconds between flags

    syn_attempts = defaultdict(list)
    last_flagged = defaultdict(float)
    completed_handshakes = defaultdict(set)

    @staticmethod
    def monitor(interface):
        from scapy.all import sniff, TCP, IP

        def process_packet(packet):
            if packet.haslayer(TCP) and packet.haslayer(IP):
                src_ip = packet[IP].src
                client_id = SessionTracker.get_client_id_by_ip(src_ip)  # <- You'll need this mapping
                if client_id:
                    SynFloodRuleManager.register_packet(packet, client_id)

        sniff(iface=interface, prn=process_packet, store=False)

    @staticmethod
    def should_session_be_flagged(session):
        client_id = session.client_id
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
    COOLDOWN = 60              # seconds between flags

    icmp_attempts = defaultdict(list)
    last_flagged = defaultdict(float)

    @staticmethod
    def register_packet(packet, client_id):
        if packet.haslayer('ICMP'):
            now = time.time()
            IcmpFloodingRuleManager.icmp_attempts[client_id].append(now)

    @staticmethod
    def should_session_be_flagged(session):
        client_id = session.client_id
        now = time.time()

        IcmpFloodingRuleManager.icmp_attempts[client_id] = [
            t for t in IcmpFloodingRuleManager.icmp_attempts[client_id]
            if now - t <= IcmpFloodingRuleManager.ICMP_WINDOW
        ]

        if now - IcmpFloodingRuleManager.last_flagged[client_id] < IcmpFloodingRuleManager.COOLDOWN:
            return False

        icmp_count = len(IcmpFloodingRuleManager.icmp_attempts[client_id])
        if icmp_count > IcmpFloodingRuleManager.ICMP_THRESHOLD:
            IcmpFloodingRuleManager.last_flagged[client_id] = now
            return True
        return False
