import ipaddress

from scapy.layers.inet import IP

from administration.logging.security_logs.legionnaire_logger import LegionnaireLogger


class PacketInspector:
    @staticmethod
    def validate_received_packet(packet: bytes, expected_src_ip: str) -> bool:
        if len(packet) < 20:
            return False
            # packet is too short to be valid IPv4 or IPv6 packet

        try:
            ip = IP(packet)

            """
            consider implementing filter for ipv4
            if ip.version != 4:
            return False
            """
            if ip.chksum != IP(bytes(ip)).chksum:
                # verifying checksum
                return False

            # drop any broadcast and multicast packets
            dst_ip = ipaddress.ip_address(expected_src_ip)
            if dst_ip.version.is_multicast or dst_ip == ipaddress.IPv4Address("255.255.255.255"):
                return False

            # Only allow TCP, UDP, ICMP
            if ip.proto not in (1, 6, 17):
                return False

            # Source IP match
            if ip.src != expected_src_ip:
                return False

            return True

        except Exception as e:
            LegionnaireLogger.log_legionnaire_activity("Failed to capture packet")
            return False