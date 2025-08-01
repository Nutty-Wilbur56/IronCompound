from scapy.packet import Raw


def extract_payload(packet):
    if Raw in packet:
        return packet[Raw].load[:512]
        # trim or pad later

    return b""