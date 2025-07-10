from scapy.all import sniff, IP

def handle_packet(packet):
    if IP in packet:
        print(f"From {packet[IP].src} to {packet[IP].dst}")

sniff(filter="ip", prn=handle_packet, count=5)