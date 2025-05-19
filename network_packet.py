from scapy.all import sniff, IP, TCP, UDP, ICMP, Ether, Raw
from datetime import datetime
import os

# Optional: Enable colored terminal output (only for supported terminals)
try:
    from termcolor import colored
    color_enabled = True
except ImportError:
    color_enabled = False

def print_colored(text, color):
    if color_enabled:
        print(colored(text, color))
    else:
        print(text)

def get_protocol_name(packet):
    if TCP in packet:
        return "TCP"
    elif UDP in packet:
        return "UDP"
    elif ICMP in packet:
        return "ICMP"
    else:
        return "Other"

def process_packet(packet):
    print("=" * 80)
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    if Ether in packet:
        src_mac = packet[Ether].src
        dst_mac = packet[Ether].dst
        print_colored(f"Time: {timestamp}", "cyan")
        print(f"Source MAC: {src_mac}")
        print(f"Destination MAC: {dst_mac}")

    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        proto = get_protocol_name(packet)
        packet_len = len(packet)

        print(f"Source IP: {src_ip}")
        print(f"Destination IP: {dst_ip}")
        print(f"Protocol: {proto}")
        print(f"Packet Size: {packet_len} bytes")

        if Raw in packet:
            payload = packet[Raw].load
            try:
                payload_text = payload.decode(errors="replace")
            except:
                payload_text = str(payload)
            print("Payload (first 100 chars):")
            print(payload_text[:100])
    else:
        print("Non-IP packet detected.")

    print("=" * 80)

def main():
    os.system("cls" if os.name == "nt" else "clear")
    print_colored("Starting Network Packet Analyzer (Press Ctrl+C to stop)\n", "green")
    sniff(prn=process_packet, store=False)

if __name__ == "__main__":
    main()

