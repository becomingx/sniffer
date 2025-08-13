from protocolNumbersImport import load_protocols
from scapy.all import sniff, IP, get_if_list
import sys

# Load protocol metadata
protocol_map = load_protocols()

# Function to process each captured packet
def process_packet(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto_num = packet[IP].proto

        # Get protocol info from CSV
        proto_info = protocol_map.get(proto_num, {'keyword': 'Unknown', 'description': 'N/A'})
        keyword = proto_info['keyword']
        description = proto_info['description']

        print(f"Packet #{packet_count[0]}: {keyword} ({proto_num}) - {description} | {src_ip} -> {dst_ip}")
        packet_count[0] += 1

# Main function to start sniffing
def start_sniffer(interface):
    print(f"Starting packet sniffer on {interface}... Press Ctrl+C to stop.")
    try:
        sniff(iface=interface, prn=process_packet, store=0)
    except KeyboardInterrupt:
        print("\nStopped sniffing.")
    except Exception as e:
        print(f"Error: {e}. Try running as admin or check interface name.")

# Entry point
if __name__ == "__main__":
    packet_count = [0]
    print("Available interfaces:", get_if_list())
    interface = input("Enter interface name (e.g., eth0, Wi-Fi): ") or "eth0"

    if interface not in get_if_list():
        print(f"Invalid interface: {interface}. Exiting.")
        sys.exit(1)

    try:
        start_sniffer(interface)
    except PermissionError:
        print("Permission denied. Run this script as admin.")
