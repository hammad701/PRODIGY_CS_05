from scapy.all import rdpcap, IP, TCP, UDP

def analyze_packets(pcap_file):
    packets = rdpcap(pcap_file)

    print(f"Analyzing packets from: {pcap_file}\n")

    for packet in packets:
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = "OTHER"

            if TCP in packet:
                protocol = "TCP"
            elif UDP in packet:
                protocol = "UDP"

            payload = bytes(packet[IP].payload)
            payload_preview = payload[:30]

            print(f"Source IP      : {src_ip}")
            print(f"Destination IP : {dst_ip}")
            print(f"Protocol       : {protocol}")
            print(f"Payload Preview: {payload_preview}")
            print("-" * 50)

if __name__ == "__main__":
    pcap_path = input("Enter PCAP file path: ")
    analyze_packets(pcap_path)
