from scapy.all import sniff

# Function to analyze and display packet structure
def analyze_packet(packet):
    print("\n=== New Packet Captured ===")
    
    if packet.haslayer("IP"):
        ip_layer = packet["IP"]
        print(f"Source IP: {ip_layer.src}")
        print(f"Destination IP: {ip_layer.dst}")
        print(f"Protocol: {ip_layer.proto}")
    
    if packet.haslayer("TCP"):
        tcp_layer = packet["TCP"]
        print(f"Source Port: {tcp_layer.sport}")
        print(f"Destination Port: {tcp_layer.dport}")

    if packet.haslayer("UDP"):
        udp_layer = packet["UDP"]
        print(f"Source Port: {udp_layer.sport}")
        print(f"Destination Port: {udp_layer.dport}")
        
    if packet.haslayer("Raw"):
        raw_data = packet["Raw"].load
        print(f"Payload: {raw_data[:100]}")  # print first 100 bytes of payload

# Start sniffing (stop after 10 packets)
sniff(count=10, prn=analyze_packet)
