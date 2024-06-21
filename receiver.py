import argparse
from scapy.all import *

def handle_packet(packet):
    if packet.haslayer(TCP) and packet[TCP].flags == 'S':
        if packet[TCP].options:
            for option in packet[TCP].options:
                option_kind = option[0]
                option_value = option[1]
                print(f"Option Kind: {option_kind}, Option Value: {option_value}")
                
                
        ip_layer = IP(src=packet[IP].dst, dst=packet[IP].src)
        tcp_layer = TCP(sport=packet[TCP].dport, dport=packet[TCP].sport, flags="SA", seq=1000, ack=packet[TCP].seq + 1)
        syn_ack_packet = ip_layer / tcp_layer
        send(syn_ack_packet)
        print(f"Sent SYN-ACK from {packet[IP].dst} to {packet[IP].src}")

def main(ip_filter):
    print("Listening for incoming TCP SYN packets...")
    sniff(filter=ip_filter, prn=handle_packet)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="filter IP address")
    parser.add_argument('--ip', type=str, default='128.105.144.164')
    args = parser.parse_args()

    ip = args.ip
    ip_filter = "tcp and src host " + ip
    main(ip_filter)
