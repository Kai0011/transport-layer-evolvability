import argparse
from scapy.all import *

def handle_packet(packet):
    if packet.haslayer(TCP) and packet[TCP].flags == 'S':
        options = []
        if packet[TCP].options:
            for option in packet[TCP].options:
                option_kind = option[0]
                option_value = option[1]
                options.append((option_kind, option_value))
                print(f"Option Kind: {option_kind}, Option Value: {option_value}")
                
        isn = 17581102
        sender_isn = 724001

        if packet[TCP].seq != sender_isn:
            print(f"Received sequence number ({packet[TCP].seq}) does not match expected ({sender_isn})")
                
        ip_layer = IP(src=packet[IP].dst, dst=packet[IP].src)
        tcp_layer = TCP(sport=packet[TCP].dport, dport=packet[TCP].sport, flags="SA", seq=isn, ack=packet[TCP].seq + 1, options=options)
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
