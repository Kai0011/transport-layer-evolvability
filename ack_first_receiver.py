import argparse
from scapy.all import *

def handle_packet(packet):
    if TCP in packet:
        if packet[TCP].flags == "S":
            ip = IP(src=packet[IP].dst, dst = packet[IP].src)
            syn_ack = TCP(sport=packet[TCP].dport, dport=packet[TCP].sport, flags="SA", seq=1000, ack=packet[TCP].seq + 1)
            send(ip/syn_ack)
            print("SYN-ACK sent")
        elif packet[TCP].flags == "A":
            print(f"ACK received: SEQ={packet[TCP].seq}, ACK={packet[TCP].ack}")
            print("Connection established")
        elif packet[TCP].flags == "PA":
            print(f"Received TCP packet with sequence number: {packet[TCP].seq} and payload: {packet[TCP].payload}")

            payload = "This is a payload from receiver with a hole"

            # 发送ACK响应
            ip = IP(src=packet[IP].dst, dst=packet[IP].src)
            tcp_ack = TCP(sport=packet[TCP].dport, dport=packet[TCP].sport, flags="PA", seq=100000, ack=packet[TCP].seq + len(packet[TCP].payload) + 321)
            ack_packet = ip/tcp_ack/payload
            send(ack_packet)
            print(f"Sent ACK with acknowledgment number: {tcp_ack.ack} and payload: {payload}")

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
