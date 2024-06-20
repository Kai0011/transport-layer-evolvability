from scapy.all import *

def handle_packet(packet):
    if packet.haslayer(TCP) and packet[TCP].flags == 'S':
        ip_layer = IP(src=packet[IP].dst, dst=packet[IP].src)
        tcp_layer = TCP(sport=packet[TCP].dport, dport=packet[TCP].sport, flags="SA", seq=1000, ack=packet[TCP].seq + 1)
        syn_ack_packet = ip_layer / tcp_layer
        send(syn_ack_packet)
        print(f"Sent SYN-ACK from {packet[IP].dst} to {packet[IP].src}")

def main():
    print("Listening for incoming TCP SYN packets...")
    sniff(filter="tcp and (tcp[tcpflags] & (tcp-syn) != 0)", prn=handle_packet)

if __name__ == "__main__":
    main()
