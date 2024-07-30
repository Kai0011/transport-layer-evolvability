import argparse
from scapy.all import *
import time

def generate_random_port():
    return random.randint(49152, 65535)

def send_tcp_packet(dst_ip, dst_port):
    ip = IP(dst=dst_ip)
    src_port = generate_random_port()

    isn = 1023
    
    syn = ip/TCP(sport=src_port, dport=dst_port, flags="S", seq=isn)
    syn_ack = sr1(syn)
    
    ack = ip/TCP(sport=src_port, dport=dst_port, flags="A", seq=syn_ack.ack, ack=syn_ack.seq + 1)
    send(ack)
    print("TCP handshake complete: SYN sent, SYN-ACK received, ACK sent")
    
    # 发送带有数据的TCP包
    payload = "Hello, Receiver! This is a data packet."
    tcp_data = TCP(sport=src_port, dport=dst_port, flags="PA", seq=syn_ack.ack, ack=syn_ack.seq + 1)
    packet = ip/tcp_data/payload
    send(packet)

    print(f"Sent TCP data packet with seq: {tcp_data.seq} and ack: {tcp_data.ack} and payload: {payload}")

    # 捕获响应数据包
    def packet_callback(packet):
        return (TCP in packet and
                packet[IP].src == dst_ip and
                packet[TCP].dport == src_port and
                packet[TCP].flags & 0x10)  # 仅捕获带有ACK标志的数据包

    response = sniff(filter=f"tcp and src host {dst_ip} and dst port {src_port}", count=1, timeout=10, lfilter=packet_callback)

    if response:
        response = response[0]
        print(f"Received response with seq: {response[TCP].seq} and ack: {response[TCP].ack}")
        
        # 发送ACK响应
        ack = TCP(sport=src_port, dport=dst_port, flags="A", seq=response.ack, ack=response.seq + len(response[TCP].payload))
        send(ip/ack)
        print(f"Sent ACK with ack number: {response.seq + len(response[TCP].payload)}")
    else:
        print("No response received")




parser = argparse.ArgumentParser(description="Process IP and port")
parser.add_argument('--ip', type=str, default='192.168.244.130')
parser.add_argument('--port', type=int, default=80)
args = parser.parse_args()

destination_ip = args.ip
destination_port = args.port
    

send_tcp_packet(destination_ip, destination_port)