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
    
    payload = "Hello, Receiver! This is a data packet."    
    tcp_data = TCP(sport=src_port, dport=dst_port, flags="PA", seq=syn_ack.ack, ack=syn_ack.seq + 1)
    packet = ip/tcp_data/payload
    print("payload packet sent")
    response = sr1(packet)

    if response and TCP in response:
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