import argparse
from scapy.all import *
import time

def generate_random_port():
    return random.randint(49152, 65535)


def send_tcp_packet(dst_ip, dst_port):
    ip = IP(dst=dst_ip)

    first_seq = 1023
    second_seq = 1736
    src_port = generate_random_port()
    
    payload1 = "Hello, Receiver. This is packet 1."
    payload2 = "Hello, Receiver. This is packet 2."
    
    payload_len1 = len(payload1)
    payload_len2 = len(payload2)

    syn = ip/TCP(sport=src_port, dport=dst_port, flags="S", seq=first_seq)
    syn_ack = sr1(syn)
    
    ack = ip/TCP(sport=src_port, dport=dst_port, flags="A", seq=syn_ack.ack, ack=syn_ack.seq + 1)
    send(ack)
    print("TCP handshake complete: SYN sent, SYN-ACK received, ACK sent")
    
    # 发送第一个包含数据的TCP包
    tcp_data1 = TCP(sport=src_port, dport=dst_port, flags="PA", seq=syn_ack.ack, ack=syn_ack.seq + 1)
    packet1 = ip/tcp_data1/payload1
    send(packet1)

    end_seq1 = tcp_data1.seq + payload_len1
    print(f"Sent TCP packet 1 with start sequence number: {tcp_data1.seq} and end sequence number: {end_seq1}")

    time.sleep(1)

    tcp_data2 = TCP(sport=src_port, dport=dst_port, flags="PA", seq=second_seq, ack=syn_ack.seq + 1)
    packet2 = ip/tcp_data2/payload2
    send(packet2)

    end_seq2 = second_seq + payload_len2
    print(f"Sent TCP packet 2 with start sequence number: {second_seq} and end sequence number: {end_seq2}")




parser = argparse.ArgumentParser(description="Process IP and port")
parser.add_argument('--ip', type=str, default='192.168.244.130')
parser.add_argument('--port', type=int, default=80)
args = parser.parse_args()

destination_ip = args.ip
destination_port = args.port
    

send_tcp_packet(destination_ip, destination_port)