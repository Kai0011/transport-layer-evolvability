import argparse
from scapy.all import *
import time

def send_tcp_packet(dst_ip, dst_port):
    ip = IP(dst=dst_ip)
    src_port = RandShort()

    first_seq = 1024
    second_seq = 1736
    
    payload1 = "Hello, Receiver. This is packet 1."
    payload2 = "Hello, Receiver. This is packet 2."
    
    payload_len1 = len(payload1)
    payload_len2 = len(payload2)
    
    # 发送第一个包含数据的TCP包
    tcp_data1 = TCP(sport=src_port, dport=dst_port, flags="PA", seq=first_seq, ack=17581103)
    packet1 = ip/tcp_data1/payload1
    send(packet1)

    end_seq1 = first_seq + payload_len1
    print(f"Sent TCP packet 1 with start sequence number: {first_seq} and end sequence number: {end_seq1}")

    time.sleep(1)

    tcp_data2 = TCP(sport=src_port, dport=dst_port, flags="PA", seq=second_seq, ack=17581199)
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