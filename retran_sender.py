import argparse
from scapy.all import *
import time

def send_tcp_packet(dst_ip, dst_port):
    ip = IP(dst=dst_ip)
    
    isn = 225300
    
    tcp = TCP(sport=RandShort(), dport=dst_port, flags='S', seq = isn)

    # 发起SYN以建立连接
    syn = ip/tcp
    syn_ack = sr1(syn)
    print(f"SYN sent with SEQ={isn}")
    print(f"SYN-ACK received with SEQ={syn_ack.seq}, ACK={syn_ack.ack}")

    # 发送ACK以完成握手
    ack = ip/TCP(dport=target_port, flags='A', seq=syn_ack.ack, ack=syn_ack.seq+1)
    send(ack)
    print(f"ACK sent with SEQ={ack.seq}, ACK={ack.ack}")
    
    # 发送第一个数据段
    data1 = "Segment 1"
    seq_num = ack.seq
    pkt1 = ip/TCP(sport=ack.sport, dport=dst_port, flags='PA', seq=seq_num, ack=ack.ack)/data1
    send(pkt1)
    print(f"Data sent: SEQ={pkt1.seq}, ACK={pkt1.ack}, DATA='{data1}'")

    seq_num2 = ack.seq + len(data1)
    # 发送第二个数据段
    data2 = "Segment 2"
    pkt2 = ip/TCP(sport=pkt1.sport, dport=dst_port, flags='PA', seq=seq_num2, ack=pkt1.ack)/data2
    send(pkt2)
    print(f"Data sent: SEQ={pkt2.seq}, ACK={pkt2.ack}, DATA='{data2}'")

    # 等待累积ACK和重复ACK
    ack1 = sniff(filter=f"tcp and host {dst_ip} and port {dst_port}", count=2)
    for pkt in ack1:
        print(f"ACK received: SEQ={pkt[TCP].seq}, ACK={pkt[TCP].ack}")

    # 发送不同数据的第二个段的重传
    data2_new = "New Segment 2"
    pkt2_new = ip/TCP(sport=pkt2.sport, dport=dst_port, flags='PA', seq=seq_num2, ack=pkt2.ack)/data2_new
    send(pkt2_new)
    print(f"Retransmission sent: SEQ={pkt2_new.seq}, ACK={pkt2_new.ack}, DATA='{data2_new}'")

    # # 可选，发送不同大小的重传段
    # data2_smaller = "Small"
    # send(ip/TCP(dport=target_port, flags='PA', seq=seq_num, ack=ack.ack)/data2_smaller)
    # data2_larger = "Larger Segment Data"
    # send(ip/TCP(dport=target_port, flags='PA', seq=seq_num, ack=ack.ack)/data2_larger)




parser = argparse.ArgumentParser(description="Process IP and port")
parser.add_argument('--ip', type=str, default='192.168.244.130')
parser.add_argument('--port', type=int, default=80)
args = parser.parse_args()

destination_ip = args.ip
destination_port = args.port
    

send_tcp_packet(destination_ip, destination_port)