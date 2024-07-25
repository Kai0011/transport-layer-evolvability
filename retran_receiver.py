import argparse
from scapy.all import *

def handle_packet(packet):
    if packet[TCP].flags == 'S':
        # 收到SYN，发送SYN-ACK
        syn_ack = IP(src=packet[IP].dst, dst=packet[IP].src)/TCP(sport=packet[TCP].dport, dport=packet[TCP].sport, flags='SA', seq=1000, ack=packet[TCP].seq+1)
        send(syn_ack)
        print(f"SYN-ACK sent with SEQ={syn_ack.seq}, ACK={syn_ack.ack}")
    elif packet[TCP].flags == 'A':
        # 收到ACK，连接已建立
        print(f"ACK received: SEQ={packet[TCP].seq}, ACK={packet[TCP].ack}")
        print("Connection established")
    elif packet[TCP].flags == 'PA':
        # 收到数据段
        data = packet[Raw].load
        seq_num = packet[TCP].seq
        ack_num = packet[TCP].ack
        print(f"Data received: SEQ={seq_num}, ACK={ack_num}, DATA='{data.decode()}'")
        if "Segment 1" in data.decode():
            # 发送第一个段的累积ACK
            ack = IP(src=packet[IP].dst, dst=packet[IP].src)/TCP(sport=packet[TCP].dport, dport=packet[TCP].sport, flags='A', seq=ack_num, ack=seq_num+len(data))
            send(ack)
            print(f"ACK sent with SEQ={ack.seq}, ACK={ack.ack}")
            # 发送重复ACK
            dup_ack = IP(src=packet[IP].dst, dst=packet[IP].src)/TCP(sport=packet[TCP].dport, dport=packet[TCP].sport, flags='A', seq=ack_num, ack=seq_num+len(data))
            send(dup_ack)
            print(f"Duplicate ACK sent with SEQ={dup_ack.seq}, ACK={dup_ack.ack}")
        elif "New Segment 2" in data.decode() or "Small" in data.decode() or "Larger Segment Data" in data.decode():
            echo = IP(src=packet[IP].dst, dst=packet[IP].src)/TCP(sport=listen_port, dport=packet[TCP].sport, flags='PA', seq=ack_num, ack=seq_num+len(data))/data
            send(echo)
            print(f"Echo sent with SEQ={echo.seq}, ACK={echo.ack}, DATA='{data.decode()}'")

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
