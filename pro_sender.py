import argparse
from scapy.all import *
import contextlib
import time



def ack_callback(packet):
    return (TCP in packet and
            packet[TCP].flags & 0x10)

def generate_random_port():
    return random.randint(49152, 65535)

def create_syn_packet(dst_port, isn, p_options):
    # generate a random src port
    src_port = generate_random_port()
    syn = TCP(sport=src_port, dport=dst_port, flags="S", seq=isn, options=p_options)
    return syn

# SYN keeps clean and data packet with options
def three_whs(dst_ip, dst_port, p_options):
    log_path = f"{logs_folder}3whs_{dst_port}_log.txt"
    with open(log_path, "a") as log_file:
        with contextlib.redirect_stdout(log_file):
            ip = IP(dst=dst_ip)
            src_port = generate_random_port()
            
            syn = create_syn_packet(dst_port, isn, MSS_option)
            syn_packet = (ip/syn)
            
            print("3whs SYN sent:")
            syn_packet.show2()
            hexdump(syn_packet)
            
            synack = sr1(syn_packet)
            
            if synack and TCP in synack:
                received_seq = synack[TCP].seq
                if received_seq != synack_isn:
                    print(f"3whs --- Received sequence number ({received_seq}) does not match expected ({synack_isn})")
                
                if (synack[TCP].flags == "SA"):
                    print("3whs SYN-ACK received:")
                    synack.show2()
                    hexdump(synack)
                    
                    ack = TCP(sport=src_port, dport=dst_port, flags="A", seq=synack[TCP].ack, ack=received_seq+1)
                    send(ip/ack)
                    print("3whs ACK sent, TCP connection established:")
                    ack.show2()
                    hexdump(ack)
                
                data_packet = ip/TCP(sport=src_port, dport=dst_port, flags="PA", seq=synack[TCP].ack, ack=received_seq+1) / "Please echo the options sent"
                send(data_packet)
                print("3whs Data sent.")
                data_packet.show2()
                hexdump(data_packet)
                
                response = sniff(filter=f"tcp and src host {dst_ip} and dst port {src_port}", count=1, timeout=10, lfilter=ack_callback)
                
                if response:
                    response = response[0]
                    print("3whs ACK received:")
                    response.show2()
                    hexdump(response)
    
def three_whs_plus(dst_ip, dst_port, p_options):
    log_path = f"{logs_folder}3whsPlus_{dst_port}_log.txt"
    with open(log_path, "a") as log_file:
        with contextlib.redirect_stdout(log_file):
            ip = IP(dst=dst_ip)
            src_port = generate_random_port()
            
            syn = create_syn_packet(dst_port, isn, p_options)
            syn_packet = (ip/syn)

            print("3whs plus SYN sent:")
            syn_packet.show2()
            hexdump(syn_packet)
            
            synack = sr1(syn_packet)
            
            if synack and TCP in synack:
                received_seq = synack[TCP].seq
                if received_seq != synack_isn:
                    print(f"3whs plus --- Received sequence number ({received_seq}) does not match expected ({synack_isn})")
                
                if (synack[TCP].flags == "SA"):
                    print("3whs plus SYN-ACK received:")
                    synack.show2()
                    hexdump(synack)
                    
                    ack = TCP(sport=src_port, dport=dst_port, flags="A", seq=synack[TCP].ack, ack=received_seq+1, options=p_options)
                    send(ip/ack)
                    print("3whs plus ACK sent, TCP connection established:")
                    ack.show2()
                    hexdump(ack)
                
                data_packet = ip/TCP(sport=src_port, dport=dst_port, flags="PA", seq=synack[TCP].ack, ack=received_seq+1) / "Please echo the options sent"
                send(data_packet)
                print("3whs plus Data sent.")
                data_packet.show2()
                hexdump(data_packet)
                
                response = sniff(filter=f"tcp and src host {dst_ip} and dst port {src_port}", count=1, timeout=10, lfilter=ack_callback)
                
                if response:
                    response = response[0]
                    print("3whs plus ACK received:")
                    response.show2()
                    hexdump(response)

                    
def data_directly(dst_ip, dst_port, p_options):
    log_path = f"{logs_folder}data_directly_{dst_port}_log.txt"
    with open(log_path, "a") as log_file:
        with contextlib.redirect_stdout(log_file):
            ip = IP(dst=dst_ip)
            src_port = generate_random_port()
            
            data_packet = ip/TCP(sport=src_port, dport=dst_port, flags="PA", seq=isn) / "Please echo the options sent"
            send(data_packet)
            
            print("data directly Data sent.")
            data_packet.show2()
            hexdump(data_packet)
            
            response = sniff(filter=f"tcp and src host {dst_ip} and dst port {src_port}", count=1, timeout=10, lfilter=ack_callback)
            
            if response:
                response = response[0]
                print("data directly ACK received:")
                response.show2()
                hexdump(response)

def ack_first_test(dst_ip, dst_port):
    log_path = f"{logs_folder}ack_first_{dst_port}_log.txt"
    with open(log_path, "a") as log_file:
        with contextlib.redirect_stdout(log_file):
            ip = IP(dst=dst_ip)
            src_port = generate_random_port()
            
            syn = create_syn_packet(dst_port, isn, MSS_option)
            syn_packet = (ip/syn)
            
            print("Ack First SYN sent:")
            syn_packet.show2()
            hexdump(syn_packet)
        
            synack = sr1(syn_packet)
            
            if synack and TCP in synack:
                if (synack[TCP].flags == "SA"):
                    print("Ack first SYN-ACK received:")
                    synack.show2()
                    hexdump(synack)

                    ack = TCP(sport=src_port, dport=dst_port, flags="A", seq=synack[TCP].ack, ack=synack[TCP].seq+1)
                    send(ip/ack)
                    print("Ack first ACK sent, TCP connection established.")
                    ack.show2()
                    hexdump(ack)
                    
                    payload = "ack first test"
                    data_packet = TCP(sport=src_port, dport=dst_port, flags="PA", seq=synack[TCP].ack, ack=synack[TCP].seq+1) / payload
                    send(ip/data_packet)
                    print("Ack first Data sent.")
                    data_packet.show2()
                    hexdump(data_packet)
                    
                    response = sniff(filter=f"tcp and src host {dst_ip} and dst port {src_port}", count=1, timeout=10, lfilter=ack_callback)
                    
                    if response:
                        response = response[0]
                        print("Ack first ACK received:")
                        response.show2()
                        hexdump(response)
                        
                    
def data_first_test(dst_ip, dst_port):
    log_path = f"{logs_folder}data_first_{dst_port}_log.txt"
    with open(log_path, "a") as log_file:
        with contextlib.redirect_stdout(log_file):
            ip = IP(dst=dst_ip)
            src_port = generate_random_port()
            
            syn = create_syn_packet(dst_port, isn, MSS_option)
            syn_packet = (ip/syn)
            
            print("Data First SYN sent:")
            syn_packet.show2()
            hexdump(syn_packet)
        
            synack = sr1(syn_packet)
            
            if synack and TCP in synack:
                if (synack[TCP].flags == "SA"):
                    print("Data First SYN-ACK received:")
                    synack.show2()
                    hexdump(synack)

                    ack = TCP(sport=src_port, dport=dst_port, flags="A", seq=synack[TCP].ack, ack=synack[TCP].seq+1)
                    send(ip/ack)
                    print("Data First ACK sent, TCP connection established: ")
                    ack.show2()
                    hexdump(ack)
                    
                    payload1 = "data first test 1"
                    payload2 = "data first test 2"
                    
                    payload1_len = len(payload1)
                    payload2_len = len(payload2)
                    
                    tcp_data1 = TCP(sport=src_port, dport=dst_port, flags="PA", seq=synack[TCP].ack, ack=synack[TCP].seq + 1)/payload1
                    packet1 = ip/tcp_data1
                    send(packet1)
                    
                    print("Data First test packet1 sent: ")
                    tcp_data1.show2()
                    hexdump(tcp_data1)
                    
                    packet1_ack = sniff(filter=f"tcp and src host {dst_ip} and dst port {src_port}", count=1, timeout=10, lfilter=ack_callback)
                    
                    print("ACK for packet1 received: ")
                    packet1_ack.show2()
                    hexdump(packet1_ack)
                    
                    time.sleep(1)

                    
                    tcp_data2 = TCP(sport=src_port, dport=dst_port, flags="PA", seq=isn + hole_size, ack=synack[TCP].seq + 1)/payload2
                    packet2 = ip/tcp_data2
                    send(packet2)
                    
                    print("Data First test packet2 sent: ")
                    tcp_data2.show2()
                    hexdump(tcp_data2)
                    
                    packet2_ack = sniff(filter=f"tcp and src host {dst_ip} and dst port {src_port}", count=1, timeout=10, lfilter=ack_callback)
                    
                    print("Data First ACK for packet2 received: ")
                    packet2_ack.show2()
                    hexdump(packet2_ack)
                    
def retransmission_test(dst_ip, dst_port):
    log_path = f"{logs_folder}retran_{dst_port}_log.txt"
    with open(log_path, "a") as log_file:
        with contextlib.redirect_stdout(log_file):
            ip = IP(dst=dst_ip)
            src_port = generate_random_port()
            
            syn = create_syn_packet(dst_port, isn, MSS_option)
            syn_packet = (ip/syn)
            
            print("Data First SYN sent:")
            syn_packet.show2()
            hexdump(syn_packet)
        
            synack = sr1(syn_packet)
            
            if synack and TCP in synack:
                if (synack[TCP].flags == "SA"):
                    print("Retransmission SYN-ACK received:")
                    synack.show2()
                    hexdump(synack)

                    ack = TCP(sport=src_port, dport=dst_port, flags="A", seq=synack[TCP].ack, ack=synack[TCP].seq+1)
                    send(ip/ack)
                    print("Retransmission ACK sent, TCP connection established: ")
                    ack.show2()
                    hexdump(ack)
                    
                    payload1 = "segment 1"
                    seq_num = ack.seq
                    tcp_packet1 = TCP(sport=src_port, dport=dst_port, flags='PA', seq=seq_num, ack=ack.ack)/payload1
                    send(ip/tcp_packet1)
                    
                    print("Retran: segment 1 sent:")
                    tcp_packet1.show2()
                    hexdump(tcp_packet1)
                    
                    seq_num2 = ack.seq + len(payload1)
                    payload2 = "segment 2"
                    tcp_packet2 = TCP(sport=src_port, dport=dst_port, flags='PA', seq=seq_num2, ack=ack.ack)/payload2 
                    send(ip/tcp_packet2)
                    
                    print("Retran: segment 2 sent:")
                    tcp_packet2.show2()
                    hexdump(tcp_packet2)

                    ack1 = sniff(filter=f"tcp and host {dst_ip} and port {dst_port}", count=2, lfilter=ack_callback)
                    for pkt in ack1:
                        print(f"Retran test: ACK received: SEQ={pkt[TCP].seq}, ACK={pkt[TCP].ack}")
                    
                    payload2_new = "new modified updated segment 2"
                    new_tcp_packet2 = TCP(sport=src_port, dport=dst_port, flags='PA', seq=seq_num2, ack=ack.ack)/payload2_new 
                    send(ip/new_tcp_packet2)
                    
                    print("Retran: new segment 2 sent: ")
                    new_tcp_packet2.show2()
                    hexdump(new_tcp_packet2)
                    


parser = argparse.ArgumentParser(description="Process IP and port")
parser.add_argument('--ip', type=str, default='192.168.244.130')
parser.add_argument('--port', type=int, default=80)
parser.add_argument('--option', type=int, default=35)
args = parser.parse_args()

destination_ip = args.ip
destination_port = args.port
option_kind = args.option


MSS_option = ('MSS', 512)
unknown_options = [MSS_option, (35, b'\x00\x00\x00')]
experiment_option = [MSS_option, (253, b'\x00\x00\x00')]
wrong_ts_option = [MSS_option, (8, 16, b'\x00' * 14)]
complete_0_option = [b'\x00\x00', b'\x00\x00', b'\x00\x00', b'\x00\x00', b'\x00\x00', b'\x00\x00', b'\x00\x00', b'\x00\x00', b'\x00\x00', b'\x00\x00', b'\x00\x00', b'\x00\x00']

options_array = []


# 将元组放入队列中
options_array.append(("unknown", unknown_options))
options_array.append(("experiment", experiment_option))
options_array.append(("wrong_ts", wrong_ts_option))
options_array.append(("complete_0", complete_0_option))

dst_ports = [80, 443, 49312]

isn = 724001
synack_isn = 17581102

logs_folder = "logs/tcp/"

for dst_port in dst_ports:
    print(f"Port {dst_port} starts")
    for name, options in options_array:
        print(f"P {dst_port}, {name}, 3whs")
        three_whs(destination_ip, dst_port, options)
        print(f"P {dst_port}, {name}, 3whs - plus")
        three_whs_plus(destination_ip, dst_port, options)
        print(f"P {dst_port}, {name}, data directly")
        data_directly(destination_ip, dst_port, options)
        
    print(f"P {dst_port}, data first")
    data_first_test(destination_ip, dst_port)
    
    print(f"P {dst_port}, ack first")
    ack_first_test(destination_ip, dst_port)
    
    print(f"P {dst_port}, retransmission")
    retransmission_test(destination_ip, dst_port)
        
    
    


