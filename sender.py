import argparse
from scapy.all import *

def create_tcp_connection(dst_ip, dst_port):
    ip = IP(dst=dst_ip)
    
    syn = TCP(sport=RandShort(), dport=dst_port, flags="S", seq=252001, options=[('MSS', 512), (173, b'ABC')])
    
    syn_packet = ip/syn
    
    synack_response = sr1(syn_packet)
    
    print(synack_response[TCP].flags)
    
    if (synack_response[TCP].flags == "SA"):
        print("SYN-ACK received")
        ack = TCP(dport=dst_port, flags="A", seq=synack_response[TCP].ack, ack=synack_response[TCP].seq+1)
        send(ip/ack)
        print("ACK sent, TCP connection established.")
        
        
        # send data
        # data_packet = ip/TCP(dport=dst_port, flags="PA", seq=synack_response[TCP].ack, ack=synack_response[TCP].seq+1) / "Hello, I'm sender"
        
        # send(data_packet)
        # print("Data sent.")

def send_syn_packet(dst_ip, dst_port):
    # create IP layer
    ip = IP(dst=dst_ip)
    
    # create TCP layer with MSS option
    tcp = TCP(sport=RandShort(), dport=dst_port, flags="S")
    
    # combine the packet and send it 
    packet = ip/tcp
    send(packet) 

def send_tcp_with_mss(dst_ip, dst_port, mss_value):
    # create IP layer
    ip = IP(dst=dst_ip)
    
    # create TCP layer with MSS option
    tcp = TCP(sport=RandShort(), dport=dst_port, flags="S", options=[('MSS', mss_value)])
    
    # combine the packet and send it 
    packet = ip/tcp
    send(packet)
    
from scapy.all import *
from scapy.layers.inet import IP, TCP

def send_custom_tcp_option(dst_ip, dst_port):    
    option_kind = 254  # from 0 ~ 255
    option_data = b'AB'  # binary data
    option_length = len(option_data) + 2  # +2 includes Kind and Length
    
    custom_option = ('Generic', {'kind': option_kind,  'value': option_data})
    
    ip = IP(dst=dst_ip)
    
    tcp = TCP(sport=RandShort(), dport=dst_port, flags="S",
                    options=[(253, b'ABC')])
    
    packet = ip/tcp
    send(packet)


parser = argparse.ArgumentParser(description="Process IP and port")
parser.add_argument('--ip', type=str, default='192.168.244.130')
parser.add_argument('--port', type=int, default=80)
args = parser.parse_args()

destination_ip = args.ip
destination_port = args.port

# test different MSS values
# mss_values = [536, 1460, 8960]


# for mss in mss_values:
#     send_tcp_with_mss(destination_ip, destination_port, mss)
#     print(f"Sent TCP packet with MSS={mss}")
    

# send_syn_packet(destination_ip, destination_port)
create_tcp_connection(destination_ip, destination_port)

# print("TCP packet with custom option sent.")
