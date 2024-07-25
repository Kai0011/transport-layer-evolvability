import argparse
from scapy.all import *
from scapy.layers.inet import IP, TCP

def generate_random_port():
    return random.randint(49152, 65535)

def create_tcp_connection(dst_ip, dst_port):
    ip = IP(dst=dst_ip)

    isn = 724001
    synack_isn = 17581102
    
    src_port = generate_random_port()
    
    syn = TCP(sport=src_port, dport=dst_port, flags="S", seq=isn, options=[('MSS', 512), (173, 'ABC')])
    syn_packet = ip/syn
    
    synack_response = sr1(syn_packet)
    
    if synack_response and TCP in synack_response:
        received_seq = synack_response[TCP].seq
        if received_seq != synack_isn:
            print(f"Received sequence number ({received_seq}) does not match expected ({synack_isn})")
        
        if synack_response[TCP].options:
            for option in synack_response[TCP].options:
                option_kind = option[0]
                option_value = option[1]
                print(f"Option Kind: {option_kind}, Option Value: {option_value}")
        
        if (synack_response[TCP].flags == "SA"):
            print("SYN-ACK received")
            
            ack = TCP(sport=src_port, dport=dst_port, flags="A", seq=synack_response[TCP].ack, ack=received_seq+1)
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
