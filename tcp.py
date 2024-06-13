from scapy.all import *

# destination IP address
target_ip = "192.168.244.130"
# target port
target_port = 80

# create a IP packet
ip = IP(dst=target_ip)
# create a TCP packet
tcp = TCP(sport=RandShort(), dport=target_port, flags="S")
# combine the packet
packet = ip/tcp
# send packet
send(packet)
