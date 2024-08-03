from scapy.all import *

# destination IP address
target_ip = "192.168.244.130"
# target port
target_port = 80

# create a IP packet
ip = IP(dst=target_ip)

options = [b'\x00\x00', b'\x00\x00', b'\x00\x00', b'\x00\x00', b'\x00\x00', b'\x00\x00', b'\x00\x00', b'\x00\x00', b'\x00\x00', b'\x00\x00', b'\x00\x00', b'\x00\x00']

wrong_ts_option = [('MSS', 512), (8, b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')]


# create a TCP packet
tcp = TCP(sport=RandShort(), dport=target_port, flags="S", options=wrong_ts_option)
# combine the packet
packet = ip/tcp

packet.show2()
hexdump(tcp)


# send packet
# send(packet)
