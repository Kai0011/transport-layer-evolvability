import argparse
from scapy.all import *
import contextlib
import os

def handle_packet(packet):
    dst_port = packet[TCP].dport
    log_path = f"{log_folder}tcp_receiver_{dst_port}_log.txt"
    with open(log_path, "a") as log_file:
        with contextlib.redirect_stdout(log_file):
            if TCP in packet:
                print(f"Flag: {packet[TCP].flags}\n")
                packet.show2()
                hexdump(packet)
                if packet[TCP].flags == "S":
                    print("SYN packet received above")
                    if packet[TCP].seq != sender_isn:
                        print(f"Received sequence number ({packet[TCP].seq}) does not match expected ({sender_isn})")
                    ip = IP(src=packet[IP].dst, dst = packet[IP].src)
                    syn_ack = TCP(sport=packet[TCP].dport, dport=packet[TCP].sport, flags="SA", seq=isn, ack=packet[TCP].seq + 1, options=packet[TCP].options)
                    syn_ack_packet = ip/syn_ack
                    send(syn_ack_packet)
                    
                    print("SYN-ACK sent:")
                    syn_ack_packet.show2()
                    hexdump(syn_ack_packet)
                    
                elif packet[TCP].flags == "A":
                    print(f"ACK received abpve")
                    
                elif packet[TCP].flags == "PA":
                    print(f"Received data packet above")
                    if packet[Raw]:
                        data = packet[Raw].load
                        if "ack first test" in data.decode():
                            payload = "response for ack first test"
                            ip = IP(src=packet[IP].dst, dst=packet[IP].src)
                            tcp_ack = TCP(sport=packet[TCP].dport, dport=packet[TCP].sport, flags="PA", seq=isn+1, ack=packet[TCP].seq + len(packet[TCP].payload) + hole_size)
                            ack_packet = ip/tcp_ack/payload
                            send(ack_packet)
                            
                            print("Response for ack first test sent:")
                            tcp_ack.show2()
                            hexdump(tcp_ack)
                        elif "segment 1" in data.decode():
                            time.sleep(0.5)
                            
                            ip = IP(src=packet[IP].dst, dst=packet[IP].src)
                            tcp_ack = TCP(sport=packet[TCP].dport, dport=packet[TCP].sport, flags='A', seq=packet[TCP].ack, ack=packet[TCP].seq + len(data))
                            send(ip/tcp_ack)
                            
                            print("Retran: first ack sent:")
                            tcp_ack.show2()
                            hexdump(tcp_ack)
                            
                            time.sleep(1)
                            
                            dup_ack = TCP(sport=packet[TCP].dport, dport=packet[TCP].sport, flags='A', seq=packet[TCP].ack, ack=packet[TCP].seq + len(data))
                            send(ip/dup_ack) 

                            print("Retran: duplicated ack sent:")
                            dup_ack.show2()
                            hexdump(dup_ack)
                            
                        elif "new modified updated segment 2" in data.decode():
                            # ip = IP(src=packet[IP].dst, dst=packet[IP].src)
                            # tcp_echo = TCP(sport=packet[TCP].dport, dport=packet[TCP].sport, flags='PA', seq=ack_num, ack=packet[TCP].seq + len(data))/data
                            # send(ip/tcp_echo)
                            
                            # print("Retran: ack for the new segment 2 sent: ")
                            # tcp_echo.show2()
                            # hexdump(tcp_echo)
                            print("Retran: new modified updated segment 2 received")
                            
                        elif "segment 2" in data.decode():
                            print("Segment 2 received above, donot do anything")
                            
                        else:
                            ip = IP(src=packet[IP].dst, dst=packet[IP].src)
                            tcp_ack = TCP(sport=packet[TCP].dport, dport=packet[TCP].sport, flags="A", seq=packet[TCP].ack, ack=packet[TCP].seq + len(packet[TCP].payload), options=packet[TCP].options)
                            ack_packet = ip/tcp_ack
                            send(ack_packet)
                            
                            print(f"Sent ACK:")
                            tcp_ack.show2()
                            hexdump(tcp_ack)
                    else:
                        print("Data packet receiver but Raw layer not found")
                        ip = IP(src=packet[IP].dst, dst=packet[IP].src)
                        tcp_ack = TCP(sport=packet[TCP].dport, dport=packet[TCP].sport, flags="A", seq=packet[TCP].ack, ack=packet[TCP].seq + len(packet[TCP].payload), options=packet[TCP].options)
                        ack_packet = ip/tcp_ack
                        send(ack_packet)
                        
                        print(f"Sent ACK:")
                        tcp_ack.show2()
                        hexdump(tcp_ack)
                    

def main(ip_filter):
    os.makedirs(log_folder, exist_ok=True)
    
    print("Listening for incoming TCP packets...")
    sniff(filter=ip_filter, prn=handle_packet)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="filter IP address")
    parser.add_argument('--ip', type=str, default='128.105.144.164')
    parser.add_argument('--fd', type=str, default='campus')
    args = parser.parse_args()
    
    ip = args.ip
    fd = args.fd

    isn = 17581102
    sender_isn = 724001
    hole_size = 500
    log_folder = f"logs/tcp/{fd}/"

    ip_filter = "tcp and src host " + ip
    main(ip_filter)
