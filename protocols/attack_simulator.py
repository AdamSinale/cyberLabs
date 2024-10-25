import random
import time
from scapy.all import IP, TCP, UDP, ICMP, DNS, DNSQR, Raw
import queue

class AttackerSimulator:
    def __init__(self, sniffer_buffer):
        self.sniffer_buffer = sniffer_buffer
        self.internal_ip = '192.168.0.1'
        self.external_ip = '8.8.8.8'
        self.trusted_domain = 'trusted-domain.com'

    def simulate_tcp_attack(self):
        # Generate TCP packets with suspicious properties
        for _ in range(5):
            # Invalid port
            packet = IP(src=self.internal_ip, dst=self.external_ip) / TCP(dport=9999)
            self.sniffer_buffer.put(packet)
            # SYN and RST flags together
            packet = IP(src=self.internal_ip, dst=self.external_ip) / TCP(dport=80, flags='SR')
            self.sniffer_buffer.put(packet)
            # Large segment with PUSH flag
            packet = IP(src=self.internal_ip, dst=self.external_ip) / TCP(dport=443, flags='P') / Raw(load='X' * 2000)
            self.sniffer_buffer.put(packet)
        time.sleep(1)

    def simulate_udp_attack(self):
        # Generate UDP packets with suspicious properties
        for _ in range(5):
            # Invalid UDP port
            packet = IP(src=self.internal_ip, dst=self.external_ip) / UDP(dport=9999)
            self.sniffer_buffer.put(packet)
            # NTP packet with invalid length
            packet = IP(src=self.internal_ip, dst=self.external_ip) / UDP(dport=123) / Raw(load='X' * 60)
            self.sniffer_buffer.put(packet)
        time.sleep(1)

    def simulate_dns_attack(self):
        # Generate DNS packets with suspicious properties
        for _ in range(5):
            # DNS on non-standard port
            packet = IP(src=self.internal_ip, dst=self.external_ip) / UDP(dport=80) / DNS(rd=1, qd=DNSQR(qname='malicious.com'))
            self.sniffer_buffer.put(packet)
            # Possible DNS tunneling
            packet = IP(src=self.internal_ip, dst=self.external_ip) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname='malicious.com')) / Raw(load='X' * 600)
            self.sniffer_buffer.put(packet)
        time.sleep(1)

    def simulate_icmp_attack(self):
        # Generate ICMP packets with suspicious properties
        for _ in range(5):
            # Large ICMP packet
            packet = IP(src=self.internal_ip, dst=self.external_ip) / ICMP() / Raw(load='X' * 100)
            self.sniffer_buffer.put(packet)
        time.sleep(1)

    def simulate_http_attack(self):
        # Generate HTTP packets with suspicious properties
        for _ in range(5):
            # HTTP with sensitive headers
            packet = IP(src=self.internal_ip, dst=self.external_ip) / TCP(dport=80) / Raw(load='GET / HTTP/1.1\r\nAuthorization: Basic YWxhZGRpbjpvcGVuc2VzYW1l\r\n\r\n')
            self.sniffer_buffer.put(packet)
            # Untrusted Referer
            packet = IP(src=self.internal_ip, dst=self.external_ip) / TCP(dport=80) / Raw(load='GET / HTTP/1.1\r\nReferer: http://untrusted.com\r\n\r\n')
            self.sniffer_buffer.put(packet)
        time.sleep(1)

    def simulate_tls_attack(self):
        # Generate TLS packets with suspicious properties
        for _ in range(5):
            # Invalid TLS handshake
            packet = IP(src=self.internal_ip, dst=self.external_ip) / TCP(dport=443) / Raw(load='\x16\x03\x01\x00\x00\x01')
            self.sniffer_buffer.put(packet)
        time.sleep(1)

    def simulate_frequent_icmp(self):
        # Generate high frequency ICMP packets
        for _ in range(15):
            packet = IP(src=self.internal_ip, dst=self.external_ip) / ICMP()
            self.sniffer_buffer.put(packet)
            time.sleep(0.5)

    def simulate_frequent_dns(self):
        # Generate high frequency DNS packets
        for _ in range(15):
            packet = IP(src=self.internal_ip, dst=self.external_ip) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname='frequent.com'))
            self.sniffer_buffer.put(packet)
            time.sleep(0.5)

    def simulate_all_attacks(self):
        self.simulate_tcp_attack()
        self.simulate_udp_attack()
        self.simulate_dns_attack()
        self.simulate_icmp_attack()
        self.simulate_http_attack()
        self.simulate_tls_attack()
        self.simulate_frequent_icmp()
        self.simulate_frequent_dns()

if __name__ == "__main__":
    packet_buffer = queue.Queue()
    simulator = AttackerSimulator(packet_buffer)
    simulator.simulate_all_attacks()
