import random
import time
from scapy.all import Ether, IP, TCP, UDP, ICMP, DNS, DNSQR, Raw
from scapy.utils import wrpcap
import queue


class AttackerSimulator:
    def __init__(self):
        self.packets = []
        self.internal_ip = '192.168.0.1'
        self.external_ip = '8.8.8.8'
        self.trusted_domain = 'trusted-domain.com'

    def ip_packet(self):
        return Ether() / IP(src=self.internal_ip, dst=self.external_ip)

    def tcp_packet(self, dp, flags=''):
        return TCP(sport=random.randint(1024, 65535), dport=dp, flags=flags)

    def udp_packet(self, dp):
        return UDP(sport=random.randint(1024, 65535), dport=dp)

    def simulate_tcp_attack(self):  # Generate TCP packets with suspicious properties
        print("Suspicious TCP packets")
        for _ in range(5):
            packet = self.ip_packet() / self.tcp_packet(9999)  # Invalid port
            self.packets.append(packet)

            packet = self.ip_packet() / self.tcp_packet(80, 'SR')  # SYN and RST flags together
            self.packets.append(packet)

            packet = self.ip_packet() / self.tcp_packet(80, 'P') / Raw(load='X' * 1470)  # Large segment with PUSH flag
            self.packets.append(packet)
            packet = self.ip_packet() / self.tcp_packet(80, 'U') / Raw(load='X' * 1470)  # Large segment with URG flag
            self.packets.append(packet)
            packet = self.ip_packet() / self.tcp_packet(443) / Raw(load='X' * 1470)  # Large TCP segment
            self.packets.append(packet)
            packet = self.ip_packet() / self.tcp_packet(80) / Raw(load='X' * 2000)  # Large TCP segment
            self.packets.append(packet)
        time.sleep(1)

    def simulate_udp_attack(self):  # Generate UDP packets with suspicious properties
        print("Suspicious UDP packets")
        for _ in range(5):
            packet = self.ip_packet() / self.udp_packet(9999)  # Invalid UDP port
            self.packets.append(packet)

            packet = self.ip_packet() / self.udp_packet(123) / Raw(load='X' * 60)  # NTP packet with invalid length
            self.packets.append(packet)
        time.sleep(1)

    def simulate_dns_attack(self):  # Generate DNS packets with suspicious properties
        print("Suspicious DNS packets")
        for _ in range(5):
            packet = self.ip_packet() / self.udp_packet(123) / DNS(rd=1, qd=DNSQR(
                qname='malicious.com'))  # DNS on non-standard port
            self.packets.append(packet)
            packet = self.ip_packet() / self.udp_packet(53)  # DNS port on non-DNS
            self.packets.append(packet)

            packet = self.ip_packet() / self.udp_packet(53) / DNS(rd=1, qd=DNSQR(qname='malicious.com')) / Raw(
                load='X' * 600)  # Possible DNS tunneling
            self.packets.append(packet)
        time.sleep(1)

    def no_prior_dns(self):
        packet = self.ip_packet() / self.udp_packet(123)  # no prior DNS
        self.packets.append(packet)

        packet = self.ip_packet() / self.udp_packet(53) / DNS(rd=1, qd=DNSQR(
            qname='good.com'))  # Now send DNS for next packets
        self.packets.append(packet)

    def simulate_icmp_attack(self):  # Generate ICMP packets with suspicious properties
        print("Suspicious ICMP packets")
        for _ in range(5):
            packet = self.ip_packet() / ICMP() / Raw(load='X' * 100)  # Large ICMP packet
            self.packets.append(packet)
        time.sleep(1)

    def simulate_http_attack(self):  # Generate HTTP packets with suspicious properties
        print("Suspicious HTTP packets")
        for _ in range(5):
            packet = self.ip_packet() / self.tcp_packet(80) / Raw(
                load='GET / HTTP/1.1\r\nAuthorization: Basic YWxhZGRpbjpvcGVuc2VzYW1l\r\n\r\n')  # HTTP with sensitive headers
            self.packets.append(packet)

            packet = self.ip_packet() / self.tcp_packet(80) / Raw(
                load='GET / HTTP/1.1\r\nReferer: http://untrusted.com\r\n\r\n')  # Untrusted Referer
            self.packets.append(packet)

            packet = self.ip_packet() / self.tcp_packet(80) / Raw(load='GET / HTTP/1.1\r\n\r\n')  # Missing Host header
            self.packets.append(packet)

            packet = self.ip_packet() / self.tcp_packet(80) / Raw(
                load='GET / HTTP/1.1\r\nContent-Length: 100\r\n\r\n')  # Incorrect Content-Length
            self.packets.append(packet)

            packet = self.ip_packet() / self.tcp_packet(80) / Raw(
                load='GET / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n')  # Chunked Transfer-Encoding
            self.packets.append(packet)

            packet = self.ip_packet() / self.tcp_packet(80) / Raw(
                load='GET / HTTP/1.1\r\nUser-Agent: python-requests/2.25.1\r\n\r\n')  # Suspicious User-Agent
            self.packets.append(packet)

            packet = self.ip_packet() / self.tcp_packet(80) / Raw(
                load='GET / HTTP/1.1\r\nHeader1: ' + 'X' * 2200 + '\r\n\r\n')  # Unusually large HTTP headers
            self.packets.append(packet)
        time.sleep(1)

    def simulate_tls_attack(self):  # Generate TLS packets with suspicious properties
        print("Suspicious TLS added packets")
        for _ in range(5):
            packet = self.ip_packet() / self.tcp_packet(443) / Raw(
                load='\x16\x03\x01\x00\x00\x01')  # Invalid TLS handshake
            self.packets.append(packet)

            packet = self.ip_packet() / self.tcp_packet(443) / Raw(
                load='\x14\x03\x01\x00\x01\x01')  # Incomplete TLS handshake
            self.packets.append(packet)

            packet = self.ip_packet() / self.tcp_packet(443) / Raw(
                load='\x16\x03\x01\x00\x20\x01\x00\x00\x1c\x00\x01\x00\x01\x02\x03')  # Weak TLS cipher suite
            self.packets.append(packet)

            packet = self.ip_packet() / self.tcp_packet(443) / Raw(
                load='\x16\x03\x00\x00\x00\x01')  # Unsupported TLS version (TLS 1.0)
            self.packets.append(packet)

            packet = self.ip_packet() / self.tcp_packet(443) / Raw(
                load='\x16\x03\x02\x00\x20\x01\x00\x00\x1c\x00\x01\x00\x01\x02\x03')  # Invalid SNI hostname mismatch
            self.packets.append(packet)
        time.sleep(1)

    def simulate_frequent_icmp(self):  # Generate high frequency ICMP packets
        print("ICMP tunneling")
        for _ in range(15):
            packet = self.ip_packet() / ICMP()
            self.packets.append(packet)
            time.sleep(0.5)

    def simulate_frequent_dns(self):  # Generate high frequency DNS packets
        print("DNS tunneling")
        for _ in range(15):
            packet = self.ip_packet() / self.udp_packet(53) / DNS(rd=1, qd=DNSQR(qname='frequent.com'))
            self.packets.append(packet)
            time.sleep(0.5)

    def simulate_all_attacks(self):
        self.no_prior_dns()
        self.simulate_tcp_attack()
        self.simulate_udp_attack()
        self.simulate_dns_attack()
        self.simulate_icmp_attack()
        self.simulate_http_attack()
        self.simulate_tls_attack()
        self.simulate_frequent_icmp()
        self.simulate_frequent_dns()
        wrpcap('attack_simulation.pcap', self.packets)


if __name__ == "__main__":
    simulator = AttackerSimulator()
    simulator.simulate_all_attacks()
