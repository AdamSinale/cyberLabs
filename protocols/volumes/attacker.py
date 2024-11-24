import random
import time
from scapy.all import Ether, IP, TCP, UDP, ICMP, DNS, DNSQR, Raw
from scapy.layers.tls.all import TLS, TLSClientHello, TLSServerHello
import netifaces

from scapy.utils import wrpcap

class AttackerSimulator:
    def __init__(self):
        self.packets = []
        self.internal_ip = '10.9.0.4'
        self.external_ip = '8.8.8.8'
        self.trusted_domain = 'trusted-domain.com'

    def ip_packet(self):
        return Ether() / IP(src=self.internal_ip, dst=self.external_ip)
    def tcp_packet(self, dp, flags=''):
        tcp_packet = TCP(sport=random.randint(1024, 65535), dport=dp, flags=flags)
        return tcp_packet
    def tls_layer(self, t='c'):
        if t == 's':
            return TLS(msg=TLSServerHello())
        elif t == 'c':
            return TLS(msg=TLSClientHello())
    def udp_packet(self, dp):
        return UDP(sport=random.randint(1024, 65535), dport=dp)

    def no_prior_dns(self):
        packet = self.ip_packet() / self.udp_packet(68)  # no prior DNS
        self.packets.append(packet)

        packet = self.ip_packet() / self.udp_packet(53) / DNS(rd=1,qd=DNSQR(qname='good.com'))  # Now send DNS for next packets
        self.packets.append(packet)
    def simulate_tcp_attack(self):  # Generate TCP packets with suspicious properties
        print("Suspicious TCP packets")
        for _ in range(5):
            packet = self.ip_packet() / self.tcp_packet(9999)  # Invalid port
            self.packets.append(packet)

            packet = self.ip_packet() / self.tcp_packet(80, 'SR')  # SYN and RST flags together
            self.packets.append(packet)

            packet = self.ip_packet() / self.tcp_packet(80, 'P') / Raw(load='X' * 1430)  # Large segment with PUSH flag
            self.packets.append(packet)
            packet = self.ip_packet() / self.tcp_packet(80, 'U') / Raw(load='X' * 1430)  # Large segment with URG flag
            self.packets.append(packet)
            packet = self.ip_packet() / self.tcp_packet(443) / self.tls_layer('s') / Raw(load='X' * 1430)  # Large TCP segment
            self.packets.append(packet)
            packet = self.ip_packet() / self.tcp_packet(443) / self.tls_layer('c') / Raw(load='X' * 1430)  # Large TCP segment
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
            packet = self.ip_packet() / self.udp_packet(68) / DNS(rd=1,qd=DNSQR(qname='malicious.com'))  # DNS on non-standard port
            self.packets.append(packet)
            packet = self.ip_packet() / self.udp_packet(53)  # DNS port on non-DNS
            self.packets.append(packet)

            packet = self.ip_packet() / self.udp_packet(53) / DNS(rd=1,qd=DNSQR(qname='malicious.com')) / Raw(load='X' * 600)  # Possible DNS tunneling
            self.packets.append(packet)
        time.sleep(1)
    def simulate_icmp_attack(self):  # Generate ICMP packets with suspicious properties
        print("Suspicious ICMP packets")
        for _ in range(5):
            packet = self.ip_packet() / ICMP() / Raw(load='X' * 100)  # Large ICMP packet
            self.packets.append(packet)
        time.sleep(1)
    def simulate_http_attack(self):  # Generate HTTP packets with suspicious properties
        print("Suspicious HTTP packets")
        for _ in range(5):
            packet = self.ip_packet() / self.tcp_packet(80) / Raw(load='GET / HTTP/1.1\r\nHost: example.com\r\nAuthorization: Basic YWxhZGRpbjpvcGVuc2VzYW1l\r\n\r\n')  # HTTP with sensitive headers
            self.packets.append(packet)

            packet = self.ip_packet() / self.tcp_packet(80) / Raw(load='GET / HTTP/1.1\r\nHost: example.com\r\nReferer: http://untrusted.com\r\n\r\n')  # Untrusted Referer
            self.packets.append(packet)

            packet = self.ip_packet() / self.tcp_packet(80) / Raw(load='GET / HTTP/1.1\r\n\r\n')  # no "Host" header
            self.packets.append(packet)

            packet = self.ip_packet() / self.tcp_packet(80) / Raw(load='GET / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 1000\r\n\r\n' + 'X' * 1000)  # Long payload
            self.packets.append(packet)

            packet = self.ip_packet() / self.tcp_packet(80) / Raw(load='GET / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n7\r\nMozilla\r\n9\r\nDeveloper\r\n7\r\nNetwork\r\n0\r\n\r\n')  # Chunked Transfer-Encoding
            self.packets.append(packet)

            packet = self.ip_packet() / self.tcp_packet(80) / Raw(load='GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: python-requests/2.25.1\r\n\r\n')  # Suspicious User-Agent
            self.packets.append(packet)

            packet = self.ip_packet() / self.tcp_packet(80) / Raw(load='GET / HTTP/1.1\r\nHost: example.com\r\nHeader1: ' + 'X' * 1200 + '\r\n\r\n')  # Unusually large HTTP headers
            self.packets.append(packet)
        time.sleep(1)
    def simulate_frequent_icmp(self):  # Generate high frequency ICMP packets
        print("ICMP tunneling")
        for _ in range(15):
            packet = self.ip_packet() / ICMP()
            self.packets.append(packet)
            time.sleep(0.25)
    def simulate_frequent_dns(self):  # Generate high frequency DNS packets
        print("DNS tunneling")
        for _ in range(15):
            packet = self.ip_packet() / self.udp_packet(53) / DNS(rd=1, qd=DNSQR(qname='frequent.com'))
            self.packets.append(packet)
            time.sleep(0.25)

    def simulate_all_attacks(self):
        self.no_prior_dns()
        self.simulate_tcp_attack()
        self.simulate_udp_attack()
        self.simulate_dns_attack()
        self.simulate_icmp_attack()
        self.simulate_http_attack()
        self.simulate_frequent_icmp()
        self.simulate_frequent_dns()
        wrpcap('attack_simulation.pcap', self.packets)


if __name__ == "__main__":
    simulator = AttackerSimulator()
    simulator.simulate_all_attacks()
