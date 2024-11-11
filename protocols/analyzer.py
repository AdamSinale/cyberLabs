import queue
import time

class Analyzer:
    def __init__(self):
        self.valid_flows = []
        self.invalid_flows = []
        self.internalIPs = ['192.168.0.1']
        self.dns_queries = {}    # Store DNS queries to track domain resolutions
        self.icmp_attempts = {}  # Track outgoing connection attempts to detect frequency anomalies
        self.dns_attempts = {}   # Track outgoing connection attempts to detect frequency anomalies
        self.http_attempts = {}  # Track outgoing connection attempts to detect frequency anomalies

    def validate(self, sniffer):
        self.valid_flows = []
        self.invalid_flows = []
        while sniffer.sniffing or not sniffer.buffer.empty():
            try:
                p = sniffer.buffer.get(timeout=1)                       # Get packet from queue with a timeout
                if hasattr(p, 'ip') and hasattr(p, p.transport_layer.lower()):  # Check if packet has IP and transport layer
                    flow_key = (p.ip.src, p.ip.dst, getattr(p[p.transport_layer.lower()],'srcport',None), getattr(p[p.transport_layer.lower()],'dstport',None), p.transport_layer)
                    isValid, reason = self.isValid(p)                   # check validation
                    if isValid:                                         # valid - check validation & add to valid
                        self.valid_flows.append(flow_key)
                    else:                                               # invalid - add to invalid
                        self.invalid_flows.append((flow_key, reason))
            except queue.Empty:
                continue                                               # Continue if the queue is empty but sniffing is ongoing
        # print("Valid Flows:", self.valid_flows)
        # print("Invalid Flows:", self.invalid_flows)
        print(f"Valid Flows: {len(self.valid_flows)} Packets")
        print(f"Invalid Flows: {len(self.invalid_flows)} Packets")
        return self.valid_flows, self.invalid_flows

    def isInternal(self, ip):
        return ip in self.internalIPs

    def isValid(self, p):
        if self.isInternal(p.ip.src) and self.isInternal(p.ip.dst):
            return True, "Internal traffic - skipping"
        if not self.isInternal(p.ip.src) and not self.isInternal(p.ip.dst):
            return True, "External traffic - skipping"
        if not self.isInternal(p.ip.src) and self.isInternal(p.ip.dst):
            return True, "Incoming traffic - skipping"

        print("\ntests - ",end="")
        if 'TCP' in p:
            print("TCP,",end="")
            tcpValid, reason = self.tcp_handle(p)
            if not tcpValid:
                return False, reason

        if 'UDP' in p:
            print("UDP,",end="")
            udpValid, reason = self.udp_handle(p)
            if not udpValid:
                return False, reason

        if 'ICMP' in p:
            print("ICMP,",end="")
            icmpValid, reason = self.icmp_handle(p)
            if not icmpValid:
                return False, reason

        if 'HTTP' in p:
            print("HTTP,",end="")
            httpValid, reason = self.http_handle(p)
            if not httpValid:
                return False, reason

        print("DNS")
        dnsValid, reason = self.dns_handle(p)                      # Perform DNS validation once for all applicable packets
        if not dnsValid:
            return False, reason

        return True, "Packet is valid"                          # all clear

    def tcp_handle(self, p):
        if p['TCP'].port not in [80, 443, 53]:                  # Only allow HTTP, HTTPS, or DNS on valid ports
            return False, f"Invalid TCP port: {p.tcp.dstport}"
        if p['TCP'].dport == 443:
            if not self.validate_tls(p):  # Combine TLS validation and length check
                return False, "Invalid TLS on HTTPS"
            elif len(p) > 1460:
                return False, "Large HTTPS packet"
        if p.tcp.flags_push or p.tcp.flags_urg:
            if len(p) > 1460:                                   # Large segments with PSH/URG flag may indicate an attack
                return False, "Large TCP segment with PUSH or URG flag"
        if len(p) > 1500:  # Typical MTU size for Ethernet
            return False, "Packet size exceeds typical MTU"
        if p.tcp.flags_syn and p.tcp.flags_rst:                 # SYN and RST together are contradictory
            return False, "Invalid SYN+RST combination"
        return True, ""

    def udp_handle(self, p):
        if p['UDP'].port not in [53, 123]:                      # Only allow DNS and NTP traffic
            return False, f"Invalid UDP port: {p.udp.dstport}"
        if p['UDP'].dport == 123 and int(p['UDP'].len) != 48:
            return False, "Invalid NTP packet"                  # NTP packets must have a specific length
        return True, ""

    def dns_handle(self, p):
        if 'DNS' in p:
            if p[p.transport_layer.lower()].srcport != 53 and p.dns.qr == 1:  # Ensure DNS responses come from port 53
                return False, "Invalid DNS response port"
            if p.dns.ancount > 0 and len(p.dns.an[0].rdata) > 512:  # Check DNS response size
                return False, "Possible DNS tunneling"
        return True, ""

    def icmp_handle(self, p):
        if int(p.len) > 64:                                  # Too big for just pinging - might contain additional info
            return False, "Large ICMP packet"
        if not self.track_attempts(p['IP'].dst, self.icmp_attempts, 10, 10):        # Track frequency of outgoing ICMP requests
            return False, "High frequency of ICMP requests"
        return True, ""

    def http_handle(self, p):
        if len(p['HTTP'].payload) > 1000:                        # Large data in HTTP payload
            return False, "Large HTTP packet"
        for f in ['Authorization', 'Cookie', 'Set-Cookie', 'Proxy-Authorization']:
            if f in p['HTTP'].fields:                         # all indicates sensitive content, potentially private data - We won't send it via HTTP
                return False, f"Sensitive header: {f}"
        if 'User-Agent' in p['HTTP'].fields:
            user_agent = p['HTTP'].fields['User-Agent']
            if 'python-requests' in user_agent.lower():         # Flag unusual User-Agent strings
                return False, f"Suspicious User-Agent: {user_agent}"
        if 'Transfer-Encoding' in p['HTTP'].fields and p['HTTP'].fields['Transfer-Encoding'] == 'chunked':
            return False, "Suspicious chunked Transfer-Encoding detected"  # Check for chunked transfer encoding
        if 'Referer' in p['HTTP'].fields:
            referer = p['HTTP'].fields['Referer']
            if not referer.startswith('https://trusted-domain.com'):
                return False, f"Untrusted Referer: {referer}"  # Check for untrusted referer
        if len(p['HTTP'].fields) > 2000:                          # Check for unusually large HTTP headers
            return False, "Unusually large HTTP headers"
        if not self.track_attempts(p['IP'].dst, self.http_attempts, 60, 100):        # Track frequency of outgoing HTTP requests
            return False, "High frequency of HTTP requests"
        return True, ""

    def validate_tls(self, p):
        try:
            if p.haslayer('TLS') and p['TLS'].handshake_type in ['client_hello', 'server_hello'] and p['TLS'].version.startswith('TLS'):
                if p['TLS'].cert_validation_status == 'valid':
                    if not p['TLS'].sni or not p['TLS'].sni == p['TLS'].certificate_hostname:  # Ensure the hostname matches the certificate
                        return False
                    if p['TLS'].version not in ['TLS 1.2', 'TLS 1.3']:                    # Only allow secure TLS versions
                        return False
                    if p['TLS'].cipher_suite in ['TLS_RSA_WITH_3DES_EDE_CBC_SHA', 'TLS_RSA_WITH_RC4_128_SHA']:  # Disallow weak cipher suites
                        return False
                    return True
            return False
        except AttributeError:
            return False

    def track_attempts(self, dst_ip, attempts, window=10, threshold=10):
        current_time = time.time()
        if dst_ip not in attempts:
            attempts[dst_ip] = []
        # Filter out connection attempts that are outside of the time window (e.g., 10 seconds)
        attempts[dst_ip] = [t for t in attempts[dst_ip] if current_time - t < window]
        attempts[dst_ip].append(current_time)
        if len(attempts[dst_ip]) > threshold:    # If there are too many attempts in a short time frame, flag it as suspicious
            return False
        return True
