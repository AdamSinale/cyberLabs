import queue
import time

class Analyzer:
    def __init__(self):
        self.valid_flows = []
        self.invalid_flows = []
        self.internalIPs = []
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
                if hasattr(p, 'ip'):                                    # if packet has an IP layer
                    flow_key = (p.ip.src, p.ip.dst, p[p.transport_layer].srcport, p[p.transport_layer].dstport, p.transport_layer)
                    isValid, reason = self.isValid(p)                   # check validation
                    if isValid:                                         # valid - check validation & add to valid
                        self.valid_flows.append(flow_key)
                    else:                                               # invalid - add to invalid
                        self.invalid_flows.append((flow_key, reason))
            except queue.Empty:
                continue                                               # Continue if the queue is empty but sniffing is ongoing
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

        if p.transport_layer == 'TCP':
            tcpValid, reason = self.tcp_handle(p)
            if not tcpValid:
                return False, reason

        if p.transport_layer == 'UDP':
            udpValid, reason = self.udp_handle(p)
            if not udpValid:
                return False, reason

        if p.transport_layer == 'ICMP':
            icmpValid, reason = self.icmp_handle(p)
            if not icmpValid:
                return False, reason

        if hasattr(p, 'http'):
            httpValid, reason = self.http_handle(p)
            if not httpValid:
                return False, reason

        dnsValid, reason = self.dns_handle(p)                      # Perform DNS validation once for all applicable packets
        if not dnsValid:
            return False, reason

        return True, "Packet is valid"                          # all clear

    def tcp_handle(self, p):
        if p.tcp.dstport not in [80, 443, 53]:                  # Only allow HTTP, HTTPS, or DNS on valid ports
            return False, f"Invalid TCP port: {p.tcp.dstport}"
        if p.tcp.dstport == 443:
            if not self.validate_tls(p):  # Combine TLS validation and length check
                return False, "Invalid TLS on HTTPS"
            elif len(p) > 1460:
                return False, "Large HTTPS packet"
        if p.tcp.flags_psh or p.tcp.flags_urg:
            if len(p) > 1460:                                   # Large segments with PSH/URG flag may indicate an attack
                return False, "Large TCP segment with PUSH or URG flag"
        if len(p) > 1500:  # Typical MTU size for Ethernet
            return False, "Packet size exceeds typical MTU"
        if p.tcp.flags_syn and p.tcp.flags_rst:                 # SYN and RST together are contradictory
            return False, "Invalid SYN+RST combination"
        return True, ""

    def udp_handle(self, p):
        if p.udp.dstport not in [53, 123]:                      # Only allow DNS and NTP traffic
            return False, f"Invalid UDP port: {p.udp.dstport}"
        if p.udp.dstport == 123 and int(p.length) != 48:
            return False, "Invalid NTP packet"                  # NTP packets must have a specific length
        return True, ""

    def dns_handle(self, p):
        if p.transport_layer in ['UDP', 'TCP']:
            if p[p.transport_layer].dstport==53 and not hasattr(p,'dns') or p[p.transport_layer].dstport!=53 and hasattr(p,'dns'):           # Ensure DNS traffic is only on port 53
                return False, "DNS not match port"
            if p[p.transport_layer].srcport==53:
                if int(p.dns.length) > 512:                         # Too big for just DNS - might contain additional info
                    return False, "Possible DNS tunneling"
                if not self.track_attempts(p.ip.dst, self.dns_attempts,60,100):        # Track frequency of outgoing DNS responses
                    return False, "High frequency of DNS responses"
                self.dns_queries[p.ip.dst] = p.dns.qry_name         # If DNS - add to list
            elif p.ip.dst not in self.dns_queries:                  # Unusual packet sent without DNS set before - how would the attacker know the IP without it?
                return False, "No prior DNS query"
        return True, ""

    def icmp_handle(self, p):
        if int(p.length) > 64:                                  # Too big for just pinging - might contain additional info
            return False, "Large ICMP packet"
        if not self.track_attempts(p.ip.dst,self.icmp_attempts,10,10):        # Track frequency of outgoing ICMP requests
            return False, "High frequency of ICMP requests"
        return True, ""

    def http_handle(self, p):
        if len(p.http.file_data) > 1000:                        # Large data in HTTP payload
            return False, "Large HTTP packet"
        for f in ['Authorization', 'Cookie', 'Set-Cookie', 'Proxy-Authorization']:
            if f in p.http.field_names:                         # all indicates sensitive content, potentially private data - We won't send it via HTTP
                return False, f"Sensitive header: {f}"
        if 'User-Agent' in p.http.field_names:
            user_agent = p.http.get_field('User-Agent')
            if 'python-requests' in user_agent.lower():         # Flag unusual User-Agent strings
                return False, f"Suspicious User-Agent: {user_agent}"
        if 'Transfer-Encoding' in p.http.field_names and p.http.get_field('Transfer-Encoding') == 'chunked':
            return False, "Suspicious chunked Transfer-Encoding detected"  # Check for chunked transfer encoding
        if 'Referer' in p.http.field_names:
            referer = p.http.get_field('Referer')
            if not referer.startswith('https://trusted-domain.com'):
                return False, f"Untrusted Referer: {referer}"  # Check for untrusted referer
        if len(p.http.headers) > 2000:                          # Check for unusually large HTTP headers
            return False, "Unusually large HTTP headers"
        if not self.track_attempts(p.ip.dst, self.http_attempts, 60, 100):        # Track frequency of outgoing HTTP requests
            return False, "High frequency of HTTP requests"
        return True, ""


    def validate_tls(self, p):
        try:
            if p.tls.handshake_type in ['client_hello', 'server_hello'] and p.tls.version.startswith('TLS'):
                if p.tls.cert_validation_status == 'valid':
                    if not p.tls.sni or not p.tls.sni == p.tls.certificate_hostname:  # Ensure the hostname matches the certificate
                        return False
                    if p.tls.version not in ['TLS 1.2', 'TLS 1.3']:                    # Only allow secure TLS versions
                        return False
                    if p.tls.cipher_suite in ['TLS_RSA_WITH_3DES_EDE_CBC_SHA', 'TLS_RSA_WITH_RC4_128_SHA']:  # Disallow weak cipher suites
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
