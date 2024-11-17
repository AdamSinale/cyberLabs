import queue
import time

class Analyzer:
    def __init__(self):
        self.flows = []
        self.internalIPs = ['127.0.0.1']
        self.icmp_attempts = {}  # Track outgoing connection attempts to detect frequency anomalies
        self.dns_attempts = {}   # Track outgoing connection attempts to detect frequency anomalies
        self.http_attempts = {}  # Track outgoing connection attempts to detect frequency anomalies

    def validate(self, sniffer):
        self.flows = []
        while sniffer.sniffing or not sniffer.buffer.empty():
            try:
                p = sniffer.buffer.get(timeout=1)  # Get packet from queue with a timeout
                if hasattr(p, 'ip'):                                                   # Handle ICMP packets
                    if hasattr(p, 'icmp'):
                        flow_key = (p.ip.src, p.ip.dst, None, 'ICMP')
                    elif p.transport_layer and hasattr(p, p.transport_layer.lower()):  # Handle TCP/UDP packets
                        transport_layer = p.transport_layer.lower()
                        flow_key = (p.ip.src, p.ip.dst, getattr(p[transport_layer], 'dstport', None), p.transport_layer)
                    else:
                        flow_key = (p.ip.src, p.ip.dst, None, 'UNKNOWN')
                    isValid, reason = self.isValid(p)
                    print(reason)
                    self.flows.append((flow_key, isValid, reason))
            except queue.Empty:
                continue  # Continue if the queue is empty but sniffing is ongoing
        print(f"Valid Flows: {len(self.flows)} Packets")

    def isInternal(self, ip):
        return ip in self.internalIPs

    def isValid(self, p):
        if self.isInternal(p.ip.src) and self.isInternal(p.ip.dst):
            return True, "Internal traffic - skipping"
        if not self.isInternal(p.ip.src) and not self.isInternal(p.ip.dst):
            return True, "External traffic - skipping"
        if not self.isInternal(p.ip.src) and self.isInternal(p.ip.dst):
            return True, "Incoming traffic - skipping"
        if 'TCP' in p:
            tcpValid, reason = self.tcp_handle(p)
            if not tcpValid:
                return False, reason
        if 'UDP' in p:
            udpValid, reason = self.udp_handle(p)
            if not udpValid:
                return False, reason
        if 'ICMP' in p:
            icmpValid, reason = self.icmp_handle(p)
            if not icmpValid:
                return False, reason
        if 'HTTP' in p:
            httpValid, reason = self.http_handle(p)
            if not httpValid:
                return False, reason
        try:
            dnsValid, reason = self.dns_handle(p)  # Perform DNS validation once for all applicable packets
            if not dnsValid:
                return False, reason
        except Exception:
            pass
        return True, "Packet is valid"  # All clear

    def tcp_handle(self, p):
        if p.tcp.dstport not in ['80','443','53']:  # Only allow HTTP, HTTPS, or DNS on valid ports
            return False, f"Invalid TCP port: {p.tcp.dstport}"
        if p.tcp.dstport == '443':
            tlsValid, reason = self.validate_tls(p)
            if not tlsValid:  # Combine TLS validation and length check
                return False, reason
            elif len(p) > 1460:
                return False, "Large HTTPS packet"
        if len(p) > 1500:  # Typical MTU size for Ethernet
            return False, f"Packet size exceeds typical MTU: {len(p)}"

        if hasattr(p.tcp, 'flags'):
            flags = int(p.tcp.flags, 16)                              # Convert flags from hex to integer
            if (flags & 0x02) and (flags & 0x04):                     # SYN (0x02) and RST (0x04) flags are both set
                return False, "Invalid SYN+RST combination"
            if flags & 0x08:                                          # PSH flag is set (0x08)
                if len(p) > 1460:
                    return False, "Large TCP segment with PUSH flag"
            if flags & 0x20:                                          # URG flag is set (0x20)
                if len(p) > 1460:
                    return False, "Large TCP segment with URG flag"

        return True, ""

    def udp_handle(self, p):
        if p.udp.dstport not in ['53','123','68']:  # Only allow DNS and NTP traffic
            return False, f"Invalid UDP port: {p.udp.dstport}"
        if p.udp.dstport == '123' and len(p) != 48:
            return False, "Invalid NTP packet"  # NTP packets must have a specific length
        return True, ""

    def dns_handle(self, p):
        dns_layer = None
        try: dns_layer = p.dns
        except AttributeError: pass

        transport_layer = p.transport_layer.lower() if hasattr(p,'transport_layer') else None
        dstport = getattr(p[transport_layer], 'dstport', None)
        if dns_layer is not None:
            if dstport != '53':
                return False, "Invalid DNS response port"
            if len(p[transport_layer].payload) > 512:  # Check DNS response size
                return False, "Possible DNS tunneling"
            if not self.track_attempts(p['IP'].dst, self.dns_attempts,15,15):  # Track frequency of outgoing HTTP requests
                return False, "High frequency of DNS requests"
        elif dstport == '53':
            return False, "Invalid port for none DNS"
        elif hasattr(p,'udp') and hasattr(p.udp,'payload'):
            payload_bytes = p.udp.payload.binary_value
            payload_str = payload_bytes.decode('utf-8', errors='ignore')
            if("com" in payload_str):
                return False, "None DNS port, but DNS response!"
        elif not self.DNS_set(p['IP'].dst):  # not DNS and not DNS port, but had DNS before?
            return False, "No previous DNS set up"
        return True, ""

    def icmp_handle(self, p):
        if len(p) > 64:  # Too big for just pinging - might contain additional info
            return False, "Large ICMP packet"
        if not self.track_attempts(p['IP'].dst, self.icmp_attempts, 10, 10):  # Track frequency of outgoing ICMP requests
            return False, "High frequency of ICMP requests"
        return True, ""

    def http_handle(self, p):
        try:
            if hasattr(p['HTTP'],'file_data') and len(p['HTTP'].file_data) > 900:                      # Check if the packet has a large payload (using file_data)
                return False, "Large HTTP payload"
            if not hasattr(p['HTTP'],'host'):
                return False, "Missing Host header"
            if len(p) > 1300:                                                       # Check for unusually large headers
                return False, "Unusually large HTTP headers"
            for f in ['authorization', 'cookie', 'set_cookie', 'proxy_authorization']:                  # Check for sensitive headers
                if hasattr(p['HTTP'], f):
                    return False, f"Sensitive header: {f}"
            if hasattr(p['HTTP'], 'user_agent') and 'python-requests' in p['HTTP'].user_agent.lower():  # Check for suspicious User-Agent
                return False, f"Suspicious User-Agent: {p['HTTP'].user_agent}"
            if hasattr(p['HTTP'], 'transfer_encoding') and p['HTTP'].transfer_encoding == 'chunked':    # Check for chunked transfer encoding
                return False, "Suspicious chunked Transfer-Encoding detected"
            if hasattr(p['HTTP'], 'referer'):                                                           # Check for untrusted Referer
                referer = p['HTTP'].referer
                if not referer.startswith('https://trusted-domain.com'):
                    return False, f"Untrusted Referer: {referer}"
            if not self.track_attempts(p['IP'].dst, self.http_attempts, 60, 100):       # Track frequency of outgoing HTTP requests
                return False, "High frequency of HTTP requests"
            # p.show()
        except AttributeError as e:
            return False, f"HTTP layer access error: {e}"
        return True, "Valid HTTP packet"

    def validate_tls(self, p):
        try:
            if 'TLS' not in p:
                return False, "none/invalid TLS"

            handshake_type = p['TLS'].get_field_value('handshake.type')
            version = p['TLS'].get_field_value('record.version')
            cipher_suite = p['TLS'].get_field_value('handshake.ciphersuite')
            sni = p['TLS'].get_field_value('handshake.extensions_server_name')  # Updated field name for SNI

            if handshake_type not in ['1','2']:
                return False, "none/invalid TLS"
            if handshake_type == '1' and not sni:
                return False, f"hostname {getattr(p['TLS'],'certificate_hostname',None)} != SNI {sni}"
            if version not in ['0x0303', '0x0304']:  # TLS 1.2 (0x0303) or TLS 1.3 (0x0304)
                return False, f"invalid TLS version {version}"
            if handshake_type == '1' and cipher_suite in ['0x0000', '0x0005']:  # `0x0000` (TLS_NULL_WITH_NULL_NULL) is invalid
                return False, f"Weak cipher suite - {cipher_suite}"
            return True, "valid TLS"
        except Exception as e:
            return False, f"TLS error: {str(e)}"

    def DNS_set(self, dst_ip):
        return dst_ip in self.dns_attempts
    def track_attempts(self, dst_ip, attempts, window=10, threshold=10):
        current_time = time.time()
        if dst_ip not in attempts:
            attempts[dst_ip] = []
        # Filter out connection attempts that are outside of the time window (e.g., 10 seconds)
        attempts[dst_ip] = [t for t in attempts[dst_ip] if current_time - t < window]
        attempts[dst_ip].append(current_time)
        if len(attempts[dst_ip]) > threshold:  # If there are too many attempts in a short time frame, flag it as suspicious
            return False
        return True
