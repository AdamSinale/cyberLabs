import queue

class Analyzer:
    def __init__(self):
        self.valid_flows = []
        self.invalid_flows = []

    def validate(self, sniffer):
        self.valid_flows = []
        self.invalid_flows = []
        while sniffer.sniffing or not sniffer.buffer.empty():
            try:
                p = sniffer.buffer.get(timeout=1)  # Get packet from queue with a timeout
                if 'IP' in p:  # Check if packet has an IP layer
                    flow_key = (p.ip.src,p.ip.dst,p[p.transport_layer].srcport,p[p.transport_layer].dstport,p.transport_layer)
                    isValid, reason = self.isValid(p)
                    if isValid:
                        self.valid_flows.append(flow_key)
                    else:
                        self.invalid_flows.append((flow_key, reason))
                else:
                    # Handle non-IP packets if needed
                    pass
            except queue.Empty:
                if not sniffer.sniffing:
                    break  # Stop if sniffing has ended and the queue is empty
        return self.valid_flows, self.invalid_flows

    def isValid(self, p):
        if p.transport_layer == 'TCP':                           # TCP Tests
            if p.tcp.flags_syn and not p.tcp.flags_ack:          #     syn but not ack
                return False, "Suspicious SYN flood detected"

        elif p.transport_layer == 'UDP':                         # UDP Tests
            if int(p.length) > 512:                              #     big packet for UDP
                return False, "Large UDP packet detected"

        elif p.transport_layer == 'ICMP':                        # ICMP Tests
            if int(p.length) > 64:                               #     big packet for ping
                return False, "Suspicious ICMP packet size"

        elif p.transport_layer == 'DNS':                         # DNS Tests
            if int(p.dns.length) > 512:                          #     big packet for DNS request
                return False, "Large DNS request detected"

        return True, "Packet is valid"                           # all clear

    def simulate_leak_attack(self, packet):
        pass  # Add attack manipulation code here
