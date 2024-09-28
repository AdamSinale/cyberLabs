import pyshark
import queue
import asyncio

class Sniffer:
    def __init__(self):
        self.sniffing = False
        self.buffer = queue.Queue()

    def sniff_packets(self, interface='Wi-Fi'):
        self.sniffing = True
        print(f"Sniffing on interface {interface}...")
        loop = asyncio.new_event_loop()                          # Create a new event loop
        asyncio.set_event_loop(loop)
        self.capture = pyshark.LiveCapture(interface=interface)  # Create the pyshark capture
        try:
            for packet in self.capture.sniff_continuously():
                if not self.sniffing:
                    break                                        # Stop sniffing when flag off
                self.buffer.put(packet)
        finally:
            # Ensure all pending packets are processed and the capture is closed
            loop.run_until_complete(self.capture.close_async())  # Properly await the close_async method
            loop.close()  # add packet to buffer
