import tkinter as tk
from sniffer import *
from analyzer import *
import threading
import time
import subprocess
import os
from scapy.all import rdpcap, sendp

class App:
    def __init__(self, root):
        self.sniffer = Sniffer()                                                 # Sniffer
        self.analyzer = Analyzer()                                               # Analyzer

        self.root = root                                                         # Create UI
        self.root.title("Network Traffic Analyzer")
        self.sniffBtn = tk.Button(root,text="Start Sniffing",command=self.mode)  # UI - Run sniffer
        self.sniffBtn.pack(pady=10)
        self.statusLbl = tk.Label(root, text="Status: Idle", fg="green")         # UI - text
        self.statusLbl.pack(pady=20)
        self.replayBtn = tk.Button(root, text="Run Simulation",command=self.run_simulation)  # UI - Run attack simulation
        self.replayBtn.pack(pady=10)

        self.interface = 'Wi-Fi' if os.name=='nt' else 'eth0'                              # Default interface
        self.pcap_file = os.path.join(os.path.dirname(__file__), "attack_simulation.pcap")

    def mode(self):
        if not self.sniffer.sniffing:
            self.start_sniffing()                                                # Start sniffing
        else:
            self.stop_sniffing()                                                 # Stop sniffing

    def start_sniffing(self):
        self.sniffer.sniffing = True
        self.sniffBtn.config(text="Stop Sniffing")                               # Change button
        self.statusLbl.config(text="Status: Sniffing...", fg="red")

        self.sniff_thread = threading.Thread(target=self.sniffer.sniff_packets, args=(self.interface,))  # create a thread for sniffing
        self.sniff_thread.start()
        self.analysis_thread = threading.Thread(target=self.analyzer.validate, args=(self.sniffer,))     # new thread for analyzing sniffed packets
        self.analysis_thread.start()

    def stop_sniffing(self):
        self.sniffer.sniffing = False                                            # stop sniffing
        self.statusLbl.config(text="Status: Stopped", fg="green")                # Change button
        self.sniffBtn.config(text="Start Sniffing")

        if threading.current_thread() != self.sniff_thread:
            self.sniff_thread.join()
        if threading.current_thread() != self.analysis_thread:
            self.analysis_thread.join()

    def run_simulation(self):
        self.statusLbl.config(text="Status: Running Simulation...", fg="blue")
        try:
            print(f"Replaying attack simulation from {self.pcap_file}...")
            subprocess.run(["sudo", "tcpreplay", "-i", self.interface, self.pcap_file], check=True)
            print("Replay complete.")
        except subprocess.CalledProcessError as e:
            print(f"Error while replaying pcap file: {e}")
        finally:
            self.statusLbl.config(text="Status: Idle", fg="green")

root = tk.Tk()
app = App(root)
root.mainloop()
