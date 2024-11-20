# sudo ip link set dev eth0 mtu 3000 (for large packets)

import tkinter as tk
from sniffer import *
from analyzer import *
import threading
import time
import subprocess
import os
from scapy.all import rdpcap, sendp
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.gridspec as gridspec

class App:
    def __init__(self, root):
        self.sniffer = Sniffer()                                                 # Sniffer
        self.analyzer = Analyzer()                                               # Analyzer

        self.root = root                                                         # Create UI
        self.root.title("Network Traffic Analyzer")
        self.sniffBtn = tk.Button(root, text="Start Sniffing", command=self.mode)  # UI - Run sniffer
        self.sniffBtn.pack(pady=10)
        self.statusLbl = tk.Label(root, text="Status: Idle", fg="green")         # UI - text
        self.statusLbl.pack(pady=20)
        self.replayBtn = tk.Button(root, text="Run Simulation", command=self.run_simulation)  # UI - Run attack simulation
        self.replayBtn.pack(pady=10)

        self.interface = 'Wi-Fi' if os.name == 'nt' else 'eth0'  # Default interface
        self.pcap_file = os.path.join(os.path.dirname(__file__), "attack_simulation.pcap")

        self.graph_frame = tk.Frame(root)
        self.graph_frame.pack(fill=tk.BOTH, expand=True)

        self.fig = plt.Figure(figsize=(10, 5))
        self.gs = gridspec.GridSpec(1, 2, figure=self.fig)
        self.ax = self.fig.add_subplot(self.gs[0, 0])
        self.ax2 = self.fig.add_subplot(self.gs[0, 1])

        self.canvas = FigureCanvasTkAgg(self.fig, master=self.graph_frame)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

    def mode(self):
        if not self.sniffer.sniffing:
            self.start_sniffing()  # Start sniffing
        else:
            self.stop_sniffing()  # Stop sniffing

    def start_sniffing(self):
        self.sniffer.sniffing = True
        self.sniffBtn.config(text="Stop Sniffing")  # Change button
        self.statusLbl.config(text="Status: Sniffing...", fg="red")

        self.sniff_thread = threading.Thread(target=self.sniffer.sniff_packets, args=(self.interface,))  # create a thread for sniffing
        self.sniff_thread.start()
        self.analysis_thread = threading.Thread(target=self.analyzer.validate, args=(self.sniffer,))  # new thread for analyzing sniffed packets
        self.analysis_thread.start()
        self.update_graph()  # Start updating the graph in real time

    def stop_sniffing(self):
        self.sniffer.sniffing = False  # stop sniffing
        self.statusLbl.config(text="Status: Stopped", fg="green")  # Change button
        self.sniffBtn.config(text="Start Sniffing")

        if threading.current_thread() != self.sniff_thread:
            print("Sniffer stopped sniffing")
            self.sniff_thread.join()
        if threading.current_thread() != self.analysis_thread:
            print("Analyzer stopped analyzing")
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

    def update_graph(self):
        if self.sniffer.sniffing:
            self.show_analysis_graph(real_time=True)
            self.show_cumulative_packet_graph(real_time=True)
            self.root.after(1000, self.update_graph)  # Update every second

    def show_analysis_graph(self, real_time=False):
        protocols = set()
        for flow in self.analyzer.flows:
            protocols.add(flow[0][3])
        protocols = list(protocols)
        total_counts = {protocol: 0 for protocol in protocols}
        valid_counts = {protocol: 0 for protocol in protocols}
        invalid_counts = {protocol: 0 for protocol in protocols}
        for flow in self.analyzer.flows:
            total_counts[flow[0][3]] += 1
            if flow[1]: valid_counts[flow[0][3]] += 1
            else: invalid_counts[flow[0][3]] += 1


        self.ax.clear()
        x = range(len(protocols))
        self.ax.bar(x, [total_counts[protocol] for protocol in protocols], width=0.2, color='b', align='center', label='Total Packets')
        self.ax.bar([i + 0.2 for i in x], [invalid_counts[protocol] for protocol in protocols], width=0.2, color='r', align='center', label='Invalid Packets')
        self.ax.bar([i + 0.4 for i in x], [valid_counts[protocol] for protocol in protocols], width=0.2, color='g', align='center', label='Valid Packets')

        self.ax.set_xlabel('Protocols')
        self.ax.set_ylabel('Number of Packets')
        self.ax.set_title('Packet Analysis by Protocol')
        self.ax.set_xticks([i + 0.2 for i in x])
        self.ax.set_xticklabels(protocols)
        self.ax.legend()

        if real_time:
            self.canvas.draw()

    def show_cumulative_packet_graph(self, real_time=False):
        valid_x = [0]
        valid_y = [0]
        invalid_x = [0]
        invalid_y = [0]

        valid_count = 0
        invalid_count = 0
        total_packets = len(self.analyzer.flows)

        for i in range(total_packets):
            if self.analyzer.flows[i][1]:
                valid_count += 1
                valid_y.append(valid_count)
                invalid_y.append(invalid_count)
            else:
                invalid_count += 1
                invalid_y.append(invalid_count)
                valid_y.append(valid_count)
            invalid_x.append(i + 1)
            valid_x.append(i + 1)

        self.ax2.clear()
        self.ax2.step(valid_x, valid_y, color='g', where='post', label='Cumulative Valid Packets')
        self.ax2.step(invalid_x, invalid_y, color='r', where='post', label='Cumulative Invalid Packets')
        self.ax2.set_xlabel('Packet Number')
        self.ax2.set_ylabel('Cumulative Count')
        self.ax2.set_title('Cumulative Number of Packets')
        self.ax2.legend()

        if real_time:
            self.canvas.draw()

root = tk.Tk()
app = App(root)
root.mainloop()