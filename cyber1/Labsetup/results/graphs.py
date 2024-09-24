import pandas as pd
import matplotlib.pyplot as plt


def readFile(file_path):
    packetTimes = []
    with open(file_path, 'r') as f:
        for line in f:
            try:
                packetTime = line.split("Time: ")[-1].split(" ")[0]
                # packetTime = line.split("time=")[-1].split(" ")[0]
                packetTimes.append(float(packetTime))
            except ValueError:
                print("End of file")
    return packetTimes

file_path = "syns_results_c.txt"
# file_path = "pings_results_c.txt"
# file_path = "syns_results_p.txt"
# file_path = "pings_results_p.txt"

if file_path == "syns_results_c.txt":
    pngName = "Syn_pkts_c.png"
    title = "Packet's Times"
    xLabel = "Time (seconds)"
    yLabel = "Packet Number"
elif file_path == "syns_results_p.txt":
    pngName = "Syn_pkts_p.png"
    title = "Packet's Times"
    xLabel = "Time (seconds)"
    yLabel = "Packet Number"
elif file_path == "pings_results_c.txt":
    pngName = "Pings_c.png"
    title = "Ping's RTT"
    xLabel = "RTT (ms)"
    yLabel = "Ping Number"
else:
    pngName = "Pings_p.png"
    title = "Ping's RTT"
    xLabel = "RTT (ms)"
    yLabel = "Ping Number"

times = readFile(file_path)                  # Get times array
# plt.figure(figsize=(20,15))
plt.scatter(times, range(1,len(times)+1), s=1)   # scatter on graph
# plt.xticks(range(1,len(times)+1))
plt.title(title)     # title
plt.xlabel(xLabel)                  # x name
plt.ylabel(yLabel)                 # y name
plt.savefig(pngName)
plt.show()
