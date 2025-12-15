from scapy.all import PcapReader, IP, TCP, Ether, conf
from bs4 import BeautifulSoup
from tqdm import tqdm
import pandas as pd
import os

file_size = os.path.getsize("Thursday_WorkingHours.pcap")

traffic_stats = {}  # Format: { '192.168.1.5': [time1, time2, time3...] }
batch_data = []     # Store rows here before writing to CSV

print(f"Processing {pcap_file}...")

try:
    with PcapReader("Thursday_WorkingHours.pcap") as pcap_file:
        with tqdm(total=file_size, unit='B', unit_scale=True, desc="Extracting") as pbar:
            for packet in pcap_file:
                pbar.update(len(packet))
                
                if not packet.haslayer(IP) or not packet.haslayer(TCP):
                    continue

                src_ip = packet[IP].src
                dst_port = packet[TCP].dport
                tcp_flags = packet[TCP].flags
                current_time = float(packet.time)

                if src_ip not in traffic_stats:
                    traffic_stats[src_ip] = []

                traffic_stats[src_ip].append(current_time)
                traffic_stats[src_ip] = [t for t in traffic_stats[src_ip] if current_time - t <= 2.0]
                
                pps = len(traffic_stats[src_ip])
                
                if len(traffic_stats[src_ip]) > 1:
                    iat = traffic_stats[src_ip][-1] - traffic_stats[src_ip][-2]
                else:
                    iat = 0.0

                batch_data.append({
                    "src_ip": src_ip,
                    "dst_port": dst_port,
                    "flags": str(tcp_flags),
                    "pps": pps,
                    "iat": iat,
                    "payload_len": len(packet[TCP].payload)
                })

                if len(batch_data) >= 5000:
                    df = pd.DataFrame(batch_data)
                    df.to_csv("network_features.csv", mode='a', header=not os.path.exists("network_features.csv"), index=False)
                    batch_data = []

except KeyboardInterrupt:
    print("\nStopping...")

print("Done!")
