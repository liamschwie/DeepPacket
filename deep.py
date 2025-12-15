from collections import deque
from scapy.all import PcapReader, IP, TCP, UDP, sniff
from tqdm import tqdm
import pandas as pd
import os
import argparse
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def main(pcap_filename, output_csv="network_features.csv", live_mode=False, batch_size=5000):
    if live_mode:
        logging.info("Running in live capture mode (requires root privileges)...")
        packets = sniff(timeout=60)  # Example: capture for 60s; adjust as needed
        process_packets(packets, output_csv, batch_size)
    else:
        file_size = os.path.getsize(pcap_filename)
        logging.info(f"Processing PCAP file: {pcap_filename} ({file_size / (1024**2):.2f} MB)")
        
        with PcapReader(pcap_filename) as pcap_reader:
            with tqdm(total=file_size, unit='B', unit_scale=True, desc="Extracting") as pbar:
                packets = []
                for packet in pcap_reader:
                    pbar.update(len(packet))
                    packets.append(packet)
                    if len(packets) >= batch_size:  # Process in batches to save memory
                        process_packets(packets, output_csv, batch_size)
                        packets = []
                if packets:
                    process_packets(packets, output_csv, batch_size)

def process_packets(packets, output_csv, batch_size):
    traffic_stats = {}  # { 'flow_key': deque([time1, time2...]) } for windowed stats
    batch_data = []
    
    for packet in packets:
        if not packet.haslayer(IP):
            continue
        
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst  # Added for better flow tracking
        
        if packet.haslayer(TCP):
            proto = 'TCP'
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            flags = str(packet[TCP].flags)
            payload_len = len(packet[TCP].payload)
        elif packet.haslayer(UDP):
            proto = 'UDP'
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            flags = 'N/A'  # UDP has no flags
            payload_len = len(packet[UDP].payload)
        else:
            continue
        
        # Define flow key for granularity (src, dst, ports, proto)
        flow_key = f"{src_ip}:{sport} -> {dst_ip}:{dport} ({proto})"
        
        current_time = float(packet.time)
        
        if flow_key not in traffic_stats:
            traffic_stats[flow_key] = deque()
        
        # Add current time and remove old ones (efficient O(1) pops)
        traffic_stats[flow_key].append(current_time)
        while traffic_stats[flow_key] and traffic_stats[flow_key][0] < current_time - 2.0:
            traffic_stats[flow_key].popleft()
        
        pps = len(traffic_stats[flow_key])
        
        if pps > 1:
            iat = traffic_stats[flow_key][-1] - traffic_stats[flow_key][-2]
        else:
            iat = 0.0
        
        # TODO: Add more features, e.g., syn_count = sum(1 for t in window if flag_check)
        
        batch_data.append({
            "flow_key": flow_key,
            "src_ip": src_ip,
            "dst_ip": dst_ip,  # Added
            "src_port": sport,  # Added
            "dst_port": dport,
            "proto": proto,     # Added
            "flags": flags,
            "pps": pps,
            "iat": iat,
            "payload_len": payload_len
        })
    
    # Write batch if ready (moved outside loop for batch processing)
    if batch_data:
        df = pd.DataFrame(batch_data)
        header = not os.path.exists(output_csv)
        df.to_csv(output_csv, mode='a', header=header, index=False)
        logging.info(f"Wrote {len(batch_data)} rows to {output_csv}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Extract network features from PCAP")
    parser.add_argument("pcap_filename", type=str, help="Path to PCAP file")
    parser.add_argument("--output", type=str, default="network_features.csv", help="Output CSV file")
    parser.add_argument("--live", action="store_true", help="Run in live capture mode")
    parser.add_argument("--batch_size", type=int, default=5000, help="Batch size for CSV writes")
    args = parser.parse_args()
    
    try:
        main(args.pcap_filename, args.output, args.live, args.batch_size)
    except KeyboardInterrupt:
        logging.info("Stopped by user.")
    except Exception as e:
        logging.error(f"Error: {e}")
    logging.info("Done!")
