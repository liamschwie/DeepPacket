from collections import deque
from scapy.all import PcapReader, IP, TCP, UDP, sniff
from tqdm import tqdm
import pandas as pd
import numpy as np
import os
import argparse
import logging
import time

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def main(pcap_filename=None, output_csv="network_features.csv", live_mode=False, batch_size=5000):
    traffic_stats = {}  # Persistent across batches
    
    if live_mode:
        logging.info("Running in live capture mode (requires root privileges)...")
        packets = sniff(timeout=60, store=True)
        process_packets(packets, output_csv, batch_size, traffic_stats)
    elif pcap_filename:
        file_size = os.path.getsize(pcap_filename)
        logging.info(f"Processing PCAP file: {pcap_filename} ({file_size / (1024**2):.2f} MB)")
        
        with PcapReader(pcap_filename) as pcap_reader:
            with tqdm(total=file_size, unit='B', unit_scale=True, desc="Extracting") as pbar:
                packets = []
                for packet in pcap_reader:
                    pbar.update(len(packet))
                    packets.append(packet)
                    if len(packets) >= batch_size:
                        process_packets(packets, output_csv, batch_size, traffic_stats)
                        packets = []
                if packets:
                    process_packets(packets, output_csv, batch_size, traffic_stats)
    else:
        logging.error("Must provide pcap_filename or use --live mode")
        return

def process_packets(packets, output_csv, batch_size, traffic_stats):
    batch_data = []
    
    for packet in packets:
        if not packet.haslayer(IP):
            continue
        
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        packet_size = len(packet)
        
        if packet.haslayer(TCP):
            proto = 'TCP'
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            tcp_flags = packet[TCP].flags
            payload_len = len(packet[TCP].payload)
        elif packet.haslayer(UDP):
            proto = 'UDP'
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            tcp_flags = None
            payload_len = len(packet[UDP].payload)
        else:
            continue
        
        # Create normalized bidirectional flow key
        flow_tuple = tuple(sorted([(src_ip, sport), (dst_ip, dport)]))
        flow_key = f"{flow_tuple[0][0]}:{flow_tuple[0][1]} <-> {flow_tuple[1][0]}:{flow_tuple[1][1]} ({proto})"
        
        # Determine flow direction
        is_forward = (src_ip, sport) == flow_tuple[0]
        
        current_time = float(packet.time)
        
        # Initialize flow tracking
        if flow_key not in traffic_stats:
            traffic_stats[flow_key] = {
                'times': deque(),
                'packet_sizes': deque(),
                'forward_packets': 0,
                'reverse_packets': 0,
                'forward_bytes': 0,
                'reverse_bytes': 0,
                'syn_count': 0,
                'rst_count': 0,
                'fin_count': 0,
                'unique_dst_ports': set(),
                'last_seen': current_time
            }
        
        flow = traffic_stats[flow_key]
        
        # Update flow statistics
        flow['times'].append(current_time)
        flow['packet_sizes'].append(packet_size)
        flow['last_seen'] = current_time
        flow['unique_dst_ports'].add(dport)
        
        # Remove old entries outside 2-second window
        while flow['times'] and flow['times'][0] < current_time - 2.0:
            flow['times'].popleft()
            flow['packet_sizes'].popleft()
        
        # Update directional counters
        if is_forward:
            flow['forward_packets'] += 1
            flow['forward_bytes'] += packet_size
        else:
            flow['reverse_packets'] += 1
            flow['reverse_bytes'] += packet_size
        
        # Track TCP flags
        if proto == 'TCP' and tcp_flags:
            if tcp_flags & 0x02:  # SYN
                flow['syn_count'] += 1
            if tcp_flags & 0x04:  # RST
                flow['rst_count'] += 1
            if tcp_flags & 0x01:  # FIN
                flow['fin_count'] += 1
        
        # Calculate features
        pps = len(flow['times'])
        
        if pps > 1:
            iat = flow['times'][-1] - flow['times'][-2]
        else:
            iat = 0.0
        
        # Calculate advanced features
        forward_reverse_ratio = flow['forward_packets'] / max(flow['reverse_packets'], 1)
        byte_ratio = flow['forward_bytes'] / max(flow['reverse_bytes'], 1)
        
        # Packet size variance (anomaly indicator)
        if len(flow['packet_sizes']) > 1:
            packet_size_variance = np.var(list(flow['packet_sizes']))
        else:
            packet_size_variance = 0.0
        
        # Port scan indicator
        port_scan_indicator = 1 if len(flow['unique_dst_ports']) > 10 else 0
        
        batch_data.append({
            "flow_key": flow_key,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": sport,
            "dst_port": dport,
            "proto": proto,
            "flags": str(tcp_flags) if tcp_flags else 'N/A',
            "pps": pps,
            "iat": iat,
            "payload_len": payload_len,
            "packet_size": packet_size,
            "forward_packets": flow['forward_packets'],
            "reverse_packets": flow['reverse_packets'],
            "forward_bytes": flow['forward_bytes'],
            "reverse_bytes": flow['reverse_bytes'],
            "forward_reverse_ratio": forward_reverse_ratio,
            "byte_ratio": byte_ratio,
            "syn_count": flow['syn_count'],
            "rst_count": flow['rst_count'],
            "fin_count": flow['fin_count'],
            "packet_size_variance": packet_size_variance,
            "port_scan_indicator": port_scan_indicator,
            "unique_dst_ports": len(flow['unique_dst_ports'])
        })
    
    # Cleanup stale flows (not seen in last 5 minutes)
    if packets:
        current_max_time = max((float(pkt.time) for pkt in packets if hasattr(pkt, 'time')), default=0)
        stale_flows = [k for k, v in traffic_stats.items() 
                       if current_max_time - v['last_seen'] > 300]
        for flow in stale_flows:
            del traffic_stats[flow]
        
        if stale_flows:
            logging.info(f"Cleaned up {len(stale_flows)} stale flows")
    
    # Write batch to CSV
    if batch_data:
        df = pd.DataFrame(batch_data)
        header = not os.path.exists(output_csv)
        df.to_csv(output_csv, mode='a', header=header, index=False)
        logging.info(f"Wrote {len(batch_data)} rows to {output_csv}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Extract network features from PCAP")
    parser.add_argument("pcap_filename", type=str, nargs='?', help="Path to PCAP file")
    parser.add_argument("--output", type=str, default="network_features.csv", help="Output CSV file")
    parser.add_argument("--live", action="store_true", help="Run in live capture mode")
    parser.add_argument("--batch_size", type=int, default=5000, help="Batch size for processing")
    args = parser.parse_args()
    
    try:
        main(args.pcap_filename, args.output, args.live, args.batch_size)
    except KeyboardInterrupt:
        logging.info("Stopped by user.")
    except Exception as e:
        logging.error(f"Error: {e}", exc_info=True)
    
    logging.info("Done!")
