"""
Script: pcap_processor
Desc: Processes and then summarises it by type then putting into output_file
Author: Turaki Annan 09/12/2024
"""

import socket
import dpkt


def get_pcap(pcap_file_path):
    """
    sorts a pcaps packets by type e.g TCP and UDP
    Args: pcap_file_path the path to the pcap
    Returns: a summary of the packets by type mean length,timestamp and count
    """
    print(f"Opening PCAP file: {pcap_file_path}")
    packet_details = {'TCP': [], 'UDP': [], 'IGMP': [], 'Other': []}

    try:
        with open(pcap_file_path, "rb") as f:
            pcap = dpkt.pcap.Reader(f)

            for timestamp, buf in pcap:
                try:
                    eth = dpkt.ethernet.Ethernet(buf)
                    # skipping non ip packets
                    if not isinstance(eth.data, dpkt.ip.IP):
                        packet_details['Other'].append({
                            'timestamp': timestamp,
                            'packet_length': len(buf)
                        })
                        continue

                    ip = eth.data
                    src = socket.inet_ntoa(ip.src)
                    dst = socket.inet_ntoa(ip.dst)
                    payload = ""
                    packet_type = 'Other'

                    # Identify packet type and extract payload
                    if isinstance(ip.data, dpkt.tcp.TCP):
                        packet_type = 'TCP'
                        payload = ip.data.data.decode('utf-8', errors='ignore')
                    elif isinstance(ip.data, dpkt.udp.UDP):
                        packet_type = 'UDP'
                        payload = ip.data.data.decode('utf-8', errors='ignore')
                    elif isinstance(ip.data, dpkt.igmp.IGMP):
                        packet_type = 'IGMP'

                    # Add packet details
                    packet_details[packet_type].append({
                        'timestamp': timestamp,
                        'src': src,
                        'dst': dst,
                        'packet_length': len(buf),
                        'payload': payload
                    })
                except dpkt.dpkt.UnpackError:
                    print("Error processing packet")
                    continue

        print("PCAP file processed successfully.")
    except FileNotFoundError:
        print(f"File not found: {pcap_file_path}")

    return packet_details


def write_to_file(packet_details, output_file):
    """
    Writes to file of the packet details in a table

    Args: takes in the packet detail and the path to oupt_file
    """
    try:
        with open(output_file, 'w', encoding='utf-8') as f:

            # HEADER OF TABLE
            f.write("Packet Summary:\n")

            # THE SIDE PARTS OF THE TABLE
            f.write(f"{'Type':<10} | {'Count':<5} |"
                    f" {'Mean Length (bytes)':<20} |"
                    f"{'First Timestamp':<20} | {'Last Timestamp':<20}\n")

            # DIVIDER BETWEEN HEADER AND DATA
            f.write("-" * 80 + "\n")

            # Write summary for each packet type
            for packet_type, packets in packet_details.items():
                count = len(packets)
                if count > 0:
                    first_timestamp = packets[0]['timestamp']
                    last_timestamp = packets[-1]['timestamp']
                    mean_length = sum(p['packet_length']
                                      for p in packets) / count
                    f.write(f"{packet_type:<10} | {count:<5} | "
                            f"{mean_length:<20.2f} | "
                            f"{first_timestamp:<20.2f} | "
                            f"{last_timestamp:<20.2f}\n")
                else:
                    f.write(f"{packet_type:<10} | {count:<5} | {'N/A':<20} | "
                            f"{'N/A':<20} | {'N/A':<20}\n")

        print(f"Results written to: {output_file}")
    except FileNotFoundError:
        print(f"Output file not found: {output_file}")
