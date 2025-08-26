"""
Script: ip_extractor
Desc: Extracts IP address pairs from a pcap file and counts traffic
direction (A to B and B to A).
Author: Turaki Annan 09/12/2024
"""

from collections import defaultdict
import socket
import dpkt


def extract_ip_pairs(pcap_file_path):
    """
    Extracts and counts the packet traffic

    args: pcap_file_path (path to the pcap file)

    return: a dictionary with ip address pairs and traffic counts
    """
    ip_pairs = defaultdict(lambda: {'A_to_B': 0, 'B_to_A': 0})

    try:
        # Opening the PCAP file
        with open(pcap_file_path, "rb") as f:
            pcap = dpkt.pcap.Reader(f)

            for _, buf in pcap:
                try:
                    eth = dpkt.ethernet.Ethernet(buf)

                    # Check if the packet has an ip
                    if not isinstance(eth.data, dpkt.ip.IP):
                        continue

                    ip = eth.data
                    src = socket.inet_ntoa(ip.src)  # Source IP
                    dst = socket.inet_ntoa(ip.dst)  # Destination IP

                    if src != dst:
                        # count the traffic bothways
                        ip_pairs[(src, dst)]['A_to_B'] += 1
                        ip_pairs[(dst, src)]['B_to_A'] += 1

                except dpkt.UnpackError as error:
                    print(f"Error processing packet: {error}")
                    continue

    except FileNotFoundError as error:
        print(f"Error reading pcap file: {error}")

    return ip_pairs
