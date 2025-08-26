"""
Script: main
Desc: Combines scripts to analyse a PCAP file.
      Finds packet details like type, emails, and IP pair counts,
      and creates a geolocation KML file.
Author: Turaki Annan 09/12/2024
"""

import os  # Used for the output file location

# Importing required functions
from pcap_processor import get_pcap, write_to_file
from email_parser import (extract_emails, extract_image_urls,
                          print_extraction_results)
from ip_extractor import extract_ip_pairs
from ip_to_kml import create_kml  # Import KML generation function

if __name__ == "__main__":
    # Set up file paths
    # Define base directory and filenames
    # pylint: disable=invalid-name
    base_dir = "C:\\Users\\Person 1\\Desktop\\course_work"
    pcap_file = "evidence-packet-analysis.pcap"
    geoip_db = "GeoLite2-City.mmdb"

    # Create full file paths
    pcap_file_path = os.path.join(base_dir, pcap_file)
    geoip_db_path = os.path.join(base_dir, geoip_db)
    output_file = os.path.join(base_dir, "packet_details.txt")

    # Process the pcap file and write details to output file
    packet_details = get_pcap(pcap_file_path)
    write_to_file(packet_details, output_file)

    # Extract email addresses and image URLs from packet payloads
    emails = extract_emails(packet_details)
    images = extract_image_urls(packet_details)

    # Extract IP pairs and their counts
    ip_pairs = extract_ip_pairs(pcap_file_path)

    # Sort IP pairs based on highest counts
    sorted_ip_pairs = sorted(
        ip_pairs.items(), key=lambda x: x[1]
        ['A_to_B'] + x[1]['B_to_A'], reverse=True
    )

    # Print sorted IP pairs in a table format
    print(f"{'Src IP':<15} {'Dest IP':<15} {
          'Packets A to B':<15} {'Packets B to A':<15}")
    print("----------------------------")
    for (src, dst), counts in sorted_ip_pairs:
        print(f"{src:<15} {dst:<15} {
              counts['A_to_B']:<15} {counts['B_to_A']:<15}")

    # Print email and image extraction results
    print_extraction_results(emails, images)

    # Create a KML file with geolocation information
    create_kml(ip_pairs, geoip_db_path=geoip_db_path,
               output_file=os.path.join(base_dir, geoip_db))
