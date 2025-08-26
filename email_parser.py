"""
Script: email_parser
    Desc: extracts email addresses and identifies the "From" and "To" feilds
    from packet payloads. Also, extracting image URLs and filenames
    Author: Turaki Annan 09/12/2024
"""

import re  # Used for patern matching
from typing import Dict, List  # used to define types


# extracts the email address from payloads
def extract_emails(packet_details: Dict[str,
                                        List[Dict]]) -> Dict[str, List[str]]:
    """
    Extract "from" and "to" email addresses from the payloads p
    ackets using regex

    args: packet_details dictionary for containing packets by type

    return: dictioanry with the to and from keys containing the email addresses
    """

    # Pattern matching to find the email address and the if its from or to
    email_pattern = r"[\w\._-]+@[\w\._-]+\.[a-zA-Z]+"  # regex email matching
    from_pattern = r"From:\s*(" + email_pattern + ")"
    to_pattern = r"To:\s*(" + email_pattern + ")"

    emails = {'to': set(), 'from': set()}  # Store unqiue emails

    # Checks the packet payloads
    for packets in packet_details.values():
        for packet in packets:
            payload = packet.get('payload', '')
            if payload:
                # Extracts email addresses from payload
                emails['to'].update(re.findall(
                    to_pattern, payload, re.IGNORECASE))
                emails['from'].update(re.findall(
                    from_pattern, payload, re.IGNORECASE))

    return {key: list(value) for key, value in emails.items()}


def extract_image_urls(packet_details:
                       Dict[str, List[Dict]]) -> Dict[str, List[str]]:
    """
    Extract the image URLs and filename from payload

    args: packet details dictionary containing packets by type

    returns: dictionary with urls and files names
    """

    # regex pattern matching
    image_pattern = r"(https?://[^\s]+?\.(?:jpg|jpeg|png|gif))"
    extracted_data = {'urls': set(), 'file_names': set()}

    for packets in packet_details.values():
        for packet in packets:
            payload = packet.get('payload', '')
            if payload:
                # Extract image URLs and filenames
                urls = re.findall(image_pattern, payload, re.IGNORECASE)
                extracted_data['urls'].update(urls)
                extracted_data['file_names'].update(
                    url.split('/')[-1] for url in urls)

    return {key: list(value) for key, value in extracted_data.items()}

# Print the extracted results


def print_extraction_results(emails: Dict[str, List[str]],
                             images: Dict[str, List[str]]):
    """
    Does the printing for the earlier functions

    args: takes in the dictionaries to then print "to" and "from" and
    images "urls" and file names
    """
    print("\nExtracted Email Addresses:")
    print("To:", *emails['to'], sep="\n  - ")
    print("From:", *emails['from'], sep="\n  - ")

    print("\nExtracted Image URLs:", *images['urls'], sep="\n  - ")
    print("\nExtracted Image Filenames:", *images['file_names'], sep="\n  - ")
