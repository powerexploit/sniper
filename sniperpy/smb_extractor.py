import os
import json
from scapy.all import rdpcap
from scapy.layers.smb2 import SMB2_Create_Request, SMB2_Create_Response, SMB2_Close_Response

class SMBExtractorError(Exception):
    """Custom exception for SMB extractor errors."""
    pass

def extract_smb_packets(pcap_file):
    """
    Extract SMB packets from a given pcap file.

    Args:
    - pcap_file (str): Path to the pcap file.

    Returns:
    - list: List of SMB packets extracted from the pcap.

    Raises:
    - SMBExtractorError: If the pcap file cannot be read.
    """
    try:
        packets = rdpcap(pcap_file)
    except FileNotFoundError:
        raise SMBExtractorError(f"File not found: {pcap_file}")
    except Exception as e:
        raise SMBExtractorError(f"Error reading pcap file: {e}")

    smb_packets = []

    for packet in packets:
        try:
            if SMB2_Create_Request in packet or SMB2_Create_Response in packet or SMB2_Close_Response in packet:
                smb_packets.append(packet)
        except Exception as e:
            print(f"Error processing packet: {e}")
            continue

    if not smb_packets:
        raise SMBExtractorError("No SMB packets found in the pcap file.")

    return smb_packets

def parse_smb_packets(smb_packets):
    """
    Parse SMB packets and extract metadata.

    Args:
    - smb_packets (list): List of SMB packets.

    Returns:
    - list: List of metadata dictionaries for each SMB packet.

    Raises:
    - SMBExtractorError: If an error occurs while parsing packets.
    """
    metadata = []

    for packet in smb_packets:
        try:
            if SMB2_Create_Request in packet:
                source_ip = packet[0][1].src
                source_port = packet[0][2].sport
                dest_ip = packet[0][1].dst
                dest_port = packet[0][2].dport

                metadata_entry = {
                    "Packet Type": "SMB2 Create Request",
                    "Source IP": source_ip,
                    "Source Port": source_port,
                    "Destination IP": dest_ip,
                    "Destination Port": dest_port
                }
                metadata.append(metadata_entry)

            elif SMB2_Create_Response in packet:
                source_ip = packet[0][1].src
                source_port = packet[0][2].sport
                dest_ip = packet[0][1].dst
                dest_port = packet[0][2].dport

                metadata_entry = {
                    "Packet Type": "SMB2 Create Response",
                    "Source IP": source_ip,
                    "Source Port": source_port,
                    "Destination IP": dest_ip,
                    "Destination Port": dest_port
                }
                metadata.append(metadata_entry)

            elif SMB2_Close_Response in packet:
                source_ip = packet[0][1].src
                source_port = packet[0][2].sport
                dest_ip = packet[0][1].dst
                dest_port = packet[0][2].dport

                metadata_entry = {
                    "Packet Type": "SMB2 Close Response",
                    "Source IP": source_ip,
                    "Source Port": source_port,
                    "Destination IP": dest_ip,
                    "Destination Port": dest_port
                }
                metadata.append(metadata_entry)

        except Exception as e:
            print(f"Error parsing packet: {e}")
            continue

    if not metadata:
        raise SMBExtractorError("No SMB metadata could be extracted.")

    return metadata

def save_extracted_files(metadata, output_dir="extracted_files"):
    """
    Save extracted metadata as a JSON file.

    Args:
    - metadata (list): List of metadata dictionaries.
    - output_dir (str): Output directory path.

    Raises:
    - SMBExtractorError: If an error occurs while saving metadata.
    """
    try:
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        metadata_path = os.path.join(output_dir, 'metadata.json')
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=4)
    except Exception as e:
        raise SMBExtractorError(f"Error saving metadata: {e}")
