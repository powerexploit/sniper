import os
import sys
import json
from scapy.all import rdpcap
from scapy.layers.smb2 import SMB2_Create_Request, SMB2_Create_Response, SMB2_Close_Response

def extract_smb_packets(pcap_file):
    """
    Extract SMB packets from a given pcap file.

    Args:
    - pcap_file (str): Path to the pcap file.

    Returns:
    - list: List of SMB packets extracted from the pcap.
    """
    packets = rdpcap(pcap_file)
    smb_packets = []

    for packet in packets:
        if SMB2_Create_Request in packet or SMB2_Create_Response in packet or SMB2_Close_Response in packet:
            smb_packets.append(packet)

    return smb_packets

def parse_smb_packets(smb_packets):
    """
    Parse SMB packets and extract metadata.

    Args:
    - smb_packets (list): List of SMB packets.

    Returns:
    - list: List of metadata dictionaries for each SMB packet.
    """
    metadata = []

    for packet in smb_packets:
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

    return metadata

def save_extracted_files(metadata, output_dir):
    """
    Save extracted metadata as a JSON file.

    Args:
    - metadata (list): List of metadata dictionaries.
    - output_dir (str): Output directory path.
    """
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    metadata_path = os.path.join(output_dir, 'metadata.json')
    with open(metadata_path, 'w') as f:
        json.dump(metadata, f, indent=4)

def main():
    """
    Main function to extract SMB packets from a pcap file, parse them,
    extract metadata, and save the metadata as a JSON file.
    """
    if len(sys.argv) != 2:
        print("Usage: python smb_extractor.py <pcap_file>")
        sys.exit(1)

    pcap_file = sys.argv[1]
    output_dir = "extracted_files"

    smb_packets = extract_smb_packets(pcap_file)
    if not smb_packets:
        print("No SMB packets found in the pcap file.")
        sys.exit(1)

    metadata = parse_smb_packets(smb_packets)
    save_extracted_files(metadata, output_dir)

    print(f"Extracted files saved to {output_dir}")
    print(f"Metadata saved to {output_dir}/metadata.json")

if __name__ == "__main__":
    main()
