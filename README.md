# Sniperpy: SMB2 Packet Analyzer
`sniperpy` is a Python package designed to extract and analyze SMB2 packets from PCAP files. It helps security engineers quickly retrieve relevant SMB2 data like Create and Close requests/responses from packet captures.

# Features
- Extract SMB2 Create and Close requests/responses from PCAP files.
- Parse and analyze metadata (source/destination IPs, ports).
- Save extracted metadata as a JSON file.

# Installation
You can install `sniperpy` using `pip`:
```
pip install sniperpy
```

# Usage
After installing the package, you can import it and use the functions provided to work with SMB2 packets in your PCAP files.

### Example Code
```
from sniperpy import extract_smb_packets, parse_smb_packets, save_extracted_files, SMBExtractorError

# Specify the path to your pcap file
pcap_file = "path_to_your_pcap_file.pcap"

try:
    # Extract SMB packets from the PCAP
    smb_packets = extract_smb_packets(pcap_file)

    # Parse SMB packet metadata
    metadata = parse_smb_packets(smb_packets)

    # Optionally, save the metadata to a JSON file
    save_extracted_files(metadata, output_dir="output_directory")

    # Print metadata to the console
    for entry in metadata:
        print(entry)

except SMBExtractorError as e:
    print(f"An error occurred: {e}")
```

# Functions Overview
- `extract_smb_packets(pcap_file)`: Extracts SMB2 packets from the provided pcap file.
- `parse_smb_packets(smb_packets)`: Parses SMB2 packets to extract metadata (IP addresses, ports, etc.).
- `save_extracted_files(metadata, output_dir)`: Saves the parsed metadata as a JSON file in the specified output directory.
- `SMBExtractorError`: Custom exception to handle errors related to SMB packet extraction and parsing.