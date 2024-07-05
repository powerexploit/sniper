# SMB2-Packet-Analyzer
This Python script extracts SMB (Server Message Block) packets from a pcap file, parses them, extracts metadata, and saves the metadata as a JSON file.

# Installation
- Clone the repository
```
git clone https://github.com/powerexploit/SMB2-Packet-Analyzer
cd smb2-packet-analyzer
```

- Ensure Python and required packages are installed:
```
pip install -r requirements.txt
```

# Usage
- Open a terminal or command prompt.
- Navigate to the directory containing `smb_extractor.py` and your pcap file.

# Running the Script
Run the script using the command:
```
python smb_extractor.py <pcap_file>
```

Replace `<pcap_file>` with the path to your pcap file containing SMB packets.

# Output
- extracted_files/: This directory will be created in the script's location.
    - Contains extracted files from SMB packets (if applicable).
- metadata.json: JSON file containing metadata extracted from SMB packets.
    - Saved in the extracted_files/ directory.