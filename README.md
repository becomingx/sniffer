Python Packet Sniffer with Protocol Metadata
  This project is a lightweight, proof of concept Python-based packet sniffer that captures IP packets.
  It does so on a specified network interface and enriches them with protocol metadata sourced from a CSV file. 
  It uses the Scapy library for packet inspection and a custom protocol mapping for human-readable output.

Features
* Captures live IP packets from a user-specified interface
* Displays source and destination IP addresses
* Maps protocol numbers to keywords and descriptions using a CSV file
* Graceful handling of invalid interfaces and permission errors
* Modular design for easy extension and integration

Requirements:
* Python 3.6+
* Scapy
* CSV file containing protocol metadata is included (used by protocolNumbersImport.load_protocols)
* Administrator/root privileges (required for packet sniffing)

File Structure
├── packet_sniffer.py           # Main script
├── protocolNumbersImport.py   # Module to load protocol metadata from CSV
├── protocol-numbers-1.csv      # CSV file with protocol number, keyword, description
├── README.md                   # Project documentation

How It Works
Protocol Mapping: 
  --Loads a dictionary mapping protocol numbers to keywords and descriptions from a CSV file.

Interface Selection: 
  --Lists available interfaces and prompts the user to select one.

Packet Sniffing: 
  --Uses Scapy to sniff IP packets on the selected interface.

Packet Processing: 
  --For each packet, extracts source/destination IPs and protocol number, then prints enriched metadata.

Notes
* You must run the script with administrative privileges to access raw sockets.
* If the interface name is invalid, the script will not output packets.
* The protocol metadata must be correctly formatted in the CSV file for accurate mapping.

Usage
* Will work with: Linux
* Not directly tested on MacOS, but likely will work due to the compatibility of Bash commands
  --Python frequently comes pre-installed on macOS, but it might be an older version.
* Untested on Windows as of yet

Install dependencies
* Python 3.6 or higher; Bash command below.
  sudo apt-get install python

* Scapy Python library
  --Pip is required to install Python libraries. Bash command below.
  python -m pip install --upgrade pip
  pip install scapy

Running the script:
  Bash command:
    sudo python packet_sniffer.py
      --Follow the prompt to select a network interface.

Sample Output
Available interfaces: ['eth0', 'lo', 'wlan0']
Enter interface name (e.g., eth0, Wi-Fi): eth0
Starting packet sniffer on eth0... Press Ctrl+C to stop.
Packet #0: TCP (6) - Transmission Control Protocol | 192.168.1.10 -> 93.184.216.34
Packet #1: UDP (17) - User Datagram Protocol | 192.168.1.10 -> 8.8.8.8

TODOs
* Add support for non-IP protocols (e.g., ARP, ICMPv6)
* Log output to a file for later analysis:
    --Enable choosing file type (rtf, txt, csv, xml, html, JSON)
* Add filtering options (e.g., by protocol or IP)


Author
Designed by Patricia Tirado
Follow me on LinkedIn: 
www.linkedin.com/comm/mynetwork/discovery-see-all?usecase=PEOPLE_FOLLOWS&followMember=patriciatirado29a
'forging better outcomes with uncommon sense'.
