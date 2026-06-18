# Task 1 — Basic Network Sniffer

**CodeAlpha Cybersecurity Internship**

## Overview
A Python-based network packet sniffer that captures and analyzes live network traffic. Displays source/destination IPs, protocols (TCP/UDP/ICMP/ARP/DNS), flags, payloads, and session statistics.

## Features
- Dual-mode: Scapy (preferred) or raw socket fallback
- Protocol detection: TCP, UDP, ICMP, ARP, DNS
- TCP flag parsing (SYN, ACK, FIN, RST, PSH)
- Payload preview (printable ASCII)
- Live session statistics
- JSON export of captured session
- BPF filter support (Scapy mode)

## Requirements
```
Python 3.7+
scapy>=2.5.0     # optional but recommended
```

Install:
```bash
pip install scapy
```

## Usage
```bash
# Basic capture (all interfaces, 100 packets)
sudo python3 network_sniffer.py

# Specific interface, custom count
sudo python3 network_sniffer.py -i eth0 -c 50

# With BPF filter
sudo python3 network_sniffer.py -f "tcp port 80" -c 20
sudo python3 network_sniffer.py -f icmp

# Help
python3 network_sniffer.py -h
```

## Arguments
| Flag | Description | Default |
|------|-------------|---------|
| `-i` | Network interface | All interfaces |
| `-c` | Packet capture count | 100 |
| `-f` | BPF filter string | None |

## Sample Output
```
[12:34:56.789] Packet #1
  [IP]  192.168.1.5 → 8.8.8.8 | TTL: 64 | Proto: UDP
  [UDP] Sport: 51234 | Dport: 53 | Len: 38
  [DNS] Query: google.com
  [STATS] TCP:0 UDP:1 ICMP:0 ARP:0 DNS:1
```

## Notes
- Requires root/sudo on Linux
- On Windows: requires WinPcap/Npcap + Scapy
- Raw socket fallback requires `AF_PACKET` (Linux only)
