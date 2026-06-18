#!/usr/bin/env python3
"""
CodeAlpha Internship - Task 1: Basic Network Sniffer
Author: Hamid | Roll No: DHC-40
Description: Captures and analyzes network packets using scapy/socket
"""

import socket
import struct
import textwrap
import sys
import datetime
import json
import os

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, DNSQR, Raw, ARP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# ─── ANSI Colors ────────────────────────────────────────────────────────────
GREEN   = "\033[92m"
CYAN    = "\033[96m"
YELLOW  = "\033[93m"
RED     = "\033[91m"
MAGENTA = "\033[95m"
BOLD    = "\033[1m"
RESET   = "\033[0m"
DIM     = "\033[2m"

BANNER = f"""
{GREEN}
  ██████╗ ███████╗████████╗    ███████╗███╗   ██╗██╗███████╗███████╗███████╗██████╗
  ██╔══██╗██╔════╝╚══██╔══╝    ██╔════╝████╗  ██║██║██╔════╝██╔════╝██╔════╝██╔══██╗
  ███████║█████╗     ██║       ███████╗██╔██╗ ██║██║█████╗  █████╗  █████╗  ██████╔╝
  ██╔══██║██╔══╝     ██║       ╚════██║██║╚██╗██║██║██╔══╝  ██╔══╝  ██╔══╝  ██╔══██╗
  ██║  ██║███████╗   ██║       ███████║██║ ╚████║██║██║     ██║     ███████╗██║  ██║
  ╚═╝  ╚═╝╚══════╝   ╚═╝       ╚══════╝╚═╝  ╚═══╝╚═╝╚═╝     ╚═╝     ╚══════╝╚═╝  ╚═╝
{RESET}
{CYAN}  CodeAlpha Internship | Task 1: Basic Network Sniffer{RESET}
{DIM}  Developed by: Hamid (DHC-40) | University of Haripur{RESET}
"""

# ─── Packet Counter ─────────────────────────────────────────────────────────
packet_count = {"total": 0, "TCP": 0, "UDP": 0, "ICMP": 0, "ARP": 0, "DNS": 0, "OTHER": 0}
captured_packets = []

def timestamp():
    return datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]

def format_mac(mac_bytes):
    return ':'.join(f'{b:02x}' for b in mac_bytes)

def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(b) if b < 32 or b > 127 else chr(b) for b in string)
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

# ─── Scapy Packet Handler ────────────────────────────────────────────────────
def scapy_packet_handler(pkt):
    global packet_count
    packet_count["total"] += 1
    pkt_info = {"timestamp": timestamp(), "layers": []}

    print(f"\n{DIM}{'─'*70}{RESET}")
    print(f"{CYAN}[{timestamp()}]{RESET} {BOLD}Packet #{packet_count['total']}{RESET}")

    if IP in pkt:
        ip = pkt[IP]
        proto_map = {6: "TCP", 17: "UDP", 1: "ICMP"}
        proto_name = proto_map.get(ip.proto, "OTHER")

        print(f"  {GREEN}[IP]{RESET} {ip.src}{CYAN} → {RESET}{ip.dst} | TTL: {ip.ttl} | Proto: {YELLOW}{proto_name}{RESET}")
        pkt_info["src"] = ip.src
        pkt_info["dst"] = ip.dst
        pkt_info["protocol"] = proto_name

        if TCP in pkt:
            packet_count["TCP"] += 1
            tcp = pkt[TCP]
            flags = []
            if tcp.flags & 0x02: flags.append("SYN")
            if tcp.flags & 0x01: flags.append("FIN")
            if tcp.flags & 0x10: flags.append("ACK")
            if tcp.flags & 0x04: flags.append("RST")
            if tcp.flags & 0x08: flags.append("PSH")
            flag_str = "|".join(flags) if flags else "NONE"
            print(f"  {MAGENTA}[TCP]{RESET} Sport: {tcp.sport} | Dport: {tcp.dport} | Flags: {YELLOW}{flag_str}{RESET} | Seq: {tcp.seq}")

        elif UDP in pkt:
            packet_count["UDP"] += 1
            udp = pkt[UDP]
            print(f"  {YELLOW}[UDP]{RESET} Sport: {udp.sport} | Dport: {udp.dport} | Len: {udp.len}")

        elif ICMP in pkt:
            packet_count["ICMP"] += 1
            icmp = pkt[ICMP]
            icmp_types = {0: "Echo Reply", 8: "Echo Request", 3: "Dest Unreachable", 11: "Time Exceeded"}
            icmp_type_str = icmp_types.get(icmp.type, f"Type {icmp.type}")
            print(f"  {RED}[ICMP]{RESET} Type: {icmp_type_str} | Code: {icmp.code}")
        else:
            packet_count["OTHER"] += 1

    if DNS in pkt and pkt.haslayer(DNSQR):
        packet_count["DNS"] += 1
        dns_query = pkt[DNSQR].qname.decode(errors='replace').strip('.')
        print(f"  {CYAN}[DNS]{RESET} Query: {YELLOW}{dns_query}{RESET}")

    if ARP in pkt:
        packet_count["ARP"] += 1
        arp = pkt[ARP]
        op = "Request" if arp.op == 1 else "Reply"
        print(f"  {GREEN}[ARP]{RESET} {op} | Who has {arp.pdst}? Tell {arp.psrc}")

    if Raw in pkt:
        raw_data = bytes(pkt[Raw])
        if len(raw_data) > 0:
            printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in raw_data[:64])
            print(f"  {DIM}[PAYLOAD] {printable}{'...' if len(raw_data) > 64 else ''}{RESET}")

    # Live stats
    print(f"  {DIM}[STATS] TCP:{packet_count['TCP']} UDP:{packet_count['UDP']} ICMP:{packet_count['ICMP']} ARP:{packet_count['ARP']} DNS:{packet_count['DNS']}{RESET}")
    captured_packets.append(pkt_info)

# ─── Raw Socket Fallback ─────────────────────────────────────────────────────
def raw_socket_sniffer(max_packets=50):
    print(f"\n{YELLOW}[!] Scapy not available. Using raw socket fallback...{RESET}")
    print(f"{DIM}    Note: Raw socket mode requires root/admin privileges{RESET}\n")

    try:
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    except PermissionError:
        print(f"{RED}[!] Root privileges required for raw socket sniffing.{RESET}")
        print(f"    Run: {YELLOW}sudo python3 network_sniffer.py{RESET}")
        sys.exit(1)
    except AttributeError:
        print(f"{RED}[!] AF_PACKET not supported on this OS (Windows).{RESET}")
        print(f"    Install scapy: {YELLOW}pip install scapy{RESET}")
        sys.exit(1)

    count = 0
    while count < max_packets:
        raw_data, addr = conn.recvfrom(65535)
        count += 1
        packet_count["total"] += 1

        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print(f"\n{DIM}{'─'*70}{RESET}")
        print(f"{CYAN}[{timestamp()}]{RESET} {BOLD}Packet #{count}{RESET}")
        print(f"  {GREEN}[ETH]{RESET} {format_mac(src_mac)} → {format_mac(dest_mac)} | Proto: {eth_proto}")

        if eth_proto == 8:  # IPv4
            version, header_length, ttl, proto, src, target, data = ipv4_packet(data)
            proto_map = {6: "TCP", 17: "UDP", 1: "ICMP"}
            proto_name = proto_map.get(proto, f"#{proto}")
            print(f"  {GREEN}[IP]{RESET} {src}{CYAN} → {RESET}{target} | TTL: {ttl} | Proto: {YELLOW}{proto_name}{RESET}")

            if proto == 6:
                packet_count["TCP"] += 1
                src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data = tcp_segment(data)
                flags = []
                if flag_syn: flags.append("SYN")
                if flag_fin: flags.append("FIN")
                if flag_ack: flags.append("ACK")
                if flag_rst: flags.append("RST")
                if flag_psh: flags.append("PSH")
                print(f"  {MAGENTA}[TCP]{RESET} Sport: {src_port} | Dport: {dest_port} | Flags: {YELLOW}{'|'.join(flags) or 'NONE'}{RESET}")
            elif proto == 17:
                packet_count["UDP"] += 1
                src_port, dest_port, length, data = udp_segment(data)
                print(f"  {YELLOW}[UDP]{RESET} Sport: {src_port} | Dport: {dest_port} | Len: {length}")
            elif proto == 1:
                packet_count["ICMP"] += 1
                icmp_type, code, checksum, data = icmp_packet(data)
                print(f"  {RED}[ICMP]{RESET} Type: {icmp_type} | Code: {code}")

def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return dest_mac, src_mac, socket.htons(proto), data[14:]

def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, socket.inet_ntoa(src), socket.inet_ntoa(target), data[header_length:]

def tcp_segment(data):
    src_port, dest_port, sequence, acknowledgement, offset_reserved_flags = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]

def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

# ─── Save Results ────────────────────────────────────────────────────────────
def save_results():
    output = {
        "session": timestamp(),
        "statistics": packet_count,
        "packets": captured_packets[:100]
    }
    filename = f"capture_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(filename, 'w') as f:
        json.dump(output, f, indent=2)
    print(f"\n{GREEN}[+] Results saved to: {filename}{RESET}")

# ─── Main ────────────────────────────────────────────────────────────────────
def main():
    print(BANNER)

    # Parse args
    interface = None
    packet_limit = 100
    filter_proto = None

    for i, arg in enumerate(sys.argv[1:]):
        if arg == "-i" and i+1 < len(sys.argv)-1:
            interface = sys.argv[i+2]
        elif arg == "-c" and i+1 < len(sys.argv)-1:
            try:
                packet_limit = int(sys.argv[i+2])
            except ValueError:
                pass
        elif arg == "-f" and i+1 < len(sys.argv)-1:
            filter_proto = sys.argv[i+2]
        elif arg in ("-h", "--help"):
            print(f"""
{BOLD}Usage:{RESET} python3 network_sniffer.py [OPTIONS]

{BOLD}Options:{RESET}
  -i <interface>   Network interface (e.g., eth0, wlan0)
  -c <count>       Number of packets to capture (default: 100)
  -f <filter>      BPF filter (e.g., 'tcp', 'udp port 53', 'icmp')
  -h               Show this help

{BOLD}Examples:{RESET}
  sudo python3 network_sniffer.py -i eth0 -c 50
  sudo python3 network_sniffer.py -f "tcp port 80" -c 20
  sudo python3 network_sniffer.py -f icmp
""")
            sys.exit(0)

    if os.geteuid() != 0:
        print(f"{RED}[!] WARNING: Not running as root. Packet capture may fail.{RESET}")
        print(f"    Recommended: {YELLOW}sudo python3 network_sniffer.py{RESET}\n")

    print(f"{GREEN}[*] Starting capture...{RESET}")
    print(f"    Interface : {CYAN}{interface or 'ALL'}{RESET}")
    print(f"    Packet Limit : {CYAN}{packet_limit}{RESET}")
    print(f"    Filter    : {CYAN}{filter_proto or 'None'}{RESET}")
    print(f"\n{DIM}Press CTRL+C to stop capture{RESET}\n")

    try:
        if SCAPY_AVAILABLE:
            sniff(
                iface=interface,
                prn=scapy_packet_handler,
                count=packet_limit,
                filter=filter_proto,
                store=False
            )
        else:
            raw_socket_sniffer(max_packets=packet_limit)
    except KeyboardInterrupt:
        print(f"\n\n{YELLOW}[!] Capture interrupted by user{RESET}")
    except Exception as e:
        print(f"\n{RED}[!] Error: {e}{RESET}")

    # Final stats
    print(f"\n{GREEN}{'='*50}{RESET}")
    print(f"{BOLD}  CAPTURE SUMMARY{RESET}")
    print(f"{GREEN}{'='*50}{RESET}")
    for k, v in packet_count.items():
        print(f"  {CYAN}{k:<10}{RESET}: {YELLOW}{v}{RESET}")
    print(f"{GREEN}{'='*50}{RESET}")

    save_results()

if __name__ == "__main__":
    main()
