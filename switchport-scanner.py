#!/usr/bin/env python3
"""
Continuous CDP Packet Sniffer & Analyzer with CSV Export
Exports to CSV only when a new connected port is detected (avoids duplicates).
Run with sudo/root privileges. Compatible with Scapy 2.6+ / 2.7.0
"""

import argparse
import csv
import os
import sys
from scapy.all import *
from scapy.contrib.cdp import *  # ✅ Correct import path for Scapy 2.6+ / 2.7.0

# Suppress Scapy's internal warning spam & known datetime bug
conf.verb = 0

# ✅ Exact order requested for both console & CSV
CSV_HEADERS = [
    "Device Hostname",
    "Connected Port",
    "Native VLAN",
    "VoIP VLAN",
    "Capabilities",
    "Duplex",
    "IOS Version",
    "Platform"
]

def decode_cdp_capabilities(cap_int):
    """Decode Cisco CDP capabilities bitmask to readable names."""
    caps = []
    if cap_int & 0x08: caps.append("Router")
    if cap_int & 0x10: caps.append("Bridge")
    if cap_int & 0x20: caps.append("Switch")
    if cap_int & 0x40: caps.append("IGMP")
    if cap_int & 0x80: caps.append("Repeater")
    if cap_int & 0x100: caps.append("Phone")
    if cap_int & 0x200: caps.append("Remote")
    if cap_int & 0x400: caps.append("IGMP")
    if cap_int & 0x800: caps.append("Telnet")
    return caps if caps else None

class CDPAnalyzer:
    def __init__(self, interface, capturefilter, csv_file="cdp_discovery.csv"):
        self.interface = interface
        self.capturefilter = capturefilter
        self.csv_file_path = csv_file
        self.last_port = None
        self.csv_file = None
        self.csv_writer = None
        self.init_csv()

    def init_csv(self):
        file_exists = os.path.isfile(self.csv_file_path)
        self.csv_file = open(self.csv_file_path, 'a', newline='', encoding='utf-8')
        self.csv_writer = csv.DictWriter(self.csv_file, fieldnames=CSV_HEADERS)
        if not file_exists:
            self.csv_writer.writeheader()
        print(f"[*] CSV output will be saved to: {os.path.abspath(self.csv_file_path)}")

    def parse_pkt(self, pkt):
        info = {}
        try:
            # 1. Device Hostname
            info['Device Hostname'] = pkt[CDPMsgDeviceID].val.decode('utf-8', errors='ignore').strip() if CDPMsgDeviceID in pkt else 'N/A'
            # 2. Connected Port
            info['Connected Port'] = pkt[CDPMsgPortID].iface.decode('utf-8', errors='ignore').strip() if CDPMsgPortID in pkt else 'N/A'
            # 3. Native VLAN
            info['Native VLAN'] = str(pkt[CDPMsgNativeVLAN].vlan) if CDPMsgNativeVLAN in pkt else 'N/A'
            # 4. VoIP VLAN
            info['VoIP VLAN'] = str(pkt[CDPMsgVoIPVLANReply].vlan) if CDPMsgVoIPVLANReply in pkt else 'N/A'
            
            # 5. Capabilities
            if CDPMsgCapabilities in pkt:
                cap_val = pkt[CDPMsgCapabilities].cap
                decoded_caps = decode_cdp_capabilities(cap_val)
                info['Capabilities'] = ', '.join(decoded_caps) if decoded_caps else f"0x{cap_val:04X}"
            else:
                info['Capabilities'] = 'N/A'
                
            # 6. Duplex
            if CDPMsgDuplex in pkt:
                duplex_map = {0: 'Half', 1: 'Full', 2: 'Unknown'}
                info['Duplex'] = duplex_map.get(pkt[CDPMsgDuplex].duplex, 'Unknown')
            else:
                info['Duplex'] = 'N/A'
                
            # 7. IOS Version
            info['IOS Version'] = pkt[CDPMsgSoftwareVersion].val.decode('utf-8', errors='ignore').strip().replace('\n', ', ') if CDPMsgSoftwareVersion in pkt else 'N/A'
            # 8. Platform
            info['Platform'] = pkt[CDPMsgPlatform].val.decode('utf-8', errors='ignore').strip() if CDPMsgPlatform in pkt else 'N/A'
            
        except Exception as e:
            print(f"[!] Error parsing packet: {e}")
            return None
        return info

    def write_to_csv(self, info):
        current_port = info.get('Connected Port', 'Unknown')
        # Only export if port changed from the last export
        if current_port != self.last_port:
            self.csv_writer.writerow(info)
            self.csv_file.flush()
            self.last_port = current_port
            print(f"[+] Exported to CSV: {current_port}")

    def callback(self, pkt):
        info = self.parse_pkt(pkt)
        if info:
            self.print_info(info)
            self.write_to_csv(info)

    def print_info(self, info):
        print("\n" + "="*50)
        print("CDP Packet Information")
        print("="*50)
        # ✅ Iterate in exact requested order
        for key in CSV_HEADERS:
            print(f"{key:20s}: {info.get(key, 'N/A')}")
        print("="*50 + "\n")

    def run(self):
        print(f"[*] Starting continuous CDP monitoring on interface: {self.interface}")
        print(f"[*] Capture filter: {self.capturefilter}")
        print("[*] Press Ctrl+C to stop.\n")
        try:
            sniff(prn=self.callback, iface=self.interface, filter=self.capturefilter, store=0)
        except KeyboardInterrupt:
            print("\n[!] Sniffing interrupted by user.")
        except PermissionError:
            print("\n[!] Error: Requires root/sudo privileges to capture packets.")
        except Exception as e:
            print(f"\n[!] Unexpected error: {e}")
        finally:
            self.cleanup()

    def cleanup(self):
        if self.csv_file:
            self.csv_file.close()
        print("[*] CSV file closed. Exiting.")

def main():
    parser = argparse.ArgumentParser(
        description="Continuous CDP Packet Sniffer & Analyzer with CSV Export",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument('-i', '--interface', type=str, default='enp1s0', help='Network interface to listen on')
    parser.add_argument('-cf', '--capturefilter', type=str, default='ether dst 01:00:0c:cc:cc:cc', help='BPF capture filter')
    parser.add_argument('-o', '--output', type=str, default='cdp_discovery.csv', help='Output CSV file path')
    args = parser.parse_args()

    analyzer = CDPAnalyzer(interface=args.interface, capturefilter=args.capturefilter, csv_file=args.output)
    analyzer.run()

if __name__ == "__main__":
    main()
