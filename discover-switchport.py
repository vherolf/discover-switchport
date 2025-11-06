#! /usr/bin/env python

# parse for a cdp package to find on which remote Cisco switch and port its connected 
from scapy.all import *
import argparse

load_contrib("cdp")
 
def cdp_monitor_callback(pkt):
  ip = "0.0.0.0"
  if (CDPMsgDeviceID in pkt):
    device=pkt["CDPMsgDeviceID"].val.decode()
    hostname=device.split(".")[0]
    if (CDPMsgPortID in pkt):
      port = pkt["CDPMsgPortID"].iface.decode()
    if (CDPMsgDeviceID in pkt):
      switchname = pkt["CDPMsgDeviceID"].val.decode()
    if (CDPMsgNativeVLAN in pkt):
      vlan = pkt["CDPMsgNativeVLAN"].vlan
    if (CDPAddrRecordIPv4 in pkt):
      ip=pkt["CDPAddrRecordIPv4"].addr
    return f"Device: {switchname} Port: {port} VLAN: {vlan} IP: {ip}"
 
interface="enp1s0"
capturefilter="ether dst 01:00:0c:cc:cc:cc"
 
def main(interface=interface, capturefilter=capturefilter):
    print("Listening for CDP packets on interface", interface)
    p=sniff(prn=cdp_monitor_callback, iface=interface, count=1, filter=capturefilter, store=0)


if __name__ == "__main__":
  parser = argparse.ArgumentParser(description="switchport discovery via CDP",
                                  formatter_class=argparse.ArgumentDefaultsHelpFormatter)
  parser.add_argument('-cf','--capturefilter', type=str, default='ether dst 01:00:0c:cc:cc:cc', help='capture filter for sniffing')
  parser.add_argument('-i','--interface', type=str, default='enp1s0', help='network interface to listen on')
  args = parser.parse_args()
  if args.interface:
      interface=args.interface
  if args.capturefilter:
      capturefilter=args.capturefilter

  main(interface=interface, capturefilter=capturefilter)  