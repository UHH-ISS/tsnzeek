#!/usr/bin/env python3
# (C) 2026 Doganalp Ergenc, written with the assistance of Claude
"""Send the frames of a pcap, one per Enter.

    sudo .venv/bin/python frames/scripts/pcap_sender.py <pcap> [interface]      (interface defaults to enp0s3)

The pcap is a path or the name of a file in frames/samples/ (ptp, ptpv2_vlan, frer, srp_talker, srp_listener),
with or without the .pcap ending.
"""
import os
import sys

from scapy.all import rdpcap, sendp

SAMPLES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "samples")


def find(name):
    for candidate in (name, os.path.join(SAMPLES, name), os.path.join(SAMPLES, name + ".pcap")):
        if os.path.isfile(candidate):
            return candidate
    sys.exit(f"{name}: no such pcap (samples: {', '.join(sorted(f for f in os.listdir(SAMPLES) if f.endswith('.pcap')))})")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    interface = sys.argv[2] if len(sys.argv) > 2 else "enp0s3"
    for packet in rdpcap(find(sys.argv[1])):
        input("Press Enter to send the next packet...")
        sendp(packet, iface=interface)
