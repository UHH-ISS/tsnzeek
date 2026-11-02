"""Send the gPTP frames of samples/ptpv2_vlan.pcap, one per Enter.

    sudo .venv/bin/python scapy/scripts/gptp_sender.py [interface]        (default enp0s3)
"""
import os
import sys

from scapy.all import rdpcap, sendp

pcap = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "samples", "ptpv2_vlan.pcap")
interface = sys.argv[1] if len(sys.argv) > 1 else "enp0s3"

for gptp_packet in rdpcap(pcap):
    input("Press Enter to send the next packet...")
    sendp(gptp_packet, iface=interface)
