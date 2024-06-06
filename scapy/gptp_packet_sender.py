from scapy.all import *


gptp_pcap_file_path = "ptpv2_vlan.pcap"



gptp_packets = rdpcap(gptp_pcap_file_path)

for gptp_packet in gptp_packets:
    print(f"Press 'Enter' to send the next packet...")
    input()  # Wait for user to press "Enter"
    
    # Send the packet
    sendp(gptp_packet, iface="enp0s3")
