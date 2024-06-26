# -----------------------------------------------------------
#
#  tsn.zeek
#
#  This file registers the packet analyzer in Zeek.
#
# (C) 2022 Robin Schenderlein, Hamburg, Germany
# Released under GNU Public License (GPL)
# email robin.schenderlein@studium.uni-hamburg.de
#
#
# This file was updated: IEEE Std 1588 and IEEE Std 802.1AS (g)PTP support for Spicy by
#
# (C) 2024 Ahmed Abdulfattah, Berlin, Germany
# Released under GNU Public License (GPL)
# email ahmed.abdulfattah@posteo.de
# -----------------------------------------------------------

module PacketAnalyzer::SPICY_TSN;

module TSN;

event zeek_init()
	{
	print( "Zeek init 1 fired");
	if ( ! PacketAnalyzer::try_register_packet_analyzer_by_name("Ethernet", 0xF1C1, "spicy::FRER") )
		print "cannot register TSN CB analyzer";
	if ( ! PacketAnalyzer::try_register_packet_analyzer_by_name("VLAN", 0xF1C1, "spicy::FRER") )
		print "cannot register TSN CB analyzer";

	if ( ! PacketAnalyzer::try_register_packet_analyzer_by_name("Ethernet", 0x22EA, "spicy::SRP") )
		print "cannot register TSN SRP analyzer";
	if ( ! PacketAnalyzer::try_register_packet_analyzer_by_name("VLAN", 0x22EA, "spicy::SRP") )
		print "cannot register TSN SRP analyzer";

	if ( ! PacketAnalyzer::try_register_packet_analyzer_by_name("Ethernet", 0x88F7, "spicy::PTP") )
		print "cannot register TSN PTP analyzer";
	if ( ! PacketAnalyzer::try_register_packet_analyzer_by_name("VLAN", 0x88F7, "spicy::PTP") )
		print "cannot register TSN PTP analyzer";
	# register_protocol_detection
	}

