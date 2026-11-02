# -----------------------------------------------------------
#
#  register.zeek
#
# Registers the Spicy packet analyzers for the TSN ethertypes.
#
# (C) 2022 Robin Schenderlein, Hamburg, Germany
# (C) 2024 Ahmed Abdulfattah, Berlin, Germany
# Released under GNU Public License (GPL)
# -----------------------------------------------------------

module TSN;

event zeek_init()
	{
	local analyzers = table(
		[0xF1C1] = PacketAnalyzer::ANALYZER_SPICY_FRER,
		[0x22EA] = PacketAnalyzer::ANALYZER_SPICY_SRP,
		[0x88F7] = PacketAnalyzer::ANALYZER_SPICY_PTP
	);

	for ( ethertype, analyzer in analyzers )
		{
		PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_ETHERNET, ethertype, analyzer);
		PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_VLAN, ethertype, analyzer);
		}
	}
