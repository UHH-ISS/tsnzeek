# -----------------------------------------------------------
#
#  cb.zeek
#
# IEEE 802.1CB (FRER): log and forward redundancy tags.
#
# (C) 2022 Robin Schenderlein, Hamburg, Germany
# (C) 2024 Ahmed Abdulfattah, Berlin, Germany
# (C) 2026 Doganalp Ergenc, written with the assistance of Claude
# Released under GNU Public License (GPL)
# -----------------------------------------------------------

module TSN;

export {
	redef enum Log::ID += { LOG_CB };

	type CBInfo: record {
		ts:           time   &log;
		src:          string &log &optional;
		dst:          string &log &optional;
		vlan:         count  &log &optional;
		reserved:     count  &log;
		sequence_nr:  count  &log;
	};

	global cb_message: event(p: raw_pkt_hdr, frame: FRER::CBFrame);
}

event cb_message(p: raw_pkt_hdr, frame: FRER::CBFrame)
	{
	local rec = CBInfo($ts = network_time(), $reserved = frame$reserved, $sequence_nr = frame$sequenceNumber);
	if ( p$l2?$src ) rec$src = p$l2$src;
	if ( p$l2?$dst ) rec$dst = p$l2$dst;
	if ( p$l2?$vlan ) rec$vlan = p$l2$vlan;
	Log::write(LOG_CB, rec);
	ids_publish("cb", rec);
	}

event zeek_init() &priority=5
	{
	Log::create_stream(LOG_CB, [$columns=CBInfo, $path="cb"]);
	}
