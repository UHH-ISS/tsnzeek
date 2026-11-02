# -----------------------------------------------------------
#
#  srp.zeek
#
# IEEE 802.1Qcc (enhanced SRP): log and forward Talker/Listener Enhanced First Value messages.
#
# (C) 2022 Robin Schenderlein, Hamburg, Germany
# Released under GNU Public License (GPL)
# -----------------------------------------------------------

module TSN;

export {
	redef enum Log::ID += { LOG_SRP };

	type SRPTuple: record {
		src:       addr   &log;
		dst:       addr   &log;
		dscp:      count  &log;
		protocol:  count  &log;
		src_port:  count  &log;
		dst_port:  count  &log;
	};

	## One row per Talker/Listener Enhanced message. Interface lists are logged as "mac/name".
	type SRPInfo: record {
		ts:                        time    &log;
		src:                       string  &log &optional;
		dst:                       string  &log &optional;
		vlan:                      count   &log &optional;

		msg_type:                  string  &log;
		stream_mac:                string  &log;
		stream_unique_id:          count   &log;
		end_station_interfaces:    vector of string &log &optional;

		## Talker only
		stream_rank:               count   &log &optional;
		interval_numerator:        count   &log &optional;
		interval_denominator:      count   &log &optional;
		max_frames_per_interval:   count   &log &optional;
		max_frame_size:            count   &log &optional;
		transmission_selection:    count   &log &optional;
		df_dst_mac:                string  &log &optional;
		df_src_mac:                string  &log &optional;
		df_vlan_pcp:               count   &log &optional;
		df_vlan_id:                count   &log &optional;
		df_ipv4:                   SRPTuple &log &optional;
		df_ipv6:                   SRPTuple &log &optional;
		earliest_transmit_offset:  count   &log &optional;
		latest_transmit_offset:    count   &log &optional;
		jitter:                    count   &log &optional;

		## Talker and Listener
		num_seamless_trees:        count   &log &optional;
		max_latency:               count   &log &optional;
		vlan_tag_capable:          bool    &log &optional;
		cb_stream_iden_types:      vector of count &log &optional;
		cb_sequence_types:         vector of count &log &optional;

		## Status
		talker_status:             string  &log;
		listener_status:           string  &log;
		failure_code:              count   &log;
		accumulated_latency:       count   &log &optional;
		interface_configurations:  count   &log &optional;
		failed_interfaces:         vector of string &log &optional;
	};

	global talkerEnhanced_FirstValueMsg:    event(p: raw_pkt_hdr, m: SRP::TalkerEnhanced_FirstValue);
	global listenerEnhanced_FirstValueMsg:  event(p: raw_pkt_hdr, m: SRP::ListenerEnhanced_FirstValue);
	global srp_unknownMsg:                  event(p: raw_pkt_hdr, m: SRP::UnknownMessage);
}

function srp_status_name(names: vector of string, code: count): string
	{
	return code < |names| ? names[code] : fmt("Unknown(%d)", code);
	}

function srp_interfaces(l: vector of SRP::InterfaceID): vector of string
	{
	local r: vector of string;
	for ( i in l )
		r += fmt("%s/%s", mac_str(l[i]$macAddress), l[i]$interfaceName);
	return r;
	}

type SRPParts: record {
	stream:    SRP::StreamID &optional;
	rank:      SRP::StreamRank &optional;
	ifaces:    vector of SRP::InterfaceID &optional;
	dfs:       vector of SRP::DataFrameItem &optional;
	traffic:   SRP::TrafficSpecification &optional;
	tspec:     SRP::TSpecTimeAware &optional;
	u2n:       SRP::UserToNetworkRequirements &optional;
	caps:      SRP::InterfaceCapabilities &optional;
	info:      SRP::StatusInfo &optional;
	latency:   SRP::AccumulatedLatency &optional;
	configs:   vector of SRP::ConfigItem &optional;
	failed:    vector of SRP::InterfaceID &optional;
	problems:  vector of string &default=vector();
};

# Collect the first TLV of every kind; unknown and repeated TLVs are recorded as problems.
function srp_scan_body(items: vector of SRP::Item, parts: SRPParts)
	{
	local seen: set[count];
	for ( i in items )
		{
		local it = items[i];
		if ( it$tlvType in seen )
			{
			parts$problems += fmt("duplicate TLV type %d", it$tlvType);
			next;
			}
		add seen[it$tlvType];

		if ( it?$streamID ) parts$stream = it$streamID;
		else if ( it?$streamRank ) parts$rank = it$streamRank;
		else if ( it?$endStationInterfaces ) parts$ifaces = it$endStationInterfaces;
		else if ( it?$dataFrameSpecification ) parts$dfs = it$dataFrameSpecification;
		else if ( it?$trafficSpecification ) parts$traffic = it$trafficSpecification;
		else if ( it?$tSpecTimeAware ) parts$tspec = it$tSpecTimeAware;
		else if ( it?$userToNetworkRequirements ) parts$u2n = it$userToNetworkRequirements;
		else if ( it?$interfaceCapabilities ) parts$caps = it$interfaceCapabilities;
		else parts$problems += fmt("unknown TLV type %d", it$tlvType);
		}
	}

function srp_scan_status(items: vector of SRP::StatusItem, parts: SRPParts)
	{
	local seen: set[count];
	for ( i in items )
		{
		local it = items[i];
		if ( it$tlvType in seen )
			{
			parts$problems += fmt("duplicate status TLV type %d", it$tlvType);
			next;
			}
		add seen[it$tlvType];

		if ( it?$statusInfo ) parts$info = it$statusInfo;
		else if ( it?$accumulatedLatency ) parts$latency = it$accumulatedLatency;
		else if ( it?$interfaceConfigurations ) parts$configs = it$interfaceConfigurations;
		else if ( it?$failedInterfaces ) parts$failed = it$failedInterfaces;
		else parts$problems += fmt("unknown status TLV type %d", it$tlvType);
		}
	}

function srp_log(p: raw_pkt_hdr, msg_type: string, parts: SRPParts): bool
	{
	# Without a stream and a status there is nothing meaningful to log.
	if ( ! parts?$stream )
		parts$problems += "missing StreamID TLV";
	if ( ! parts?$info )
		parts$problems += "missing StatusInfo TLV";

	for ( i in parts$problems )
		event parse_error(p, "SRP", fmt("%s: %s", msg_type, parts$problems[i]));

	if ( ! parts?$stream || ! parts?$info )
		return F;

	local rec = SRPInfo(
		$ts = network_time(),
		$msg_type = msg_type,
		$stream_mac = mac_str(parts$stream$macAddress),
		$stream_unique_id = parts$stream$uniqueID,
		$talker_status = srp_status_name(vector("None", "Ready", "Failed"), parts$info$talkerStatus),
		$listener_status = srp_status_name(vector("None", "Ready", "PartialFailed", "Failed"), parts$info$listenerStatus),
		$failure_code = parts$info$failureCode);

	if ( p?$l2 )
		{
		if ( p$l2?$src ) rec$src = p$l2$src;
		if ( p$l2?$dst ) rec$dst = p$l2$dst;
		if ( p$l2?$vlan ) rec$vlan = p$l2$vlan;
		}

	if ( parts?$ifaces )
		rec$end_station_interfaces = srp_interfaces(parts$ifaces);
	if ( parts?$rank )
		rec$stream_rank = parts$rank$streamRank$rank;

	if ( parts?$traffic )
		{
		rec$interval_numerator = parts$traffic$intervalNumerator;
		rec$interval_denominator = parts$traffic$intervalDenominator;
		rec$max_frames_per_interval = parts$traffic$maxFramesPerInterval;
		rec$max_frame_size = parts$traffic$maxFrameSize;
		rec$transmission_selection = parts$traffic$transmissionSelection;
		}

	if ( parts?$dfs )
		for ( i in parts$dfs )
			{
			local d = parts$dfs[i];
			if ( d?$ieee802MacAddresses )
				{
				rec$df_dst_mac = mac_str(d$ieee802MacAddresses$destinationMacAddress);
				rec$df_src_mac = mac_str(d$ieee802MacAddresses$sourceMacAddress);
				}
			else if ( d?$ieee802VlanTag )
				{
				rec$df_vlan_pcp = d$ieee802VlanTag$priorityCodePoint;
				rec$df_vlan_id = d$ieee802VlanTag$vlanId;
				}
			else if ( d?$ipv4Tuple )
				rec$df_ipv4 = SRPTuple($src = d$ipv4Tuple$sourceIpAddress, $dst = d$ipv4Tuple$destinationIpAddress,
				                       $dscp = d$ipv4Tuple$dscp, $protocol = d$ipv4Tuple$protocol,
				                       $src_port = d$ipv4Tuple$sourcePort, $dst_port = d$ipv4Tuple$destinationPort);
			else if ( d?$ipv6Tuple )
				rec$df_ipv6 = SRPTuple($src = d$ipv6Tuple$sourceIpAddress, $dst = d$ipv6Tuple$destinationIpAddress,
				                       $dscp = d$ipv6Tuple$dscp, $protocol = d$ipv6Tuple$protocol,
				                       $src_port = d$ipv6Tuple$sourcePort, $dst_port = d$ipv6Tuple$destinationPort);
			}

	if ( parts?$tspec )
		{
		rec$earliest_transmit_offset = parts$tspec$earliestTransmitOffset;
		rec$latest_transmit_offset = parts$tspec$latestTransmitOffset;
		rec$jitter = parts$tspec$jitter;
		}
	if ( parts?$u2n )
		{
		rec$num_seamless_trees = parts$u2n$numSeamlessTrees;
		rec$max_latency = parts$u2n$maxLatency;
		}
	if ( parts?$caps )
		{
		rec$vlan_tag_capable = parts$caps$vlan$vlanTagCapable != 0;
		rec$cb_stream_iden_types = parts$caps$cbStreamIdenTypeList;
		rec$cb_sequence_types = parts$caps$cbSequenceTypeList;
		}
	if ( parts?$latency )
		rec$accumulated_latency = parts$latency$accumulatedLatency;
	if ( parts?$configs )
		{
		local n = 0;
		for ( i in parts$configs )
			if ( parts$configs[i]?$interfaceID )
				++n;
		rec$interface_configurations = n;
		}
	if ( parts?$failed )
		rec$failed_interfaces = srp_interfaces(parts$failed);

	Log::write(LOG_SRP, rec);
	ids_publish("srp", rec);
	return T;
	}

event talkerEnhanced_FirstValueMsg(p: raw_pkt_hdr, m: SRP::TalkerEnhanced_FirstValue)
	{
	local parts = SRPParts();
	srp_scan_body(m$talker$items, parts);
	srp_scan_status(m$status$status$items, parts);

	if ( ! parts?$rank )
		parts$problems += "missing StreamRank TLV";
	if ( ! parts?$traffic )
		parts$problems += "missing TrafficSpecification TLV";
	if ( ! parts?$latency )
		parts$problems += "missing AccumulatedLatency TLV";

	srp_log(p, "TalkerEnhanced", parts);
	}

event listenerEnhanced_FirstValueMsg(p: raw_pkt_hdr, m: SRP::ListenerEnhanced_FirstValue)
	{
	local parts = SRPParts();
	srp_scan_body(m$listener$items, parts);
	srp_scan_status(m$status$status$items, parts);

	srp_log(p, "ListenerEnhanced", parts);
	}

event srp_unknownMsg(p: raw_pkt_hdr, m: SRP::UnknownMessage)
	{
	event parse_error(p, "SRP", fmt("unsupported first TLV type %d", m$tlvType));
	}

event zeek_init() &priority=5
	{
	Log::create_stream(LOG_SRP, [$columns=SRPInfo, $path="srp"]);
	}
