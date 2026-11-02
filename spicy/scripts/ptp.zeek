# -----------------------------------------------------------
#
#  ptp.zeek
#
# IEEE 1588 / IEEE 802.1AS (g)PTP: log and forward PTP messages.
#
# (C) 2024 Ahmed Abdulfattah, Berlin, Germany
# Released under GNU Public License (GPL)
# -----------------------------------------------------------

module TSN;

export {
	redef enum Log::ID += { LOG_PTP };

	## One row per PTP message: the common header plus the fields of the respective message type.
	## PTP timestamps (48-bit seconds, 32-bit nanoseconds) are kept as integers; a double cannot hold them.
	type PTPInfo: record {
		ts:                          time    &log;
		src:                         string  &log &optional;
		dst:                         string  &log &optional;
		vlan:                        count   &log &optional;

		## Only set for PTP over UDP: src/dst then hold the IP addresses.
		uid:                         string  &log &optional;
		src_port:                    count   &log &optional;
		dst_port:                    count   &log &optional;

		msg_type:                    string  &log;
		transport_specific:          count   &log;
		version_ptp:                 count   &log;
		minor_version_ptp:           count   &log;
		message_length:              count   &log;
		domain_number:               count   &log;
		minor_sdo_id:                count   &log;
		alternate_master:            bool    &log;
		two_step:                    bool    &log;
		unicast:                     bool    &log;
		leap61:                      bool    &log;
		leap59:                      bool    &log;
		current_utc_offset_valid:    bool    &log;
		ptp_timescale:               bool    &log;
		time_traceable:              bool    &log;
		frequency_traceable:         bool    &log;
		synchronization_uncertain:   bool    &log;
		correction_field:            int     &log;
		source_clock_id:             string  &log;
		source_port:                 count   &log;
		sequence_id:                 count   &log;
		control_field:               count   &log;
		log_message_interval:        int     &log;

		## The message's timestamp: origin, receive, request receipt, precise origin or response origin.
		timestamp_sec:               count   &log &optional;
		timestamp_ns:                count   &log &optional;
		requesting_clock_id:         string  &log &optional;
		requesting_port:             count   &log &optional;

		## Announce
		current_utc_offset:          int     &log &optional;
		gm_priority1:                count   &log &optional;
		gm_clock_class:              count   &log &optional;
		gm_clock_accuracy:           count   &log &optional;
		gm_offset_scaled_log_variance: count &log &optional;
		gm_priority2:                count   &log &optional;
		gm_identity:                 string  &log &optional;
		steps_removed:               count   &log &optional;
		time_source:                 count   &log &optional;

		## Signaling and Management
		target_clock_id:             string  &log &optional;
		target_port:                 count   &log &optional;
		tlv_type:                    count   &log &optional;
		tlv_length:                  count   &log &optional;
		management_id:               count   &log &optional;
		action_field:                count   &log &optional;
	};

	global ptp_announceMsg:          event(p: raw_pkt_hdr, m: PTP::AnnounceMessage);
	global ptp_syncMsg:              event(p: raw_pkt_hdr, m: PTP::SyncMessage);
	global ptp_delayReqMsg:          event(p: raw_pkt_hdr, m: PTP::DelayReqMessage);
	global ptp_followUpMsg:          event(p: raw_pkt_hdr, m: PTP::FollowUpMessage);
	global ptp_delayRespMsg:         event(p: raw_pkt_hdr, m: PTP::DelayRespMessage);
	global ptp_pdelayReqMsg:         event(p: raw_pkt_hdr, m: PTP::PdelayReqMessage);
	global ptp_pdelayRespMsg:        event(p: raw_pkt_hdr, m: PTP::PdelayRespMessage);
	global ptp_pdelayRespFollowUpMsg: event(p: raw_pkt_hdr, m: PTP::PdelayRespFollowUpMessage);
	global ptp_signalingMsg:         event(p: raw_pkt_hdr, m: PTP::SignalingMessage);
	global ptp_managementMsg:        event(p: raw_pkt_hdr, m: PTP::ManagementMessage);
	global ptp_unknownMsg:           event(p: raw_pkt_hdr, m: PTP::UnknownMessage);

	## Raised once per parsed PTP frame with the messageLength of its header and the size of the PTP payload.
	global ptp_frame: event(p: raw_pkt_hdr, msg_type: count, declared: count, actual: count);

	## Raised once per PTP datagram on UDP ports 319/320 with the message that was parsed.
	global ptp_udp_frame: event(c: connection, is_orig: bool, f: PTP::PTPBody);
}

function ptp_info(h: PTP::MessageHeader, msg_type: string): PTPInfo
	{
	local rec = PTPInfo(
		$ts = network_time(),
		$msg_type = msg_type,
		$transport_specific = h$sdoAndType$transportSpecific,
		$version_ptp = h$version$versionPTP,
		$minor_version_ptp = h$version$minorVersionPTP,
		$message_length = h$messageLength,
		$domain_number = h$domainNumber,
		$minor_sdo_id = h$minorSdoId,
		$alternate_master = h$flags$alternateMasterFlag != 0,
		$two_step = h$flags$twoStepFlag != 0,
		$unicast = h$flags$unicastFlag != 0,
		$leap61 = h$flags$leap61 != 0,
		$leap59 = h$flags$leap59 != 0,
		$current_utc_offset_valid = h$flags$currentUtcOffsetValid != 0,
		$ptp_timescale = h$flags$ptpTimescale != 0,
		$time_traceable = h$flags$timeTraceable != 0,
		$frequency_traceable = h$flags$frequencyTraceable != 0,
		$synchronization_uncertain = h$flags$synchronizationUncertain != 0,
		$correction_field = h$correctionField,
		$source_clock_id = bytestring_to_hexstr(h$sourcePortIdentity$clockIdentity),
		$source_port = h$sourcePortIdentity$portNumber,
		$sequence_id = h$sequenceId,
		$control_field = h$controlField,
		$log_message_interval = h$logMessageInterval);

	return rec;
	}

function ptp_ctx_packet(rec: PTPInfo, p: raw_pkt_hdr)
	{
	if ( p?$l2 )
		{
		if ( p$l2?$src ) rec$src = p$l2$src;
		if ( p$l2?$dst ) rec$dst = p$l2$dst;
		if ( p$l2?$vlan ) rec$vlan = p$l2$vlan;
		}
	}

function ptp_ctx_conn(rec: PTPInfo, c: connection, is_orig: bool)
	{
	rec$uid = c$uid;
	rec$src = cat(is_orig ? c$id$orig_h : c$id$resp_h);
	rec$dst = cat(is_orig ? c$id$resp_h : c$id$orig_h);
	rec$src_port = port_to_count(is_orig ? c$id$orig_p : c$id$resp_p);
	rec$dst_port = port_to_count(is_orig ? c$id$resp_p : c$id$orig_p);
	}

function ptp_set_timestamp(rec: PTPInfo, t: PTP::Timestamp)
	{
	rec$timestamp_sec = (t$secondsMSB * 4294967296) + t$secondsLSB;
	rec$timestamp_ns = t$nanoSeconds;
	}

function ptp_set_requesting(rec: PTPInfo, id: PTP::PortIdentity)
	{
	rec$requesting_clock_id = bytestring_to_hexstr(id$clockIdentity);
	rec$requesting_port = id$portNumber;
	}

function ptp_log(rec: PTPInfo)
	{
	Log::write(LOG_PTP, rec);
	ids_publish("ptp", rec);
	}

function ptp_make_announceMsg(m: PTP::AnnounceMessage): PTPInfo
	{
	local rec = ptp_info(m$messageHeader, "Announce");
	local a = m$announceField;
	ptp_set_timestamp(rec, a$originTimestamp);
	rec$current_utc_offset = a$currentUtcOffset;
	rec$gm_priority1 = a$grandmasterPriority1;
	rec$gm_clock_class = a$grandmasterClockQuality$clockClass;
	rec$gm_clock_accuracy = a$grandmasterClockQuality$clockAccuracy;
	rec$gm_offset_scaled_log_variance = a$grandmasterClockQuality$offsetScaledLogVariance;
	rec$gm_priority2 = a$grandmasterPriority2;
	rec$gm_identity = bytestring_to_hexstr(a$grandmasterIdentity);
	rec$steps_removed = a$stepsRemoved;
	rec$time_source = a$timeSource;
	return rec;
	}

event ptp_announceMsg(p: raw_pkt_hdr, m: PTP::AnnounceMessage)
	{
	local rec = ptp_make_announceMsg(m);
	ptp_ctx_packet(rec, p);
	ptp_log(rec);
	}

function ptp_make_syncMsg(m: PTP::SyncMessage): PTPInfo
	{
	local rec = ptp_info(m$messageHeader, "Sync");
	ptp_set_timestamp(rec, m$syncField$originTimestamp);
	return rec;
	}

event ptp_syncMsg(p: raw_pkt_hdr, m: PTP::SyncMessage)
	{
	local rec = ptp_make_syncMsg(m);
	ptp_ctx_packet(rec, p);
	ptp_log(rec);
	}

function ptp_make_delayReqMsg(m: PTP::DelayReqMessage): PTPInfo
	{
	local rec = ptp_info(m$messageHeader, "Delay_Req");
	ptp_set_timestamp(rec, m$delayReqField$originTimestamp);
	return rec;
	}

event ptp_delayReqMsg(p: raw_pkt_hdr, m: PTP::DelayReqMessage)
	{
	local rec = ptp_make_delayReqMsg(m);
	ptp_ctx_packet(rec, p);
	ptp_log(rec);
	}

function ptp_make_followUpMsg(m: PTP::FollowUpMessage): PTPInfo
	{
	local rec = ptp_info(m$messageHeader, "Follow_Up");
	ptp_set_timestamp(rec, m$followUpField$preciseOriginTimestamp);
	return rec;
	}

event ptp_followUpMsg(p: raw_pkt_hdr, m: PTP::FollowUpMessage)
	{
	local rec = ptp_make_followUpMsg(m);
	ptp_ctx_packet(rec, p);
	ptp_log(rec);
	}

function ptp_make_delayRespMsg(m: PTP::DelayRespMessage): PTPInfo
	{
	local rec = ptp_info(m$messageHeader, "Delay_Resp");
	ptp_set_timestamp(rec, m$delayRespField$receiveTimestamp);
	ptp_set_requesting(rec, m$delayRespField$requestingPortIdentity);
	return rec;
	}

event ptp_delayRespMsg(p: raw_pkt_hdr, m: PTP::DelayRespMessage)
	{
	local rec = ptp_make_delayRespMsg(m);
	ptp_ctx_packet(rec, p);
	ptp_log(rec);
	}

function ptp_make_pdelayReqMsg(m: PTP::PdelayReqMessage): PTPInfo
	{
	local rec = ptp_info(m$messageHeader, "Pdelay_Req");
	ptp_set_timestamp(rec, m$pdelayReqField$originTimestamp);
	return rec;
	}

event ptp_pdelayReqMsg(p: raw_pkt_hdr, m: PTP::PdelayReqMessage)
	{
	local rec = ptp_make_pdelayReqMsg(m);
	ptp_ctx_packet(rec, p);
	ptp_log(rec);
	}

function ptp_make_pdelayRespMsg(m: PTP::PdelayRespMessage): PTPInfo
	{
	local rec = ptp_info(m$messageHeader, "Pdelay_Resp");
	ptp_set_timestamp(rec, m$pdelayRespField$requestReceiptTimestamp);
	ptp_set_requesting(rec, m$pdelayRespField$requestingPortIdentity);
	return rec;
	}

event ptp_pdelayRespMsg(p: raw_pkt_hdr, m: PTP::PdelayRespMessage)
	{
	local rec = ptp_make_pdelayRespMsg(m);
	ptp_ctx_packet(rec, p);
	ptp_log(rec);
	}

function ptp_make_pdelayRespFollowUpMsg(m: PTP::PdelayRespFollowUpMessage): PTPInfo
	{
	local rec = ptp_info(m$messageHeader, "Pdelay_Resp_Follow_Up");
	ptp_set_timestamp(rec, m$pdelayRespFollowUpField$responseOriginTimestamp);
	ptp_set_requesting(rec, m$pdelayRespFollowUpField$requestingPortIdentity);
	return rec;
	}

event ptp_pdelayRespFollowUpMsg(p: raw_pkt_hdr, m: PTP::PdelayRespFollowUpMessage)
	{
	local rec = ptp_make_pdelayRespFollowUpMsg(m);
	ptp_ctx_packet(rec, p);
	ptp_log(rec);
	}

function ptp_make_signalingMsg(m: PTP::SignalingMessage): PTPInfo
	{
	local rec = ptp_info(m$messageHeader, "Signaling");
	rec$target_clock_id = bytestring_to_hexstr(m$signalingField$targetPortIdentity$clockIdentity);
	rec$target_port = m$signalingField$targetPortIdentity$portNumber;
	rec$tlv_type = m$signalingField$tlv$tlvType;
	rec$tlv_length = m$signalingField$tlv$lengthField;
	return rec;
	}

event ptp_signalingMsg(p: raw_pkt_hdr, m: PTP::SignalingMessage)
	{
	local rec = ptp_make_signalingMsg(m);
	ptp_ctx_packet(rec, p);
	ptp_log(rec);
	}

function ptp_make_managementMsg(m: PTP::ManagementMessage): PTPInfo
	{
	local rec = ptp_info(m$messageHeader, "Management");
	local f = m$managementField;
	rec$target_clock_id = bytestring_to_hexstr(f$targetPortIdentity$clockIdentity);
	rec$target_port = f$targetPortIdentity$portNumber;
	rec$action_field = f$actionField;
	rec$tlv_type = f$managementTLV$tlvType;
	rec$tlv_length = f$managementTLV$lengthField;
	rec$management_id = f$managementTLV$managementId;
	return rec;
	}

event ptp_managementMsg(p: raw_pkt_hdr, m: PTP::ManagementMessage)
	{
	local rec = ptp_make_managementMsg(m);
	ptp_ctx_packet(rec, p);
	ptp_log(rec);
	}

event ptp_unknownMsg(p: raw_pkt_hdr, m: PTP::UnknownMessage)
	{
	event parse_error(p, "PTP", fmt("reserved messageType 0x%x", m$messageType));
	}

# Smallest valid messageLength per messageType: 34-octet header plus the mandatory body.
const ptp_min_length: table[count] of count = {
	[0x0] = 44,   # Sync
	[0x1] = 44,   # Delay_Req
	[0x2] = 54,   # Pdelay_Req
	[0x3] = 54,   # Pdelay_Resp
	[0x8] = 44,   # Follow_Up
	[0x9] = 54,   # Delay_Resp
	[0xA] = 54,   # Pdelay_Resp_Follow_Up
	[0xB] = 64,   # Announce
	[0xC] = 48,   # Signaling: target port identity and one TLV header
	[0xD] = 54,   # Management: target port identity, 4 octets, management TLV header
};

# Ethernet pads the payload to 46 octets, so shorter messages (e.g. Sync, 44) may arrive with padding.
const ptp_padding_floor = 46;

## Problems with the declared length of a PTP message. `floor` is the smallest payload the carrier can
## deliver for a short message: Ethernet pads to 46 octets, UDP does not pad.
function ptp_length_problems(msg_type: count, declared: count, actual: count, floor: count): vector of string
	{
	local problems: vector of string;

	if ( msg_type in ptp_min_length && declared < ptp_min_length[msg_type] )
		problems += fmt("messageLength %d below the minimum %d for messageType 0x%x", declared, ptp_min_length[msg_type], msg_type);

	if ( declared > actual )
		problems += fmt("messageLength %d exceeds the PTP payload of %d octets", declared, actual);
	else if ( actual > (declared > floor ? declared : floor) )
		problems += fmt("%d octets beyond messageLength %d", actual - declared, declared);

	return problems;
	}

event ptp_frame(p: raw_pkt_hdr, msg_type: count, declared: count, actual: count)
	{
	for ( _, msg in ptp_length_problems(msg_type, declared, actual, ptp_padding_floor) )
		event parse_error(p, "PTP", msg);
	}

event ptp_udp_frame(c: connection, is_orig: bool, f: PTP::PTPBody)
	{
	for ( _, msg in ptp_length_problems(f$messageType, f$declaredLength, f$actualLength, 0) )
		event parse_error_udp(c, "PTP", msg);

	local rec: PTPInfo;

	if ( f?$syncMessage ) rec = ptp_make_syncMsg(f$syncMessage);
	else if ( f?$delayReqMessage ) rec = ptp_make_delayReqMsg(f$delayReqMessage);
	else if ( f?$pdelayReqMessage ) rec = ptp_make_pdelayReqMsg(f$pdelayReqMessage);
	else if ( f?$pdelayRespMessage ) rec = ptp_make_pdelayRespMsg(f$pdelayRespMessage);
	else if ( f?$followUpMessage ) rec = ptp_make_followUpMsg(f$followUpMessage);
	else if ( f?$delayRespMessage ) rec = ptp_make_delayRespMsg(f$delayRespMessage);
	else if ( f?$pdelayRespFollowUpMessage ) rec = ptp_make_pdelayRespFollowUpMsg(f$pdelayRespFollowUpMessage);
	else if ( f?$announceMessage ) rec = ptp_make_announceMsg(f$announceMessage);
	else if ( f?$signalingMessage ) rec = ptp_make_signalingMsg(f$signalingMessage);
	else if ( f?$managementMessage ) rec = ptp_make_managementMsg(f$managementMessage);
	else
		{
		if ( f?$unknownMessage )
			event parse_error_udp(c, "PTP", fmt("reserved messageType 0x%x", f$unknownMessage$messageType));
		return;
		}

	ptp_ctx_conn(rec, c, is_orig);
	ptp_log(rec);
	}

event zeek_init() &priority=5
	{
	Log::create_stream(LOG_PTP, [$columns=PTPInfo, $path="ptp"]);
	}
