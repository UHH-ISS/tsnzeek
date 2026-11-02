# -----------------------------------------------------------
#
#  main.zeek
#
# Shared definitions for TSNZeek: options, the parse error log and the
# helper that forwards events to the external IDS.
#
# (C) 2022 Robin Schenderlein, Hamburg, Germany
# (C) 2024 Ahmed Abdulfattah, Berlin, Germany
# (C) 2026 Doganalp Ergenc, written with the assistance of Claude
# Released under GNU Public License (GPL)
# -----------------------------------------------------------

module TSN;

@load base/frameworks/notice
@load policy/protocols/conn/vlan-logging
@load policy/protocols/conn/mac-logging

export {
	## Forward events to an external IDS over Broker. Disable for offline pcap runs.
	const enable_broker = T &redef;

	redef enum Log::ID += { LOG_ERRORS };

	redef enum Notice::Type += {
		Possible_Attack
	};

	type ErrorInfo: record {
		ts:        time   &log;
		src:       string &log &optional;
		dst:       string &log &optional;
		vlan:      count  &log &optional;
		uid:       string &log &optional;
		protocol:  string &log;
		reason:    string &log;
	};

	## Raised when a TSN frame could not be parsed.
	global parse_error: event(p: raw_pkt_hdr, proto: string, msg: string);

	## Raised when a TSN message carried over a connection (e.g. PTP over UDP) could not be parsed.
	global parse_error_udp: event(c: connection, proto: string, msg: string);

	## Format a 6-octet MAC address as aa:bb:cc:dd:ee:ff.
	global mac_str: function(b: string): string;

	## One parsed TSN message for the external IDS. `kind` is "cb", "ptp" or "srp"; `data` is the JSON
	## encoding of the record that is also written to the respective log.
	global ids_message: event(kind: string, data: string);

	## Send a log record to the external IDS; a no-op unless enable_broker is set.
	global ids_publish: function(kind: string, rec: any);
}

function mac_str(b: string): string
	{
	local h = bytestring_to_hexstr(b);
	return fmt("%s:%s:%s:%s:%s:%s", h[0:2], h[2:4], h[4:6], h[6:8], h[8:10], h[10:12]);
	}

function ids_publish(kind: string, rec: any)
	{
	if ( enable_broker )
		Broker::publish("/topic/tsn", Broker::make_event(ids_message, kind, to_json(rec, T)));
	}

# Spicy appends the grammar location, e.g. " (/path/FRER.spicy:17:19-17:24)"; it is machine-specific.
function error_reason(msg: string): string
	{
	return sub(msg, /[[:blank:]]\([^()]*\.spicy:[0-9:-]+\)$/, "");
	}

event parse_error_udp(c: connection, proto: string, msg: string)
	{
	Log::write(LOG_ERRORS, ErrorInfo($ts = network_time(), $uid = c$uid, $src = cat(c$id$orig_h),
	                                 $dst = cat(c$id$resp_h), $protocol = proto, $reason = error_reason(msg)));
	}

event parse_error(p: raw_pkt_hdr, proto: string, msg: string)
	{
	local rec = ErrorInfo($ts = network_time(), $protocol = proto, $reason = error_reason(msg));
	if ( p?$l2 )
		{
		if ( p$l2?$src ) rec$src = p$l2$src;
		if ( p$l2?$dst ) rec$dst = p$l2$dst;
		if ( p$l2?$vlan ) rec$vlan = p$l2$vlan;
		}
	Log::write(LOG_ERRORS, rec);
	}

event zeek_init() &priority=5
	{
	Log::create_stream(LOG_ERRORS, [$columns=ErrorInfo, $path="tsn_errors"]);
	}
