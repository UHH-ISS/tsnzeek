# -----------------------------------------------------------
#
#  main.zeek
#
# This file adds Zeek events and their data structure.
# It defines which fields to log.
# It activates the Zeek Broker.
#
# (C) 2022 Robin Schenderlein, Hamburg, Germany
# Released under GNU Public License (GPL)
# email robin.schenderlein@studium.uni-hamburg.de
# -----------------------------------------------------------

module TSN;
@load policy/protocols/conn/vlan-logging
@load policy/protocols/conn/mac-logging
@load base/frameworks/notice

export {
	redef enum Log::ID += { LOG_CB, LOG_SRP_TALKER, LOG_SRP_LISTENER };

	redef enum Notice::Type += {
		Possible_Attack
	};

	type CBFrameSequenceNr: count;

	type IPTuple: record {
		sourceIpAddress       : addr &log;
		destinationIpAddress  : addr &log;
		dscp                  : count &log;
		protocol              : count &log;
		sourcePort            : count &log;
		destinationPort       : count &log;
	};

	type IEEE802VlanTag: record {
		priorityCodePoint  : count &log;
		vlanId             : count &log;
	};

	type IEEE802MacAddresses: record {
		destinationMacAddress  : string &log;
		sourceMacAddress       : string &log;
	};

	type InterfaceID: record {
		macAddress     : string;
		interfaceName  : string;
	};

	type EndStationInterfaces: vector of InterfaceID;

	type StreamID: record {
		macAddress  : string &log;
		uniqueID    : count &log;
	};

	type StreamRank: count &log;

	type TrafficSpecification: record {
		intervalNumerator      : count &log;
		intervalDenominator    : count &log;
		maxFramesPerInterval   : count &log;
		maxFrameSize           : count &log;
		transmissionSelection  : count &log;
	};

	type DataFrameSpecification: record {
		ieee802MacAddresses  : IEEE802MacAddresses &optional &log;
		ieee802VlanTag       : IEEE802VlanTag &optional &log;
		ipv4Tuple            : IPTuple &optional &log;
		ipv6Tuple            : IPTuple &optional &log;
	};

	type TSpecTimeAware: record {
		earliestTransmitOffset  : count &log;
		latestTransmitOffset    : count &log;
		jitter                  : count &log;
	};

	type InterfaceCapabilities: record {
		vlanTagCapable        : count;
		numITL                : count;
		numSTL                : count;
		cbStreamIdenTypeList  : vector of count;
		cbSequenceTypeList    : vector of count;
	};

	type UserToNetworkRequirements: record {
		numSeamlessTrees  : count &log;
		maxLatency        : count &log;
	};

	type Talker: record {
		streamID                   : StreamID &log;
		streamRank                 : StreamRank &log;
		endStationInterfaces       : EndStationInterfaces &optional;
		dataFrameSpecification     : DataFrameSpecification &optional &log;
		trafficSpecification       : TrafficSpecification &log;
		tSpecTimeAware             : TSpecTimeAware &optional &log;
		userToNetworkRequirements  : UserToNetworkRequirements &optional &log;
		interfaceCapabilities      : InterfaceCapabilities &optional;
	};

	type TimeAwareOffset: count;

	type InterfaceConfiguration: record {
		interfaceID          : InterfaceID;
		ieee802MacAddresses  : IEEE802MacAddresses &optional;
		ieee802VlanTag       : IEEE802VlanTag &optional;
		ipv4Tuple            : IPTuple &optional;
		ipv6Tuple            : IPTuple &optional;
		timeAwareOffset      : TimeAwareOffset &optional;
	};

	type InterfaceConfigurations: vector of InterfaceConfiguration;
	
	type StatusInfo: record {
		talkerStatus    : SRP::EnumTalkerStatus &log;
		listenerStatus  : SRP::EnumListenerStatus &log;
		failureCode     : count &log;
	};

	type AccumulatedLatency: count &log;

	type FailedInterfaces: vector of InterfaceID;

	type Status: record {
		statusInfo               : StatusInfo &log;
		accumulatedLatency       : AccumulatedLatency &log;
		interfaceConfigurations  : InterfaceConfigurations &optional;
		failedInterfaces         : FailedInterfaces &optional;
	};

	type StatusGroup: record {
		statusInfo               : StatusInfo &log;
		interfaceConfigurations  : InterfaceConfigurations &optional;
		failedInterfaces         : FailedInterfaces &optional;
	};

	type Listener: record {
		streamID                   : StreamID &log;
		endStationInterfaces       : EndStationInterfaces &optional;
		userToNetworkRequirements  : UserToNetworkRequirements &optional &log;
		interfaceCapabilities      : InterfaceCapabilities &optional;
	};

	type ListenerEnhanced_FirstValue: record {
		listener     : Listener &log;
		statusGroup  : StatusGroup &log;
	};

	type TalkerEnhanced_FirstValue: record {
		talker  : Talker &log;
		status  : Status &log;
	};

	type CBInfo: record {
		ts:           time &log;
		src:          string &log;
		dst:          string &log;
		vlan:         count &log;
		sequence_nr:  count &log;
	};

	type SRPTalkerEnhancedInfo: record {
		ts:      time &log;
		src:     string &log;
		dst:     string &log;
		vlan:    count &log;
		talker:  Talker &log;
		status:  Status &log;
	};

	type SRPListenerEnhancedInfo: record {
		ts:           time &log;
		src:          string &log;
		dst:          string &log;
		vlan:         count &log;
		listener:     Listener &log;
		statusGroup:  StatusGroup &log;
	};
}

event TSN::listenerEnhanced_FirstValueMsg(p: raw_pkt_hdr, hdr: ListenerEnhanced_FirstValue )
{
	local rec: TSN::SRPListenerEnhancedInfo = [
		$ts = network_time(),
		$src = p$l2$src,
		$dst = p$l2$dst,
		$vlan = p$l2$vlan,
		$listener = hdr$listener,
		$statusGroup = hdr$statusGroup];
	Log::write(TSN::LOG_SRP_LISTENER, rec);
	print("ListenerEnhanced_FirstValue received");
}

event TSN::talkerEnhanced_FirstValueMsg(p: raw_pkt_hdr, hdr: TalkerEnhanced_FirstValue )
{
	local rec: TSN::SRPTalkerEnhancedInfo = [
		$ts = network_time(),
		$src = p$l2$src,
		$dst = p$l2$dst,
		$vlan = p$l2$vlan,
		$talker = hdr$talker,
		$status = hdr$status];
	Log::write(TSN::LOG_SRP_TALKER, rec);
	print("TalkerEnhanced_FirstValue received");
}

event TSN::cb_message(p: raw_pkt_hdr, hdr: CBFrameSequenceNr, ts: time)
{
	local rec: TSN::CBInfo = [
		$ts = network_time(),
		$src = p$l2$src,
		$dst = p$l2$dst,
		$vlan = p$l2$vlan,
		$sequence_nr = hdr];
	Log::write(TSN::LOG_CB, rec);
	print("FRER frame received");
}

event raise_notice(msg: string)
{
	NOTICE([$note=Possible_Attack, $msg=msg]);
}

event zeek_init() &priority=5
	{
	Log::create_stream(TSN::LOG_CB, [$columns=CBInfo, $path="cb"]);
	Log::create_stream(TSN::LOG_SRP_TALKER, [$columns=SRPTalkerEnhancedInfo, $path="TSN_SRPTalkerEnhancedInfo"]);
	Log::create_stream(TSN::LOG_SRP_LISTENER, [$columns=SRPListenerEnhancedInfo, $path="TSN_SRPListenerEnhancedInfo"]);
	Broker::listen("127.0.0.1", 9999/tcp);
	Broker::auto_publish("/topic/tsn/cb", TSN::cb_message);
	Broker::auto_publish("/topic/tsn/srp/talker_enhanced", TSN::talkerEnhanced_FirstValueMsg);
	Broker::auto_publish("/topic/tsn/srp/listener_enhanced", TSN::listenerEnhanced_FirstValueMsg);
	Broker::subscribe("/topic/tsn");
	}
