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
#
#
# This file was updated: IEEE Std 1588 and IEEE Std 802.1AS (g)PTP support for Spicy by
#
# (C) 2024 Ahmed Abdulfattah, Berlin, Germany
# Released under GNU Public License (GPL)
# email ahmed.abdulfattah@posteo.de
# -----------------------------------------------------------

module TSN;
@load policy/protocols/conn/vlan-logging
@load policy/protocols/conn/mac-logging
@load base/frameworks/notice


export {
	redef enum Log::ID += { LOG_CB, LOG_SRP_TALKER, LOG_SRP_LISTENER, LOG_PTP
	};

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

	type TLV: record {
		TLVType	: count &log;
		length	: count &log;
		value	: vector of count &log;
	};

	type ManagementTLV: record {
		tlvType			: count &log;
		lengthField		: count &log;
		managementId	: count &log;
		dataField		: vector of count &log;
	};


	type ClockQuality: record {
		clockClass				: count &log;
		clockAccuracy			: count &log;
		offsetScaledLogVariance	: count &log;
	};

	type Timestamp: record {
		secondsMSB	: count &log;
		secondsLSB	: count &log;
		nanoSeconds	: count &log;
	};

	type Version: record {
		versionPTP		: count &log;
		minorVersionPTP	: count &log;
	};

	type Flags: record {
		alternateMasterFlag			: count &log;
        twoStepFlag					: count &log;
        unicastFlag					: count &log;
        reserved_3					: count &log;
        reserved_4					: count &log;
        ptp_profile_specific_1		: count &log;
        ptp_profile_specific_2		: count &log;
        reserved_7					: count &log;
        leap61						: count &log;
        leap59						: count &log;
        currentUtcOffsetValid		: count &log;
        ptpTimescale				: count &log;
        timeTraceable				: count &log;
        frequencyTraceable			: count &log;
        synchronizationUncertain	: count &log;
        reserved_15					: count &log;
	};

	type PortIdentity: record {
		clockIdentity	: vector of count;
    	portNumber		: count &log;
	};

	type PTP_AnnounceField: record {
		originTimestamp			: Timestamp &log;
		currentUtcOffset		: count &log;
		reserved				: count &log;
		grandmasterPriority1	: count &log;
		grandmasterClockQuality	: ClockQuality &log;
		grandmasterPriority2	: count &log;
		grandmasterIdentity		: vector of count &log;
		stepsRemoved			: count &log;
		timeSource				: count &log;
	};

	type PTP_MessageHeader: record {
		version							: Version &log;
		messageLength					: count &log;
		domainNumber					: count &log;
		minorSdoId						: count &log;
		flags							: Flags &log;
		correctionField					: count &log;
		messageTypeSpecific				: count;
		sourcePortIdentity				: PortIdentity &log;
		sequenceId						: count &log;
		controlField					: count;
		logMessageInterval				: count;
	};


	type PTP_AnnounceMessage: record {
		messageHeader	: PTP_MessageHeader &log;
		announceField	: PTP_AnnounceField &log;
	};


	type PTP_SyncField: record {
		originTimestamp: Timestamp &log;
	};

	type PTP_SyncMessage: record {
		messageHeader	: PTP_MessageHeader &log;
		syncField		: PTP_SyncField &log;
	};

	type PTP_DelayReqField: record {
		originTimestamp: Timestamp &log;
	};

	type PTP_DelayReqMessage: record {
		messageHeader: PTP_MessageHeader &log;
		delayReqField: PTP_DelayReqField &log;
	};

	type PTP_FollowUpField: record {
		preciseOriginTimestamp: Timestamp &log;
	};

	type PTP_FollowUpMessage: record {
		messageHeader: PTP_MessageHeader &log;
		followUpField: PTP_FollowUpField &log;
	};

	type PTP_DelayRespField: record {
		receiveTimestamp		: Timestamp &log;
		requestingPortIdentity	: PortIdentity &log;
	};

	type PTP_DelayRespMessage: record {
		messageHeader	: PTP_MessageHeader &log;
		delayRespField	: PTP_DelayRespField &log;
	};

	type PTP_PdelayReqField: record {
		originTimestamp	: Timestamp &log;
		reserved		: vector of count;
	};

	type PTP_PdelayReqMessage: record {
		messageHeader	: PTP_MessageHeader &log;
		pdelayReqField	: PTP_PdelayReqField &log;
	};

	type PTP_PdelayRespField: record {
		requestReceiptTimestamp	: Timestamp &log;
		requestingPortIdentity	: PortIdentity &log;
	};

	type PTP_PdelayRespMessage: record {
		messageHeader	: PTP_MessageHeader &log;
		pdelayRespField	: PTP_PdelayRespField &log;
	};

	type PTP_PdelayRespFollowUpField: record {
		responseOriginTimestamp	: Timestamp &log;
		requestingPortIdentity	: PortIdentity &log;
	};


	type PTP_PdelayRespFollowUpMessage: record {
		messageHeader			: PTP_MessageHeader &log;
		pdelayRespFollowUpField	: PTP_PdelayRespFollowUpField &log;
	};

	type PTP_SignalingField: record {
		targetPortIdentity	: PortIdentity &log;
		tlv					: TLV &log;
	};

	type PTP_SignalingMessage: record {
		messageHeader	: PTP_MessageHeader &log;
		signalingField	: PTP_SignalingField &log;
	};

	type PTP_ManagementField: record {
		targetPortIdentity		: PortIdentity &log;
		startingBoundaryHops	: count &log;
		boundaryHops			: count &log;
		actionField				: count &log;
		reserverd				: count &log;
		managementTLV			: ManagementTLV;
	};

	type PTP_ManagementMessage: record {
		messageHeader	: PTP_MessageHeader &log;
		managementField	: PTP_ManagementField &log;
	};


	type PTP_ManagementField: record {
		targetPortIdentity		: PortIdentity &log;
		startingBoundaryHops	: count &log;
		boundaryHops			: count &log;
		actionField				: count &log;
		reserverd				: count &log;
		managementTLV			: ManagementTLV &log;
	};


	type PTPAnnounceInfo: record {
		ts:				time &log;
		src:			string &log;
		dst:			string &log;
		vlan:			count &log;
		msg_hdr:		PTP_MessageHeader &log;
		announceField:	PTP_AnnounceField &log;
	};

	type PTPSyncInfo: record {
		ts:			time &log;
		src:		string &log;
		dst:		string &log;
		vlan:		count &log;
		msg_hdr:	PTP_MessageHeader &log;
		syncField:	PTP_SyncField &log;
	};

	type PTPDelayReqInfo: record {
		ts:					time &log;
		src:				string &log;
		dst:				string &log;
		vlan:				count &log;
		msg_hdr:			PTP_MessageHeader &log;
		delayReqField:		PTP_DelayReqField &log;
	};

	type PTPFollowUpInfo: record {
		ts:					time &log;
		src:				string &log;
		dst:				string &log;
		vlan:				count &log;
		msg_hdr:			PTP_MessageHeader &log;
		followUpField:		PTP_FollowUpField &log;
	};

	type PTPDelayRespInfo: record {
		ts:					time &log;
		src:				string &log;
		dst:				string &log;
		vlan:				count &log;
		msg_hdr:			PTP_MessageHeader &log;
		delayRespField:		PTP_DelayRespField &log;
	};

	type PTPPdelayReqInfo: record {
		ts:					time &log;
		src:				string &log;
		dst:				string &log;
		vlan:				count &log;
		msg_hdr:			PTP_MessageHeader &log;
		pdelayReqField:		PTP_PdelayReqField &log;
	};

	type PTPPdelayRespInfo: record {
		ts:					time &log;
		src:				string &log;
		dst:				string &log;
		vlan:				count &log;
		msg_hdr:			PTP_MessageHeader &log;
		pdelayRespField:	PTP_PdelayRespField &log;
	};

	type PTPPdelayRespFollowUpInfo: record {
		ts:							time &log;
		src:						string &log;
		dst:						string &log;
		vlan:						count &log;
		msg_hdr:					PTP_MessageHeader &log;
		pdelayRespFollowUpField:	PTP_PdelayRespFollowUpField &log;
	};

	type PTPSignalingInfo: record {
		ts:					time &log;
		src:				string &log;
		dst:				string &log;
		vlan:				count &log;
		msg_hdr:			PTP_MessageHeader &log;
		signalingField:		PTP_SignalingField &log;
	};

	type PTPManagementInfo: record {
		ts:					time &log;
		src:				string &log;
		dst:				string &log;
		vlan:				count &log;
		msg_hdr:			PTP_MessageHeader &log;
		managementField:	PTP_ManagementField &log;
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

event TSN::ptp_announceMsg(p: raw_pkt_hdr, hdr: PTP_AnnounceMessage)
{
	local rec: TSN::PTPAnnounceInfo = [
		$ts = network_time(),
		$src = p$l2$src,
		$dst = p$l2$dst,
		$vlan = p$l2$vlan,
		$msg_hdr = hdr$messageHeader,
		$announceField = hdr$announceField];
		
	Log::write(TSN::LOG_PTP, rec);
	print("PTP Announce message received");
}

event TSN::ptp_syncMsg(p: raw_pkt_hdr, hdr: PTP_SyncMessage)
{
	print("PTP Sync message received");
	local rec: TSN::PTPSyncInfo = [
		$ts = network_time(),
		$src = p$l2$src,
		$dst = p$l2$dst,
		$vlan = p$l2$vlan,
		$msg_hdr = hdr$messageHeader,
		$syncField = hdr$syncField];
		
	Log::write(TSN::LOG_PTP, rec);
	print("PTP Sync message received");
}

event TSN::ptp_delayReqMsg(p: raw_pkt_hdr, hdr: PTP_DelayReqMessage)
{
	local rec: TSN::PTPDelayReqInfo = [
		$ts = network_time(),
		$src = p$l2$src,
		$dst = p$l2$dst,
		$vlan = p$l2$vlan,
		$msg_hdr = hdr$messageHeader,
		$delayReqField = hdr$delayReqField];
		
	Log::write(TSN::LOG_PTP, rec);
	print("PTP DelayReq message received");
}

event TSN::ptp_followUpMsg(p: raw_pkt_hdr, hdr: PTP_FollowUpMessage)
{
	local rec: TSN::PTPFollowUpInfo = [
		$ts = network_time(),
		$src = p$l2$src,
		$dst = p$l2$dst,
		$vlan = p$l2$vlan,
		$msg_hdr = hdr$messageHeader,
		$followUpField = hdr$followUpField];
		
	Log::write(TSN::LOG_PTP, rec);
	print("PTP FollowUp message received");
}

event TSN::ptp_delayRespMsg(p: raw_pkt_hdr, hdr: PTP_DelayRespMessage)
{
	local rec: TSN::PTPDelayRespInfo = [
		$ts = network_time(),
		$src = p$l2$src,
		$dst = p$l2$dst,
		$vlan = p$l2$vlan,
		$msg_hdr = hdr$messageHeader,
		$delayRespField = hdr$delayRespField];
		
	Log::write(TSN::LOG_PTP, rec);
	print("PTP DelayResp message received");
}

event TSN::ptp_pdelayReqMsg(p: raw_pkt_hdr, hdr: PTP_PdelayReqMessage)
{
	local rec: TSN::PTPPdelayReqInfo = [
		$ts = network_time(),
		$src = p$l2$src,
		$dst = p$l2$dst,
		$vlan = p$l2$vlan,
		$msg_hdr = hdr$messageHeader,
		$pdelayReqField = hdr$pdelayReqField];
		
	Log::write(TSN::LOG_PTP, rec);
	print("PTP PdelayReq message received");
}

event TSN::ptp_pdelayRespMsg(p: raw_pkt_hdr, hdr: PTP_PdelayRespMessage)
{
	local rec: TSN::PTPPdelayRespInfo = [
		$ts = network_time(),
		$src = p$l2$src,
		$dst = p$l2$dst,
		$vlan = p$l2$vlan,
		$msg_hdr = hdr$messageHeader,
		$pdelayRespField = hdr$pdelayRespField];
		
	Log::write(TSN::LOG_PTP, rec);
	print("PTP PdelayResp message received");
}


event TSN::ptp_pdelayRespFollowUpMsg(p: raw_pkt_hdr, hdr: PTP_PdelayRespFollowUpMessage)
{
	local rec: TSN::PTPPdelayRespFollowUpInfo = [
		$ts = network_time(),
		$src = p$l2$src,
		$dst = p$l2$dst,
		$vlan = p$l2$vlan,
		$msg_hdr = hdr$messageHeader,
		$pdelayRespFollowUpField = hdr$pdelayRespFollowUpField];
		
	Log::write(TSN::LOG_PTP, rec);
	print("PTP PdelayRespFollowUp message received");
}


event TSN::ptp_signalingMsg(p: raw_pkt_hdr, hdr: PTP_SignalingMessage)
{
	local rec: TSN::PTPSignalingInfo = [
		$ts = network_time(),
		$src = p$l2$src,
		$dst = p$l2$dst,
		$vlan = p$l2$vlan,
		$msg_hdr = hdr$messageHeader,
		$signalingField = hdr$signalingField];
		
	Log::write(TSN::LOG_PTP, rec);
	print("PTP Signaling message received");
}


event TSN::ptp_managementMsg(p: raw_pkt_hdr, hdr: PTP_ManagementMessage)
{
	local rec: TSN::PTPManagementInfo = [
		$ts = network_time(),
		$src = p$l2$src,
		$dst = p$l2$dst,
		$vlan = p$l2$vlan,
		$msg_hdr = hdr$messageHeader,
		$managementField = hdr$managementField];
		
	Log::write(TSN::LOG_PTP, rec);
	print("PTP Management message received");
}


event raise_notice(msg: string)
{
	NOTICE([$note=Possible_Attack, $msg=msg]);
}

event zeek_init() &priority=5
	{
	print("zeek_init() started");
	Log::create_stream(TSN::LOG_CB, [$columns=CBInfo, $path="cb"]);
	Log::create_stream(TSN::LOG_SRP_TALKER, [$columns=SRPTalkerEnhancedInfo, $path="TSN_SRPTalkerEnhancedInfo"]);
	Log::create_stream(TSN::LOG_SRP_LISTENER, [$columns=SRPListenerEnhancedInfo, $path="TSN_SRPListenerEnhancedInfo"]);
	
	Log::create_stream(TSN::LOG_PTP, [$columns=PTPManagementInfo, $path="ptp"]);
	Log::create_stream(TSN::LOG_PTP, [$columns=PTPSignalingInfo, $path="ptp"]);
	Log::create_stream(TSN::LOG_PTP, [$columns=PTPPdelayRespFollowUpInfo, $path="ptp"]);
	Log::create_stream(TSN::LOG_PTP, [$columns=PTPPdelayRespInfo, $path="ptp"]);
	Log::create_stream(TSN::LOG_PTP, [$columns=PTPPdelayReqInfo, $path="ptp"]);
	Log::create_stream(TSN::LOG_PTP, [$columns=PTPDelayReqInfo, $path="ptp"]);
	Log::create_stream(TSN::LOG_PTP, [$columns=PTPDelayRespInfo, $path="ptp"]);
	Log::create_stream(TSN::LOG_PTP, [$columns=PTPFollowUpInfo, $path="ptp"]);
	Log::create_stream(TSN::LOG_PTP, [$columns=PTPSyncInfo, $path="ptp"]);
	Log::create_stream(TSN::LOG_PTP, [$columns=PTPAnnounceInfo, $path="ptp"]);

	Broker::listen("127.0.0.1", 9999/tcp);
	Broker::auto_publish("/topic/tsn/cb", TSN::cb_message);
	Broker::auto_publish("/topic/tsn/srp/talker_enhanced", TSN::talkerEnhanced_FirstValueMsg);
	Broker::auto_publish("/topic/tsn/srp/listener_enhanced", TSN::listenerEnhanced_FirstValueMsg);

	Broker::auto_publish("/topic/tsn/ptp", TSN::ptp_syncMsg);
	Broker::auto_publish("/topic/tsn/ptp", TSN::ptp_delayReqMsg);
	Broker::auto_publish("/topic/tsn/ptp", TSN::ptp_followUpMsg);
	Broker::auto_publish("/topic/tsn/ptp", TSN::ptp_delayRespMsg);
	Broker::auto_publish("/topic/tsn/ptp", TSN::ptp_pdelayReqMsg);
	Broker::auto_publish("/topic/tsn/ptp", TSN::ptp_pdelayRespMsg);
	Broker::auto_publish("/topic/tsn/ptp", TSN::ptp_pdelayRespFollowUpMsg);
	Broker::auto_publish("/topic/tsn/ptp", TSN::ptp_signalingMsg);
	Broker::auto_publish("/topic/tsn/ptp", TSN::ptp_managementMsg);


	Broker::subscribe("/topic/tsn");
	}