#!/usr/bin/env python3

# -----------------------------------------------------------
#
#  srp.py --- IEEE 802.1Qcc Enhancements to SRP support for Scapy
#
# (C) 2022 Robin Schenderlein, Hamburg, Germany
# Released under GNU Public License (GPL)
# email robin.schenderlein@studium.uni-hamburg.de
# -----------------------------------------------------------

# scapy.contrib.description = IEEE 802.1Qcc
# scapy.contrib.status = loads

import logging

from scapy.config import conf
from scapy.fields import ShortField, MACField, BitField, ByteField, IntField, IPField, IP6Field, \
    ByteEnumField, FieldLenField, FieldListField, StrLenField, PacketListField
from scapy.layers.l2 import Ether
from scapy.main import interact
from scapy.packet import Packet, bind_layers

logger = logging.getLogger("scapy")
logger.setLevel(logging.INFO)

talkerStatus = {
    0: "None",
    1: "Ready",
    2: "Failed"
}

listenerStatus = {
    0: "None",
    1: "Ready",
    2: "PartialFailed",
    3: "Failed"
}


class SrpGenericTlv(Packet):
    name = "SRP Generic TLV"
    fields_desc = [ByteField("TLV_type", 0),
                   FieldLenField("TLV_length", None, length_of="value", fmt="B"),
                   StrLenField("value", b'', length_from=lambda x: x.TLV_length)
                   ]

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt and len(_pkt) >= 2:
            t = _pkt[:1][0]
            cls = _SRP_TLV_CLS.get(t, "DtpGenericTlv")
        return cls

    def guess_payload_class(self, p):
        return conf.padding_layer


class SrpGenericDataFrameSpecTlv(SrpGenericTlv):
    name = "SRP Generic DataFrameSpec TLV"


class Talker(SrpGenericTlv):
    name = "Talker"
    fields_desc = [ByteField("TLV_type", 1),
                   FieldLenField("TLV_length", None, length_of="tlvlist", fmt="B"),
                   PacketListField("tlvlist", [], SrpGenericTlv, length_from=lambda x: x.TLV_length)]


class StreamID(SrpGenericTlv):
    name = "StreamID"
    fields_desc = [ByteField("TLV_type", 2),
                   ByteField("TLV_length", 8),
                   MACField("MacAddress", "00:00:00:00:00:00"),
                   ShortField("UniqueID", 0)]


class StreamRank(SrpGenericTlv):
    name = "StreamRank"
    fields_desc = [ByteField("TLV_type", 3),
                   ByteField("TLV_length", 1),
                   BitField("reserved", 0, 7),
                   BitField("Rank", 1, 1)]


class InterfaceID(SrpGenericTlv):
    name = "Interface_ID"
    fields_desc = [ByteField("TLV_type", 5),
                   FieldLenField("TLV_length", None, length_of="InterfaceName", fmt="B", adjust=lambda pkt, x: x + 6),
                   MACField("MacAddress", "00:00:00:00:00:00"),
                   StrLenField("InterfaceName", b'', length_from=lambda x: x.TLV_length - 6)]


class EndStationInterfaces(SrpGenericTlv):
    name = "EndStationInterfaces"
    fields_desc = [ByteField("TLV_type", 4),
                   FieldLenField("TLV_length", None, length_of="interfaces", fmt="B"),
                   PacketListField("interfaces", None, InterfaceID, length_from=lambda x: x.TLV_length)
                   ]


class IEEE802MacAddresses(SrpGenericTlv):
    name = "IEEE802MacAddresses"
    fields_desc = [ByteField("TLV_type", 7),
                   ByteField("TLV_length", 12),
                   MACField("DestinationMacAddress", "00:00:00:00:00:00"),
                   MACField("SourceMacAddress", "00:00:00:00:00:00")]


class IEEE802VlanTag(SrpGenericTlv):
    name = "IEEE802VlanTag"
    fields_desc = [ByteField("TLV_type", 8),
                   ByteField("TLV_length", 12),
                   ByteField("PriorityCodePoint", 0),
                   ShortField("VlanId", 0)]


class IPv4tuple(SrpGenericTlv):
    name = "IPv4tuple"
    fields_desc = [ByteField("TLV_type", 9),
                   ByteField("TLV_length", 15),
                   IPField("SourceIpAddress", "0.0.0.0"),
                   IPField("DestinationIpAddress", "0.0.0.0"),
                   ByteField("Dscp", 0),
                   ShortField("Protocol", 0),
                   ShortField("SourcePort", 0),
                   ShortField("DestinationPort", 0)]


class IPv6tuple(SrpGenericTlv):
    name = "IPv6tuple"
    fields_desc = [ByteField("TLV_type", 10),
                   ByteField("TLV_length", 39),
                   IP6Field("SourceIpAddress", "::"),
                   IP6Field("DestinationIpAddress", "::"),
                   ByteField("Dscp", 0),
                   ShortField("Protocol", 0),
                   ShortField("SourcePort", 0),
                   ShortField("DestinationPort", 0)]


class DataFrameSpecification(SrpGenericTlv):
    name = "DataFrameSpecification"
    fields_desc = [ByteField("TLV_type", 6),
                   FieldLenField("TLV_length", None, length_of="tlvlist", fmt="B"),
                   PacketListField("tlvlist", [], SrpGenericTlv, length_from=lambda x: x.TLV_length)]


class TrafficSpecification(SrpGenericTlv):
    name = "TrafficSpecification"
    fields_desc = [ByteField("TLV_type", 11),
                   ByteField("TLV_length", 13),
                   IntField("IntervalNumerator", 0),
                   IntField("IntervalDenominator", 1),
                   ShortField("MaxFramesPerInterval", 0),
                   ShortField("MaxFrameSize", 0),
                   ByteField("TransmissionSelection", 0)]


class TSpecTimeAware(SrpGenericTlv):
    name = "TSpecTimeAware"
    fields_desc = [ByteField("TLV_type", 12),
                   ByteField("TLV_length", 12),
                   IntField("EarliestTransmitOffset", 0),
                   IntField("LatestTransmitOffset", 0),
                   IntField("Jitter", 0)]


class UserToNetworkRequirements(SrpGenericTlv):
    name = "UserToNetworkRequirements"
    fields_desc = [ByteField("TLV_type", 13),
                   ByteField("TLV_length", 5),
                   ByteField("NumSeamlessTrees", 0),
                   IntField("MaxLatency", 0)]


class InterfaceCapabilities(SrpGenericTlv):
    name = "InterfaceCapabilities"
    fields_desc = [ByteField("TLV_type", 14),
                   FieldLenField("TLV_length", None, length_of="CBStreamIdenTypeList", fmt="B",
                                 adjust=lambda pkt, val: val + len(pkt.CBSequenceTypeList) * 4 + 3),
                   BitField("reserved", 0, 7),
                   BitField("VlanTagCapable", 1, 1),
                   FieldLenField("NumITL", None, fmt="B", count_of="CBStreamIdenTypeList"),
                   FieldLenField("NumSTL", None, fmt="B", count_of="CBSequenceTypeList"),
                   FieldListField("CBStreamIdenTypeList", [], IntField("CB-StreamIdenType", 0),
                                  count_from=lambda pkt: pkt.NumITL),
                   FieldListField("CBSequenceTypeList", [], IntField("CB-SequenceType", 0),
                                  count_from=lambda pkt: pkt.NumSTL)]


class Listener(SrpGenericTlv):
    name = "Listener"
    fields_desc = [ByteField("TLV_type", 15),
                   FieldLenField("TLV_length", None, length_of="tlvlist", fmt="B"),
                   PacketListField("tlvlist", [], SrpGenericTlv, length_from=lambda x: x.TLV_length)]


class Status(SrpGenericTlv):
    name = "Status"
    fields_desc = [ByteField("TLV_type", 16),
                   FieldLenField("TLV_length", None, length_of="tlvlist", fmt="B"),
                   PacketListField("tlvlist", [], SrpGenericTlv, length_from=lambda x: x.TLV_length)]


class StatusInfo(SrpGenericTlv):
    name = "StatusInfo"
    fields_desc = [ByteField("TLV_type", 17),
                   ByteField("TLV_length", 3),
                   ByteEnumField("TalkerStatus", 0, talkerStatus),
                   ByteEnumField("ListenerStatus", 0, listenerStatus),
                   ByteField("FailureCode", 0)]


class AccumulatedLatency(SrpGenericTlv):
    name = "AccumulatedLatency"
    fields_desc = [ByteField("TLV_type", 18),
                   ByteField("TLV_length", 4),
                   IntField("AccumulatedLatency", 0)]


class TimeAwareOffset(SrpGenericTlv):
    name = "TimeAwareOffset"
    fields_desc = [ByteField("TLV_type", 20),
                   ByteField("TLV_length", 4),
                   IntField("TimeAwareOffset", 0)]


class InterfaceConfiguration(SrpGenericTlv):
    name = "InterfaceConfiguration"
    fields_desc = [ByteField("TLV_type", 19),
                   FieldLenField("TLV_length", None, length_of="tlvlist", fmt="B"),
                   PacketListField("tlvlist", [], SrpGenericTlv, length_from=lambda x: x.TLV_length)]


class FailedInterfaces(SrpGenericTlv):
    name = "FailedInterfaces"
    fields_desc = [ByteField("TLV_type", 21),
                   FieldLenField("TLV_length", None, length_of="interfaces", fmt="B"),
                   PacketListField("interfaces", None, InterfaceID, length_from=lambda x: x.TLV_length)
                   ]


_SRP_TLV_CLS = {
    1: Talker,
    2: StreamID,
    3: StreamRank,
    4: EndStationInterfaces,
    5: InterfaceID,
    6: DataFrameSpecification,
    7: IEEE802MacAddresses,
    8: IEEE802VlanTag,
    9: IPv4tuple,
    10: IPv6tuple,
    11: TrafficSpecification,
    12: TSpecTimeAware,
    13: UserToNetworkRequirements,
    14: InterfaceCapabilities,
    15: Listener,
    16: Status,
    17: StatusInfo,
    18: AccumulatedLatency,
    19: InterfaceConfiguration,
    20: TimeAwareOffset,
    21: FailedInterfaces
}


class SRP(Packet):
    name = "SRP"
    fields_desc = [PacketListField("tlvlist", [], SrpGenericTlv)]


bind_layers(Ether, SRP, type=0x22ea)

if __name__ == "__main__":
    interact(mydict=globals(), mybanner="Test add-on TSN")

    # TODO Hardcode length of fields vs calculation for types with fixed length
