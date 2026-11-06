#!/usr/bin/env python3
# (C) 2026 Doganalp Ergenc, written with the assistance of Claude

# IEEE 1588 / 802.1AS (gPTP) header for Scapy, and the small helpers that build message bodies.
# The tests, the demo and the sample senders build their PTP frames with it.

# scapy.contrib.description = IEEE 1588 PTP v2 / 802.1AS
# scapy.contrib.status = loads

import logging
import struct

from scapy.fields import (BitEnumField, BitField, ByteField, SignedByteField, SignedLongField, ShortField,
                          IntField, StrFixedLenField, XByteField, XShortField)
from scapy.layers.l2 import Dot1Q, Ether
from scapy.main import interact
from scapy.packet import Packet, bind_layers

logger = logging.getLogger("scapy")
logger.setLevel(logging.INFO)

ETH_PTP = 0x88F7
CLOCK = bytes.fromhex("008063ffff0009ba")               # clock identity of the default master

MESSAGE_TYPES = {0x0: "Sync", 0x1: "Delay_Req", 0x2: "Pdelay_Req", 0x3: "Pdelay_Resp", 0x8: "Follow_Up",
                 0x9: "Delay_Resp", 0xA: "Pdelay_Resp_Follow_Up", 0xB: "Announce", 0xC: "Signaling", 0xD: "Management"}


class PTP(Packet):
    """The 34-byte PTP header. `messageLength` is filled in from the payload unless it is given, so that frames with an
    inconsistent length can be built on purpose. transportSpecific is 1 for gPTP over Ethernet, 0 for PTP over UDP."""
    name = "PTP"
    fields_desc = [BitField("transportSpecific", 1, 4),
                   BitEnumField("messageType", 0, 4, MESSAGE_TYPES),
                   XByteField("versionPTP", 0x02),
                   ShortField("messageLength", None),
                   ByteField("domainNumber", 0),
                   ByteField("reserved1", 0),
                   XShortField("flagField", 0x0200),
                   SignedLongField("correctionField", 0),
                   IntField("reserved2", 0),
                   StrFixedLenField("clockIdentity", CLOCK, 8),
                   ShortField("portNumber", 1),
                   ShortField("sequenceId", 1),
                   ByteField("controlField", 0),
                   SignedByteField("logMessageInterval", -3)]

    def post_build(self, pkt, pay):
        if self.messageLength is None:
            pkt = pkt[:2] + struct.pack("!H", len(pkt) + len(pay)) + pkt[4:]
        return pkt + pay

    def extract_padding(self, s):
        return b"", s                                    # the body is not dissected; it stays in the payload


def timestamp(sec=1700000000, ns=123456789):
    """The 10-byte PTP timestamp (48-bit seconds, 32-bit nanoseconds)."""
    return struct.pack("!HII", sec >> 32, sec & 0xFFFFFFFF, ns)


def announce_body(priority1=246, clock_class=248, identity=CLOCK, priority2=246):
    """The Announce body: the grandmaster's priority, clock quality and identity."""
    return (timestamp() + struct.pack("!hbB", 37, 0, priority1) + bytes([clock_class, 0x21])
            + struct.pack("!H", 0x4E5D) + bytes([priority2]) + identity + struct.pack("!HB", 1, 0xA0))


def tlv(tlv_type, value=b"", length=None):
    return struct.pack("!HH", tlv_type, len(value) if length is None else length) + value


bind_layers(Ether, PTP, type=ETH_PTP)
bind_layers(Dot1Q, PTP, type=ETH_PTP)

if __name__ == "__main__":
    interact(mydict=globals(), mybanner="Test add-on TSN")
