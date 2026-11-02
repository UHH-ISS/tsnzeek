#!/usr/bin/env python3
"""Generate the synthetic pcaps used by tests/run.sh (needs scapy: .venv/bin/python tests/gen_pcaps.py)."""
import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scapy", "layers"))

from scapy.all import IP, IPv6, UDP, Dot1Q, Ether, Raw, raw, wrpcap  # noqa: E402
import srp  # noqa: E402  (scapy/layers/srp.py)

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pcaps")
SRC, DST = "00:00:00:00:00:01", "00:00:00:00:00:02"
ETH_FRER = 0xF1C1
ETH_PTP = 0x88F7
ETH_SRP = 0x22EA
GPTP_DST = "01:80:c2:00:00:0e"
CLOCK = bytes.fromhex("008063ffff0009ba")


def frer(seq=1, reserved=0, vlan=150, tail=b"", src=SRC):
    body = Raw(reserved.to_bytes(2, "big") + seq.to_bytes(2, "big") + tail)
    if vlan is None:
        return Ether(src=src, dst=DST, type=ETH_FRER) / body
    return Ether(src=src, dst=DST) / Dot1Q(vlan=vlan, type=ETH_FRER) / body



def port_id(clock=CLOCK, port=1):
    return clock + struct.pack("!H", port)


def timestamp(sec=1700000000, ns=123456789):
    return struct.pack("!HII", sec >> 32, sec & 0xFFFFFFFF, ns)


def ptp_header(msg_type, length, seq=1, transport=1, domain=0, flags=0x0200, control=0, log_interval=-3, clock=CLOCK):
    return (struct.pack("!BBHBBH", (transport << 4) | msg_type, 0x02, length, domain, 0, flags)
            + struct.pack("!qI", 0, 0) + port_id(clock) + struct.pack("!HBb", seq, control, log_interval))


def announce_body(priority1=246, clock_class=248, identity=CLOCK, priority2=246):
    """The Announce body: the grandmaster's priority, clock quality and identity."""
    return (timestamp() + struct.pack("!hbB", 37, 0, priority1) + bytes([clock_class, 0x21])
            + struct.pack("!H", 0x4E5D) + bytes([priority2]) + identity + struct.pack("!HB", 1, 0xA0))


def ptp_msg(msg_type, body=b"", seq=1, length=None, **kw):
    """A PTP message; `length` overrides messageLength so inconsistent frames can be built."""
    return ptp_header(msg_type, 34 + len(body) if length is None else length, seq, **kw) + body


def tlv(tlv_type, value=b"", length=None):
    return struct.pack("!HH", tlv_type, len(value) if length is None else length) + value


def ptp(payload, vlan=None):
    if vlan is None:
        return Ether(src=SRC, dst=GPTP_DST, type=ETH_PTP) / Raw(payload)
    return Ether(src=SRC, dst=GPTP_DST) / Dot1Q(vlan=vlan, type=ETH_PTP) / Raw(payload)



def ptp_udp(payload, port=319, v6=False, vlan=None, src_port=None):
    """PTP over UDP: event messages use port 319, general messages port 320."""
    if v6:
        ip = IPv6(src="fe80::1", dst="ff02::6b")
    else:
        ip = IP(src="192.0.2.1", dst="224.0.1.129")
    eth = Ether(src=SRC, dst="01:00:5e:00:01:81")
    if vlan is not None:
        eth = eth / Dot1Q(vlan=vlan)
    return eth / ip / UDP(sport=src_port or port, dport=port) / Raw(payload)


def srp_frame(payload, vlan=1000):
    payload = bytes(payload)
    if vlan is None:
        return Ether(src=SRC, dst="00:00:00:00:00:04", type=ETH_SRP) / Raw(payload)
    return Ether(src=SRC, dst="00:00:00:00:00:04") / Dot1Q(vlan=vlan, type=ETH_SRP) / Raw(payload)


def srp_samples():
    """The frames of scapy/srp_sample, plus IPv6/second-interface variants."""
    i1 = srp.InterfaceID(InterfaceName="thisIsAnInterfaceName", MacAddress="00:00:00:00:00:0a")
    i2 = srp.InterfaceID(InterfaceName="thisIsAnotherInterfaceName", MacAddress="00:00:00:00:00:0b")
    stream = srp.StreamID(MacAddress="00:00:00:00:00:02", UniqueID=7)
    traffic = srp.TrafficSpecification(IntervalNumerator=1, IntervalDenominator=8000,
                                       MaxFramesPerInterval=2, MaxFrameSize=128, TransmissionSelection=1)
    talker_full = srp.SRP(tlvlist=[
        srp.Talker(tlvlist=[
            stream, srp.StreamRank(),
            srp.EndStationInterfaces(interfaces=[i1, i2]),
            srp.DataFrameSpecification(tlvlist=[
                srp.IEEE802MacAddresses(DestinationMacAddress="01:00:5e:00:00:01", SourceMacAddress="00:00:00:00:00:02"),
                srp.IEEE802VlanTag(PriorityCodePoint=3, VlanId=150),
                srp.IPv4tuple(SourceIpAddress="10.0.0.2", DestinationIpAddress="10.0.0.3", Dscp=46, Protocol=17,
                              SourcePort=5000, DestinationPort=6000),
                srp.IPv6tuple(SourceIpAddress="fe80::2", DestinationIpAddress="ff02::1", Dscp=46, Protocol=17,
                              SourcePort=5000, DestinationPort=6000)]),
            traffic,
            srp.TSpecTimeAware(EarliestTransmitOffset=10, LatestTransmitOffset=20, Jitter=3),
            srp.UserToNetworkRequirements(NumSeamlessTrees=2, MaxLatency=500),
            srp.InterfaceCapabilities(CBStreamIdenTypeList=[1, 2], CBSequenceTypeList=[3, 4])]),
        srp.Status(tlvlist=[
            srp.StatusInfo(TalkerStatus=1), srp.AccumulatedLatency(AccumulatedLatency=250),
            srp.InterfaceConfiguration(tlvlist=[i1, srp.TimeAwareOffset(TimeAwareOffset=55), i2]),
            srp.FailedInterfaces(interfaces=[i1, i2])])])
    talker_min = srp.SRP(tlvlist=[
        srp.Talker(tlvlist=[stream, srp.StreamRank(), traffic]),
        srp.Status(tlvlist=[srp.StatusInfo(), srp.AccumulatedLatency()])])
    listener_full = srp.SRP(tlvlist=[
        srp.Listener(tlvlist=[
            stream, srp.EndStationInterfaces(interfaces=[i1, i2]),
            srp.UserToNetworkRequirements(NumSeamlessTrees=12, MaxLatency=13),
            srp.InterfaceCapabilities(CBStreamIdenTypeList=[1, 2], CBSequenceTypeList=[3, 4])]),
        srp.Status(tlvlist=[
            srp.StatusInfo(ListenerStatus=2, FailureCode=4),
            srp.InterfaceConfiguration(tlvlist=[i1, srp.TimeAwareOffset(TimeAwareOffset=55)]),
            srp.FailedInterfaces(interfaces=[i1, i2])])])
    listener_min = srp.SRP(tlvlist=[
        srp.Listener(tlvlist=[stream]), srp.Status(tlvlist=[srp.StatusInfo()])])
    return talker_full, talker_min, listener_full, listener_min


def write(name, packets, times=None):
    # Fixed timestamps keep the golden logs stable; `times` gives seconds after the base time.
    for i, p in enumerate(packets):
        p.time = 1700000000 + (i if times is None else times[i])
    wrpcap(os.path.join(OUT, name), packets)


def talker_msg(uid, mac="00:00:00:00:00:02", num=1, den=8000, frames_=2, size=128, vlan=1000, rank=False):
    sid = srp.StreamID(MacAddress=mac, UniqueID=uid)
    traffic = srp.TrafficSpecification(IntervalNumerator=num, IntervalDenominator=den,
                                       MaxFramesPerInterval=frames_, MaxFrameSize=size)
    st = srp.Status(tlvlist=[srp.StatusInfo(), srp.AccumulatedLatency()])
    return srp_frame(raw(srp.SRP(tlvlist=[srp.Talker(tlvlist=[sid, traffic] + ([srp.StreamRank()] if rank else [])), st])), vlan=vlan)


ROGUE = bytes.fromhex("deadbeefcafe0001")
UNKNOWN = bytes.fromhex("feedfacefeed0002")


def write_ids_cases():
    """Traffic for the IDS rules (tests/ids/); see tests/run_ids.sh for the thresholds used."""
    # gPTP: a healthy master, then a rogue grandmaster, a Sync from a clock nobody announced, and sequenceId abuse.
    ptp_pkts = [
        (0, ptp(ptp_msg(0xB, announce_body(), seq=1))),
        (0.1, ptp(ptp_msg(0x0, timestamp(), seq=1))), (0.2, ptp(ptp_msg(0x8, timestamp(), seq=1))),
        (1, ptp(ptp_msg(0x0, timestamp(), seq=2))), (1.1, ptp(ptp_msg(0x8, timestamp(), seq=2))),
        (1.2, ptp_udp(ptp_msg(0x0, timestamp(), seq=2, transport=0))),     # UDP counts separately from Ethernet
        (2, ptp(ptp_msg(0x0, timestamp(), seq=3))), (2.1, ptp(ptp_msg(0x8, timestamp(), seq=3))),
        (3, ptp(ptp_msg(0xB, announce_body(priority1=1, clock_class=6, identity=ROGUE), seq=1, clock=ROGUE))),   # ptp_rogue_grandmaster
        (3.5, ptp(ptp_msg(0xB, announce_body(), seq=2))),                  # the real master again: a backup, no alert
        (4, ptp(ptp_msg(0x0, timestamp(), seq=1, clock=UNKNOWN))),         # ptp_unannounced_sync
        (5, ptp(ptp_msg(0x0, timestamp(), seq=4))),
        (6, ptp(ptp_msg(0x0, timestamp(), seq=4))),                        # ptp_sequence_id: repeated
        (7, ptp(ptp_msg(0x0, timestamp(), seq=9))),                        # ptp_sequence_id: skipped 5-8
        (8, ptp(ptp_msg(0x0, timestamp(), seq=10))),
    ]
    write("ids_ptp.pcap", [p for _, p in ptp_pkts], [t for t, _ in ptp_pkts])

    mac_b = "00:00:00:00:00:02"
    # (time, seq, src): the stream is healthy for sequence numbers 1-5 (two copies each, as configured).
    frames = []
    for seq in range(1, 6):
        frames += [(seq - 1, seq, SRC), (seq - 1 + 0.5, seq, SRC)]
    frames += [(5, 6, SRC), (5.1, 6, SRC), (5.2, 6, SRC)]        # third copy: more frames than expected
    frames += [(6, 7, SRC)]                                      # only one copy: a member stream is dead
    frames += [(7, 11, SRC)]                                     # skips 8-10: accepted out of order
    frames += [(8, 5000, SRC)]                                   # far outside the window: discarded
    frames += [(30, 1, mac_b)]                                   # advances the clock past the timeouts
    write("ids_frer.pcap", [frer(seq, src=src) for _, seq, src in frames], [t for t, _, _ in frames])

    # A sender that restarts its counter: discarded while the old sequence is still fresh, accepted after the
    # recovery reset time (3 s in tests/ids/config.json) without an accepted frame.
    restart = [(0, 100), (0.1, 100), (1, 101), (1.1, 101), (2, 102), (2.1, 102),
               (3.5, 1), (4, 2),                                  # restart, 1.4 s and 1.9 s after the last accepted
               (6, 3), (6.1, 3), (7, 4), (7.1, 4)]                # 3.9 s after: recovery reset, no alert
    write("ids_frer_restart.pcap", [frer(seq) for _, seq in restart], [t for t, _ in restart])

    srp_pkts = [
        (0, talker_msg(1)), (1, talker_msg(2)), (2, talker_msg(3)),          # three equal requests
        (3, talker_msg(4, frames_=4)),                                       # twice the bandwidth: srp_bandwidth_jump
        (4, talker_msg(5, num=20, den=1, frames_=50, size=2000)),            # all thresholds exceeded
        (5, talker_msg(1)),                                                  # changes reservation 1: srp_reservation_change
        (6, talker_msg(9, mac="00:00:00:00:00:03")),                         # no FRER traffic: srp_unused_reservation
        (7, talker_msg(10, den=0)),                                          # invalid interval
    ]
    # FRER data (two copies each) for the first stream only, so that exactly the reservation of ...:03
    # lacks traffic. The pair at t=12 moves the clock past the 5 s timeout of that reservation.
    for t, seq in ((2.5, 1), (12, 2)):
        srp_pkts += [(t, frer(seq, vlan=1000, src=mac_b)), (t + 0.1, frer(seq, vlan=1000, src=mac_b))]
    srp_pkts.sort(key=lambda x: x[0])
    write("ids_srp.pcap", [p for _, p in srp_pkts], [t for t, _ in srp_pkts])


def main():
    os.makedirs(OUT, exist_ok=True)
    write("frer.pcap", [
        frer(1), frer(2), frer(65535),
        frer(3, vlan=None),               # untagged
        frer(4, reserved=0xFFFF),         # reserved bits set: parsed, flagged by the IDS later
        frer(5, tail=b"\x08\x00" + b"\xaa" * 20),   # encapsulated payload after the tag
        Ether(src=SRC, dst=DST) / Dot1Q(vlan=150, type=ETH_FRER) / Raw(b"\x00\x00\x00"),  # truncated tag
        Ether(src=SRC, dst=DST) / Dot1Q(vlan=150, type=ETH_FRER) / Raw(b"\x00"),          # truncated tag
    ])

    announce = announce_body()
    write("ptp_messages.pcap", [
        ptp(ptp_msg(0xB, announce, seq=1)),
        ptp(ptp_msg(0x0, timestamp(), seq=2)),
        ptp(ptp_msg(0x8, timestamp(), seq=2)),
        ptp(ptp_msg(0x1, timestamp(), seq=3, transport=0)),
        ptp(ptp_msg(0x9, timestamp() + port_id(bytes(range(8)), 7), seq=3, transport=0)),
        ptp(ptp_msg(0x2, timestamp() + bytes(10), seq=4)),
        ptp(ptp_msg(0x3, timestamp() + port_id(bytes(range(8)), 7), seq=4)),
        ptp(ptp_msg(0xA, timestamp() + port_id(bytes(range(8)), 7), seq=4)),
        ptp(ptp_msg(0xC, port_id(bytes(range(8)), 2) + tlv(0x0003, b"\x01\x02\x03\x04"), seq=5)),
        ptp(ptp_msg(0xD, port_id(bytes(range(8)), 2) + struct.pack("!BBBB", 1, 1, 0, 0)
                    + struct.pack("!HHH", 0x0001, 2 + 4, 0x2000) + b"\xde\xad\xbe\xef", seq=6)),
        ptp(ptp_msg(0x0, timestamp(), seq=7), vlan=150),                       # VLAN tagged
    ])

    pad = bytes(2)           # Ethernet pads a 44-octet Sync to the 46-octet minimum
    suffix_tlv = tlv(0x0003, bytes(28))   # e.g. the follow-up information TLV of 802.1AS
    write("ptp_length.pcap", [
        ptp(ptp_msg(0x0, timestamp(), seq=1) + pad),                                       # ok: padding
        ptp(ptp_msg(0x8, timestamp() + suffix_tlv, seq=2)),                                # ok: suffix TLV counted
        ptp(ptp_msg(0x0, timestamp(), seq=3) + b"\xaa" * 8),                               # 8 octets beyond messageLength
        ptp(ptp_msg(0x0, timestamp(), seq=4, length=9999)),                               # messageLength exceeds frame
        ptp(ptp_msg(0x0, timestamp(), seq=5, length=10)),                                 # below the 44-octet minimum
        ptp(ptp_msg(0xB, announce, seq=6, length=40) + b"\x00" * 0),                       # Announce below its minimum
        ptp(ptp_msg(0x0, timestamp(), seq=7, length=60) + bytes(16)),                     # declared > body, but frame matches
    ])

    write("ptp_malformed.pcap", [
        ptp(ptp_msg(0x4, b"\x00" * 10, seq=1)),                               # reserved types
        ptp(ptp_msg(0xF, b"\x00" * 10, seq=2)),
        ptp(ptp_msg(0x0, timestamp(), seq=3)[:40]),                           # truncated in the body
        ptp(ptp_msg(0x0, timestamp(), seq=4)[:20]),                           # truncated in the header
        ptp(b"\x10"),                                                         # one octet
        ptp(ptp_msg(0xC, port_id() + tlv(0x0003, b"\x01\x02", length=500), seq=5)),   # TLV longer than frame
        ptp(ptp_msg(0xD, port_id() + struct.pack("!BBBB", 1, 1, 0, 0) + struct.pack("!HHH", 1, 1, 0x2000), seq=6)),  # mgmt TLV length < 2
        ptp(ptp_msg(0xD, port_id() + struct.pack("!BBBB", 1, 1, 0, 0) + struct.pack("!HHH", 1, 2, 0x2000), seq=7)),  # mgmt TLV, no data
        ptp(ptp_msg(0xB, b"\x00" * 5, seq=8)),                                # Announce with a short body
    ])

    write("ptp_udp.pcap", [
        ptp_udp(ptp_msg(0xB, announce, seq=1, transport=0), port=320),
        ptp_udp(ptp_msg(0x0, timestamp(), seq=2, transport=0)),
        ptp_udp(ptp_msg(0x8, timestamp(), seq=2, transport=0), port=320),
        ptp_udp(ptp_msg(0x1, timestamp(), seq=3, transport=0), src_port=40000),
        ptp_udp(ptp_msg(0x9, timestamp() + port_id(bytes(range(8)), 7), seq=3, transport=0), port=320),
        ptp_udp(ptp_msg(0x2, timestamp() + bytes(10), seq=4, transport=0)),
        ptp_udp(ptp_msg(0x0, timestamp(), seq=5, transport=0), v6=True),
        ptp_udp(ptp_msg(0x0, timestamp(), seq=6, transport=0), vlan=150),
        ptp_udp(ptp_msg(0xC, port_id(bytes(range(8)), 2) + tlv(0x0003, b"\x01\x02\x03\x04"), seq=7, transport=0), port=320),
        ptp_udp(ptp_msg(0x8, timestamp() + suffix_tlv, seq=8, transport=0), port=320),     # ok: suffix TLV counted
    ])

    # The Spicy UDP analyzer stops parsing a flow after its first parse error, so every datagram
    # uses its own source port to be seen at all.
    write("ptp_udp_malformed.pcap", [
        ptp_udp(ptp_msg(0x4, b"\x00" * 10, seq=1, transport=0), src_port=10001),  # reserved type
        ptp_udp(ptp_msg(0x0, timestamp(), seq=2, transport=0)[:40], src_port=10002),  # truncated in the body
        ptp_udp(ptp_msg(0x0, timestamp(), seq=3, transport=0)[:20], src_port=10003),  # truncated in the header
        ptp_udp(b"\x10", src_port=10004),  # one octet
        ptp_udp(ptp_msg(0x0, timestamp(), seq=4, transport=0) + b"\x00" * 2, src_port=10005),  # UDP is not padded: 2 octets beyond
        ptp_udp(ptp_msg(0x0, timestamp(), seq=5, transport=0, length=9999), src_port=10006),  # messageLength exceeds datagram
        ptp_udp(ptp_msg(0x0, timestamp(), seq=6, transport=0, length=10), src_port=10007),  # below the 44-octet minimum
        ptp_udp(ptp_msg(0xC, port_id() + tlv(0x0003, b"\x01\x02", length=500), seq=7, transport=0), port=320, src_port=10008),
    ])

    write_ids_cases()

    tf, tm, lf, lm = (raw(x) for x in srp_samples())
    write("srp_messages.pcap", [
        srp_frame(tf), srp_frame(tm), srp_frame(lf), srp_frame(lm),
        srp_frame(tf, vlan=None),                       # untagged
        srp_frame(tm + b"\xaa" * 6),                    # trailing bytes after the Status TLV
    ])

    # Offsets inside the minimal talker: [0]=type [1]=talkerLen [2:4]=StreamID header ...
    def patch(b, offset, value):
        b = bytearray(b)
        b[offset] = value
        return bytes(b)

    write("srp_malformed.pcap", [
        srp_frame(bytes([9, 3, 1, 2, 3])),                    # unsupported first TLV
        srp_frame(tm[:20]),                                   # truncated inside the Talker
        srp_frame(tm[:2 + tm[1]]),                            # Talker without Status
        srp_frame(patch(tm, 3, 9)),                           # StreamID length != 8
        srp_frame(patch(tm, 1, 5)),                           # talkerLen shorter than its content
        srp_frame(patch(tm, 1, 200)),                         # talkerLen longer than the frame
        srp_frame(patch(tf, 2 + 10 + 3 + 2 + 1, 3)),          # InterfaceID length < 6
        srp_frame(lf[:-3]),                                   # truncated inside FailedInterfaces
        srp_frame(bytes([1, 0])),                             # empty Talker
    ])

    stream = srp.StreamID(MacAddress="00:00:00:00:00:02", UniqueID=7)
    traffic = srp.TrafficSpecification(IntervalNumerator=1, IntervalDenominator=8000, MaxFramesPerInterval=2, MaxFrameSize=128)
    status = srp.Status(tlvlist=[srp.StatusInfo(), srp.AccumulatedLatency()])

    def talker(items, st=status):
        return raw(srp.SRP(tlvlist=[srp.Talker(tlvlist=items), st]))

    write("srp_structure.pcap", [
        srp_frame(talker([stream, traffic])),                                   # no StreamRank
        srp_frame(talker([stream, srp.StreamRank()])),                          # no TrafficSpecification
        srp_frame(talker([stream, stream, srp.StreamRank(), traffic])),         # duplicate StreamID
        srp_frame(talker([stream, srp.StreamRank(), srp.SrpGenericTlv(TLV_type=99, value=b"abc"), traffic])),  # unknown TLV
        srp_frame(talker([srp.StreamRank(), traffic])),                         # no StreamID: not logged
        srp_frame(talker([stream, srp.StreamRank(), traffic], srp.Status(tlvlist=[srp.AccumulatedLatency()]))),  # no StatusInfo
        srp_frame(talker([traffic, srp.StreamRank(), stream])),                 # reordered: accepted
        srp_frame(raw(srp.SRP(tlvlist=[srp.Listener(tlvlist=[stream]), srp.Status(tlvlist=[srp.StatusInfo()])]))),
    ])


if __name__ == "__main__":
    sys.exit(main())
