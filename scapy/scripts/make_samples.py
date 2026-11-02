#!/usr/bin/env python3
# (C) 2026 Doganalp Ergenc, written with the assistance of Claude
"""Write the sample pcaps of scapy/samples/ (fixed timestamps, so the files do not change between runs).

    .venv/bin/python scapy/scripts/make_samples.py

Writes frer.pcap (the FRER tag with growing sequence numbers) and srp_talker.pcap / srp_listener.pcap
(the minimal and the complete message of each kind). Send them with pcap_sender.py.
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "layers"))

from scapy.all import Dot1Q, Ether, wrpcap  # noqa: E402
import cb  # noqa: E402,F401  (binds the FRER tag to Dot1Q)
import srp  # noqa: E402

OUT = os.path.join(HERE, "..", "samples")
BASE_TIME = 1700000000
SRC, DST = "00:00:00:00:00:02", "00:00:00:00:00:04"


def frame(payload, vlan=1000):
    return Ether(src=SRC, dst=DST) / Dot1Q(vlan=vlan) / payload


def write(name, packets):
    for i, p in enumerate(packets):
        p.time = BASE_TIME + i
    wrpcap(os.path.join(OUT, name), packets)
    print(f"{name}: {len(packets)} frames")


def srp_messages():
    i1 = srp.InterfaceID(InterfaceName="thisIsAnInterfaceName")
    i2 = srp.InterfaceID(InterfaceName="thisIsAnotherInterfaceName")
    talker_full = srp.SRP(tlvlist=[
        srp.Talker(tlvlist=[
            srp.StreamID(), srp.StreamRank(),
            srp.EndStationInterfaces(interfaces=[i1, i2]),
            srp.DataFrameSpecification(tlvlist=[
                srp.IEEE802MacAddresses(), srp.IEEE802VlanTag(), srp.IPv4tuple(), srp.IPv6tuple()]),
            srp.TrafficSpecification(), srp.TSpecTimeAware(),
            srp.UserToNetworkRequirements(NumSeamlessTrees=12, MaxLatency=13),
            srp.InterfaceCapabilities(CBStreamIdenTypeList=[1, 2], CBSequenceTypeList=[3, 4])]),
        srp.Status(tlvlist=[
            srp.StatusInfo(), srp.AccumulatedLatency(),
            srp.InterfaceConfiguration(tlvlist=[i1, srp.TimeAwareOffset(TimeAwareOffset=55)]),
            srp.FailedInterfaces(interfaces=[i1, i2])])])
    talker_min = srp.SRP(tlvlist=[
        srp.Talker(tlvlist=[srp.StreamID(), srp.StreamRank(), srp.TrafficSpecification()]),
        srp.Status(tlvlist=[srp.StatusInfo(), srp.AccumulatedLatency()])])
    listener_full = srp.SRP(tlvlist=[
        srp.Listener(tlvlist=[
            srp.StreamID(), srp.EndStationInterfaces(interfaces=[i1, i2]),
            srp.UserToNetworkRequirements(NumSeamlessTrees=12, MaxLatency=13),
            srp.InterfaceCapabilities(CBStreamIdenTypeList=[1, 2], CBSequenceTypeList=[3, 4])]),
        srp.Status(tlvlist=[
            srp.StatusInfo(),
            srp.InterfaceConfiguration(tlvlist=[i1, srp.TimeAwareOffset(TimeAwareOffset=55)]),
            srp.FailedInterfaces(interfaces=[i1, i2])])])
    listener_min = srp.SRP(tlvlist=[
        srp.Listener(tlvlist=[srp.StreamID()]), srp.Status(tlvlist=[srp.StatusInfo()])])
    return talker_min, talker_full, listener_min, listener_full


if __name__ == "__main__":
    write("frer.pcap", [frame(cb.CB(sequence_nr=n)) for n in range(1, 6)])
    talker_min, talker_full, listener_min, listener_full = srp_messages()
    write("srp_talker.pcap", [frame(talker_min), frame(talker_full)])
    write("srp_listener.pcap", [frame(listener_min), frame(listener_full)])
