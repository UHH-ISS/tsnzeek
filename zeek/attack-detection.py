# -----------------------------------------------------------
#
#  attack-detection.py
#
# This script polls events from a Zeek Broker and analyses the frames and checks for attacks
#
# (C) 2022 Robin Schenderlein, Hamburg, Germany
# Released under GNU Public License (GPL)
# email robin.schenderlein@studium.uni-hamburg.de
# -----------------------------------------------------------

import broker
import sys
import time
from collections import OrderedDict
from collections import deque
from datetime import datetime

import numpy as np
from BitVector import BitVector

streams = dict()
streams_history = dict()
streams_with_death = dict()
srp_configs = dict()  # talker mac as key
srp_talker_requests = dict()  # key is unique_id holds [ts, data]
srp_history = deque()
srp_bandwidth_history_len = 10
srp_bandwidth_history = deque(maxlen=srp_bandwidth_history_len)
# Change the source of the following values to an external config file
frer_history_size = 5
nr_of_member_streams = 5
timeout = 60
# max values for resource allocation thresholds
interval_threshold = 10
max_frames_per_interval_threshold = 10  # max value is 65535
max_frame_size_threshold = 1000  # max value is 65535 byte
# max values for maximum allowed requests in moving time window
nr_of_requests_threshold = 10
time_window_threshold = 10
# attack2 related stuff
frer_history = dict()
frer_history2_size = 25
talker_interval = 1
srp_configs2 = dict()
interval_start = datetime.now()
interval_start.replace(microsecond=0)
interval_start_ts = interval_start.timestamp().__floor__()
# interval_start = interval_start.timestamp()
o = 0
dd = dict()


def publish_notice(msg):
    print(msg)
    raise_notice = broker.zeek.Event("raise_notice", msg)
    ep.publish("/topic/tsn", raise_notice)


def identify_source_vlan_stream(source_address, vlan_identifier):
    return (str(source_address) + str(vlan_identifier)).__hash__()


def cleanup_srp_history():
    # removes entries older than time_window_threshold
    current_time = time.time()
    while srp_history:
        if current_time - srp_history[0] > time_window_threshold:
            srp_history.popleft()
        else:
            return


def check_attack1(stream_id, sequence_nr):
    # Attack 1 - Check for more frames received for compound stream than expected.
    if stream_id not in streams_history:
        streams_history[stream_id] = OrderedDict()
    if sequence_nr not in streams_history[stream_id]:
        streams_history[stream_id][sequence_nr] = [0, -1]
    streams_history[stream_id][sequence_nr][0] += 1
    streams_history[stream_id][sequence_nr][1] = time.time()
    if streams_history[stream_id][sequence_nr][0] > nr_of_member_streams:
        publish_notice(f'Got more frames for compound stream {stream_id} then expected')


def check_attack2(stream_id, sequence_nr, dtime):
    # WIP for future reference
    if stream_id not in frer_history:
        frer_history[stream_id] = deque(maxlen=frer_history2_size)
    frer_history[stream_id].append((dtime.timestamp() - interval_start_ts) % talker_interval)
    for stream_id in frer_history:
        if len(frer_history[stream_id]) < 25:
            continue


def check_attack4():
    # Attack 4 - Check for dead member streams
    delete_streams = []
    for stream_id, stream_history in streams_history.items():
        while True:
            sequence_nr_count, sequence_nr_ts = next(iter(stream_history.values()))
            if (time.time() - sequence_nr_ts) > timeout:
                if sequence_nr_count < nr_of_member_streams:
                    nr_of_dead_streams = nr_of_member_streams - sequence_nr_count
                    if stream_id not in streams_with_death or streams_with_death[stream_id] != nr_of_dead_streams:
                        streams_with_death[stream_id] = nr_of_dead_streams
                        publish_notice(f'{nr_of_dead_streams} member stream[s] of stream {stream_id} are '
                                       'probably dead')
                stream_history.popitem(False)  # remove oldest entry
                if not stream_history:
                    publish_notice(f'All member streams of stream {stream_id} are probably dead')
                    delete_streams.append(stream_id)
                    break
                    # could reset everything for stream
            else:
                break
    for stream_id in delete_streams:
        streams_history.pop(stream_id)


def check_attack5(interval, max_frames_per_interval, max_frame_size, stream_id):
    # Attack 5 - Violating SRP resource allocation restricted by a threshold
    if interval > interval_threshold:
        publish_notice(f'Threshold for Interval exceeded for stream {stream_id}: \n'
                       f'Allowed: {interval_threshold} Requested: {interval}')
    if max_frames_per_interval > max_frames_per_interval_threshold:
        publish_notice(f'Threshold for MaxFramesPerInterval exceeded for stream {stream_id}: \n'
                       f'Allowed: {max_frames_per_interval_threshold} Requested: {max_frames_per_interval}')
    if max_frame_size > max_frame_size_threshold:
        publish_notice(f'Threshold for MaxFrameSize exceeded for stream {stream_id}: \n'
                       f'Allowed: {max_frame_size_threshold} Requested: {max_frame_size}')
    # not sure if I should let requests exceeding a threshold get further processed


def check_attack6(interval, max_frames_per_interval, max_frame_size, stream_id):
    # Attack 6 - SRP bandwidth requests deviates too much from previous requests.
    max_bandwidth = max_frame_size * max_frames_per_interval / interval  # byte/second
    if len(srp_bandwidth_history) == srp_bandwidth_history_len:
        std_deviation = np.std(srp_bandwidth_history)
        mean = np.mean(srp_bandwidth_history)
        low = mean - 2 * std_deviation
        high = mean + 2 * std_deviation
        print(f'low: {low} bandwidth: {max_bandwidth} high: {high}')
        if not low < max_bandwidth < high:
            publish_notice(f'SRP request with more than two standard deviations difference for bandwidth for '
                           f'stream id {stream_id}. \n Requested: {max_bandwidth} Mean: {mean}')
    srp_bandwidth_history.append(max_bandwidth)


def check_attack7(time_stamp):
    # Attack 7 - Too many SRP requests in short time.
    srp_history.append(time_stamp)
    cleanup_srp_history()
    if len(srp_history) > nr_of_requests_threshold:
        publish_notice(f'Too many SRP requests received in short time.')
    # Count only different msgs or should it count same msgs as well. Might imply stuck transmitter?
    # Currently, gives one notice for each msg that is too much.


def check_attack8(mac, unique_id, stream_id):
    # Attack 8 - Changes to existing config
    if mac not in srp_configs:
        srp_configs[mac] = dict()
    if unique_id not in srp_configs[mac]:
        srp_configs[mac][unique_id] = [time.time(), stream_id]
    else:
        publish_notice(f'SRP request for changing an existing resource allocation with config id {mac}{unique_id}.')
        # Should only fire this if there has been an TalkerEnhanced_FirstValue msg with:
        # Matching mac and unique_id
        # Status -> StatusInfo -> TalkerStatus = 1 / Ready


def check_attack9():
    # Attack 9 - Check if FRER streams arrive for reserved streams
    delete_configs = set()
    for talker_mac, talker_config in srp_configs.items():
        for unique_id, config in talker_config.items():
            # check if stream data has been received
            timestamp, stream_id = config
            if time.time() - timestamp > timeout:
                if stream_id not in streams_history:
                    publish_notice(f'For SRP request with stream id {stream_id} no FRER packet was received.')
                    delete_configs.add(talker_mac)
    for talker_mac in delete_configs:
        srp_configs.pop(talker_mac)
    # would actually need confirmation beforehand with TalkerStatus == 1


def on_talker_srp_data_indication(data_srp):
    # dissecting event
    ethernet_data = data_srp[0][0]
    vlan = ethernet_data[5]
    talker_data = data_srp[1][0]
    stream_id_group = talker_data[0]
    mac = stream_id_group[0]
    unique_id = stream_id_group[1].value
    stream_id = identify_source_vlan_stream(mac, vlan)
    traffic_spec = talker_data[4]
    interval = traffic_spec[0].value / traffic_spec[1].value
    max_frames_per_interval = traffic_spec[2].value
    max_frame_size = traffic_spec[3].value
    global srp_configs

    check_attack8(mac, unique_id, stream_id)
    check_attack5(interval, max_frames_per_interval, max_frame_size, stream_id)
    check_attack6(interval, max_frames_per_interval, max_frame_size, stream_id)
    check_attack7(time.time())

    # prepare_attack2()
    # srp_configs2.


def on_cb_data_indication(data_cb):
    # dissecting event
    ethernet_data = data_cb[0][0]
    cb_data = data_cb[1]
    src, dst, vlan = ethernet_data[3:6]
    sequence_nr = cb_data.value
    stream_id = identify_source_vlan_stream(src, vlan)
    dtime = data_cb[2]
    global streams_history
    check_attack1(stream_id, sequence_nr)
    check_attack2(stream_id, sequence_nr, dtime)
    # -----Add to new state-----
    # Simplified Stream Recovery function
    if stream_id not in streams:
        streams[stream_id] = [sequence_nr, BitVector(size=frer_history_size)]
        streams[stream_id][1][0] = 1  # mark
        # process PRESENT_DATA
        return

    latest_valid = streams[stream_id][0]
    valid_range = range(latest_valid - frer_history_size, latest_valid + frer_history_size)
    if sequence_nr in valid_range:  # frame is in valid range
        delta = sequence_nr - latest_valid
        history = streams[stream_id][1]
        if sequence_nr <= latest_valid:  # old frame
            if 0 == history[delta]:  # has not been seen yet
                # add frame_counter[stream_id]=last_seen_counted[]
                # process PRESENT_DATA & reset RemainingTicks
                pass
            else:
                # discard
                pass
        else:  # frame is ahead
            if delta != 1:  # exactly one ahead
                publish_notice(f'Out of order frame accepted for stream id {stream_id}: sequence_nr: {sequence_nr}'
                               f' latest_valid: {latest_valid} delta: {delta} ')
                pass
            history.shift_right(delta)
            history[0] = 1
            streams[stream_id][0] = sequence_nr
            # reset RemainingTicks
            # process PRESENT_DATA
    else:
        pass
        publish_notice(f'Out of order frame discarded for stream id {stream_id}: sequence_nr: {sequence_nr}')


# Zeek Broker
# Setup endpoint and connect to Zeek.
ep = broker.Endpoint()
sub = ep.make_subscriber("/topic/tsn")
ss = ep.make_status_subscriber(True)
ep.peer("127.0.0.1", 9999)
# Wait until connection is established.
st = ss.get()

if not (type(st) == broker.Status and st.code() == broker.SC.PeerAdded):
    print("Could not connect")
    sys.exit(1)
print("Connected to publisher")

# init_attack2

while True:
    time.sleep(0.5)
    poll_result = sub.poll()
    check_attack9()
    check_attack4()
    if not poll_result:
        continue
    for (topic, data) in poll_result:
        event = broker.zeek.Event(data)
        if topic == "/topic/tsn/cb":
            on_cb_data_indication(event.args())
        elif topic == "/topic/tsn/srp/talker_enhanced":
            on_talker_srp_data_indication(event.args())
        elif topic == "/topic/tsn/srp/listener_enhanced":
            pass
