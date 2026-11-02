# -----------------------------------------------------------
#
#  srp.py
#
# Rules for SRP (802.1Qcc) reservations, working on the Talker records of srp.log. The numbers are those of the
# original attack-detection.py.
#
#   srp_oversized_request      a request above a resource threshold                    (attack5)
#   srp_bandwidth_jump         a bandwidth that deviates from the recent requests      (attack6)
#   srp_request_burst          too many requests in a time window                      (attack7)
#   srp_reservation_change     a request for a reservation that exists already         (attack8)
#   srp_unused_reservation     a reservation with no FRER traffic                      (attack9)
#
# The last rule also reads the records of cb.log: a reservation is used when frames of its stream arrive.
#
# (C) 2022 Robin Schenderlein, Hamburg, Germany
# Released under GNU Public License (GPL)
# -----------------------------------------------------------

import statistics
from collections import deque
from typing import Dict, List, Optional, Tuple

from .config import Config
from .engine import Alert, Detector, stream_key

OVERSIZED_REQUEST = "srp_oversized_request"
BANDWIDTH_JUMP = "srp_bandwidth_jump"
REQUEST_BURST = "srp_request_burst"
RESERVATION_CHANGE = "srp_reservation_change"
UNUSED_RESERVATION = "srp_unused_reservation"


class SrpDetector(Detector):
    def __init__(self, config: Config = Config()):
        self.c = config
        self.reservations: Dict[Tuple[str, int], Tuple[float, Optional[int]]] = {}   # (mac, id) -> (ts, data vlan)
        self.judged: set = set()                                     # reservations that were checked for traffic
        self.traffic: Dict[str, Dict[Optional[int], float]] = {}     # src mac -> vlan -> last FRER frame
        self.requests: deque = deque()
        self.bandwidth: deque = deque(maxlen=config.srp_bandwidth_history_len)

    def on_message(self, kind, msg):
        if kind == "cb":
            self.traffic.setdefault(msg.get("src"), {})[msg.get("vlan")] = msg["ts"]
        elif kind == "srp" and msg.get("msg_type") == "TalkerEnhanced":
            return self._talker(msg)
        return ()

    def on_tick(self, now):
        return self._unused_reservations(now)

    def _talker(self, msg) -> List[Alert]:
        ts = msg["ts"]
        mac, uid = msg["stream_mac"], msg["stream_unique_id"]
        sid = stream_key(mac, msg.get("vlan"))
        alerts = self._reservation_change(ts, mac, uid, msg.get("df_vlan_id"))
        num, den = msg.get("interval_numerator"), msg.get("interval_denominator")
        frames, size = msg.get("max_frames_per_interval"), msg.get("max_frame_size")
        if None in (num, den, frames, size):
            return alerts
        if den == 0 or num == 0:
            alerts.append(Alert(ts, OVERSIZED_REQUEST, f"Invalid interval {num}/{den} requested for stream {sid}", sid))
            return alerts + self._request_burst(ts)
        interval = num / den
        return alerts + self._oversized(ts, interval, frames, size, sid) \
            + self._bandwidth_jump(ts, interval, frames, size, sid) + self._request_burst(ts)

    def _oversized(self, ts, interval, frames, size, sid) -> List[Alert]:
        c, alerts = self.c, []
        if interval > c.interval_threshold:
            alerts.append(Alert(ts, OVERSIZED_REQUEST, f"Threshold for Interval exceeded for stream {sid}: "
                                                       f"Allowed: {c.interval_threshold} Requested: {interval}", sid))
        if frames > c.max_frames_per_interval_threshold:
            alerts.append(Alert(ts, OVERSIZED_REQUEST, f"Threshold for MaxFramesPerInterval exceeded for stream {sid}: "
                                                       f"Allowed: {c.max_frames_per_interval_threshold} Requested: {frames}", sid))
        if size > c.max_frame_size_threshold:
            alerts.append(Alert(ts, OVERSIZED_REQUEST, f"Threshold for MaxFrameSize exceeded for stream {sid}: "
                                                       f"Allowed: {c.max_frame_size_threshold} Requested: {size}", sid))
        return alerts

    def _bandwidth_jump(self, ts, interval, frames, size, sid) -> List[Alert]:
        bandwidth = size * frames / interval            # byte/second
        alerts = []
        if len(self.bandwidth) == self.bandwidth.maxlen:
            mean, dev = statistics.fmean(self.bandwidth), statistics.pstdev(self.bandwidth)
            if abs(bandwidth - mean) > 2 * dev:
                alerts.append(Alert(ts, BANDWIDTH_JUMP, f"SRP request with more than two standard deviations difference "
                                                        f"for bandwidth for stream id {sid}. Requested: {bandwidth:g} "
                                                        f"Mean: {mean:g}", sid))
        self.bandwidth.append(bandwidth)
        return alerts

    def _request_burst(self, ts) -> List[Alert]:
        self.requests.append(ts)
        while self.requests and ts - self.requests[0] > self.c.time_window_threshold:
            self.requests.popleft()
        if len(self.requests) > self.c.nr_of_requests_threshold:
            return [Alert(ts, REQUEST_BURST, "Too many SRP requests received in short time.")]
        return []

    def _reservation_change(self, ts, mac, uid, data_vlan) -> List[Alert]:
        key = (mac, uid)
        if key in self.reservations:
            return [Alert(ts, RESERVATION_CHANGE, f"SRP request for changing an existing resource allocation "
                                                  f"with config id {mac}/{uid}.", stream_key(mac, data_vlan))]
        self.reservations[key] = (ts, data_vlan)
        return []

    def _unused_reservations(self, now) -> List[Alert]:
        alerts = []
        for (mac, uid), (ts, vlan) in list(self.reservations.items()):
            if (mac, uid) in self.judged or now - ts <= self.c.timeout:
                continue
            self.judged.add((mac, uid))
            if not any(last >= ts and (vlan is None or v == vlan) for v, last in self.traffic.get(mac, {}).items()):
                alerts.append(Alert(now, UNUSED_RESERVATION, f"For SRP request {mac}/{uid} no FRER packet was received.",
                                    stream_key(mac, vlan)))
        return alerts
