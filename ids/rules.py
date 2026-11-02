# -----------------------------------------------------------
#
#  rules.py
#
# The rule-based detectors for FRER (802.1CB) and SRP (802.1Qcc) streams. The rule numbers are those
# of the original attack-detection.py; attack 2 (work in progress there) is not implemented.
#
#   attack1  more frames for one sequence number than member streams
#   attack3  out of order frames (accepted or discarded by the recovery function)
#   attack4  dead member streams
#   attack5  SRP resource request above a threshold
#   attack6  SRP bandwidth deviates from recent requests
#   attack7  too many SRP requests in a time window
#   attack8  SRP request for an existing reservation
#   attack9  reservation without FRER traffic
#
# (C) 2022 Robin Schenderlein, Hamburg, Germany
# Released under GNU Public License (GPL)
# -----------------------------------------------------------

import statistics
from collections import OrderedDict, deque
from dataclasses import dataclass, fields, replace
from typing import Dict, List, Optional, Tuple

from .engine import Alert, Detector


@dataclass(frozen=True)
class Config:
    # FRER
    frer_history_size: int = 5          # sequence recovery window
    nr_of_member_streams: int = 5       # copies of each frame expected on the wire
    timeout: float = 60.0               # seconds without a (complete) sequence number / reserved stream data
    recovery_reset_time: float = 10.0   # seconds without an accepted frame after which recovery starts over
    # SRP resource thresholds
    interval_threshold: float = 10.0
    max_frames_per_interval_threshold: int = 10
    max_frame_size_threshold: int = 1000
    # SRP request rate
    nr_of_requests_threshold: int = 10
    time_window_threshold: float = 10.0
    # SRP bandwidth
    srp_bandwidth_history_len: int = 10
    # PTP (rules in ptp_rules.py)
    ptp_gm_timeout: float = 10.0         # seconds without an Announce after which a master counts as gone
    ptp_learning_time: float = 5.0       # a Sync with no Announce yet is tolerated this long after the first PTP message
    ptp_seq_gap_tolerance: int = 0       # sequenceIds that may be missing between two messages before it is an alert
    ptp_seq_reset_time: float = 10.0     # seconds of silence after which a sequenceId may start anywhere

    @staticmethod
    def from_dict(d: dict) -> "Config":
        known = {f.name for f in fields(Config)}
        unknown = set(d) - known
        if unknown:
            raise ValueError(f"unknown config keys: {sorted(unknown)}")
        return replace(Config(), **d)


def stream_key(mac, vlan) -> str:
    return f"{mac}/{'-' if vlan is None else vlan}"


class RuleDetector(Detector):
    def __init__(self, config: Config = Config()):
        self.c = config
        # FRER
        self.recovery: Dict[str, list] = {}                          # stream -> [latest, seen bitmask, last accepted ts]
        self.history: Dict[str, "OrderedDict[int, list]"] = {}       # stream -> seq -> [count, last ts]
        self.dead: Dict[str, int] = {}
        self.cb_seen: Dict[str, Dict[Optional[int], float]] = {}     # src mac -> vlan -> last ts
        # SRP
        self.reservations: Dict[Tuple[str, int], Tuple[float, Optional[int]]] = {}   # (mac, id) -> (ts, data vlan)
        self.judged: set = set()                                     # reservations attack9 has already ruled on
        self.requests: deque = deque()
        self.bandwidth: deque = deque(maxlen=config.srp_bandwidth_history_len)

    # ---------------------------------------------------------------- dispatch

    def on_message(self, kind, msg):
        if kind == "cb":
            return self._cb(msg)
        if kind == "srp" and msg.get("msg_type") == "TalkerEnhanced":
            return self._talker(msg)
        return ()

    def on_tick(self, now):
        return self._attack4(now) + self._attack9(now)

    # ---------------------------------------------------------------- FRER

    def _cb(self, msg) -> List[Alert]:
        ts, seq = msg["ts"], msg["sequence_nr"]
        src, vlan = msg.get("src"), msg.get("vlan")
        sid = stream_key(src, vlan)
        self.cb_seen.setdefault(src, {})[vlan] = ts
        return self._attack1(sid, seq, ts) + self._recovery(sid, seq, ts)

    def _attack1(self, sid, seq, ts) -> List[Alert]:
        entry = self.history.setdefault(sid, OrderedDict()).setdefault(seq, [0, ts])
        entry[0] += 1
        entry[1] = ts
        if entry[0] == self.c.nr_of_member_streams + 1:   # once per sequence number
            return [Alert(ts, "attack1", f"Got more frames for compound stream {sid} than expected "
                                         f"(sequence_nr {seq})", sid)]
        return []

    def _recovery(self, sid, seq, ts) -> List[Alert]:
        """Simplified sequence recovery (802.1CB 7.4.3.2) on 16-bit sequence numbers.

        Frames outside the window are discarded, but only until `recovery_reset_time` has passed without an
        accepted frame (the standard's recovery reset): then the next frame starts a new sequence, which is
        how a restarted sender gets back in. Duplicates (bit already set) are normal, they are the replicas.
        """
        h = self.c.frer_history_size
        state = self.recovery.get(sid)
        if state is None or ts - state[2] > self.c.recovery_reset_time:
            self.recovery[sid] = [seq, 1, ts]
            return []
        latest, seen, _ = state
        delta = ((seq - latest + 0x8000) & 0xFFFF) - 0x8000
        if not -h <= delta < h:
            return [Alert(ts, "attack3", f"Out of order frame discarded for stream id {sid}: "
                                         f"sequence_nr: {seq} latest_valid: {latest}", sid)]
        mask = (1 << h) - 1
        if delta <= 0:
            if not seen >> -delta & 1:
                state[2] = ts                                  # an old frame that was missing: accepted
            state[1] = (seen | (1 << -delta)) & mask
            return []
        state[0], state[1], state[2] = seq, ((seen << delta) | 1) & mask, ts
        if delta != 1:
            return [Alert(ts, "attack3", f"Out of order frame accepted for stream id {sid}: "
                                         f"sequence_nr: {seq} latest_valid: {latest} delta: {delta}", sid)]
        return []

    def _attack4(self, now) -> List[Alert]:
        alerts = []
        n = self.c.nr_of_member_streams
        for sid in list(self.history):
            hist = self.history[sid]
            while hist:
                seq, (count, last) = next(iter(hist.items()))
                if now - last <= self.c.timeout:
                    break
                hist.popitem(last=False)
                if count < n and self.dead.get(sid) != n - count:
                    self.dead[sid] = n - count
                    alerts.append(Alert(now, "attack4", f"{n - count} member stream[s] of stream {sid} "
                                                        "are probably dead", sid))
            if not hist:
                alerts.append(Alert(now, "attack4", f"All member streams of stream {sid} are probably dead", sid))
                del self.history[sid]
                self.dead.pop(sid, None)
        return alerts

    # ---------------------------------------------------------------- SRP

    def _talker(self, msg) -> List[Alert]:
        ts = msg["ts"]
        mac, uid = msg["stream_mac"], msg["stream_unique_id"]
        sid = stream_key(mac, msg.get("vlan"))
        alerts = self._attack8(ts, mac, uid, msg.get("df_vlan_id"))
        num, den = msg.get("interval_numerator"), msg.get("interval_denominator")
        frames, size = msg.get("max_frames_per_interval"), msg.get("max_frame_size")
        if None in (num, den, frames, size):
            return alerts
        if den == 0 or num == 0:
            alerts.append(Alert(ts, "attack5", f"Invalid interval {num}/{den} requested for stream {sid}", sid))
            return alerts + self._attack7(ts)
        interval = num / den
        return alerts + self._attack5(ts, interval, frames, size, sid) \
            + self._attack6(ts, interval, frames, size, sid) + self._attack7(ts)

    def _attack5(self, ts, interval, frames, size, sid) -> List[Alert]:
        c, alerts = self.c, []
        if interval > c.interval_threshold:
            alerts.append(Alert(ts, "attack5", f"Threshold for Interval exceeded for stream {sid}: "
                                              f"Allowed: {c.interval_threshold} Requested: {interval}", sid))
        if frames > c.max_frames_per_interval_threshold:
            alerts.append(Alert(ts, "attack5", f"Threshold for MaxFramesPerInterval exceeded for stream {sid}: "
                                              f"Allowed: {c.max_frames_per_interval_threshold} Requested: {frames}", sid))
        if size > c.max_frame_size_threshold:
            alerts.append(Alert(ts, "attack5", f"Threshold for MaxFrameSize exceeded for stream {sid}: "
                                              f"Allowed: {c.max_frame_size_threshold} Requested: {size}", sid))
        return alerts

    def _attack6(self, ts, interval, frames, size, sid) -> List[Alert]:
        bandwidth = size * frames / interval            # byte/second
        alerts = []
        if len(self.bandwidth) == self.bandwidth.maxlen:
            mean, dev = statistics.fmean(self.bandwidth), statistics.pstdev(self.bandwidth)
            if abs(bandwidth - mean) > 2 * dev:
                alerts.append(Alert(ts, "attack6", f"SRP request with more than two standard deviations difference "
                                                  f"for bandwidth for stream id {sid}. Requested: {bandwidth:g} "
                                                  f"Mean: {mean:g}", sid))
        self.bandwidth.append(bandwidth)
        return alerts

    def _attack7(self, ts) -> List[Alert]:
        self.requests.append(ts)
        while self.requests and ts - self.requests[0] > self.c.time_window_threshold:
            self.requests.popleft()
        if len(self.requests) > self.c.nr_of_requests_threshold:
            return [Alert(ts, "attack7", "Too many SRP requests received in short time.")]
        return []

    def _attack8(self, ts, mac, uid, data_vlan) -> List[Alert]:
        key = (mac, uid)
        if key in self.reservations:
            return [Alert(ts, "attack8", f"SRP request for changing an existing resource allocation "
                                         f"with config id {mac}/{uid}.", stream_key(mac, data_vlan))]
        self.reservations[key] = (ts, data_vlan)
        return []

    def _attack9(self, now) -> List[Alert]:
        alerts = []
        for (mac, uid), (ts, vlan) in list(self.reservations.items()):
            if (mac, uid) in self.judged or now - ts <= self.c.timeout:
                continue
            self.judged.add((mac, uid))
            if not any(last >= ts and (vlan is None or v == vlan) for v, last in self.cb_seen.get(mac, {}).items()):
                alerts.append(Alert(now, "attack9", f"For SRP request {mac}/{uid} no FRER packet was received.",
                                    stream_key(mac, vlan)))
        return alerts
