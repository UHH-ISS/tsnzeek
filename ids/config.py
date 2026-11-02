# -----------------------------------------------------------
#
#  config.py
#
# The thresholds of all rules. `python3 -m ids --config thresholds.json` overrides any of them by name.
#
# (C) 2022 Robin Schenderlein, Hamburg, Germany
# (C) 2026 Doganalp Ergenc, written with the assistance of Claude
# Released under GNU Public License (GPL)
# -----------------------------------------------------------

from dataclasses import dataclass, fields, replace


@dataclass(frozen=True)
class Config:
    # FRER (frer.py)
    frer_history_size: int = 5          # sequence recovery window
    nr_of_member_streams: int = 5       # copies of each frame expected on the wire
    timeout: float = 60.0               # seconds without a (complete) sequence number / reserved stream data
    recovery_reset_time: float = 10.0   # seconds without an accepted frame after which recovery starts over
    # SRP resource thresholds (srp.py)
    interval_threshold: float = 10.0
    max_frames_per_interval_threshold: int = 10
    max_frame_size_threshold: int = 1000
    # SRP request rate
    nr_of_requests_threshold: int = 10
    time_window_threshold: float = 10.0
    # SRP bandwidth
    srp_bandwidth_history_len: int = 10
    # PTP (ptp.py)
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
