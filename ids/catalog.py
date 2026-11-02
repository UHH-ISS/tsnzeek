# -----------------------------------------------------------
#
#  catalog.py
#
# The rules of the IDS as data: name, protocol, what it detects and which thresholds of `Config` it uses.
# The web interface lists them per protocol and switches them; a test keeps this list equal to the rules
# the detectors can raise.
#
# (C) 2026 Doganalp Ergenc, written with the assistance of Claude
# Released under GNU Public License (GPL)
# -----------------------------------------------------------
from dataclasses import dataclass
from typing import Tuple


@dataclass(frozen=True)
class Rule:
    name: str
    protocol: str                     # "frer", "srp" or "ptp"
    summary: str
    thresholds: Tuple[str, ...] = ()  # fields of Config


RULES = (
    Rule("frer_excess_copies", "frer", "more copies of a frame than member streams", ("nr_of_member_streams",)),
    Rule("frer_out_of_order", "frer", "sequence numbers out of order, accepted or discarded by the sequence recovery",
         ("frer_history_size", "recovery_reset_time")),
    Rule("frer_dead_stream", "frer", "member streams that stopped (all or some copies)", ("timeout",)),
    Rule("srp_oversized_request", "srp", "a reservation above the resource thresholds",
         ("interval_threshold", "max_frames_per_interval_threshold", "max_frame_size_threshold")),
    Rule("srp_bandwidth_jump", "srp", "a bandwidth more than two standard deviations from the recent requests",
         ("srp_bandwidth_history_len",)),
    Rule("srp_request_burst", "srp", "too many requests in a time window",
         ("nr_of_requests_threshold", "time_window_threshold")),
    Rule("srp_reservation_change", "srp", "a request for a reservation that exists already"),
    Rule("srp_unused_reservation", "srp", "a reservation with no FRER traffic", ("timeout",)),
    Rule("ptp_rogue_grandmaster", "ptp", "a grandmaster with a better clock than the current one announces itself",
         ("ptp_gm_timeout",)),
    Rule("ptp_unannounced_sync", "ptp", "Sync or Follow_Up from a clock that never announced itself",
         ("ptp_learning_time",)),
    Rule("ptp_sequence_id", "ptp", "sequenceId repeated, going back or skipping",
         ("ptp_seq_gap_tolerance", "ptp_seq_reset_time")),
)

NAMES = frozenset(r.name for r in RULES)
