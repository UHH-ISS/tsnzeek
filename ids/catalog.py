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
    """`id` is stable: 1xx FRER, 2xx SRP, 3xx PTP. A new rule gets the next free number, a removed rule's number is never reused."""
    id: int
    name: str
    protocol: str                     # "frer", "srp" or "ptp"
    summary: str
    thresholds: Tuple[str, ...] = ()  # fields of Config


RULES = (
    Rule(101, "frer_excess_copies", "frer", "more copies of a frame than member streams", ("nr_of_member_streams",)),
    Rule(102, "frer_out_of_order", "frer", "sequence numbers out of order, accepted or discarded by the sequence recovery",
         ("frer_history_size", "recovery_reset_time")),
    Rule(103, "frer_dead_stream", "frer", "member streams that stopped (all or some copies)", ("timeout",)),
    Rule(201, "srp_oversized_request", "srp", "a reservation above the resource thresholds",
         ("interval_threshold", "max_frames_per_interval_threshold", "max_frame_size_threshold")),
    Rule(202, "srp_bandwidth_jump", "srp", "a bandwidth more than two standard deviations from the recent requests",
         ("srp_bandwidth_history_len",)),
    Rule(203, "srp_request_burst", "srp", "too many requests in a time window",
         ("nr_of_requests_threshold", "time_window_threshold")),
    Rule(204, "srp_reservation_change", "srp", "a request for a reservation that exists already"),
    Rule(205, "srp_unused_reservation", "srp", "a reservation with no FRER traffic", ("timeout",)),
    Rule(301, "ptp_rogue_grandmaster", "ptp", "a grandmaster with a better clock than the current one announces itself",
         ("ptp_gm_timeout",)),
    Rule(302, "ptp_unannounced_sync", "ptp", "Sync or Follow_Up from a clock that never announced itself",
         ("ptp_learning_time",)),
    Rule(303, "ptp_sequence_id", "ptp", "sequenceId repeated, going back or skipping",
         ("ptp_seq_gap_tolerance", "ptp_seq_reset_time")),
)

NAMES = frozenset(r.name for r in RULES)
BY_ID = {r.id: r.name for r in RULES}


def rule_name(ref):
    """A rule given by name or by number (an int, or a string of digits); None if there is no such rule."""
    if isinstance(ref, str) and ref.isdigit():
        ref = int(ref)
    if isinstance(ref, bool):
        return None
    return BY_ID.get(ref) if isinstance(ref, int) else (ref if ref in NAMES else None)
