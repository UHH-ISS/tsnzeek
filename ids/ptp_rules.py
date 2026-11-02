# -----------------------------------------------------------
#
#  ptp_rules.py
#
# Rule-based detectors for (g)PTP, working on the records of ptp.log (Ethernet and UDP alike).
#
#   ptp1  a different grandmaster announces itself with a better clock than the current one (BMCA takeover)
#   ptp2  Sync or Follow_Up from a clock that has not announced itself in the domain
#   ptp3  sequenceId of a master's Sync/Follow_Up/Announce does not advance by one (replay, injection, loss)
#
# The hosts of a test network can share one clock, so no rule compares timestamps with the local time.
#
# (C) 2024 Ahmed Abdulfattah, Berlin, Germany
# Released under GNU Public License (GPL)
# -----------------------------------------------------------

from typing import Dict, List, Optional, Set, Tuple

from .engine import Alert, Detector
from .rules import Config


SLAVE_ONLY = 255                         # clockClass of a clock that can only be a client


def dataset(msg) -> Optional[tuple]:
    """The grandmaster attributes the best master clock algorithm compares; smaller is better (IEEE 1588 9.3.4)."""
    try:
        return (msg["gm_priority1"], msg["gm_clock_class"], msg["gm_clock_accuracy"],
                msg["gm_offset_scaled_log_variance"], msg["gm_priority2"], msg["gm_identity"])
    except KeyError:
        return None


class PtpDetector(Detector):
    def __init__(self, config: Config = Config()):
        self.c = config
        self.first_seen: Dict[int, float] = {}                         # domain -> first PTP message
        self.grandmaster: Dict[int, Tuple[tuple, float]] = {}          # domain -> (dataset, last Announce)
        self.announcers: Dict[int, Dict[str, float]] = {}              # domain -> clock identity -> last Announce
        self.flagged: Set[Tuple[int, str]] = set()                     # clocks ptp2 has already reported
        self.sequence: Dict[tuple, Tuple[int, float]] = {}             # stream key -> (last sequenceId, last ts)

    def on_message(self, kind, msg):
        if kind != "ptp":
            return ()
        ts, domain, mtype = msg["ts"], msg["domain_number"], msg["msg_type"]
        self.first_seen.setdefault(domain, ts)
        alerts: List[Alert] = []
        if mtype == "Announce":
            alerts += self._announce(msg, ts, domain)
        elif mtype in ("Sync", "Follow_Up"):
            alerts += self._source(msg, ts, domain)
        if mtype in ("Announce", "Sync", "Follow_Up"):
            alerts += self._sequence(msg, ts, domain, mtype)
        return alerts

    def _announce(self, msg, ts, domain) -> List[Alert]:
        self.announcers.setdefault(domain, {})[msg["source_clock_id"]] = ts
        new = dataset(msg)
        if new is None or new[1] == SLAVE_ONLY:
            return []                   # a slave-only clock (ptp4l announces itself so until it hears a master) cannot win
        current = self.grandmaster.get(domain)
        if current is None or ts - current[1] > self.c.ptp_gm_timeout:
            self.grandmaster[domain] = (new, ts)                        # first master, or a failover after silence
            return []
        old = current[0]
        if new[-1] == old[-1]:
            self.grandmaster[domain] = (new, ts)                        # the same grandmaster, maybe re-tuned
            return []
        if new < old:                                                   # another clock would win the BMCA
            self.grandmaster[domain] = (new, ts)
            return [Alert(ts, "ptp1", f"Grandmaster {new[-1]} announces itself in domain {domain} with a better clock "
                                      f"(priority1 {new[0]}, class {new[1]}) than the current {old[-1]} "
                                      f"(priority1 {old[0]}, class {old[1]}); source {msg['source_clock_id']}",
                          f"domain {domain}")]
        return []                                                       # a backup master: expected

    def _source(self, msg, ts, domain) -> List[Alert]:
        clock = msg["source_clock_id"]
        masters = {c for c, last in self.announcers.get(domain, {}).items() if ts - last <= self.c.ptp_gm_timeout}
        if clock in masters or (domain, clock) in self.flagged:
            return []
        if not masters and ts - self.first_seen[domain] <= self.c.ptp_learning_time:
            return []                                                   # the Announce may simply not have been seen yet
        self.flagged.add((domain, clock))
        return [Alert(ts, "ptp2", f"{msg['msg_type']} from clock {clock} in domain {domain}, which has not announced "
                                  f"itself" + (f" (masters: {', '.join(sorted(masters))})" if masters else ""),
                      f"domain {domain}")]

    def _sequence(self, msg, ts, domain, mtype) -> List[Alert]:
        transport = "udp" if "uid" in msg else "ethernet"
        key = (domain, msg["source_clock_id"], msg["source_port"], mtype, transport)
        seq = msg["sequence_id"]
        last = self.sequence.get(key)
        self.sequence[key] = (seq, ts)
        if last is None or ts - last[1] > self.c.ptp_seq_reset_time:
            return []
        delta = ((seq - last[0] + 0x8000) & 0xFFFF) - 0x8000
        if delta == 1 or 1 < delta <= 1 + self.c.ptp_seq_gap_tolerance:
            return []
        who = f"{mtype} of {msg['source_clock_id']}/{msg['source_port']} ({transport}, domain {domain})"
        if delta == 0:
            what = f"sequenceId {seq} repeated"
        elif delta < 0:
            what = f"sequenceId went back from {last[0]} to {seq}"
        else:
            what = f"sequenceId jumped from {last[0]} to {seq} ({delta - 1} missing)"
        return [Alert(ts, "ptp3", f"{who}: {what}", f"domain {domain}")]
