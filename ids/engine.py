# -----------------------------------------------------------
#
#  engine.py
#
# Transport-independent core of the IDS. Detectors see parsed TSN messages (plain dicts, the JSON
# records Zeek also writes to cb.log, ptp.log and srp.log) and a clock that is the timestamp of the
# newest message, so a pcap replayed at any speed gives the same alerts as live traffic.
#
# A detector is anything with on_message/on_tick: the rules of frer.py, srp.py and ptp.py, a statistical test or an
# embedded ML model all plug in the same way.
#
# (C) 2022 Robin Schenderlein, Hamburg, Germany
# Released under GNU Public License (GPL)
# -----------------------------------------------------------

from dataclasses import dataclass
from typing import Iterable, List, Optional


@dataclass(frozen=True)
class Alert:
    ts: float
    rule: str
    msg: str
    stream: Optional[str] = None

    def __str__(self):
        return f"{self.rule}: {self.msg}"


def stream_key(mac, vlan) -> str:
    """How alerts name a stream: source (or stream) MAC address and VLAN id."""
    return f"{mac}/{'-' if vlan is None else vlan}"


class Detector:
    """Base class. Override the hooks you need; both return the alerts they raise."""

    def on_message(self, kind: str, msg: dict) -> Iterable[Alert]:
        """`kind` is "cb", "ptp" or "srp"; `msg` is the decoded record, always with a `ts`."""
        return ()

    def on_tick(self, now: float) -> Iterable[Alert]:
        """Called when the clock has advanced by `tick_interval`; for timeouts."""
        return ()


class Engine:
    def __init__(self, detectors: List[Detector], tick_interval: float = 1.0):
        self.detectors = detectors
        self.tick_interval = tick_interval
        self.now = 0.0
        self._last_tick = None

    def feed(self, kind: str, msg: dict) -> List[Alert]:
        alerts: List[Alert] = []
        self.now = max(self.now, msg["ts"])
        for d in self.detectors:
            alerts.extend(d.on_message(kind, msg))
        if self._last_tick is None:
            self._last_tick = self.now
        if self.now - self._last_tick >= self.tick_interval:
            alerts.extend(self.tick(self.now))
        return alerts

    def tick(self, now: float) -> List[Alert]:
        """Advance the clock without a message (live idle time, or draining at the end of a pcap)."""
        self.now = max(self.now, now)
        self._last_tick = self.now
        alerts: List[Alert] = []
        for d in self.detectors:
            alerts.extend(d.on_tick(self.now))
        return alerts
