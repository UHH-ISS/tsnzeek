"""Messages and a test case shared by the detector tests: hand-made records like those of cb.log and srp.log."""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

from ids.config import Config  # noqa: E402
from ids.engine import Engine  # noqa: E402

MAC = "00:00:00:00:00:02"


def cb(ts, seq, src="00:00:00:00:00:01", vlan=150):
    return "cb", {"ts": ts, "src": src, "vlan": vlan, "reserved": 0, "sequence_nr": seq}


def talker(ts, uid, mac=MAC, num=1, den=8000, frames=2, size=128, data_vlan=None):
    msg = {"ts": ts, "msg_type": "TalkerEnhanced", "stream_mac": mac, "stream_unique_id": uid, "vlan": 1000,
           "interval_numerator": num, "interval_denominator": den,
           "max_frames_per_interval": frames, "max_frame_size": size}
    if data_vlan is not None:
        msg["df_vlan_id"] = data_vlan
    return "srp", msg


class DetectorTest(unittest.TestCase):
    """Feed messages to the detectors in `detectors` and return the names of the rules that fired."""

    detectors = ()

    def run_rules(self, messages, ticks=(), **config):
        """Feed (kind, msg) pairs, then advance the clock to each of `ticks`; return the rules alerted."""
        engine = Engine([d(Config.from_dict(config)) for d in self.detectors])
        alerts = []
        for kind, msg in messages:
            alerts += engine.feed(kind, msg)
        for now in ticks:
            alerts += engine.tick(now)
        self.alerts = alerts
        return [a.rule for a in alerts]
