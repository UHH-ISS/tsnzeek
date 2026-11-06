# -----------------------------------------------------------
#
#  frer.py
#
# Rules for FRER (802.1CB) streams, working on the records of frer.log. The numbers are those of the original
# attack-detection.py.
#
#   frer_excess_copies   more copies of a frame than member streams              (attack1)
#   frer_out_of_order    sequence numbers out of order, accepted or discarded    (attack3)
#   frer_dead_stream     member streams that stopped                             (attack4)
#
# (The timing attack 2 of the original script was never implemented there.)
#
# (C) 2022 Robin Schenderlein, Hamburg, Germany
# (C) 2026 Doganalp Ergenc, written with the assistance of Claude
# Released under GNU Public License (GPL)
# -----------------------------------------------------------

from collections import OrderedDict
from typing import Dict, List

from .config import Config
from .engine import Alert, Detector, stream_key

EXCESS_COPIES = "frer_excess_copies"
OUT_OF_ORDER = "frer_out_of_order"
DEAD_STREAM = "frer_dead_stream"


class FrerDetector(Detector):
    def __init__(self, config: Config = Config()):
        self.c = config
        self.recovery: Dict[str, list] = {}                          # stream -> [latest, seen bitmask, last accepted ts]
        self.history: Dict[str, "OrderedDict[int, list]"] = {}       # stream -> seq -> [count, last ts]
        self.dead: Dict[str, int] = {}

    def on_message(self, kind, msg):
        if kind != "frer":
            return ()
        ts, seq = msg["ts"], msg["sequence_nr"]
        sid = stream_key(msg.get("src"), msg.get("vlan"))
        return self._copies(sid, seq, ts) + self._recovery(sid, seq, ts)

    def on_tick(self, now):
        return self._dead_streams(now)

    def _copies(self, sid, seq, ts) -> List[Alert]:
        entry = self.history.setdefault(sid, OrderedDict()).setdefault(seq, [0, ts])
        entry[0] += 1
        entry[1] = ts
        if entry[0] == self.c.nr_of_member_streams + 1:   # once per sequence number
            return [Alert(ts, EXCESS_COPIES, f"Got more frames for compound stream {sid} than expected "
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
            return [Alert(ts, OUT_OF_ORDER, f"Out of order frame discarded for stream id {sid}: "
                                            f"sequence_nr: {seq} latest_valid: {latest}", sid)]
        mask = (1 << h) - 1
        if delta <= 0:
            if not seen >> -delta & 1:
                state[2] = ts                                  # an old frame that was missing: accepted
            state[1] = (seen | (1 << -delta)) & mask
            return []
        state[0], state[1], state[2] = seq, ((seen << delta) | 1) & mask, ts
        if delta != 1:
            return [Alert(ts, OUT_OF_ORDER, f"Out of order frame accepted for stream id {sid}: "
                                            f"sequence_nr: {seq} latest_valid: {latest} delta: {delta}", sid)]
        return []

    def _dead_streams(self, now) -> List[Alert]:
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
                    alerts.append(Alert(now, DEAD_STREAM, f"{n - count} member stream[s] of stream {sid} "
                                                          "are probably dead", sid))
            if not hist:
                alerts.append(Alert(now, DEAD_STREAM, f"All member streams of stream {sid} are probably dead", sid))
                del self.history[sid]
                self.dead.pop(sid, None)
        return alerts
