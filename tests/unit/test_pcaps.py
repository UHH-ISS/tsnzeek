"""Run Zeek over tests/pcaps/ids_*.pcap and check which rules the resulting logs trigger.

Needs a Zeek install with Spicy (ZEEK_PREFIX, default /opt/zeek); the tests are skipped without one. These are the
same pcaps as tests/run_ids.sh, but replayed from Zeek's JSON logs, so no Broker is involved.
"""
import collections
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
sys.path.insert(0, ROOT)

from ids.__main__ import build_engine, load_logs  # noqa: E402

ZEEK = os.path.join(os.environ.get("ZEEK_PREFIX", "/opt/zeek"), "bin", "zeek")
CONFIG = os.path.join(ROOT, "tests", "ids", "config.json")


@unittest.skipUnless(os.access(ZEEK, os.X_OK), "Zeek not installed")
class PcapRules(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        subprocess.run([os.path.join(ROOT, "build.sh"), "--no-test"], check=True, capture_output=True)
        cls.work = tempfile.mkdtemp()
        cls.addClassCleanup(shutil.rmtree, cls.work)

    def alerts(self, case):
        out = os.path.join(self.work, case)
        os.makedirs(out, exist_ok=True)
        env = dict(os.environ, ZEEK_SPICY_MODULE_PATH=os.path.join(ROOT, "build", "spicy"))
        subprocess.run([ZEEK, "-C", "-D", "-r", os.path.join(ROOT, "tests", "pcaps", case + ".pcap"),
                        os.path.join(ROOT, "spicy", "scripts"), "TSN::enable_broker=F", "LogAscii::use_json=T"],
                       cwd=out, env=env, check=True, capture_output=True)
        logs = [os.path.join(out, f) for f in ("cb.log", "ptp.log", "srp.log") if os.path.exists(os.path.join(out, f))]
        engine = build_engine(CONFIG)
        alerts = []
        for kind, msg in load_logs(logs):
            alerts += engine.feed(kind, msg)
        return alerts

    def count(self, case):
        return dict(collections.Counter(a.rule for a in self.alerts(case)))

    def test_frer(self):
        self.assertEqual(self.count("ids_frer"), {"frer_excess_copies": 1, "frer_out_of_order": 2, "frer_dead_stream": 2})

    def test_frer_restart(self):
        alerts = self.alerts("ids_frer_restart")
        self.assertEqual([(a.rule, round(a.ts) - 1700000000) for a in alerts], [("frer_out_of_order", 4), ("frer_out_of_order", 4)])

    def test_ptp(self):
        alerts = self.alerts("ids_ptp")
        self.assertEqual([(a.rule, round(a.ts) - 1700000000) for a in alerts],
                         [("ptp_rogue_grandmaster", 3), ("ptp_unannounced_sync", 4), ("ptp_sequence_id", 6), ("ptp_sequence_id", 7)])

    def test_srp(self):
        self.assertEqual(self.count("ids_srp"),
                         {"srp_oversized_request": 4, "srp_bandwidth_jump": 2, "srp_request_burst": 3, "srp_reservation_change": 1, "srp_unused_reservation": 1})


if __name__ == "__main__":
    unittest.main()
