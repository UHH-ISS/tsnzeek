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
        self.assertEqual(self.count("ids_frer"), {"attack1": 1, "attack3": 2, "attack4": 2})

    def test_frer_restart(self):
        alerts = self.alerts("ids_frer_restart")
        self.assertEqual([(a.rule, round(a.ts) - 1700000000) for a in alerts], [("attack3", 4), ("attack3", 4)])

    def test_ptp(self):
        alerts = self.alerts("ids_ptp")
        self.assertEqual([(a.rule, round(a.ts) - 1700000000) for a in alerts],
                         [("ptp1", 3), ("ptp2", 4), ("ptp3", 6), ("ptp3", 7)])

    def test_srp(self):
        self.assertEqual(self.count("ids_srp"),
                         {"attack5": 4, "attack6": 2, "attack7": 3, "attack8": 1, "attack9": 1})


if __name__ == "__main__":
    unittest.main()
