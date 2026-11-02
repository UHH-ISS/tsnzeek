"""Unit tests of the engine and the configuration."""
import unittest

import helpers  # noqa: F401  (puts the repository on sys.path)
from ids.config import Config
from ids.engine import Detector, Engine


class EngineTest(unittest.TestCase):
    def test_config_rejects_unknown_keys(self):
        with self.assertRaises(ValueError):
            Config.from_dict({"nr_of_members": 2})

    def test_detectors_plug_in_and_ticks_follow_message_time(self):
        class Probe(Detector):
            def __init__(self):
                self.kinds, self.ticks = [], []

            def on_message(self, kind, msg):
                self.kinds.append(kind)
                return ()

            def on_tick(self, now):
                self.ticks.append(now)
                return ()

        probe = Probe()
        engine = Engine([probe], tick_interval=1.0)
        for ts in (0.0, 0.5, 1.0, 1.4, 2.1):
            engine.feed("ptp", {"ts": ts})
        self.assertEqual(probe.kinds, ["ptp"] * 5)
        self.assertEqual(probe.ticks, [1.0, 2.1])
        engine.feed("ptp", {"ts": 0.1})                           # late message: the clock never goes back
        self.assertEqual(engine.now, 2.1)


if __name__ == "__main__":
    unittest.main()
