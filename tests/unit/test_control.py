# (C) 2026 Doganalp Ergenc, written with the assistance of Claude

"""The rule catalog and the control channel to the web interface (ids/catalog.py, ids/control.py)."""
import json
import os
import tempfile
import unittest

import helpers  # noqa: F401  (puts the repository on sys.path)
from helpers import frer as frer_msg
from ids import frer, ptp, srp
from ids.__main__ import build_engine
from ids.catalog import NAMES, RULES, rule_name
from ids.config import Config
from ids.control import CONTROL, STATE, Control, validate


def make(directory, **overrides):
    config = Config.from_dict(overrides)
    engine = build_engine(None, config)
    return Control(directory, config, engine), engine


def write(directory, data):
    with open(os.path.join(directory, CONTROL), "w") as f:
        json.dump(data, f)


def state(directory):
    with open(os.path.join(directory, STATE)) as f:
        return json.load(f)


class CatalogTest(unittest.TestCase):
    def test_catalog_lists_exactly_the_rules_the_detectors_can_raise(self):
        raised = {v for m in (frer, srp, ptp) for k, v in vars(m).items() if k.isupper() and isinstance(v, str)
                  and v.startswith(("frer_", "srp_", "ptp_"))}
        self.assertEqual(NAMES, raised)

    def test_thresholds_of_the_catalog_are_config_fields(self):
        fields = set(Config.__dataclass_fields__)
        for rule in RULES:
            self.assertLessEqual(set(rule.thresholds), fields, rule.name)


    def test_rule_numbers_are_unique_and_follow_the_protocol(self):
        self.assertEqual(len({r.id for r in RULES}), len(RULES))
        base = {"frer": 100, "srp": 200, "ptp": 300}
        for r in RULES:
            self.assertEqual(r.id // 100 * 100, base[r.protocol], r.name)

    def test_rule_by_name_or_number(self):
        self.assertEqual([rule_name(x) for x in ("srp_request_burst", 203, "203", 999, "nope", True)],
                         ["srp_request_burst", "srp_request_burst", "srp_request_burst", None, None, None])


class ValidateTest(unittest.TestCase):
    def test_accepts_rules_and_numbers_and_keeps_the_type_of_the_field(self):
        self.assertEqual(validate({"disabled_rules": [103, "202"]}, Config())[0], {"frer_dead_stream", "srp_bandwidth_jump"})
        disabled, config = validate({"disabled_rules": ["frer_dead_stream"], "config": {"timeout": 30, "frer_history_size": 7.0}},
                                    Config())
        self.assertEqual(disabled, {"frer_dead_stream"})
        self.assertEqual((config.timeout, config.frer_history_size), (30.0, 7))
        self.assertIsInstance(config.frer_history_size, int)

    def test_rejects_what_does_not_fit(self):
        for bad in ({"disabled_rules": ["nope"]}, {"disabled_rules": [999]}, {"disabled_rules": "frer_dead_stream"}, {"config": {"nope": 1}},
                    {"config": {"timeout": "30"}}, {"config": {"timeout": True}}, {"config": {"timeout": -1}},
                    {"config": {"frer_history_size": 2.5}}, {"other": 1}, []):
            with self.assertRaises(ValueError, msg=bad):
                validate(bad, Config())


class ControlTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def excess(self, engine, seq=1, t0=0.0):
        """The rules named frer_excess_copies for three copies of one sequence number (two member streams expected)."""
        alerts = []
        for i in range(3):
            alerts += engine.feed(*frer_msg(t0 + i * 0.01, seq))
        return [a for a in alerts if a.rule == "frer_excess_copies"]

    def test_state_lists_every_rule_with_its_protocol_and_the_active_config(self):
        control, _ = make(self.dir, nr_of_member_streams=2)
        control.poll()
        st = state(self.dir)
        self.assertEqual({r["name"] for r in st["rules"]}, NAMES)
        self.assertTrue(all(r["enabled"] for r in st["rules"]))
        self.assertEqual(st["config"]["active"]["nr_of_member_streams"], 2)
        self.assertEqual(st["config"]["changed"], ["nr_of_member_streams"])

    def test_disabled_rule_raises_no_alerts_and_comes_back(self):
        control, engine = make(self.dir, nr_of_member_streams=2)
        write(self.dir, {"disabled_rules": ["frer_excess_copies"]})
        control.poll()
        self.assertEqual(self.excess(engine), [])
        self.assertFalse(next(r for r in state(self.dir)["rules"] if r["name"] == "frer_excess_copies")["enabled"])
        os.remove(os.path.join(self.dir, CONTROL))
        control.poll()
        self.assertEqual([a.rule for a in self.excess(engine, seq=2, t0=100.0)], ["frer_excess_copies"])

    def test_threshold_change_applies_at_once_and_keeps_what_was_learned(self):
        control, engine = make(self.dir, nr_of_member_streams=5)
        detector = engine.detectors[0]
        engine.feed(*frer_msg(0.0, 6))
        learned = dict(detector.history)
        self.assertEqual(self.excess(engine, seq=1, t0=1.0), [])                   # 3 copies of 5 expected: fine
        write(self.dir, {"config": {"nr_of_member_streams": 2}})
        control.poll()
        self.assertEqual(detector.c.nr_of_member_streams, 2)
        self.assertIs(engine.detectors[0], detector)                     # same object, same state
        self.assertTrue(set(learned) <= set(detector.history))
        self.assertEqual([a.rule for a in self.excess(engine, seq=7, t0=2.0)], ["frer_excess_copies"])

    def test_invalid_file_is_ignored_as_a_whole_and_reported(self):
        control, engine = make(self.dir)
        write(self.dir, {"disabled_rules": ["frer_dead_stream"], "config": {"nope": 1}})
        control.poll()
        self.assertEqual(engine.disabled, set())
        self.assertIn("unknown config keys", state(self.dir)["error"])
        write(self.dir, {"disabled_rules": ["frer_dead_stream"]})
        control.poll()
        self.assertIsNone(state(self.dir)["error"])
        self.assertEqual(engine.disabled, {"frer_dead_stream"})

    def test_bandwidth_history_is_resized_without_losing_it(self):
        control, engine = make(self.dir, srp_bandwidth_history_len=3)
        detector = engine.detectors[1]
        detector.bandwidth.extend([1, 2, 3])
        write(self.dir, {"config": {"srp_bandwidth_history_len": 5}})
        control.poll()
        self.assertEqual((list(detector.bandwidth), detector.bandwidth.maxlen), ([1, 2, 3], 5))

    def test_state_has_counters_streams_and_a_rate(self):
        control, engine = make(self.dir)
        for i in range(4):
            control.note_message("frer")
            engine.feed(*frer_msg(float(i), i + 1))
        control.poll()
        st = state(self.dir)
        self.assertEqual(st["messages"], {"frer": 4})
        self.assertEqual(st["streams"]["frer"][0]["stream"], "00:00:00:00:00:01/150")
        self.assertIn("messages_per_second", st)


if __name__ == "__main__":
    unittest.main()
