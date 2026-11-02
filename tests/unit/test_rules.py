"""Unit tests of the rule detectors on hand-made messages (no Zeek, no Broker needed)."""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

from ids.engine import Detector, Engine  # noqa: E402
from ids.rules import Config, RuleDetector  # noqa: E402

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


class RuleTest(unittest.TestCase):
    def run_rules(self, messages, ticks=(), **config):
        """Feed (kind, msg) pairs, then advance the clock to each of `ticks`; return the rule ids alerted."""
        engine = Engine([RuleDetector(Config.from_dict(config))])
        alerts = []
        for kind, msg in messages:
            alerts += engine.feed(kind, msg)
        for now in ticks:
            alerts += engine.tick(now)
        self.alerts = alerts
        return [a.rule for a in alerts]


class Frer(RuleTest):
    def test_replicas_are_not_attacks(self):
        msgs = [cb(t, s) for t, s in ((0, 1), (0, 1), (1, 2), (1, 2), (2, 3), (2, 3))]
        self.assertEqual(self.run_rules(msgs, nr_of_member_streams=2), [])

    def test_extra_copy_alerts_once_per_sequence_number(self):
        msgs = [cb(0, 1)] * 4 + [cb(1, 2)] * 2
        self.assertEqual(self.run_rules(msgs, nr_of_member_streams=2), ["attack1"])

    def test_sequence_numbers_wrap_at_16_bits(self):
        msgs = [cb(0, 65534), cb(1, 65535), cb(2, 0), cb(3, 1)]
        self.assertEqual(self.run_rules(msgs, nr_of_member_streams=1), [])

    def test_skipped_numbers_are_accepted_with_an_alert(self):
        self.assertEqual(self.run_rules([cb(0, 1), cb(1, 2), cb(2, 6)], nr_of_member_streams=1), ["attack3"])
        self.assertIn("accepted", self.alerts[0].msg)

    def test_late_frame_inside_the_window_is_fine(self):
        self.assertEqual(self.run_rules([cb(0, 1), cb(1, 2), cb(2, 3), cb(3, 2)], nr_of_member_streams=2), [])

    def test_frame_outside_the_window_is_discarded_with_an_alert(self):
        self.assertEqual(self.run_rules([cb(0, 1), cb(1, 2), cb(2, 5000)], nr_of_member_streams=1), ["attack3"])
        self.assertIn("discarded", self.alerts[0].msg)

    def test_restarted_sender_is_discarded_until_the_recovery_reset(self):
        old = [cb(0, 100), cb(1, 101), cb(2, 102)]
        rules = self.run_rules(old + [cb(3, 1), cb(4, 2)], nr_of_member_streams=1, recovery_reset_time=3)
        self.assertEqual(rules, ["attack3", "attack3"])
        # 3.5 s after the last accepted frame the function starts over: no alert, and the next frames are fine.
        rules = self.run_rules(old + [cb(5.5, 1), cb(6, 2), cb(7, 3)], nr_of_member_streams=1, recovery_reset_time=3)
        self.assertEqual(rules, [])

    def test_streams_are_tracked_per_source_and_vlan(self):
        msgs = [cb(0, 1), cb(1, 2), cb(2, 3), cb(3, 1, src="00:00:00:00:00:09"), cb(4, 1, vlan=7)]
        self.assertEqual(self.run_rules(msgs, nr_of_member_streams=1), [])

    def test_dead_member_stream(self):
        msgs = [cb(0, 1), cb(0, 1), cb(1, 2)]                    # sequence number 2 has only one of two copies
        self.assertEqual(self.run_rules(msgs, ticks=[10], nr_of_member_streams=2, timeout=5),
                         ["attack4", "attack4"])
        self.assertIn("1 member", self.alerts[0].msg)
        self.assertIn("All member streams", self.alerts[1].msg)

    def test_the_same_number_of_dead_members_is_reported_once(self):
        msgs = [cb(0, 1), cb(1, 2), cb(2, 3)]
        rules = self.run_rules(msgs, ticks=[100], nr_of_member_streams=2, timeout=5)
        self.assertEqual(rules.count("attack4"), 2)              # "1 member dead" once, then "all dead"

    def test_healthy_stream_that_ends_is_reported_dead_only_after_the_timeout(self):
        msgs = [cb(0, 1), cb(0, 1)]
        self.assertEqual(self.run_rules(msgs, ticks=[4], nr_of_member_streams=2, timeout=5), [])
        self.assertEqual(self.run_rules(msgs, ticks=[6], nr_of_member_streams=2, timeout=5), ["attack4"])


class Srp(RuleTest):
    def test_request_within_the_thresholds(self):
        self.assertEqual(self.run_rules([talker(0, 1)]), [])

    def test_each_threshold(self):
        for kwargs, text in (({"num": 20, "den": 1}, "Interval"), ({"frames": 50}, "MaxFramesPerInterval"),
                             ({"size": 2000}, "MaxFrameSize")):
            with self.subTest(text):
                self.assertEqual(self.run_rules([talker(0, 1, **kwargs)]), ["attack5"])
                self.assertIn(text, self.alerts[0].msg)

    def test_zero_interval_is_reported_instead_of_dividing(self):
        for kwargs in ({"den": 0}, {"num": 0}):
            self.assertEqual(self.run_rules([talker(0, 1, **kwargs)]), ["attack5"])

    def test_listener_and_unrelated_messages_are_ignored(self):
        listener = ("srp", {"ts": 0, "msg_type": "ListenerEnhanced", "stream_mac": MAC, "stream_unique_id": 1})
        self.assertEqual(self.run_rules([listener, ("ptp", {"ts": 1, "msg_type": "Sync"})]), [])

    def test_identical_requests_do_not_deviate(self):
        msgs = [talker(i, i) for i in range(8)]
        self.assertEqual(self.run_rules(msgs, srp_bandwidth_history_len=3, nr_of_requests_threshold=100), [])

    def test_bandwidth_deviation(self):
        msgs = [talker(i, i) for i in range(3)] + [talker(3, 3, frames=4)]
        self.assertEqual(self.run_rules(msgs, srp_bandwidth_history_len=3), ["attack6"])

    def test_request_rate_uses_a_sliding_window(self):
        burst = [talker(i * 0.1, i) for i in range(6)]
        self.assertEqual(self.run_rules(burst, nr_of_requests_threshold=5, time_window_threshold=10),
                         ["attack7"])
        spread = [talker(i * 3, i) for i in range(6)]
        self.assertEqual(self.run_rules(spread, nr_of_requests_threshold=5, time_window_threshold=10), [])

    def test_changing_an_existing_reservation(self):
        self.assertEqual(self.run_rules([talker(0, 1), talker(1, 1)]), ["attack8"])
        self.assertEqual(self.run_rules([talker(0, 1), talker(1, 2), talker(2, 1, mac="00:00:00:00:00:03")]), [])

    def test_reservation_without_traffic(self):
        self.assertEqual(self.run_rules([talker(0, 1)], ticks=[6], timeout=5), ["attack9"])
        self.assertEqual(self.run_rules([talker(0, 1)], ticks=[4], timeout=5), [])

    def test_reservation_with_traffic(self):
        msgs = [talker(0, 1), cb(2, 1, src=MAC, vlan=1000)]
        self.assertEqual(self.run_rules(msgs, ticks=[6], timeout=5), [])

    def test_traffic_before_the_reservation_does_not_count(self):
        msgs = [cb(0, 1, src=MAC), talker(1, 1)]
        # (the old frame also makes the stream "dead" by then, which is attack4's business)
        self.assertIn("attack9", self.run_rules(msgs, ticks=[7], timeout=5, nr_of_member_streams=1))

    def test_traffic_on_another_data_vlan_does_not_count(self):
        msgs = [talker(0, 1, data_vlan=20), cb(2, 1, src=MAC, vlan=30)]
        self.assertEqual(self.run_rules(msgs, ticks=[6], timeout=5), ["attack9"])
        msgs = [talker(0, 1, data_vlan=20), cb(2, 1, src=MAC, vlan=20)]
        self.assertEqual(self.run_rules(msgs, ticks=[6], timeout=5), [])

    def test_a_reservation_is_judged_once(self):
        self.run_rules([talker(0, 1)], ticks=[6, 7, 8], timeout=5)
        self.assertEqual([a.rule for a in self.alerts], ["attack9"])


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
