# (C) 2026 Doganalp Ergenc, written with the assistance of Claude

"""Unit tests of the SRP rules on hand-made messages (no Zeek, no Broker needed)."""
import unittest

from helpers import MAC, DetectorTest, frer, talker
from ids.srp import SrpDetector


class Srp(DetectorTest):
    detectors = (SrpDetector,)

    def test_request_within_the_thresholds(self):
        self.assertEqual(self.run_rules([talker(0, 1)]), [])

    def test_each_threshold(self):
        for kwargs, text in (({"num": 20, "den": 1}, "Interval"), ({"frames": 50}, "MaxFramesPerInterval"),
                             ({"size": 2000}, "MaxFrameSize")):
            with self.subTest(text):
                self.assertEqual(self.run_rules([talker(0, 1, **kwargs)]), ["srp_oversized_request"])
                self.assertIn(text, self.alerts[0].msg)

    def test_zero_interval_is_reported_instead_of_dividing(self):
        for kwargs in ({"den": 0}, {"num": 0}):
            self.assertEqual(self.run_rules([talker(0, 1, **kwargs)]), ["srp_oversized_request"])

    def test_listener_and_unrelated_messages_are_ignored(self):
        listener = ("srp", {"ts": 0, "msg_type": "ListenerEnhanced", "stream_mac": MAC, "stream_unique_id": 1})
        self.assertEqual(self.run_rules([listener, ("ptp", {"ts": 1, "msg_type": "Sync"})]), [])

    def test_identical_requests_do_not_deviate(self):
        msgs = [talker(i, i) for i in range(8)]
        self.assertEqual(self.run_rules(msgs, srp_bandwidth_history_len=3, nr_of_requests_threshold=100), [])

    def test_bandwidth_deviation(self):
        msgs = [talker(i, i) for i in range(3)] + [talker(3, 3, frames=4)]
        self.assertEqual(self.run_rules(msgs, srp_bandwidth_history_len=3), ["srp_bandwidth_jump"])

    def test_request_rate_uses_a_sliding_window(self):
        burst = [talker(i * 0.1, i) for i in range(6)]
        self.assertEqual(self.run_rules(burst, nr_of_requests_threshold=5, time_window_threshold=10),
                         ["srp_request_burst"])
        spread = [talker(i * 3, i) for i in range(6)]
        self.assertEqual(self.run_rules(spread, nr_of_requests_threshold=5, time_window_threshold=10), [])

    def test_changing_an_existing_reservation(self):
        self.assertEqual(self.run_rules([talker(0, 1), talker(1, 1)]), ["srp_reservation_change"])
        self.assertEqual(self.run_rules([talker(0, 1), talker(1, 2), talker(2, 1, mac="00:00:00:00:00:03")]), [])

    def test_reservation_without_traffic(self):
        self.assertEqual(self.run_rules([talker(0, 1)], ticks=[6], timeout=5), ["srp_unused_reservation"])
        self.assertEqual(self.run_rules([talker(0, 1)], ticks=[4], timeout=5), [])

    def test_reservation_with_traffic(self):
        msgs = [talker(0, 1), frer(2, 1, src=MAC, vlan=1000)]
        self.assertEqual(self.run_rules(msgs, ticks=[6], timeout=5), [])

    def test_traffic_before_the_reservation_does_not_count(self):
        msgs = [frer(0, 1, src=MAC), talker(1, 1)]
        self.assertEqual(self.run_rules(msgs, ticks=[7], timeout=5), ["srp_unused_reservation"])

    def test_traffic_on_another_data_vlan_does_not_count(self):
        msgs = [talker(0, 1, data_vlan=20), frer(2, 1, src=MAC, vlan=30)]
        self.assertEqual(self.run_rules(msgs, ticks=[6], timeout=5), ["srp_unused_reservation"])
        msgs = [talker(0, 1, data_vlan=20), frer(2, 1, src=MAC, vlan=20)]
        self.assertEqual(self.run_rules(msgs, ticks=[6], timeout=5), [])

    def test_a_reservation_is_judged_once(self):
        self.run_rules([talker(0, 1)], ticks=[6, 7, 8], timeout=5)
        self.assertEqual([a.rule for a in self.alerts], ["srp_unused_reservation"])


if __name__ == "__main__":
    unittest.main()
