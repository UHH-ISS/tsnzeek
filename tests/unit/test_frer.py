# (C) 2026 Doganalp Ergenc, written with the assistance of Claude

"""Unit tests of the FRER rules on hand-made messages (no Zeek, no Broker needed)."""
import unittest

from helpers import DetectorTest, frer
from ids.frer import FrerDetector


class Frer(DetectorTest):
    detectors = (FrerDetector,)

    def test_replicas_are_not_attacks(self):
        msgs = [frer(t, s) for t, s in ((0, 1), (0, 1), (1, 2), (1, 2), (2, 3), (2, 3))]
        self.assertEqual(self.run_rules(msgs, nr_of_member_streams=2), [])

    def test_extra_copy_alerts_once_per_sequence_number(self):
        msgs = [frer(0, 1)] * 4 + [frer(1, 2)] * 2
        self.assertEqual(self.run_rules(msgs, nr_of_member_streams=2), ["frer_excess_copies"])

    def test_sequence_numbers_wrap_at_16_bits(self):
        msgs = [frer(0, 65534), frer(1, 65535), frer(2, 0), frer(3, 1)]
        self.assertEqual(self.run_rules(msgs, nr_of_member_streams=1), [])

    def test_skipped_numbers_are_accepted_with_an_alert(self):
        self.assertEqual(self.run_rules([frer(0, 1), frer(1, 2), frer(2, 6)], nr_of_member_streams=1), ["frer_out_of_order"])
        self.assertIn("accepted", self.alerts[0].msg)

    def test_late_frame_inside_the_window_is_fine(self):
        self.assertEqual(self.run_rules([frer(0, 1), frer(1, 2), frer(2, 3), frer(3, 2)], nr_of_member_streams=2), [])

    def test_frame_outside_the_window_is_discarded_with_an_alert(self):
        self.assertEqual(self.run_rules([frer(0, 1), frer(1, 2), frer(2, 5000)], nr_of_member_streams=1), ["frer_out_of_order"])
        self.assertIn("discarded", self.alerts[0].msg)

    def test_restarted_sender_is_discarded_until_the_recovery_reset(self):
        old = [frer(0, 100), frer(1, 101), frer(2, 102)]
        rules = self.run_rules(old + [frer(3, 1), frer(4, 2)], nr_of_member_streams=1, recovery_reset_time=3)
        self.assertEqual(rules, ["frer_out_of_order", "frer_out_of_order"])
        # 3.5 s after the last accepted frame the function starts over: no alert, and the next frames are fine.
        rules = self.run_rules(old + [frer(5.5, 1), frer(6, 2), frer(7, 3)], nr_of_member_streams=1, recovery_reset_time=3)
        self.assertEqual(rules, [])

    def test_streams_are_tracked_per_source_and_vlan(self):
        msgs = [frer(0, 1), frer(1, 2), frer(2, 3), frer(3, 1, src="00:00:00:00:00:09"), frer(4, 1, vlan=7)]
        self.assertEqual(self.run_rules(msgs, nr_of_member_streams=1), [])

    def test_dead_member_stream(self):
        msgs = [frer(0, 1), frer(0, 1), frer(1, 2)]                    # sequence number 2 has only one of two copies
        self.assertEqual(self.run_rules(msgs, ticks=[10], nr_of_member_streams=2, timeout=5),
                         ["frer_dead_stream", "frer_dead_stream"])
        self.assertIn("1 member", self.alerts[0].msg)
        self.assertIn("All member streams", self.alerts[1].msg)

    def test_the_same_number_of_dead_members_is_reported_once(self):
        msgs = [frer(0, 1), frer(1, 2), frer(2, 3)]
        rules = self.run_rules(msgs, ticks=[100], nr_of_member_streams=2, timeout=5)
        self.assertEqual(rules.count("frer_dead_stream"), 2)              # "1 member dead" once, then "all dead"

    def test_healthy_stream_that_ends_is_reported_dead_only_after_the_timeout(self):
        msgs = [frer(0, 1), frer(0, 1)]
        self.assertEqual(self.run_rules(msgs, ticks=[4], nr_of_member_streams=2, timeout=5), [])
        self.assertEqual(self.run_rules(msgs, ticks=[6], nr_of_member_streams=2, timeout=5), ["frer_dead_stream"])


if __name__ == "__main__":
    unittest.main()
