"""Unit tests of the PTP rules on hand-made ptp.log records (no Zeek, no Broker needed)."""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

from ids.engine import Engine  # noqa: E402
from ids.ptp_rules import PtpDetector  # noqa: E402
from ids.rules import Config  # noqa: E402

GM, ROGUE, OTHER = "008063ffff0009ba", "deadbeefcafe0001", "feedfacefeed0002"


def ptp(ts, mtype, seq, clock=GM, port=1, domain=0, udp=False, **extra):
    msg = {"ts": ts, "msg_type": mtype, "domain_number": domain, "source_clock_id": clock, "source_port": port,
           "sequence_id": seq}
    if udp:
        msg["uid"] = "Cabc"
    msg.update(extra)
    return "ptp", msg


def announce(ts, seq, gm=GM, clock=None, p1=128, cls=248, **kw):
    return ptp(ts, "Announce", seq, clock=clock or gm, gm_identity=gm, gm_priority1=p1, gm_clock_class=cls,
               gm_clock_accuracy=0x21, gm_offset_scaled_log_variance=0x4E5D, gm_priority2=128, **kw)


class PtpRules(unittest.TestCase):
    def run_rules(self, messages, **config):
        engine = Engine([PtpDetector(Config.from_dict(config))])
        self.alerts = [a for kind, msg in messages for a in engine.feed(kind, msg)]
        return [a.rule for a in self.alerts]

    # ---- ptp1

    def test_a_steady_master_is_fine(self):
        msgs = [announce(0, 1), ptp(0.1, "Sync", 1), ptp(0.2, "Follow_Up", 1), announce(1, 2), ptp(1.1, "Sync", 2)]
        self.assertEqual(self.run_rules(msgs), [])

    def test_a_better_grandmaster_takes_over(self):
        msgs = [announce(0, 1), announce(1, 1, gm=ROGUE, p1=1, cls=6)]
        self.assertEqual(self.run_rules(msgs), ["ptp1"])
        self.assertIn(ROGUE, self.alerts[0].msg)

    def test_a_takeover_is_reported_once(self):
        msgs = [announce(0, 1), announce(1, 1, gm=ROGUE, p1=1), announce(2, 2, gm=ROGUE, p1=1), announce(3, 3, gm=ROGUE, p1=1)]
        self.assertEqual(self.run_rules(msgs), ["ptp1"])

    def test_the_old_master_announcing_again_is_a_backup_not_a_second_alert(self):
        msgs = [announce(0, 1), announce(1, 1, gm=ROGUE, p1=1), announce(2, 2)]
        self.assertEqual(self.run_rules(msgs), ["ptp1"])

    def test_a_worse_second_clock_is_a_backup(self):
        msgs = [announce(0, 1, p1=100), announce(1, 1, gm=OTHER, p1=200), announce(2, 2, p1=100)]
        self.assertEqual(self.run_rules(msgs), [])

    def test_each_attribute_of_the_dataset_counts(self):
        for kwargs in ({"p1": 128, "cls": 6}, {"p1": 127}):
            with self.subTest(kwargs):
                self.assertEqual(self.run_rules([announce(0, 1), announce(1, 1, gm=ROGUE, **kwargs)]), ["ptp1"])

    def test_failover_after_the_master_went_silent_is_legitimate(self):
        msgs = [announce(0, 1), announce(20, 1, gm=OTHER, p1=1)]
        self.assertEqual(self.run_rules(msgs, ptp_gm_timeout=10), [])

    def test_a_slave_only_clock_is_not_a_grandmaster_candidate(self):
        # ptp4l of a client announces itself with clockClass 255 until it hears a master; the real master then follows.
        msgs = [announce(0, 1, gm=OTHER, p1=248, cls=255), announce(1, 1, p1=100), ptp(1.1, "Sync", 1)]
        self.assertEqual(self.run_rules(msgs), [])

    def test_a_slave_only_announce_does_not_hide_a_real_takeover(self):
        msgs = [announce(0, 1), announce(1, 1, gm=OTHER, p1=248, cls=255), announce(2, 1, gm=ROGUE, p1=1, cls=6)]
        self.assertEqual(self.run_rules(msgs), ["ptp1"])

    def test_domains_are_independent(self):
        msgs = [announce(0, 1), announce(1, 1, gm=OTHER, p1=1, domain=1)]
        self.assertEqual(self.run_rules(msgs), [])

    # ---- ptp2

    def test_sync_from_a_clock_that_never_announced(self):
        msgs = [announce(0, 1), ptp(1, "Sync", 1, clock=OTHER)]
        self.assertEqual(self.run_rules(msgs), ["ptp2"])

    def test_follow_up_counts_too_and_is_reported_once_per_clock(self):
        msgs = [announce(0, 1), ptp(1, "Sync", 1, clock=OTHER), ptp(2, "Follow_Up", 1, clock=OTHER),
                ptp(3, "Sync", 2, clock=OTHER)]
        self.assertEqual(self.run_rules(msgs), ["ptp2"])

    def test_a_rogue_that_announced_is_a_master_for_ptp2(self):
        msgs = [announce(0, 1), announce(1, 1, gm=ROGUE, p1=1), ptp(2, "Sync", 1, clock=ROGUE)]
        self.assertEqual(self.run_rules(msgs), ["ptp1"])

    def test_sync_before_any_announce_is_tolerated_while_learning(self):
        msgs = [ptp(0, "Sync", 1), ptp(1, "Sync", 2), announce(2, 1)]
        self.assertEqual(self.run_rules(msgs, ptp_learning_time=5), [])

    def test_sync_without_any_announce_is_reported_after_learning(self):
        msgs = [ptp(0, "Sync", 1), ptp(10, "Sync", 2)]
        self.assertEqual(self.run_rules(msgs, ptp_learning_time=5), ["ptp2"])

    def test_an_announced_master_is_checked_immediately(self):
        msgs = [ptp(0, "Sync", 1), announce(0.5, 1), ptp(1, "Sync", 2, clock=OTHER)]
        self.assertEqual(self.run_rules(msgs, ptp_learning_time=5), ["ptp2"])

    # ---- ptp3

    def test_sequence_ids_advance_by_one_and_wrap(self):
        msgs = [announce(0, 1)] + [ptp(i, "Sync", s) for i, s in enumerate((65534, 65535, 0, 1), 1)]
        self.assertEqual(self.run_rules(msgs), [])

    def test_a_repeated_sequence_id(self):
        self.assertEqual(self.run_rules([announce(0, 1), ptp(1, "Sync", 5), ptp(2, "Sync", 5)]), ["ptp3"])
        self.assertIn("repeated", self.alerts[0].msg)

    def test_a_sequence_id_going_back(self):
        self.assertEqual(self.run_rules([announce(0, 1), ptp(1, "Sync", 5), ptp(2, "Sync", 3)]), ["ptp3"])
        self.assertIn("went back", self.alerts[0].msg)

    def test_a_skipped_sequence_id(self):
        self.assertEqual(self.run_rules([announce(0, 1), ptp(1, "Sync", 5), ptp(2, "Sync", 9)]), ["ptp3"])
        self.assertIn("3 missing", self.alerts[0].msg)

    def test_a_tolerated_gap(self):
        msgs = [announce(0, 1), ptp(1, "Sync", 5), ptp(2, "Sync", 7)]
        self.assertEqual(self.run_rules(msgs, ptp_seq_gap_tolerance=1), [])
        self.assertEqual(self.run_rules(msgs, ptp_seq_gap_tolerance=0), ["ptp3"])

    def test_injection_is_followed_by_one_more_alert_when_the_real_master_resumes(self):
        msgs = [announce(0, 1), ptp(1, "Sync", 5), ptp(2, "Sync", 1000), ptp(3, "Sync", 6)]
        self.assertEqual(self.run_rules(msgs), ["ptp3", "ptp3"])

    def test_message_types_ethernet_and_udp_are_counted_separately(self):
        msgs = [announce(0, 1), ptp(1, "Sync", 5), ptp(1.1, "Follow_Up", 5), ptp(1.2, "Sync", 5, udp=True),
                ptp(2, "Sync", 6), ptp(2.1, "Sync", 6, udp=True)]
        self.assertEqual(self.run_rules(msgs), [])

    def test_sources_and_ports_are_counted_separately(self):
        msgs = [announce(0, 1), announce(0, 1, gm=OTHER, p1=200), ptp(1, "Sync", 5), ptp(1.1, "Sync", 5, port=2),
                ptp(1.2, "Sync", 5, clock=OTHER)]
        self.assertEqual(self.run_rules(msgs), [])

    def test_after_a_long_silence_the_sequence_may_restart(self):
        msgs = [announce(0, 1), ptp(1, "Sync", 500), announce(15, 2), ptp(16, "Sync", 3)]
        self.assertEqual(self.run_rules(msgs, ptp_seq_reset_time=10), [])

    def test_other_message_types_are_ignored(self):
        msgs = [announce(0, 1), ptp(1, "Delay_Req", 7), ptp(2, "Delay_Req", 7), ptp(3, "Pdelay_Req", 1, clock=OTHER)]
        self.assertEqual(self.run_rules(msgs), [])


if __name__ == "__main__":
    unittest.main()
