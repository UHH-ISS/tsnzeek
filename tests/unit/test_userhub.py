# (C) 2026 Doganalp Ergenc, written with the assistance of Claude

"""Unit tests of the parts of the user-space hub that need no raw socket."""
import os
import socket
import struct
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "live"))

import userhub  # noqa: E402

MACS = bytes.fromhex("01 80 c2 00 00 0e 00 00 00 00 00 01".replace(" ", ""))
PAYLOAD = bytes.fromhex("88f7") + b"\x10" * 20


def aux(status=0, tci=0, tpid=0):
    return userhub.AUXDATA.pack(status, 0, 0, 0, 0, tci, tpid)


class FakePort:
    """What recvmsg of an AF_PACKET socket returns."""

    def __init__(self, data, pkttype=socket.PACKET_HOST, ancillary=()):
        self.reply = (data, list(ancillary), 0, ("eth0", 3, pkttype, 1, b""))

    def recvmsg(self, size, ancillary_size):
        if self.reply is None:
            raise BlockingIOError
        reply, self.reply = self.reply, None
        return reply


class UserHub(unittest.TestCase):
    def test_a_frame_without_a_stripped_tag_is_unchanged(self):
        frame = MACS + PAYLOAD
        self.assertEqual(userhub.with_vlan_tag(frame, aux()), frame)

    def test_a_stripped_tag_is_put_back(self):
        tagged = userhub.with_vlan_tag(MACS + PAYLOAD, aux(userhub.TP_STATUS_VLAN_VALID, tci=150))
        self.assertEqual(tagged, MACS + struct.pack("!HH", 0x8100, 150) + PAYLOAD)

    def test_the_tag_keeps_its_own_protocol_identifier(self):
        status = userhub.TP_STATUS_VLAN_VALID | userhub.TP_STATUS_VLAN_TPID_VALID
        tagged = userhub.with_vlan_tag(MACS + PAYLOAD, aux(status, tci=7, tpid=0x88A8))
        self.assertEqual(tagged[12:16], struct.pack("!HH", 0x88A8, 7))

    def test_receive_returns_the_frame_and_then_nothing(self):
        port = FakePort(MACS + PAYLOAD)
        self.assertEqual(userhub.receive(port), MACS + PAYLOAD)
        self.assertIsNone(userhub.receive(port))

    def test_what_the_hub_sent_itself_is_skipped(self):
        self.assertEqual(userhub.receive(FakePort(MACS + PAYLOAD, pkttype=socket.PACKET_OUTGOING)), b"")

    def test_receive_restores_the_tag_from_the_ancillary_data(self):
        ancillary = [(userhub.SOL_PACKET, userhub.PACKET_AUXDATA, aux(userhub.TP_STATUS_VLAN_VALID, tci=1000))]
        frame = userhub.receive(FakePort(MACS + PAYLOAD, ancillary=ancillary))
        self.assertEqual(frame, MACS + struct.pack("!HH", 0x8100, 1000) + PAYLOAD)


if __name__ == "__main__":
    unittest.main()
