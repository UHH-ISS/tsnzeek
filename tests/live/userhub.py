#!/usr/bin/env python3
"""A hub in user space: every frame that arrives on one port is sent out of all the others.

    userhub.py <interface> <interface> ...

Why not a switch in the kernel? A frame that ptp4l sends with software time stamping asks every device it passes
for a time stamp, and the kernel gives one to the *sending socket's* error queue whenever the same buffer is sent
out of a virtual interface again, as a bridge or OVS does with the original buffer of the last output. ptp4l finds
such leftovers in the error queue and takes the port down ("error on fda[0]: Success", FAULTY). A frame that is
read here and sent again is a new buffer owned by this process, so ptp4l sees exactly one time stamp.

A hub is also what a monitoring port needs: the monitor is simply one more port and sees every frame once.
Needs root (raw sockets).
"""
import select
import socket
import struct
import sys

ETH_P_ALL = 0x0003
SOL_PACKET = getattr(socket, "SOL_PACKET", 263)       # missing from older Pythons' socket module
PACKET_AUXDATA = 8
TP_STATUS_VLAN_VALID = 1 << 4
TP_STATUS_VLAN_TPID_VALID = 1 << 6
AUXDATA = struct.Struct("IIIHHHH")       # tp_status tp_len tp_snaplen tp_mac tp_net tp_vlan_tci tp_vlan_tpid


def with_vlan_tag(frame, auxdata):
    """The kernel strips an 802.1Q tag from the frame and reports it as ancillary data; put it back."""
    status, _, _, _, _, tci, tpid = AUXDATA.unpack_from(auxdata)
    if not status & TP_STATUS_VLAN_VALID:
        return frame
    if not status & TP_STATUS_VLAN_TPID_VALID:
        tpid = 0x8100
    return frame[:12] + struct.pack("!HH", tpid, tci) + frame[12:]


def open_port(name):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    s.setsockopt(SOL_PACKET, PACKET_AUXDATA, 1)
    s.bind((name, 0))
    s.setblocking(False)
    return s


def receive(port):
    """The next frame that came in on `port`, or None. What this process sent itself is skipped."""
    try:
        data, ancillary, _, address = port.recvmsg(65535, socket.CMSG_SPACE(AUXDATA.size))
    except BlockingIOError:
        return None
    if address[2] == socket.PACKET_OUTGOING:
        return b""
    for level, kind, payload in ancillary:
        if level == SOL_PACKET and kind == PACKET_AUXDATA:
            data = with_vlan_tag(data, payload)
    return data


def run(names):
    ports = [open_port(n) for n in names]
    while True:
        readable, _, _ = select.select(ports, [], [])
        for port in readable:
            while True:
                frame = receive(port)
                if frame is None:
                    break
                if not frame:
                    continue
                for other in ports:
                    if other is not port:
                        try:
                            other.send(frame)
                        except OSError:
                            pass                # a port that is down must not stop the others


if __name__ == "__main__":
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    try:
        run(sys.argv[1:])
    except KeyboardInterrupt:
        pass
