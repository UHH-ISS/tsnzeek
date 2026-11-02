#!/usr/bin/env python3
"""Live tests in Mininet: Zeek and the IDS run on `mon`, frames come from h1 and the attacker.

    ./build.sh                                  # once, as yourself: the run must not create root-owned files in build/
    sudo python3 tests/live/run_live.py         # all scenarios
    sudo python3 tests/live/run_live.py ptp     # one scenario
    sudo python3 tests/live/run_live.py --cli   # start the monitor and leave the network up for manual Scapy
    sudo -E python3 tests/live/run_live.py --demo   # the same, plus windows: Zeek logs, IDS alerts, a shell on h1 and attacker
    sudo -E python3 tests/live/run_live.py --demo --ptp   # ... with ptp4l running as gPTP master (h1) and client (h2)
    sudo python3 tests/live/run_live.py ptp_real ptp_real_attacks   # real ptp4l traffic, then attacks on it

Real ptp4l runs need the user-space hub instead of OVS (see userhub.py); it is used automatically for them
and with --ptp, and can be forced with --hub or --ovs.

Every scenario starts a fresh Zeek and IDS so that no state leaks between them, sends its frames with
tests/live/send.py and compares what Zeek logged and the IDS alerted with the expectation below. The output of each
run is kept in a directory under /tmp that is printed at the end.
"""
import collections
import json
import os
import re
import signal
import subprocess
import sys
import tempfile
import time

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

ZEEK_PREFIX = os.environ.get("ZEEK_PREFIX", "/opt/zeek")
PY = os.path.join(ROOT, ".venv", "bin", "python")        # the Python that has Scapy
CONFIG = os.path.join(ROOT, "tests", "live", "config.json")
SEND = os.path.join(ROOT, "tests", "live", "send.py")

REAL_PTP_TYPES = {"Announce", "Sync", "Follow_Up", "Pdelay_Req", "Pdelay_Resp", "Pdelay_Resp_Follow_Up"}


def scenario(steps, wait, alerts, ptp_rows=0, **options):
    return dict(steps=steps, wait=wait, alerts=alerts, ptp_rows=ptp_rows, **options)


# steps: (host, send.py command), or ("wait", seconds). `wait` is the time to let the IDS finish afterwards: it must
# exceed the 5 s timeout of config.json plus one tick for the timeout rules (frer_dead_stream, srp_unused_reservation) to fire.
# ptp_rows is the expected number of ptp.log rows (None: do not check), ptp_types message types that must appear in it,
# real: run ptp4l as master on h1 and client on h2.
SCENARIOS = {
    "frer_mixed": scenario([("h1", "frer_mixed")], 8, {"frer_excess_copies": 1, "frer_out_of_order": 1, "frer_dead_stream": 2}),
    "frer_excess_copies": scenario([("attacker", "frer_excess_copies")], 8, {"frer_excess_copies": 6, "frer_dead_stream": 1}),
    "frer_out_of_order": scenario([("attacker", "frer_out_of_order")], 8, {"frer_out_of_order": 5, "frer_dead_stream": 1}),
    "srp_oversized_request": scenario([("attacker", "srp_oversized_request")], 8, {"srp_oversized_request": 3, "srp_unused_reservation": 1}),
    "srp_reservation_change": scenario([("attacker", "srp_reservation_change")], 8, {"srp_reservation_change": 1, "srp_unused_reservation": 1}),
    "ptp": scenario([("h1", "ptp")], 2, {}, 5),
    "ptp_attacks": scenario([("h1", "ptp"), ("attacker", "ptp_rogue_grandmaster"), ("attacker", "ptp_unannounced_sync"),
                             ("attacker", "ptp_sequence_id")], 3, {"ptp_rogue_grandmaster": 1, "ptp_unannounced_sync": 1, "ptp_sequence_id": 2}, 16),
    # Real ptp4l messages (gPTP profile). Do they get parsed, logged and passed on, and does the IDS stay quiet?
    "ptp_real": scenario([("wait", 10)], 1, {}, None, real=True, ptp_types=REAL_PTP_TYPES),
    # ... and do the attacks work against a real master? ptp_sequence_id needs the master's clock identity (h1's MAC, as ptp4l builds it).
    "ptp_real_attacks": scenario([("wait", 8), ("attacker", "ptp_rogue_grandmaster"), ("attacker", "ptp_unannounced_sync"),
                                  ("attacker", "ptp_sequence_id --clock real")], 3, {"ptp_rogue_grandmaster": 1, "ptp_unannounced_sync": 1, "ptp_sequence_id": 3}, None,
                                 real=True, ptp_types=REAL_PTP_TYPES),
}

PTP_CONFIGS = {"h1": os.path.join(ROOT, "tests", "live", "ptp", "master.cfg"),
               "h2": os.path.join(ROOT, "tests", "live", "ptp", "slave.cfg")}


class RealPtp:
    """ptp4l as gPTP master on h1 and client on h2.

    The hosts share the OS clock, so a ptp4l that adjusts its clock would adjust the clock of this machine: both
    configurations must say `free_running 1`, and nothing starts otherwise.
    """

    def __init__(self, net, out):
        for host, cfg in PTP_CONFIGS.items():
            with open(cfg) as f:
                if not re.search(r"^free_running\s+1\b", f.read(), re.M):
                    sys.exit(f"{cfg} lacks `free_running 1`; ptp4l would adjust the clock of this machine")
        os.makedirs(out, exist_ok=True)
        self.logs = {host: f"{out}/ptp4l-{host}.log" for host in PTP_CONFIGS}
        # The hosts share the file system: each ptp4l needs its own management sockets.
        self.procs = [net[host].popen(["ptp4l", "-f", cfg, "-i", f"{host}-eth0", "-m",
                                       f"--uds_address=/var/run/ptp4l-{host}", f"--uds_ro_address=/var/run/ptp4lro-{host}"],
                                      stdout=open(self.logs[host], "w"), stderr=subprocess.STDOUT)
                      for host, cfg in PTP_CONFIGS.items()]

    def stop(self):
        for proc in self.procs:
            proc.terminate()
        for proc in self.procs:
            try:
                proc.wait(5)
            except subprocess.TimeoutExpired:
                proc.kill()

    def mentions(self, host, clock_hex):
        """Does the log of `host` name the clock? ptp4l writes identities as xxxxxx.xxxx.xxxxxx."""
        text = f"{clock_hex[:6]}.{clock_hex[6:10]}.{clock_hex[10:]}"
        with open(self.logs[host]) as f:
            return text in f.read()

    def selected(self, host, clock_hex):
        """Did `host` pick the clock as its best master?"""
        text = f"selected best master clock {clock_hex[:6]}.{clock_hex[6:10]}.{clock_hex[10:]}"
        with open(self.logs[host]) as f:
            return text in f.read()

    def faults(self):
        """How often a port went FAULTY, per host."""
        counts = {}
        for host, path in self.logs.items():
            with open(path) as f:
                counts[host] = f.read().count("to FAULTY")
        return counts

    def tail(self, host, lines=8):
        with open(self.logs[host]) as f:
            return "".join(f.readlines()[-lines:])


def read_json_log(path):
    if not os.path.exists(path):
        return []
    with open(path) as f:
        return [json.loads(line) for line in f if line.strip()]


class Monitor:
    """Zeek and the IDS on the `mon` host."""

    def __init__(self, net, out):
        self.mon, self.out = net["mon"], out
        env = dict(os.environ, ZEEK_SPICY_MODULE_PATH=os.path.join(ROOT, "build", "spicy"),
                   PYTHONPATH=f"{ZEEK_PREFIX}/lib/zeek/python:{ROOT}")
        os.makedirs(out, exist_ok=True)
        self.zeek = self.mon.popen(
            [f"{ZEEK_PREFIX}/bin/zeek", "-C", "-i", "mon-eth0", os.path.join(ROOT, "spicy", "scripts"),
             "LogAscii::use_json=T", "TSN::log_flush_interval=500msec"], cwd=out, env=env, stdout=open(f"{out}/zeek.out", "w"), stderr=subprocess.STDOUT)
        for _ in range(100):                               # Zeek listens for the IDS once it has loaded the grammars
            if "9999" in self.mon.cmd("ss -ltn"):
                break
            time.sleep(0.2)
        else:
            raise RuntimeError(f"Zeek did not start, see {out}/zeek.out")
        self.ids = self.mon.popen([sys.executable, "-m", "ids", "--config", CONFIG], cwd=ROOT, env=env,
                                  stdout=open(f"{out}/ids.out", "w"), stderr=subprocess.STDOUT)
        time.sleep(1.5)                                    # let the IDS connect and subscribe

    def stop(self):
        self.ids.terminate()
        self.zeek.send_signal(signal.SIGINT)               # Zeek flushes its logs on SIGINT
        for proc in (self.ids, self.zeek):
            try:
                proc.wait(10)
            except subprocess.TimeoutExpired:
                proc.kill()

    def alerts(self):
        with open(f"{self.out}/ids.out") as f:
            return collections.Counter(m.group(1) for m in re.finditer(r"^ALERT (\w+) ", f.read(), re.M))

    def log(self, name):
        return read_json_log(f"{self.out}/{name}.log")


PANEL = 60        # pixels the desktop panel and the window decorations take at the top; adjust for your desktop


def screen_geometry():
    """(width, height, x, y) of the primary screen."""
    try:
        text = subprocess.run(["xrandr", "--current"], capture_output=True, text=True, check=True).stdout
        lines = [l for l in text.splitlines() if " connected" in l]
        line = next((l for l in lines if " primary " in l), lines[0])
        w, h, x, y = map(int, re.search(r"(\d+)x(\d+)\+(\d+)\+(\d+)", line).groups())
        return w, h, x, y
    except (OSError, subprocess.CalledProcessError, StopIteration, AttributeError, IndexError):
        return 1920, 1080, 0, 0


def open_windows(net, mon, ptp4l=None):
    """The demo windows, one in each corner of the screen: Zeek's logs and the IDS alerts on the monitor, a shell on
    h1 and on the attacker.

            Zeek logs | IDS alerts
            ----------+-----------
            h1        | attacker

    With ptp4l running, a fifth window with the logs of both ptp4l instances opens in the middle.
    """
    if not os.environ.get("DISPLAY"):
        print("No DISPLAY: start with `sudo -E` (and `xhost +si:localuser:root` once) to get windows. "
              f"Logs are in {mon.out}.")
        return []
    sw, sh, sx, sy = screen_geometry()
    w, h = sw // 2 - 20, (sh - PANEL) // 2 - 60                          # text area of one window, in pixels
    font = 12 if sw >= 2560 else 10
    shell = os.path.join(ROOT, "tests", "live", "demo_shell.sh")
    windows = [   # title, column, row, host, command
        ("Zeek logs (mon)", 0, 0, None, [sys.executable, os.path.join(ROOT, "tests", "live", "watch.py"), mon.out]),
        ("IDS alerts (mon)", 1, 0, None, ["tail", "-n", "+1", "-F", f"{mon.out}/ids.out"]),
        ("h1", 0, 1, "h1", ["bash", shell, "h1-eth0"]),
        ("attacker", 1, 1, "attacker", ["bash", shell, "attacker-eth0"]),
    ]
    if ptp4l:
        windows.append(("ptp4l: h1 master, h2 client", None, None, None, ["tail", "-n", "+1", "-F"] + list(ptp4l.logs.values())))
    # xterm moves and resizes itself in pixels on request (allowWindowOps), so the layout does not depend on the font.
    place = 'printf "\\033[4;%d;%dt\\033[3;%d;%dt" "$1" "$2" "$3" "$4"; shift 4; exec "$@"'
    procs = []
    for title, col, row, host, cmd in windows:
        if col is None:                                                  # the ptp4l window: centered, over the others
            wh, ww = h // 2, w
            x, y = sx + (sw - w) // 2, sy + PANEL + (sh - PANEL) // 2 - wh // 2
        else:
            wh, ww = h, w
            x, y = sx + col * (sw // 2) + 4, sy + PANEL + row * ((sh - PANEL) // 2)
        argv = ["xterm", "-title", title, "-fa", "Monospace", "-fs", str(font), "-xrm", "XTerm*allowWindowOps: true",
                "-e", "bash", "-c", place, "_", str(wh), str(ww), str(x), str(y)] + cmd
        procs.append(net[host].popen(argv, stderr=subprocess.PIPE) if host else
                     subprocess.Popen(argv, stderr=subprocess.PIPE))
    time.sleep(1.5)
    for (title, *_), proc in zip(windows, procs):
        if proc.poll() is not None:
            print(f"window '{title}' did not open: {proc.stderr.read().decode().strip()}\n"
                  "  Allow root to use your display once with `xhost +si:localuser:root` and start with `sudo -E`.")
    return procs


def check(label, ok, detail=""):
    print(f"  {'ok  ' if ok else 'FAIL'} {label}{(' ' + detail) if detail else ''}")
    return ok


def probe(net, workdir):
    """Does the monitor see a link-local gPTP frame and an ordinary frame exactly once, and does h2 get the gPTP frame?"""
    # Only the probe's frames: without a filter the IPv6 neighbor discovery of the new interfaces fills a capture limit.
    bpf = "ether proto 0x88f7 or ether proto 0xf1c1 or (vlan and ether proto 0xf1c1)"
    caps = {host: net[host].popen(["tcpdump", "-i", f"{host}-eth0", "-nn", "-e", "-l", "-Q", "in", bpf],
                                  stdout=open(f"{workdir}/probe-{host}.txt", "w"),
                                  stderr=open(f"{workdir}/probe-{host}.err", "w"))
            for host in ("mon", "h2")}
    time.sleep(1)
    net["h1"].cmd(f"{PY} {SEND} probe h1-eth0")
    time.sleep(2)
    for cap in caps.values():
        cap.terminate()
        cap.wait()
    seen = {}
    for host in caps:
        with open(f"{workdir}/probe-{host}.txt") as f:
            text = f.read()
        seen[host] = (text.count("0x88f7"), text.count("0xf1c1"))
    ok = check("monitor sees the gPTP frame once", seen["mon"][0] == 1, f"(seen {seen['mon'][0]} times)")
    ok &= check("monitor sees the FRER frame once", seen["mon"][1] == 1, f"(seen {seen['mon'][1]} times)")
    ok &= check("h2 receives the gPTP frame (ptp4l needs it)", seen["h2"][0] == 1, f"(seen {seen['h2'][0]} times)")
    if not ok:                                                  # tcpdump's own messages say why it saw nothing
        for host in caps:
            with open(f"{workdir}/probe-{host}.err") as f:
                err = f.read().strip()
            print(f"  tcpdump on {host}: {err or '(no message)'}")
    return ok


def run_scenario(net, name, workdir):
    sc = SCENARIOS[name]
    print(f"{name}:")
    out = os.path.join(workdir, name)
    mon = Monitor(net, out)
    ptp4l = RealPtp(net, out) if sc.get("real") else None
    try:
        for host, command in sc["steps"]:
            if host == "wait":
                time.sleep(float(command))
                continue
            net[host].cmd(f"{PY} {SEND} {command} {host}-eth0")
            time.sleep(0.5)
        time.sleep(sc["wait"])
    finally:
        if ptp4l:
            ptp4l.stop()
        mon.stop()
    want = sc["alerts"]
    got = mon.alerts()
    ok = check("alerts", got == want, f"want {want} got {dict(got)}")
    notices = sum(1 for n in mon.log("notice") if n.get("note") == "TSN::Possible_Attack")
    ok &= check("every alert reached Zeek as a notice", notices == sum(got.values()),
                f"({sum(got.values())} alerts, {notices} notices)")
    rows = mon.log("ptp")
    if sc["ptp_rows"] is not None:
        ok &= check("ptp.log rows", len(rows) == sc["ptp_rows"], f"want {sc['ptp_rows']} got {len(rows)}")
    if sc.get("ptp_types"):
        types = collections.Counter(r["msg_type"] for r in rows)
        missing = sc["ptp_types"] - set(types)
        ok &= check("ptp4l's messages are logged", not missing,
                    f"({', '.join(f'{t} {n}' for t, n in sorted(types.items()))})" if not missing else f"missing {sorted(missing)}; got {dict(types)}")
    if ptp4l:
        faults = ptp4l.faults()
        ok &= check("ptp4l ports stay out of FAULTY", not any(faults.values()), f"({faults})")
    errors = mon.log("tsn_errors")
    ok &= check("no parse errors", not errors, "" if not errors else
                f"{len(errors)}, e.g. {errors[0]['protocol']}: {errors[0]['reason']}")
    if ptp4l and not ok:
        for host in PTP_CONFIGS:
            print(f"  --- last lines of ptp4l on {host} ({ptp4l.logs[host]}):")
            print("".join("      " + l + "\n" for l in ptp4l.tail(host).splitlines()))
    if ptp4l and name == "ptp_real_attacks":      # what the attack did to the real client, for information
        rogue = "deadbeefcafe0001"
        print(f"  info the client's ptp4l noticed the rogue grandmaster: {ptp4l.mentions('h2', rogue)}, "
              f"selected it as best master: {ptp4l.selected('h2', rogue)} (see {ptp4l.logs['h2']})")
    return ok


def main():
    if os.geteuid() != 0:
        sys.exit(__doc__)
    if not os.path.exists(os.path.join(ROOT, "build", "spicy", "tsn.hlto")):
        sys.exit("run ./build.sh first")
    args = sys.argv[1:]
    demo = "--demo" in args
    real = "--ptp" in args
    cli = "--cli" in args or demo
    names = [a for a in args if not a.startswith("--")] or list(SCENARIOS)
    for n in names:
        if n not in SCENARIOS:
            sys.exit(f"unknown scenario {n}; choose from {', '.join(SCENARIOS)}")

    from mininet.cli import CLI
    from mininet.log import setLogLevel
    from topo import build_net, start_monitoring

    setLogLevel("warning")
    hub = "--hub" in args or (not "--ovs" in args and (real or any(SCENARIOS[n].get("real") for n in names)))
    workdir = tempfile.mkdtemp(prefix="tsnzeek-live-")
    os.chmod(workdir, 0o755)
    net = build_net(hub=hub)
    print(f"switch: {'user-space hub' if hub else 'OVS with a mirror port'}")
    net.start()
    ok = True
    try:
        start_monitoring(net)
        if cli:
            mon = Monitor(net, os.path.join(workdir, "cli"))
            ptp4l = RealPtp(net, os.path.join(workdir, "cli")) if real else None
            windows = open_windows(net, mon, ptp4l) if demo else []
            print(f"Zeek and the IDS run on mon (output in {workdir}/cli). Send with, e.g.\n"
                  f"  h1 {PY} {SEND} frer_mixed h1-eth0\nType exit to stop everything.")
            CLI(net)
            for w in windows:
                w.terminate()
            if ptp4l:
                ptp4l.stop()
            mon.stop()
        else:
            ok = probe(net, workdir)
            for n in names:
                ok &= run_scenario(net, n, workdir)
    finally:
        net.stop()
        # The run is root's; give the output to the user who started it.
        if os.environ.get("SUDO_UID"):
            subprocess.run(["chown", "-R", f"{os.environ['SUDO_UID']}:{os.environ.get('SUDO_GID', os.environ['SUDO_UID'])}", workdir])
    print(f"output kept in {workdir}")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
