# -----------------------------------------------------------
#
#  __main__.py
#
# Command line of the IDS.
#
#   python3 -m ids                          connect to Zeek over Broker and run until interrupted
#   python3 -m ids --offline --idle-exit 2  drive one `zeek -r x.pcap ... TSN::wait_for_peer=T` run
#   python3 -m ids --replay frer.log srp.log  analyse Zeek's JSON logs, no Zeek or Broker needed
#
# Broker's Python bindings ship with Zeek: PYTHONPATH=/opt/zeek/lib/zeek/python
#
# (C) 2022 Robin Schenderlein, Hamburg, Germany
# (C) 2026 Doganalp Ergenc, written with the assistance of Claude
# Released under GNU Public License (GPL)
# -----------------------------------------------------------

import argparse
import json
import os
import sys
import time

from .engine import Engine
from .config import Config
from .control import Control
from .frer import FrerDetector
from .ptp import PtpDetector
from .srp import SrpDetector

LOG_KINDS = {"frer": "frer", "ptp": "ptp", "srp": "srp"}


SYSTEM_CONFIG = "/etc/tsnzeek/ids.json"


def find_config(path):
    """--config, else $TSNZEEK_CONFIG, else /etc/tsnzeek/ids.json if it exists, else None (the defaults of Config)."""
    path = path or os.environ.get("TSNZEEK_CONFIG")
    if path:
        return path
    return SYSTEM_CONFIG if os.path.isfile(SYSTEM_CONFIG) else None


def load_config(config_path):
    config_path = find_config(config_path)
    config = Config()
    if config_path:
        with open(config_path) as f:
            config = Config.from_dict(json.load(f))
    return config


def build_engine(config_path, config=None):
    config = config or load_config(config_path)
    return Engine([FrerDetector(config), SrpDetector(config), PtpDetector(config)])


ALERT_LOG = None        # file object of --alert-log, set by main()


def report(alerts, notify=None):
    for a in alerts:
        line = f"ALERT {a.rule} ts={a.ts:.6f} {a.msg}"
        print(line, flush=True)
        if ALERT_LOG:
            ALERT_LOG.write(line + "\n")
            ALERT_LOG.flush()
        if notify:
            notify(str(a))


def load_logs(paths):
    """Merge Zeek JSON logs by timestamp (frer.log -> "frer", srp.log -> "srp", ptp.log -> "ptp")."""
    records = []
    for path in paths:
        kind = path.rsplit("/", 1)[-1].split(".")[0]
        if kind not in LOG_KINDS:
            sys.exit(f"{path}: expected frer.log, ptp.log or srp.log (written with LogAscii::use_json=T)")
        with open(path) as f:
            for line in f:
                if line.strip():
                    msg = json.loads(line)
                    records.append((msg["ts"], kind, msg))
    records.sort(key=lambda r: r[0])
    return [(kind, msg) for _, kind, msg in records]


def replay(args):
    engine = build_engine(args.config)
    for kind, msg in load_logs(args.replay):
        report(engine.feed(kind, msg))
    if args.drain:
        report(engine.tick(engine.now + args.drain))


def live(args):
    import broker                                       # imported late: replay must work without it
    import broker.zeek

    config = load_config(args.config)
    engine = build_engine(args.config, config)
    control_dir = args.control_dir or os.environ.get("TSNZEEK_CONTROL_DIR")
    control = Control(control_dir, config, engine, {"mode": "service" if args.service else "live"}) if control_dir else None
    if control:
        control.poll()
    last_poll = time.monotonic()

    ep = broker.Endpoint()
    sub = ep.make_subscriber("/topic/tsn")
    status = ep.make_status_subscriber(True)
    ep.peer_nosync(args.host, args.port, 1.0)           # does not block while Zeek is down; Broker retries every second
    deadline = None if args.service else time.monotonic() + args.connect_timeout
    connected = False
    while not connected:
        if deadline and time.monotonic() > deadline:
            sys.exit(f"could not connect to Zeek at {args.host}:{args.port}")
        for st in status.poll():                        # errors while Zeek is not up yet are retried by Broker
            connected = connected or (isinstance(st, broker.Status) and st.code() == broker.SC.PeerAdded)
        if control and time.monotonic() - last_poll >= 0.5:
            control.poll()
            last_poll = time.monotonic()
        time.sleep(0.1)
    print("Connected to Zeek", flush=True)
    control and control.set_connected(True)

    def send(name, *a):
        ep.publish("/topic/tsn", broker.zeek.Event(name, *a))

    def handle(kind, msg):
        if control:
            control.note_message(kind)
        alerts = engine.feed(kind, msg)
        if control:
            control.note_alerts(alerts)
        report(alerts, lambda m: send("TSN::raise_notice", m))

    if args.offline:
        time.sleep(0.5)                                 # let Zeek see the subscription before it publishes
        send("TSN::ids_ready")

    idle_since = time.monotonic()
    while True:
        if args.service:                                # Broker re-peers by itself when Zeek restarts
            for st in status.poll():
                if isinstance(st, broker.Status) and st.code() in (broker.SC.PeerLost, broker.SC.PeerRemoved):
                    print("Lost Zeek, waiting for it to come back", flush=True)
                    control and control.set_connected(False)
                elif isinstance(st, broker.Status) and st.code() == broker.SC.PeerAdded:
                    print("Connected to Zeek", flush=True)
                    control and control.set_connected(True)
        if control and time.monotonic() - last_poll >= 0.5:      # a stat() and, now and then, a small file
            control.poll()
            last_poll = time.monotonic()
        batch = sub.poll()
        if not batch:
            if args.offline:
                if time.monotonic() - idle_since > args.idle_exit:
                    break
            else:
                alerts = engine.tick(time.time())
                control and control.note_alerts(alerts)
                report(alerts, lambda m: send("TSN::raise_notice", m))
            time.sleep(0.1)
            continue
        idle_since = time.monotonic()
        for _topic, data in batch:
            ev = broker.zeek.Event(data)
            if ev.name() != "TSN::ids_message":
                continue
            kind, payload = ev.args()
            handle(kind, json.loads(payload))

    if args.drain:
        report(engine.tick(engine.now + args.drain), lambda m: send("TSN::raise_notice", m))
    time.sleep(0.3)
    send("TSN::ids_done")
    time.sleep(0.3)


def main():
    ap = argparse.ArgumentParser(prog="python3 -m ids", description="TSNZeek intrusion detection: consumes the messages Zeek parsed and raises alerts.")
    ap.add_argument("--config", help="JSON file overriding the thresholds in ids/config.py Config "
                                     "(default: $TSNZEEK_CONFIG, else /etc/tsnzeek/ids.json if it exists, else the defaults)")
    ap.add_argument("--alert-log", metavar="FILE", help="also append the alerts to this file (default: $TSNZEEK_ALERT_LOG, else none)")
    ap.add_argument("--control-dir", metavar="DIR",
                    help="directory of the control channel to the web interface: the IDS writes state.json (rules, active "
                         "configuration, streams, rates) and applies control.json at run time (default: $TSNZEEK_CONTROL_DIR, else none)")
    ap.add_argument("--service", action="store_true",
                    help="run as a service: wait for Zeek without a time limit and keep running when Zeek restarts")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=9999)
    ap.add_argument("--connect-timeout", type=float, default=30.0, help="seconds to wait for Zeek")
    ap.add_argument("--replay", nargs="+", metavar="LOG", help="analyse Zeek JSON logs instead of connecting")
    ap.add_argument("--offline", action="store_true",
                    help="Zeek runs a pcap with TSN::wait_for_peer=T; exit when it has gone quiet")
    ap.add_argument("--idle-exit", type=float, default=2.0, help="--offline: seconds of silence that end the run")
    ap.add_argument("--drain", type=float, default=0.0,
                    help="advance the clock by this many seconds at the end so that timeouts fire")
    args = ap.parse_args()
    global ALERT_LOG
    alert_log = args.alert_log or os.environ.get("TSNZEEK_ALERT_LOG")
    if alert_log:
        ALERT_LOG = open(alert_log, "a")
    (replay if args.replay else live)(args)


if __name__ == "__main__":
    main()
