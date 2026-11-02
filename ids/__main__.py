# -----------------------------------------------------------
#
#  __main__.py
#
# Command line of the IDS.
#
#   python3 -m ids                          connect to Zeek over Broker and run until interrupted
#   python3 -m ids --offline --idle-exit 2  drive one `zeek -r x.pcap ... TSN::wait_for_peer=T` run
#   python3 -m ids --replay cb.log srp.log  analyse Zeek's JSON logs, no Zeek or Broker needed
#
# Broker's Python bindings ship with Zeek: PYTHONPATH=/opt/zeek/lib/zeek/python
#
# (C) 2022 Robin Schenderlein, Hamburg, Germany
# Released under GNU Public License (GPL)
# -----------------------------------------------------------

import argparse
import json
import sys
import time

from .engine import Engine
from .ptp_rules import PtpDetector
from .rules import Config, RuleDetector

LOG_KINDS = {"cb": "cb", "ptp": "ptp", "srp": "srp"}


def build_engine(config_path):
    config = Config()
    if config_path:
        with open(config_path) as f:
            config = Config.from_dict(json.load(f))
    return Engine([RuleDetector(config), PtpDetector(config)])


def report(alerts, notify=None):
    for a in alerts:
        print(f"ALERT {a.rule} ts={a.ts:.6f} {a.msg}", flush=True)
        if notify:
            notify(str(a))


def load_logs(paths):
    """Merge Zeek JSON logs by timestamp (cb.log -> "cb", srp.log -> "srp", ptp.log -> "ptp")."""
    records = []
    for path in paths:
        kind = path.rsplit("/", 1)[-1].split(".")[0]
        if kind not in LOG_KINDS:
            sys.exit(f"{path}: expected cb.log, ptp.log or srp.log (written with LogAscii::use_json=T)")
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

    ep = broker.Endpoint()
    sub = ep.make_subscriber("/topic/tsn")
    status = ep.make_status_subscriber(True)
    ep.peer(args.host, args.port, 1.0)                  # Broker retries every second
    deadline = time.monotonic() + args.connect_timeout
    connected = False
    while not connected:
        if time.monotonic() > deadline:
            sys.exit(f"could not connect to Zeek at {args.host}:{args.port}")
        for st in status.poll():                        # errors while Zeek is not up yet are retried by Broker
            connected = connected or (isinstance(st, broker.Status) and st.code() == broker.SC.PeerAdded)
        time.sleep(0.1)
    print("Connected to Zeek", flush=True)

    def send(name, *a):
        ep.publish("/topic/tsn", broker.zeek.Event(name, *a))

    engine = build_engine(args.config)
    if args.offline:
        time.sleep(0.5)                                 # let Zeek see the subscription before it publishes
        send("TSN::ids_ready")

    idle_since = time.monotonic()
    while True:
        batch = sub.poll()
        if not batch:
            if args.offline:
                if time.monotonic() - idle_since > args.idle_exit:
                    break
            else:
                report(engine.tick(time.time()), lambda m: send("TSN::raise_notice", m))
            time.sleep(0.1)
            continue
        idle_since = time.monotonic()
        for _topic, data in batch:
            ev = broker.zeek.Event(data)
            if ev.name() != "TSN::ids_message":
                continue
            kind, payload = ev.args()
            report(engine.feed(kind, json.loads(payload)), lambda m: send("TSN::raise_notice", m))

    if args.drain:
        report(engine.tick(engine.now + args.drain), lambda m: send("TSN::raise_notice", m))
    time.sleep(0.3)
    send("TSN::ids_done")
    time.sleep(0.3)


def main():
    ap = argparse.ArgumentParser(prog="python3 -m ids", description="TSNZeek intrusion detection: consumes the messages Zeek parsed and raises alerts.")
    ap.add_argument("--config", help="JSON file overriding the thresholds in ids/rules.py Config")
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
    (replay if args.replay else live)(args)


if __name__ == "__main__":
    main()
