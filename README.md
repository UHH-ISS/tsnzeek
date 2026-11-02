# TSNZeek: Monitoring and Intrusion Detection System for IEEE 802.1 TSN Networks

TSNZeek monitors Time-Sensitive Networking (TSN) traffic and detects attacks against it. It teaches
[Zeek](https://zeek.org) the TSN control and data protocols with [Spicy](https://docs.zeek.org/projects/spicy) grammars,
logs everything it parses, and passes the messages to an intrusion detection module that raises alerts.

## Features

- **Protocol analysis** of SRP (802.1Qcc), FRER (802.1CB) and (g)PTP (IEEE 1588 / 802.1AS, over Ethernet and UDP), written to
  `srp.log`, `cb.log` and `ptp.log`; malformed frames are reported in `tsn_errors.log`.
- **Attack detection** with rules for the three protocols:

  | Protocol | Detected attacks |
  | --- | --- |
  | FRER | more copies of a frame than member streams, skipped or out-of-order sequence numbers, dead member streams |
  | SRP | reservations above the resource thresholds, bandwidth deviating from earlier requests, request flooding, changes to an existing reservation, reservations without traffic |
  | PTP | a rogue grandmaster, Sync from a clock that never announced itself, replayed or injected sequence ids |

- **Pluggable detection:** a detector is any object with `on_message`/`on_tick`, so statistical tests or an embedded
  machine-learning model run next to the rules ([ids/README.md](ids/README.md)).
- **Reproducible:** pcap-based tests, and a Mininet environment with legit traffic, attacks and real `ptp4l`.

## Architecture

```
 TSN frames ──► Zeek + Spicy grammars ──► logs (srp, cb, ptp, tsn_errors)
                    │
                    └── Broker (JSON per message) ──► IDS ──► alerts ──► Zeek notice.log
```

| Path | Content |
| --- | --- |
| [`spicy/`](spicy/README.md) | grammars, `TSN.evt`, the Zeek scripts (data plane) |
| [`ids/`](ids/README.md) | the intrusion detection (control plane) |
| [`deploy/`](deploy/README.md) | optional systemd services, configuration and log locations |
| [`tests/`](tests/README.md) | unit and pcap tests; [`tests/live/`](tests/live/README.md) the Mininet network, live tests and demo |
| [`scapy/`](scapy/README.md) | Scapy layers for FRER and SRP, the original attack script |
| `build.sh` | compiles the grammars and runs the unit tests afterwards (`--no-test` skips them) |
| [`CHANGELOG.md`](CHANGELOG.md) | what changed since the original release |

## Installation

**Requirements** (tested on Ubuntu 24.04)

- [Zeek 9.0.1 LTS](https://zeek.org/get-zeek/) from the official packages, in `/opt/zeek` (set `ZEEK_PREFIX` for another
  location). Spicy and the Python bindings of Broker come with it.
- Python 3.8 or later (tested with 3.12). The IDS needs nothing beyond the Broker bindings in `/opt/zeek/lib/zeek/python`.

**Optional**, for the tests and the Mininet environment:

```sh
sudo apt-get install python3-venv mininet openvswitch-switch tcpdump xterm linuxptp
python3 -m venv .venv && .venv/bin/pip install scapy
```

**Build** the grammars once, and after changing them:

```sh
git clone https://github.com/UHH-ISS/tsnzeek.git && cd tsnzeek
./build.sh                  # compiles build/spicy/tsn.hlto, then runs the unit tests; nothing to do if it is up to date
```

## Usage

Analyse a pcap (logs are written to the current directory, `LogAscii::use_json=T` makes them JSON):

```sh
ZEEK_SPICY_MODULE_PATH=build/spicy /opt/zeek/bin/zeek -C -r x.pcap spicy/scripts TSN::enable_broker=F LogAscii::use_json=T
```

`TSN::enable_broker=F` (`F` is false) is needed here: by default Zeek listens for the IDS over Broker, and a listener keeps Zeek running after the pcap ends. See [`spicy/`](spicy/README.md#options).

Monitor an interface with the IDS (two terminals; Zeek waits for the IDS on `127.0.0.1:9999`):

```sh
sudo ZEEK_SPICY_MODULE_PATH=build/spicy /opt/zeek/bin/zeek -C -i <interface> spicy/scripts LogAscii::use_json=T
PYTHONPATH=/opt/zeek/lib/zeek/python python3 -m ids [--config thresholds.json]
```

For a run without a terminal window, see [Headless](#headless-no-terminal-window-no-service) below; for a permanent installation
as systemd services (optional), see [`deploy/`](deploy/README.md).

Alerts appear on the IDS console and come back to Zeek as `Possible_Attack` entries of `notice.log`. To run the rules on
logs of an earlier run, without Zeek or Broker: `python3 -m ids --replay cb.log srp.log ptp.log`.

## Headless (no terminal window, no service)

Zeek and the IDS in the background of a server or an SSH session, started by hand. Nothing is installed; stop them
when you are done. (For something that starts at boot, use the [systemd services](deploy/README.md).)

1. Build once: `./build.sh`
2. Pick the interface (`ip -br link`) and a directory for the logs:

   ```sh
   IFACE=eth0
   LOGS=$HOME/tsnzeek-logs && mkdir -p "$LOGS"
   ```

3. Start the IDS first. It waits for Zeek, so the order does not matter for correctness, but it must be up before the
   traffic you want checked. The alerts go to `alerts.log` (and the console output to `ids.out`):

   ```sh
   PYTHONPATH=/opt/zeek/lib/zeek/python setsid nohup python3 -m ids --service \
       --alert-log "$LOGS/alerts.log" >"$LOGS/ids.out" 2>&1 &
   echo $! >"$LOGS/ids.pid"
   ```

   Add `--config my-thresholds.json` to change thresholds (the keys are the fields of `Config` in `ids/config.py`).

4. Start Zeek. Capturing needs root (or `sudo setcap cap_net_raw,cap_net_admin=eip /opt/zeek/bin/zeek` once, then no `sudo`).
   It writes its logs into the current directory:

   ```sh
   cd "$LOGS" && sudo ZEEK_SPICY_MODULE_PATH="$OLDPWD/build/spicy" setsid nohup /opt/zeek/bin/zeek -C -i "$IFACE" \
       "$OLDPWD/spicy/scripts" LogAscii::use_json=T TSN::log_flush_interval=1sec >zeek.out 2>&1 &
   cd -
   ```

5. Check that both run and watch the traffic:

   ```sh
   cat "$LOGS/ids.out"                       # "Connected to Zeek"
   tail -f "$LOGS"/cb.log "$LOGS"/ptp.log "$LOGS"/srp.log   # one JSON line per message
   tail -f "$LOGS/alerts.log" "$LOGS/notice.log"            # the alerts
   ```

6. Stop: `kill "$(cat "$LOGS/ids.pid")"; sudo pkill -x zeek` (Zeek finishes the logs on SIGTERM).

`TSN::wait_for_peer` is for pcaps run together with the IDS; a live run does not need it.

## Testing

```sh
python3 -m unittest discover -s tests/unit   # rules and pcaps
tests/run.sh && tests/run_ids.sh             # Zeek logs and Zeek + IDS end to end
```

Step by step guides: [`tests/README.md`](tests/README.md) (the automatic tests) and [`tests/live/README.md`](tests/live/README.md) (the Mininet demo).

## Citation

If you use TSNZeek in your work, please cite the paper that introduces it:

```bibtex
@inproceedings{ergenc2023tsnzek,
    author = {Ergen{\c{c}}, Doğanalp and Schenderlein, Robin and Fischer, Mathias},
    doi = {10.23919/IFIPNetworking57963.2023.10186421},
    title = {{TSNZeek: An Open-source Intrusion Detection System for IEEE 802.1 Time-sensitive Networking}},
    pages = {1--6},
    publisher = {Institute of Electrical and Electronics Engineers (IEEE)},
    address = {Barcelona, Spain},
    booktitle = {IFIP Networking Conference (Networking 2023), International Workshop on Time-Sensitive and Deterministic Networking (TENSOR 2023)},
    month = {6},
    year = {2023}
}
```

## License

BSD 2-Clause, see [LICENSE](LICENSE).
