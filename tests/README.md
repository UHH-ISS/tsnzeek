# Tests

## Step by step

1. **Install** what the tests need (Zeek 9 in `/opt/zeek` is required for all but the first row; see the [README](../README.md#installation)):

   ```sh
   sudo apt-get install python3-venv
   python3 -m venv .venv && .venv/bin/pip install scapy      # only for gen_pcaps.py and the Mininet part
   ```

2. **Build** the grammars: `./build.sh`. It compiles `build/spicy/tsn.hlto` if a grammar changed and then runs the unit tests (step 3), so a grammar that compiles but parses wrongly shows up at once. `./build.sh --no-test` only compiles.
3. **Rules and pcaps through Zeek**, about two seconds: `python3 -m unittest discover -s tests/unit`. Expect `OK`.
4. **Zeek's logs** against the golden logs, about ten seconds: `tests/run.sh`. One line per case, `ok   <case>`; a `FAIL` line is followed by the diff. `tests/run.sh frer ptp_udp` runs only the named cases.
5. **Zeek and the IDS together**: `tests/run_ids.sh`. It starts Zeek on each `ids_*` pcap with `TSN::wait_for_peer=T` and the IDS with `--offline`, and checks that the alerts equal `expected/<case>/alerts.txt` and that each alert also came back as a notice.
6. **The web interface**, optional, needs Django: `.venv/bin/python web/manage.py test console`. Expect `OK`.
7. **Live**, in Mininet, optional and needs root: `sudo python3 tests/live/run_live.py` ([guide](live/README.md)).

If you changed behaviour on purpose, rewrite the golden files with `tests/run.sh --update` and `tests/run_ids.sh --update`, and read `git diff tests/expected` before committing. A run that hangs is usually Zeek waiting for the IDS or a Broker listener: a plain pcap needs `TSN::enable_broker=F` (the runners set it).

## Layers

| Layer | Command | What it checks |
| --- | --- | --- |
| Rules | `python3 -m unittest discover -s tests/unit` | every IDS rule on hand-made messages (no Zeek), and on the `ids_*` pcaps through Zeek; the user-space hub |
| Zeek logs | `tests/run.sh` | Zeek's logs for every pcap in `tests/pcaps/` against `tests/expected/` |
| End to end | `tests/run_ids.sh` | Zeek and the IDS over Broker on the `ids_*` pcaps; every alert must also reach Zeek as a notice |
| Web interface | `.venv/bin/python web/manage.py test console` | the API of the web interface (rules, thresholds, log tail, CSRF, validation) against temporary directories; needs Django (`.venv/bin/pip install -r web/requirements.txt`) |
| Live | `sudo python3 tests/live/run_live.py` | the same in Mininet, with real `ptp4l`; see [live/README.md](live/README.md) |

`./build.sh` runs the unit tests after every compilation (`--no-test` skips them; the runners below use it, so tests do not
start tests), so a grammar that compiles but parses wrongly shows up at once. The first three need Zeek in `/opt/zeek` (`ZEEK_PREFIX`), compile the grammars when they changed, and run in about ten
seconds. Zeek runs with `-D`, so uids in the logs are reproducible.

## Pcaps and expected output

- `gen_pcaps.py` writes the synthetic pcaps to `pcaps/` (`.venv/bin/python tests/gen_pcaps.py`, needs Scapy): messages of
  every protocol, malformed frames, PTP over UDP, and the traffic of the attacks. Timestamps are fixed. `ptp_sample.pcap`
  is a real capture.
- `expected/<case>/` holds the golden logs (`*.log`) and, for the `ids_*` cases, the alerts (`alerts.txt`).
  `tests/run.sh --update` and `tests/run_ids.sh --update` rewrite them; review the diff before committing.
- `ids/config.json` holds the thresholds of the `ids_*` cases.

## Adding a case

Add the frames to `gen_pcaps.py` (an `ids_*` pcap for a rule), regenerate, run `tests/run.sh --update <case>` and, for an
`ids_*` case, `tests/run_ids.sh --update <case>`, and assert the rules in `tests/unit/test_pcaps.py`.
