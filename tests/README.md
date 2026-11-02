# Tests

| Layer | Command | What it checks |
| --- | --- | --- |
| Rules | `python3 -m unittest discover -s tests/unit` | every IDS rule on hand-made messages (no Zeek), and on the `ids_*` pcaps through Zeek; the user-space hub |
| Zeek logs | `tests/run.sh` | Zeek's logs for every pcap in `tests/pcaps/` against `tests/expected/` |
| End to end | `tests/run_ids.sh` | Zeek and the IDS over Broker on the `ids_*` pcaps; every alert must also reach Zeek as a notice |
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
