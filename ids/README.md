# IDS

The intrusion detection of TSNZeek. Zeek parses the TSN frames (see [`spicy/`](../spicy/README.md)) and sends every
message to this module over Broker; alerts go back to Zeek and appear in `notice.log` as `TSN::Possible_Attack`.

```
PYTHONPATH=/opt/zeek/lib/zeek/python python3 -m ids [--config thresholds.json]   # live, connects to Zeek
python3 -m ids --replay frer.log srp.log ptp.log                                    # Zeek's JSON logs, no Zeek or Broker
```

`--service` waits for Zeek without a time limit and keeps running when Zeek restarts (used by the systemd unit, see [`deploy/`](../deploy/README.md));
`--alert-log FILE` (or `$TSNZEEK_ALERT_LOG`) also appends the alerts to a file. Without `--config` the thresholds come from
`$TSNZEEK_CONFIG`, else `/etc/tsnzeek/ids.json` if it exists, else the defaults. `--drain SECONDS` advances the clock at the end so that timeouts fire, `--offline` is for `zeek -r x.pcap ...
TSN::wait_for_peer=T` runs (the tests use it). Thresholds come from a JSON file whose keys are the fields of `Config` in
`config.py`.

## Run-time control

`--control-dir DIR` (or `$TSNZEEK_CONTROL_DIR`; the systemd service uses `/var/lib/tsnzeek`, `deploy/headless.sh` uses
`$TSNZEEK_DIR/control`) opens a channel for the web interface, two JSON files in that directory:

| File | Written by | Content |
| --- | --- | --- |
| `state.json` | the IDS, about every two seconds and at once after a change | whether Zeek is connected, the rules with protocol, thresholds, enabled flag and alert count, the active configuration with the defaults and what differs, messages and messages per second, the tracked streams (`frer`, `srp`, `ptp`) |
| `control.json` | the web interface (atomically, `os.replace`) | `{"disabled_rules": ["srp_request_burst"], "config": {"timeout": 30}}` |

Changes apply within half a second and cost the packet path nothing: the main loop looks at the file's `stat` twice a
second, and the detectors read their thresholds as `self.c.<field>` where they use them, so a new config is one
assignment (`Detector.reconfigure`) and nothing learned (streams, grandmasters, sequence numbers) is lost. A disabled rule
keeps running, so that it knows the traffic when you enable it again, but raises no alerts. A file that does not validate
(unknown rule or key, a string or negative number, a fraction for a whole number) is ignored as a whole and the reason is
in `state.json` under `error`. The list of rules is `catalog.py`; a test keeps it equal to what the detectors can raise.

## Rules

Every rule has a name that says what it detects; the same name appears in alerts, tests and the `tsn` attack commands of
the [live demo](../tests/live/README.md) (where one exists). The last column is the number in the original
`attack-detection.py` and the paper.

| File | Rule (number) | Detects | Main thresholds (`Config`) | Original |
| --- | --- | --- | --- | --- |
| `frer.py` | `frer_excess_copies` | more copies of a frame than member streams | `nr_of_member_streams` | attack1 |
| | `frer_out_of_order` | sequence numbers out of order, accepted or discarded by the sequence recovery | `frer_history_size`, `recovery_reset_time` | attack3 |
| | `frer_dead_stream` | member streams that stopped (all or some copies) | `timeout` | attack4 |
| `srp.py` | `srp_oversized_request` | a reservation above the resource thresholds | `interval_threshold`, `max_frames_per_interval_threshold`, `max_frame_size_threshold` | attack5 |
| | `srp_bandwidth_jump` | a bandwidth more than two standard deviations from the recent requests | `srp_bandwidth_history_len` | attack6 |
| | `srp_request_burst` | too many requests in a time window | `nr_of_requests_threshold`, `time_window_threshold` | attack7 |
| | `srp_reservation_change` | a request for a reservation that exists already | | attack8 |
| | `srp_unused_reservation` | a reservation with no FRER traffic | `timeout` | attack9 |
| `ptp.py` | `ptp_rogue_grandmaster` | a grandmaster with a better clock than the current one announces itself | `ptp_gm_timeout` | |
| | `ptp_unannounced_sync` | Sync or Follow_Up from a clock that never announced itself | `ptp_learning_time` | |
| | `ptp_sequence_id` | sequenceId repeated, going back or skipping (Ethernet and UDP counted apart) | `ptp_seq_gap_tolerance`, `ptp_seq_reset_time` | |

The timing attack 2 of the original script (`frer_timing_jitter` in `frames/scripts/attacks.py`) has no rule.

One detector per protocol: `FrerDetector` (frer.log), `SrpDetector` (srp.log; it also reads frer.log to see whether a reservation
is used) and `PtpDetector` (ptp.log). `config.py` holds all thresholds. The PTP rules judge message content and sequences,
never the local clock, and learn what is normal from the traffic: a master that announced itself, the sequence so far.
Announce messages of slave-only clocks (class 255) are not grandmaster candidates.

## Design

The engine (`engine.py`) feeds messages to detectors and keeps a clock that is the timestamp of the newest message,
so a pcap replayed at any speed gives the alerts of live traffic. Messages are the JSON records that Zeek also writes to
`frer.log`, `ptp.log` and `srp.log`, delivered as `TSN::ids_message(kind, json)`.

To add a detector (a statistical test, an embedded ML model), subclass `Detector` (`engine.py`), implement `on_message(kind, msg)`
(`kind` is `frer`, `ptp` or `srp`, `msg` a dict) and/or `on_tick(now)`, return `Alert`s, and add the instance to the engine in `build_engine()` of
`__main__.py`. Alerts return to Zeek as `TSN::raise_notice`.

## Known gaps

- No PTP rules for the Sync rate, timestamp jumps or Follow_Up mismatches.
- Attack 2 of the original script (work in progress there) is not implemented.
