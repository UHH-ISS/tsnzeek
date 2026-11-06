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

## Rules

Every rule has a name that says what it detects; the same name appears in alerts, tests and the `tsn` attack commands of
the [live demo](../tests/live/README.md) (where one exists).

| File | Rule | Detects | Main thresholds (`Config`) |
| --- | --- | --- | --- |
| `frer.py` | `frer_excess_copies` | more copies of a frame than member streams | `nr_of_member_streams` |
| | `frer_out_of_order` | sequence numbers out of order, accepted or discarded by the sequence recovery | `frer_history_size`, `recovery_reset_time` |
| | `frer_dead_stream` | member streams that stopped (all or some copies) | `timeout` |
| `srp.py` | `srp_oversized_request` | a reservation above the resource thresholds | `interval_threshold`, `max_frames_per_interval_threshold`, `max_frame_size_threshold` |
| | `srp_bandwidth_jump` | a bandwidth more than two standard deviations from the recent requests | `srp_bandwidth_history_len` |
| | `srp_request_burst` | too many requests in a time window | `nr_of_requests_threshold`, `time_window_threshold` |
| | `srp_reservation_change` | a request for a reservation that exists already | |
| | `srp_unused_reservation` | a reservation with no FRER traffic | `timeout` |
| `ptp.py` | `ptp_rogue_grandmaster` | a grandmaster with a better clock than the current one announces itself | `ptp_gm_timeout` |
| | `ptp_unannounced_sync` | Sync or Follow_Up from a clock that never announced itself | `ptp_learning_time` |
| | `ptp_sequence_id` | sequenceId repeated, going back or skipping (Ethernet and UDP counted apart) | `ptp_seq_gap_tolerance`, `ptp_seq_reset_time` |

The FRER timing attack `frer_timing_jitter` (`frames/scripts/attacks.py`) has no rule.

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
- No rule for `frer_timing_jitter`, a change in the inter-arrival time of FRER frames.
