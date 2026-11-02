# IDS

The intrusion detection of TSNZeek. Zeek parses the TSN frames (see [`spicy/`](../spicy/README.md)) and sends every
message to this module over Broker; alerts go back to Zeek and appear in `notice.log` as `TSN::Possible_Attack`.

```
PYTHONPATH=/opt/zeek/lib/zeek/python python3 -m ids [--config thresholds.json]   # live, connects to Zeek
python3 -m ids --replay cb.log srp.log ptp.log                                    # Zeek's JSON logs, no Zeek or Broker
```

`--drain SECONDS` advances the clock at the end so that timeouts fire, `--offline` is for `zeek -r x.pcap ...
TSN::wait_for_peer=T` runs (the tests use it). Thresholds come from a JSON file whose keys are the fields of `Config` in
`rules.py`.

## Rules

| Rule | Detects | Main thresholds (`Config`) |
| --- | --- | --- |
| `attack1` | more copies of a FRER frame than member streams | `nr_of_member_streams` |
| `attack3` | FRER frames out of order, accepted or discarded by the sequence recovery | `frer_history_size`, `recovery_reset_time` |
| `attack4` | dead member streams (a stream or some copies stop) | `timeout` |
| `attack5` | an SRP reservation above the resource thresholds | `interval_threshold`, `max_frames_per_interval_threshold`, `max_frame_size_threshold` |
| `attack6` | an SRP bandwidth request more than two standard deviations from the recent ones | `srp_bandwidth_history_len` |
| `attack7` | too many SRP requests in a time window | `nr_of_requests_threshold`, `time_window_threshold` |
| `attack8` | a request that changes an existing reservation | |
| `attack9` | an SRP reservation with no FRER traffic | `timeout` |
| `ptp1` | a grandmaster with a better clock than the current one announces itself | `ptp_gm_timeout` |
| `ptp2` | Sync or Follow_Up from a clock that never announced itself | `ptp_learning_time` |
| `ptp3` | sequenceId repeated, going back or skipping (Ethernet and UDP counted apart) | `ptp_seq_gap_tolerance`, `ptp_seq_reset_time` |

FRER and SRP rules are in `rules.py`, PTP rules in `ptp_rules.py`. The PTP rules judge message content and sequences,
never the local clock, and they learn what is normal from the traffic: a master that announced itself, the sequence so far.
Announce messages of slave-only clocks (class 255) are not grandmaster candidates.

## Design

The engine (`engine.py`) feeds messages to detectors and keeps a clock that is the timestamp of the newest message,
so a pcap replayed at any speed gives the alerts of live traffic. Messages are the JSON records that Zeek also writes to
`cb.log`, `ptp.log` and `srp.log`, delivered as `TSN::ids_message(kind, json)`.

To add a detector (a statistical test, an embedded ML model), subclass `Detector`, implement `on_message(kind, msg)`
(`kind` is `cb`, `ptp` or `srp`, `msg` a dict) and/or `on_tick(now)`, return `Alert`s, and add the instance to the engine in
`__main__.py`. Alerts return to Zeek as `TSN::raise_notice`.

## Known gaps

- No PTP rules for the Sync rate, timestamp jumps or Follow_Up mismatches.
- Attack 2 of the original script (work in progress there) is not implemented.
