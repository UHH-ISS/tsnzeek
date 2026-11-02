# Changelog

## Unreleased

### Version upgrades
- Target Zeek 9.0.1 LTS from the official package (`/opt/zeek`); Spicy and Broker now ship with Zeek, so the separate Spicy, spicy-plugin and Broker builds and the Python 3.9 pin are dropped.
- Adapt the grammars to the current Spicy syntax (`* -> : void;` in switches).
- Adapt to the renamed packet analyzers (`spicy_FRER`, `spicy_SRP`, `spicy_PTP`).
- Replace `Broker::auto_publish` (removed from Zeek) by `Broker::publish` through `TSN::ids_publish`.
- Load the compiled grammar through `ZEEK_SPICY_MODULE_PATH`, so `zeek -r x.pcap spicy/scripts` is the whole invocation.

### New features
- Log malformed frames to the new `tsn_errors.log` through a `TSN::parse_error` event raised from the `%error` hooks.
- PTP: compare `messageLength` with the payload size and the per-type minimum, tolerating Ethernet padding and suffix TLVs.
- PTP: log `transportSpecific` (802.1AS) and report reserved message types (0x4-0x7, 0xE, 0xF).
- PTP: analyze PTP over UDP/IPv4 and UDP/IPv6 (ports 319/320) through a Spicy protocol analyzer; `ptp.log` rows then carry `uid`, `src_port` and `dst_port` and `src`/`dst` hold IP addresses, and `tsn_errors.log` gets a `uid` column. UDP is not padded, so any octet beyond `messageLength` is reported.
- PTP: forward `Announce` messages to the IDS (they were not published before).
- SRP: report missing mandatory, duplicate and unknown TLVs, and accept TLVs in any order.
- FRER: expose the `reserved` field so a non-zero value can be flagged.
- Add `TSN::enable_broker` (default on) so offline pcap runs do not wait for Broker peers.
- Add `build.sh`, which compiles the grammars to `build/spicy/tsn.hlto` (skipped when up to date) and runs the unit tests after a compilation; `--no-test` skips them, as the test runners do.
- Add `tests/` with a Scapy pcap generator and a replay-and-diff runner (`tests/run.sh`, `--update` regenerates the golden logs).

### IDS
- Port `zeek/attack-detection.py` to the `ids/` package (`python3 -m ids`): `ids/engine.py` (detector interface, clock driven by message timestamps), one module per protocol (`ids/frer.py`, `ids/srp.py`, `ids/ptp.py`, thresholds in `ids/config.py`) and a CLI with live Broker, `--offline` and `--replay` (Zeek JSON logs, no Broker) modes. A detector is any object with `on_message`/`on_tick`, so a statistical test or ML model plugs in next to the rules.
- Thresholds come from a JSON file (`--config`) instead of constants; drop the numpy and BitVector dependencies.
- Zeek now sends the IDS one `TSN::ids_message(kind, json)` per message, the JSON of the record also written to `cb.log`/`ptp.log`/`srp.log`, instead of positional Spicy tuples with raw packet headers. Alerts return as `TSN::raise_notice` and become `Possible_Attack` notices.
- Add `TSN::wait_for_peer`, `ids_ready` and `ids_done` so an offline pcap run waits for the IDS and ends with it; `tests/run_ids.sh` uses them for end-to-end tests (`ids_frer`, `ids_srp`).
- FRER sequence recovery now implements the 802.1CB recovery reset (`recovery_reset_time`, default 10 s): after that long without an accepted frame the next frame starts a new sequence, so a sender that restarted its counter is no longer discarded forever.
- Add 29 unit tests (`python3 -m unittest discover -s tests/unit`): `test_frer.py`, `test_srp.py` and `test_ptp.py` feed hand-made messages to the rules (no Zeek), `test_pcaps.py` runs Zeek over the `ids_*` pcaps and checks the rules that fire.
- Add a Mininet test network (`tests/live/topo.py`: h1, attacker, h2, mon behind an OVS switch that mirrors to `mon`) and live tests (`tests/live/run_live.py`, root) that run Zeek and the IDS on `mon` and send the frames of `tests/gen_pcaps.py` from h1 and the attacker. PTP is sent as crafted frames because the Mininet hosts share one clock. `mininet/sshd.py` uses the new topology.
- Add a demo mode (`sudo -E python3 tests/live/run_live.py --demo`): windows with Zeek's logs as readable lines (`tests/live/watch.py`), the IDS alerts, and a shell on h1 and on the attacker where `tsn stream`, `tsn ptp_loop`, `tsn srp_oversized_request`, `tsn replay x.pcap`, ... start traffic by hand. Add `TSN::log_flush_interval` so the logs appear as they are written.
- Add the PTP rules `ptp_rogue_grandmaster` (a grandmaster with a better clock than the current one announces itself), `ptp_unannounced_sync` (Sync or Follow_Up from a clock that never announced itself) and `ptp_sequence_id` (sequenceId repeated, going back or skipping; Ethernet and UDP are counted separately) in `ids/ptp.py`, with thresholds in `Config`. Timestamps are deliberately not compared with the local clock.
- The demo's `tsn` commands are split into legit traffic and attacks (`tsn commands`, also the banner of the windows), with attack commands for FRER, SRP and the new PTP rules, and invalid commands, options and interfaces give a short message instead of a traceback. The four demo windows open in the corners of the screen.
- Run real traffic through the test network: `run_live.py --ptp` and the scenarios `ptp_real` and `ptp_real_attacks` start `ptp4l` (gPTP profile, software timestamps, `free_running 1`: the Mininet hosts share the OS clock, which must not be adjusted) as master on h1 and client on h2; the scenarios check that its messages are logged without parse errors and that the IDS stays quiet, then that the PTP attacks are detected. `tsn ptp_sequence_id` and `tsn ptp_unannounced_sync` take `--clock real` for the ptp4l master.
- The ptp4l configurations set `asCapable true`: with software timestamps on virtual links the measured peer delay is far above the profile's 800 ns threshold, and ptp4l then never sends Announce or Sync (only peer delay). The rogue Announce of `ptp_rogue_grandmaster` carries the path trace TLV that 802.1AS requires. `send.py` accepts options before the interface (`ptp_sequence_id --clock real h1-eth0` used to fail silently), `run_live.py` gives its output directory to `$SUDO_USER`, prints tcpdump's error when the probe fails and the end of both ptp4l logs when the real-traffic checks fail.
- Real ptp4l runs through a user-space hub (`tests/live/userhub.py`, `topo.py --hub`) instead of OVS: a kernel switch re-sends the buffer that ptp4l's socket owns, every extra virtual-interface hop adds a software TX time stamp to that socket's error queue, and ptp4l treats the leftover as a fault (`error on fda[0]: Success`, port FAULTY every ~2 s, so no Announce or Sync was ever sent). The real-PTP scenarios and `--ptp` select the hub by themselves; the scenarios now also check that no ptp4l port went FAULTY. The probe filters on the ethertypes it sends (IPv6 neighbor discovery had used up its packet limit), and each ptp4l gets its own management sockets.
- `ptp_rogue_grandmaster` ignores Announce messages of slave-only clocks (clockClass 255): a client's ptp4l announces itself as grandmaster until it hears a real one, which made the real master look like a takeover at start-up. `ptp_rogue_grandmaster` announces six times (ptp4l wants a few before it believes a new master), `ptp_sequence_id` sends its two Sync messages back to back (a real master's Sync in between turned the repeat into another jump), and `ptp_real_attacks` reports whether the real client noticed and whether it selected the rogue.
- The rogue Announce of `ptp_rogue_grandmaster` carries `logMessageInterval` 0 (it was the Sync value -3): ptp4l only counts a foreign master's Announce messages inside a window of the announced interval, so the rogue was noticed but never became a candidate. `tsn` sends frames with `gap 0` in one `sendp` call, because each call takes ~25 ms and a real master's Sync could fall between two frames that were meant to be back to back.
- `tests/live/topo.py` sets `forward-bpdu` on the switch instead of an explicit OpenFlow rule for link-local multicast, so that gPTP also reaches the other hosts; the probe of `run_live.py` checks that the monitor still sees each frame once and that h2 receives the gPTP frame.
- Rule fixes: stream keys no longer use Python's randomized `hash()`; srp_bandwidth_jump no longer alerts on identical requests; frer_dead_stream no longer crashes on an empty history; srp_unused_reservation judges each reservation once and matches the reservation's data VLAN; a zero SRP interval is reported instead of dividing by zero; sequence numbers wrap at 16 bits; attacks 4 and 9 use message time, not wall-clock.

### Bug fixes
- Publish to the IDS with `Broker::publish`: `Cluster::publish` never reached a peer that connected to `Broker::listen`, so the IDS received nothing.
- PTP: stop creating ten log streams on one log ID, which produced `orphan field` errors on every Sync and Pdelay_Req.
- PTP: fix `ManagementTLV`, whose `dataField` ignored that `lengthField` includes `managementId`.
- PTP: keep `transportSpecific`, which the old grammar masked away.
- PTP: remove the duplicate `PTP_ManagementField` declaration, which Zeek 9 rejects.
- PTP: keep timestamps as integer seconds and nanoseconds, since a double cannot hold them.
- SRP: replace the `tlvT1` peek hack and the look-ahead switches, which failed at the end of data.
- SRP: enforce the fixed TLV lengths and the container lengths, which were ignored before.
- SRP: keep unknown status codes as raw numbers instead of enums that turned them into `Undef`.
- Log optional L2 fields (`src`, `dst`, `vlan`) only when present, instead of failing on untagged frames.
- `scapy/SRP.py`: bind SRP to `Dot1Q`, as `CB.py` does.
- `scapy/SRP.py`: fix the fallback in `dispatch_hook` (a copy-pasted string from the DTP module).
- `scapy/SRP.py`: set the `IEEE802VlanTag` TLV length to 3, matching its fields.

### Naming and layout
- Every rule has a name that says what it detects instead of `attack1`...`attack9`: `frer_excess_copies`, `frer_out_of_order`, `frer_dead_stream`, `srp_oversized_request`, `srp_bandwidth_jump`, `srp_request_burst`, `srp_reservation_change`, `srp_unused_reservation` and the PTP rules `ptp_rogue_grandmaster`, `ptp_unannounced_sync`, `ptp_sequence_id` (the original numbers are listed in `ids/README.md`). The names are used in alerts, tests, and the functions of the old attack script (`frer_timing_jitter` is its attack 2, which has no rule).
- The attack commands of the live demo carry the name of the rule they trigger: `frer_excess_copies`, `frer_out_of_order`, `srp_oversized_request`, `srp_reservation_change`, `ptp_rogue_grandmaster`, `ptp_unannounced_sync`, `ptp_sequence_id`; the mixed FRER scenario is `frer_mixed`.
- `ids/rules.py` is split by protocol (`frer.py`, `srp.py`, `ptp.py`), the thresholds moved to `ids/config.py`; the unit tests follow (`test_frer.py`, `test_srp.py`, `test_ptp.py`, `test_engine.py`, shared `helpers.py`).
- `scapy/` is sorted into `layers/` (`cb.py`, `srp.py`), `samples/` (the sample frames and the gPTP capture) and `scripts/` (`gptp_sender.py`, `attacks.py`).

### Optimizations and hardening
- PTP: read TLV values as `bytes &size=` instead of a `uint8` vector sized by an attacker-controlled length.
- Remove the debug `print` statements from the grammars and scripts, which ran for every packet.
- Remove the 54 MB prebuilt `TSN.hlto` from git; the 2 MB build output is generated locally.

### Refactoring
- Remove `Zeek_TSN.spicy` (tuple types and `make*` converters); units reach Zeek directly and their record types are generated with `export` in `TSN.evt`.
- Drop the hand-written protocol records (`PTP_*`, `Talker`, `Status`, ...) from the Zeek scripts.
- Split `main.zeek` (698 lines) into `main`, `register`, `broker`, `cb`, `ptp` and `srp`; `TSN.zeek` is merged into `register.zeek`.
- PTP: log all message types into one `ptp.log` schema; SRP: log both message kinds into one `srp.log` with `aa:bb:cc:dd:ee:ff` MAC addresses.
- PTP: replace the single-field `Version`, `Flags` and message type units by bitfields, removing the `sequence` wrapper records.
- SRP: parse TLV bodies as bounded item lists (`Item[] &eod`) instead of fixed optional sequences.

### Documentation
- Rewrite the README for the new build and run flow, the IDS and the tests; distribute the documentation over the `ids/`, `spicy/`, `tests/` and `tests/live/` READMEs (the `zeek/` folder, which only held a README, is gone); add the citation of the TSNZeek paper.
- Remove `mininet/sshd.py`; the Mininet network now lives in `tests/live/` (`topo.py`, `userhub.py`).

### Known gaps
- PTP rules are limited to `ptp_rogue_grandmaster`-`ptp_sequence_id`; there are none for the Sync rate, timestamp jumps or Follow_Up mismatches. frer_timing_jitter (WIP in the original) is not implemented.
- PTP over UDP: the Spicy UDP analyzer stops parsing a flow after its first parse error, so one malformed datagram blinds the analyzer for that 4-tuple until the connection times out (a spoofed source blinds that flow). Length problems are still reported, since they are not parse errors.
