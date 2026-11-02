# Live tests and demo

Zeek and the IDS run on the monitor of an emulated Mininet network (below); frames come from `h1` and the
`attacker` (and from `ptp4l` on `h1` and `h2`). Everything here needs root, Mininet and Open vSwitch, `tcpdump`, and the
project's venv with Scapy; `ptp4l` (linuxptp) and `xterm` for the real-PTP and window parts. Build the grammars first,
as yourself: `./build.sh`.

## Step by step: the demo

1. **Install** (once): `sudo apt-get install mininet openvswitch-switch tcpdump xterm linuxptp python3-venv`, then `python3 -m venv .venv && .venv/bin/pip install scapy` in the repository.
2. **Build** as yourself, not with sudo, so that `build/` does not become root-owned: `./build.sh`.
3. **Allow root to open windows** on your display (once per login): `xhost +si:localuser:root`. Without a display, use `--cli` below.
4. **Start** the network, Zeek, the IDS and the windows: `sudo -E python3 tests/live/run_live.py --demo` (add `--ptp` for real `ptp4l`). Four windows open in the corners of the screen; this terminal becomes the Mininet CLI.
5. **Legit traffic**: in the **h1** window run `tsn ptp_loop` (or `tsn stream` for FRER). The **Zeek logs** window fills with one line per message; the **IDS alerts** window stays empty.
6. **An attack**: in the **attacker** window run `tsn ptp_rogue_grandmaster`. Within a moment the IDS window shows `ALERT ptp_rogue_grandmaster ...` and the Zeek window shows the notice `TSN::Possible_Attack`. `tsn commands` lists the others (table below).
7. **Stop**: Ctrl-C a running `tsn` command, then type `exit` in the Mininet CLI. Everything is stopped; the logs stay under the `/tmp/tsnzeek-live-*` directory printed at the end. After a crash run `sudo mn -c`.

No display (SSH, a server): `sudo python3 tests/live/run_live.py --cli` starts the same network, Zeek and IDS without windows and prints where their output goes (`/tmp/tsnzeek-live-*/cli`, `tail -f` the logs there) and a sample command. Send frames from the Mininet CLI, e.g. `h1 .venv/bin/python tests/live/send.py frer_mixed h1-eth0`; `exit` stops everything.

## Demo

```sh
xhost +si:localuser:root                              # once per login: lets root open windows on your display
sudo -E python3 tests/live/run_live.py --demo         # crafted PTP
sudo -E python3 tests/live/run_live.py --demo --ptp   # real ptp4l, with a fifth window for its logs
```

Four windows open, one in each corner of the screen; the Mininet CLI stays in the terminal (`exit` stops everything):

| | left | right |
| --- | --- | --- |
| top | **Zeek logs** (mon): one line per parsed message, and the alerts as notices | **IDS alerts** (mon) |
| bottom | **h1**: a shell, `tsn <command>` sends frames | **attacker**: the same shell |

`tsn commands` lists what can be sent, legit traffic and attacks apart:

| Legit traffic | Attacks (each raises the IDS rule of the same name) |
| --- | --- |
| `stream` (FRER), `ptp_loop` (gPTP and PTP/UDP), `ptp`, `srp_normal`, `replay x.pcap` | `frer_excess_copies`, `frer_out_of_order`, `frer_mixed` (several FRER rules), `srp_oversized_request` (also `srp_unused_reservation` later), `srp_reservation_change`, `ptp_rogue_grandmaster`, `ptp_unannounced_sync`, `ptp_sequence_id` |

A walk-through: in the h1 window start `tsn ptp_loop` (the log window fills with Sync lines, the IDS stays silent), then
in the attacker window `tsn ptp_rogue_grandmaster`, `tsn ptp_unannounced_sync`, `tsn ptp_sequence_id`. With `--ptp` do not run `ptp_loop`; the
attacks work against the real master (`tsn ptp_sequence_id --clock real`). The same with `tsn stream` and `tsn frer_excess_copies`;
stop a stream with Ctrl-C and the IDS reports it dead after five seconds. Invalid commands and options give a short message.

## Scenarios

```sh
sudo python3 tests/live/run_live.py                           # probe, then every scenario
sudo python3 tests/live/run_live.py ptp_real ptp_real_attacks # chosen scenarios
```

The probe checks that the monitor sees a gPTP frame and an ordinary frame exactly once each and that h2 receives the gPTP
frame; if it fails, the later results are not trustworthy. Each scenario starts a fresh Zeek and IDS, sends its frames and
compares the alerts, the notices, the `ptp.log` rows and the parse errors with its expectation (`SCENARIOS` in
`run_live.py`). `ptp_real` checks that ptp4l's messages are logged without parse errors and that the IDS stays quiet;
`ptp_real_attacks` that the PTP attacks are detected, and reports whether the real client noticed and selected the rogue
grandmaster. The output stays under `/tmp/tsnzeek-live-*`, owned by you.

## The network

An emulated TSN segment (`topo.py`):

```
  h1 (talker, ptp4l master) ---+
  attacker --------------------+--- s1 ---+--- h2 (receiver, ptp4l client)
                                           |
                                           +--- mon (Zeek and the IDS)
```

| Host | MAC | IP |
| --- | --- | --- |
| h1 | `00:00:00:00:00:01` | `10.0.0.1` |
| h2 | `00:00:00:00:00:02` | `10.0.0.2` |
| attacker | `00:00:00:00:00:66` | `10.0.0.66` |
| mon | `00:00:00:00:00:99` | `10.0.0.99` |

The MAC addresses match those in `../gen_pcaps.py`, so the frames of the offline tests can be sent unchanged.

### Create the network

Mininet needs root and the system Python (Scapy lives in the project's venv; the scripts here call it themselves):

```sh
sudo python3 tests/live/topo.py            # OVS switch that mirrors every port to mon; opens the Mininet CLI
sudo python3 tests/live/topo.py --hub      # user-space hub instead of OVS, needed for real ptp4l
```

Inside the CLI, `h1 ip addr` or `xterm h1` work as usual. Zeek, the IDS and the traffic are started by
`run_live.py`; `sudo mn -c` cleans up after a crash.

### Why a user-space hub

Real `ptp4l` does not survive a kernel switch. With software time stamping it asks for a TX stamp on every frame it sends,
and each further virtual-interface hop of the same buffer (a switch's last output, a flood) adds another stamp to ptp4l's
socket. `ptp4l` reads the leftover as an error (`error on fda[0]: Success`), the port goes FAULTY every ~2 s and no
Announce or Sync is sent. `userhub.py` reads every frame and sends it again as a new buffer to all other ports, `mon`
included, so ptp4l sees one stamp. OVS stays the default for crafted traffic, which has no stamps to lose.

### PTP in the emulation

All hosts share the OS clock, so nothing is really synchronized. Two ways to get PTP traffic:

- **Crafted** (default): `tsn ptp_loop` on h1 plays the master with hand-made Announce, Sync and Follow_Up messages. The PTP
  rules judge message content and sequences, not time, so this is enough to test them; start it before the attacks.
- **Real**: `ptp4l` as gPTP master on h1 and client on h2 (`ptp/*.cfg`: the 802.1AS profile, software time stamps,
  `asCapable true` because the peer delay of virtual links exceeds the profile's threshold). Both set `free_running 1`, as a
  ptp4l that adjusted its clock would adjust the clock of this machine; `run_live.py` refuses to start without it.

What cannot be shown is the effect of an attack on the synchronization itself, or attacks on timing.

## Files

| File | Purpose |
| --- | --- |
| `topo.py`, `userhub.py` | the Mininet network and the user-space hub |
| `run_live.py` | builds the network, starts Zeek, the IDS and `ptp4l`, runs scenarios or the demo |
| `send.py` | the `tsn` commands (`send.py commands` lists them); Scapy, run inside a host |
| `watch.py` | follows Zeek's JSON logs and prints one readable line per record |
| `demo_shell.sh` | the shell of the host windows |
| `config.json` | thresholds with short timeouts, for the scenarios |
| `ptp/master.cfg`, `slave.cfg` | `ptp4l` (gPTP) |

## Troubleshooting

- Windows do not open: use `sudo -E`, run `xhost +si:localuser:root`; without X11 use `--cli`.
- `ptp4l` ports go FAULTY: the network was not built with the user-space hub (`--hub`; `--ptp` and the `ptp_real` scenarios do it).
- Alert counts of `frer_dead_stream`/`srp_unused_reservation` differ: they depend on timeouts and wall-clock ticks; the scenarios wait 8 s.
- After a crash: `sudo mn -c`.
