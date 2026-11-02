# Running TSNZeek as a service

Optional. TSNZeek does not need a service: without any of this, `zeek ... spicy/scripts` and `python3 -m ids` run with the
defaults of the scripts and `ids/config.py` (see the [README](../README.md)). The files here run the same two programs under
systemd.

| Unit | Runs |
| --- | --- |
| `tsnzeek-monitor.service` | the monitor: Zeek on one interface with the TSN analyzers, as user `tsnzeek` with only `CAP_NET_RAW` and `CAP_NET_ADMIN` |
| `tsnzeek-ids.service` | the IDS, `python3 -m ids --service`: waits for the monitor without a time limit, keeps running when it restarts |
| `tsnzeek-web.service` | optional: the [web interface](../web/README.md) on `127.0.0.1:8000`, as the same user (installed only with `--with-web`) |
| `tsnzeek.target` | the monitor and the IDS (and the web interface, if installed); start and stop them together |

The two are independent units: `sudo systemctl stop|start|restart tsnzeek-monitor` or `tsnzeek-ids` act on one, `tsnzeek.target` on both. (`tsnzeek-ids` `Wants=` the monitor, so starting the IDS alone starts the monitor too.) An older install with `tsnzeek-zeek.service` is replaced by `install.sh`.

## Install

```sh
./build.sh
sudo deploy/install.sh --no-start
sudoedit /etc/tsnzeek/tsnzeek.env        # TSNZEEK_INTERFACE=<the interface to monitor>
sudo systemctl start tsnzeek.target
```

`install.sh` creates the user `tsnzeek`, `/etc/tsnzeek/` and `/var/log/tsnzeek/`, and writes the units to
`/etc/systemd/system/` with the path of this checkout (it has to stay where it is). `ZEEK_PREFIX` (default `/opt/zeek`)
selects another Zeek. `sudo deploy/install.sh --uninstall` removes the units again; configuration and logs stay.

## With the web interface (optional)

The web interface needs Django in the project's venv. Install it with the rest, or add it later by running `install.sh` again:

```sh
python3 -m venv .venv && .venv/bin/pip install -r web/requirements.txt     # once
sudo deploy/install.sh --with-web                                          # --with-web --no-start to install only
```

Open <http://127.0.0.1:8000/> (this machine only, no login). It runs as the user `tsnzeek`, like the IDS, so it can replace
`/var/lib/tsnzeek/control.json`, and reads `/var/log/tsnzeek`. Start and stop it on its own with
`sudo systemctl start|stop tsnzeek-web`; `tsnzeek.target` includes it once it is enabled. Without `--with-web` nothing about it is
installed.

## Check that it runs

```sh
systemctl --no-pager status tsnzeek-monitor tsnzeek-ids      # both "active (running)" (and tsnzeek-web, if installed)
journalctl --no-pager -u tsnzeek-ids -n 20                # "Connected to Zeek"
ls /var/log/tsnzeek                                       # cb.log, ptp.log, srp.log ... as frames arrive
tail -f /var/log/tsnzeek/alerts.log                       # the alerts
```

`--no-pager` avoids the warning `terminal is not fully functional`, which `systemctl` prints when its pager (`less`)
cannot run, for example in a shell without a proper `TERM`. It has nothing to do with TSNZeek; `export SYSTEMD_PAGER=` turns the pager off for the session.

## Day to day

| Task | Command |
| --- | --- |
| stop / start / restart both | `sudo systemctl stop\|start\|restart tsnzeek.target` |
| change the interface | edit `/etc/tsnzeek/tsnzeek.env`, `sudo systemctl restart tsnzeek-monitor` |
| change thresholds | edit `/etc/tsnzeek/ids.json`, `sudo systemctl restart tsnzeek-ids` |
| not at boot any more | `sudo systemctl disable tsnzeek.target` |
| remove the units | `sudo deploy/install.sh --uninstall` |

## Configuration

| File | Content | Without it |
| --- | --- | --- |
| `/etc/tsnzeek/tsnzeek.env` | interface and optional environment (`KEY=value`) | `install.sh` writes one with `eth0` |
| `/etc/tsnzeek/ids.json` | IDS thresholds, the keys of `Config` in [`ids/config.py`](../ids/config.py); `install.sh` writes one with all keys at their defaults (`deploy/ids.json`), edit the values you want to change, and delete a key to get its default | the defaults of `config.py` |

The IDS looks for its thresholds in this order: `--config FILE`, `$TSNZEEK_CONFIG`, `/etc/tsnzeek/ids.json`, the defaults.
Restart the IDS after a change: `sudo systemctl restart tsnzeek-ids`. The Broker address of Zeek can be moved with
`TSN::broker_listen_addr` and `TSN::broker_listen_port` (and `--host`, `--port` of the IDS) if `127.0.0.1:9999` is taken.

## Logs

| Where | Content |
| --- | --- |
| `/var/log/tsnzeek/cb.log`, `ptp.log`, `srp.log`, `tsn_errors.log`, `notice.log`, ... | Zeek's logs as JSON, flushed every second; Zeek rotates them daily (the old ones get the date in their name) |
| `/var/log/tsnzeek/alerts.log` | the alerts of the IDS, one line each; rotated weekly by logrotate |
| `journalctl -u tsnzeek-ids -f` | the same alerts, and the messages about the connection to Zeek |
| `journalctl -u tsnzeek-monitor` | errors of Zeek itself |

Outside a service the alert file is `--alert-log FILE` or `$TSNZEEK_ALERT_LOG`; without either, alerts go to the console only.

## Troubleshooting

- `tsnzeek-monitor` fails at once: `journalctl -u tsnzeek-monitor -n 30`. A wrong interface name in `tsnzeek.env`, or a grammar that was not built (`./build.sh`), are the usual causes.
- No `*.log` files: there was no TSN traffic yet, or Zeek sees the wrong interface (`ip -br link`). Zeek creates a log when its first row is written.
- `tsnzeek-ids` says `Lost Zeek, waiting for it to come back`: Zeek restarted or stopped; the IDS reconnects by itself.
- Nothing in `alerts.log` although you attack: check that the IDS was connected (`Connected to Zeek`) before the traffic, and that the thresholds in `/etc/tsnzeek/ids.json` are not too high.
- `tsnzeek-ids` or `tsnzeek-web` cannot start (`Permission denied`, `No module named ids`): the services run as user `tsnzeek` from this checkout, so that user has to be able to enter its path. On Ubuntu a home directory is `0750`; use `chmod o+x ~` (or keep the checkout outside the home).
- The web interface says `IDS: no state.json`: the IDS is not running or does not use `/var/lib/tsnzeek`; `systemctl status tsnzeek-ids`.
- The checkout moved: run `install.sh` again, the units contain its path.
