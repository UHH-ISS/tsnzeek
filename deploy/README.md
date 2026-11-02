# Running TSNZeek as a service

Optional. TSNZeek does not need a service: without any of this, `zeek ... spicy/scripts` and `python3 -m ids` run with the
defaults of the scripts and `ids/config.py` (see the [README](../README.md)). The files here run the same two programs under
systemd.

| Unit | Runs |
| --- | --- |
| `tsnzeek-zeek.service` | Zeek on one interface with the TSN analyzers, as user `tsnzeek` with only `CAP_NET_RAW` and `CAP_NET_ADMIN` |
| `tsnzeek-ids.service` | `python3 -m ids --service`: waits for Zeek without a time limit, keeps running when Zeek restarts |
| `tsnzeek.target` | both; start and stop them together |

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

## Configuration

| File | Content | Without it |
| --- | --- | --- |
| `/etc/tsnzeek/tsnzeek.env` | interface and optional environment (`KEY=value`) | `install.sh` writes one with `eth0` |
| `/etc/tsnzeek/ids.json` | IDS thresholds, the keys of `Config` in [`ids/config.py`](../ids/config.py) | the defaults of `config.py` |

The IDS looks for its thresholds in this order: `--config FILE`, `$TSNZEEK_CONFIG`, `/etc/tsnzeek/ids.json`, the defaults.
Restart the IDS after a change: `sudo systemctl restart tsnzeek-ids`. The Broker address of Zeek can be moved with
`TSN::broker_listen_addr` and `TSN::broker_listen_port` (and `--host`, `--port` of the IDS) if `127.0.0.1:9999` is taken.

## Logs

| Where | Content |
| --- | --- |
| `/var/log/tsnzeek/cb.log`, `ptp.log`, `srp.log`, `tsn_errors.log`, `notice.log`, ... | Zeek's logs as JSON, flushed every second; Zeek rotates them daily (the old ones get the date in their name) |
| `/var/log/tsnzeek/alerts.log` | the alerts of the IDS, one line each; rotated weekly by logrotate |
| `journalctl -u tsnzeek-ids -f` | the same alerts, and the messages about the connection to Zeek |
| `journalctl -u tsnzeek-zeek` | errors of Zeek itself |

Outside a service the alert file is `--alert-log FILE` or `$TSNZEEK_ALERT_LOG`; without either, alerts go to the console only.
