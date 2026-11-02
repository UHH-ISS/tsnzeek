# Web interface

A small Django app for the detection side of TSNZeek, for the machine it runs on (it listens on `127.0.0.1` only and
accepts only local host names; there is no login). It has no database: it reads the files of the IDS and of Zeek and writes
one file, `control.json`.

| Tab | Shows | Can change |
| --- | --- | --- |
| Overview | connection to Zeek, messages per second, alerts per rule, rules on or off, what differs from the defaults, the tracked FRER streams, SRP reservations and PTP domains, the latest alerts | |
| Rules | every rule per protocol with its number (`#101` ...), summary, thresholds and alert count | switch a rule on or off |
| Config | every threshold: default, active value, which rules use it | set a value, or go back to the default |
| Logs | live tail of `alerts`, `notice`, `cb`, `ptp`, `srp`, `tsn_errors`, `weird` and `stats` | |

Changes reach the IDS within half a second, without a restart, and stay across restarts of the IDS (see
[`ids/README.md`](../ids/README.md#run-time-control)). A disabled rule keeps running but raises no alerts.

## Step by step

1. **Install** Django into the project's venv (once): `python3 -m venv .venv && .venv/bin/pip install -r web/requirements.txt`
2. **Start the IDS and the monitor** so that there is something to show, with the control directory switched on:
   - `deploy/headless.sh start -i <interface>` (the control directory is `~/tsnzeek/control`), or
   - the systemd services (`/var/lib/tsnzeek`), see [`deploy/`](../deploy/README.md).
3. **Start the web interface.** The quickest ways: `deploy/headless.sh start -i <interface> -w` starts it with the monitor and the IDS, and `sudo deploy/install.sh --with-web` makes it a service. By hand, and telling it where the files are:

   ```sh
   .venv/bin/python web/manage.py runserver 127.0.0.1:8000
   ```

   It finds a headless run by itself (`$TSNZEEK_DIR`, default `~/tsnzeek`). For the services:

   ```sh
   TSNZEEK_CONTROL_DIR=/var/lib/tsnzeek TSNZEEK_LOG_DIR=/var/log/tsnzeek \
       .venv/bin/python web/manage.py runserver 127.0.0.1:8000
   ```

4. **Open** <http://127.0.0.1:8000/>. The badges at the top say whether the IDS writes `state.json` and whether Zeek is
   connected to it. Without an IDS the page says so and shows nothing else.
5. **Try it**: send an attack (`tsn frer_excess_copies` in the [demo](../tests/live/README.md), or replay `tests/pcaps/ids_frer.pcap`),
   watch the alert appear, switch `frer_excess_copies` off in *Rules* and repeat: no alert; switch it on again.

## Permissions with the services

The IDS service writes `/var/lib/tsnzeek/state.json` as user `tsnzeek`, and the web interface has to replace
`control.json` in that directory. `tsnzeek-web.service` runs as `tsnzeek` too, so this works. Started by hand, run it as that user
(`sudo -u tsnzeek ...`) or make the directory group-writable for yours (`sudo chmod g+ws /var/lib/tsnzeek`). The logs in
`/var/log/tsnzeek` are only read.

## The API

The page uses these; scripts can too. The POSTs need the CSRF cookie and `X-CSRFToken` header that the page sets.

| Request | Does |
| --- | --- |
| `GET /api/state` | `state.json` with its age (`stale` after 6 s), the current `control.json`, the logs that exist |
| `POST /api/rule` `{"rule": "srp_request_burst" or 203, "enabled": false}` | switch a rule |
| `POST /api/config` `{"set": {"timeout": 30}, "unset": ["frer_history_size"]}` | set thresholds, or return them to the default |
| `POST /api/reset` | remove `control.json`: all rules on, thresholds as in the config file of the IDS |
| `GET /api/logs?name=cb&offset=-1` | the last lines (offset -1) or the new whole lines since the byte offset; the answer carries the next offset |

Everything is validated by `ids/control.py`, the code the IDS applies it with, so the web interface cannot write what the IDS
would refuse; a refusal is a `400` with the reason.

## Tests

`.venv/bin/python web/manage.py test console` (the API against temporary directories, no IDS needed).
