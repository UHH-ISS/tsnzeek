#!/usr/bin/env bash
# (C) 2026 Doganalp Ergenc, written with the assistance of Claude
# Run Zeek and the IDS in the background without a terminal window and without installing a service.
#
#   deploy/headless.sh start [-i INTERFACE] [-d TSNZEEK_DIR] [-c IDS_CONFIG.json]
#   deploy/headless.sh stop   [-d TSNZEEK_DIR]
#   deploy/headless.sh status [-d TSNZEEK_DIR]
#
# Everything lives in one directory: logs/ (Zeek's logs, alerts.log, ids.out, monitor.out), run/ (pid files) and control/ (state.json and
# control.json, the channel to the web interface).
# Defaults: interface $TSNZEEK_INTERFACE (else the first non-loopback one), directory $TSNZEEK_DIR (else ~/tsnzeek),
# IDS config $TSNZEEK_CONFIG (else /etc/tsnzeek/ids.json if it exists, else the defaults).
# Inside a Mininet host (the CLI runs as root): `mon deploy/headless.sh start -i mon-eth0`; see tests/live/README.md.
# Capturing needs root: the script uses sudo for Zeek unless you are root or Zeek has been given the capabilities
# (sudo setcap cap_net_raw,cap_net_admin=eip /opt/zeek/bin/zeek).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ZEEK_PREFIX="${ZEEK_PREFIX:-/opt/zeek}"
IFACE="${TSNZEEK_INTERFACE:-}"
# Started as root through sudo (also from the Mininet CLI, which runs as root): use the home of the user who ran sudo, and
# give the directory to that user, so that the web interface, which runs as that user, can write control.json.
OWNER=""
[[ $EUID -eq 0 && -n "${SUDO_USER:-}" && "$SUDO_USER" != root ]] && OWNER="$SUDO_USER"
USER_HOME="$HOME"
[[ -n "$OWNER" ]] && USER_HOME="$(getent passwd "$OWNER" | cut -d: -f6)"
DIR="${TSNZEEK_DIR:-$USER_HOME/tsnzeek}"
CONFIG="${TSNZEEK_CONFIG:-}"

cmd="${1:-}"; [[ $# -gt 0 ]] && shift
while getopts "i:d:c:" opt; do
	case "$opt" in
		i) IFACE="$OPTARG" ;;
		d) DIR="$OPTARG" ;;
		c) CONFIG="$OPTARG" ;;
		*) exit 2 ;;
	esac
done

LOGS="$DIR/logs"
RUN="$DIR/run"
IDS_PID="$RUN/ids.pid"
MONITOR_PID="$RUN/monitor.pid"

alive() { [[ -f "$1" ]] && kill -0 "$(cat "$1")" 2>/dev/null; }          # signal 0 fails for root's Zeek if we are not root
running() { [[ -f "$1" ]] && [[ -d "/proc/$(cat "$1")" ]]; }
as_root() { if [[ $EUID -eq 0 ]]; then "$@"; else sudo "$@"; fi; }

stop_one() {    # name pidfile
	local name="$1" pf="$2"
	if ! running "$pf"; then echo "$name: not running"; rm -f "$pf"; return 0; fi
	local pid; pid="$(cat "$pf")"
	as_root kill "$pid" 2>/dev/null || true                                # SIGTERM: Zeek finishes its logs
	for _ in $(seq 100); do running "$pf" || break; sleep 0.1; done
	if running "$pf"; then
		echo "$name: still running after 10 s, sending SIGKILL"; as_root kill -9 "$pid" 2>/dev/null || true
	fi
	rm -f "$pf"; echo "$name: stopped (pid $pid)"
}

case "$cmd" in
start)
	if running "$IDS_PID" || running "$MONITOR_PID"; then
		echo "already running (deploy/headless.sh status); stop it first" >&2; exit 1
	fi
	[[ -f "$ROOT/build/spicy/tsn.hlto" ]] || { echo "build first: $ROOT/build.sh" >&2; exit 1; }
	[[ -x "$ZEEK_PREFIX/bin/zeek" ]] || { echo "no Zeek in $ZEEK_PREFIX (set ZEEK_PREFIX)" >&2; exit 1; }
	if [[ -z "$IFACE" ]]; then
		IFACE="$(ip -o link show | awk -F': ' '{print $2}' | sed 's/@.*//' | grep -v '^lo$' | head -1 || true)"
		[[ -n "$IFACE" ]] || { echo "no interface found; use -i" >&2; exit 1; }
	fi
	# `ip link` shows the interfaces of the network namespace this runs in (a Mininet host: `mon deploy/headless.sh ...`);
	# /sys/class/net would show those of the namespace sysfs was mounted in.
	ip link show dev "$IFACE" >/dev/null 2>&1 || { echo "no such interface: $IFACE (ip -br link)" >&2; exit 1; }
	mkdir -p "$LOGS" "$RUN" "$DIR/control"
	[[ -n "$OWNER" ]] && chown -R "$OWNER": "$DIR"

	ids_args=(--service --alert-log "$LOGS/alerts.log" --control-dir "$DIR/control")
	[[ -n "$CONFIG" ]] && ids_args+=(--config "$CONFIG")
	# Only the python command goes to the background (`&` after `&&` would background the whole list, and $! would be a subshell).
	(cd "$ROOT"; PYTHONPATH="$ZEEK_PREFIX/lib/zeek/python" setsid nohup python3 -m ids "${ids_args[@]}" \
		>"$LOGS/ids.out" 2>&1 & echo $! >"$IDS_PID")

	# Zeek writes its logs into the working directory (logs/). The wrapper records the pid of Zeek itself (exec keeps it).
	zeek_cmd=(env ZEEK_SPICY_MODULE_PATH="$ROOT/build/spicy" sh -c 'echo $$ >"$0"; exec "$@"' "$MONITOR_PID"
		"$ZEEK_PREFIX/bin/zeek" -C -i "$IFACE" "$ROOT/spicy/scripts" LogAscii::use_json=T TSN::log_flush_interval=1sec)
	if [[ $EUID -ne 0 ]] && getcap "$ZEEK_PREFIX/bin/zeek" 2>/dev/null | grep -q cap_net_raw; then
		(cd "$LOGS" && setsid nohup "${zeek_cmd[@]}" >monitor.out 2>&1 &)
	else
		(cd "$LOGS" && as_root setsid nohup "${zeek_cmd[@]}" >monitor.out 2>&1 &)
	fi
	for _ in $(seq 50); do running "$MONITOR_PID" && break; sleep 0.1; done
	sleep 1
	if running "$MONITOR_PID" && running "$IDS_PID"; then
		echo "started: interface $IFACE, everything in $DIR (logs in $LOGS)"
		echo "  tail -f $LOGS/alerts.log     stop: deploy/headless.sh stop -d $DIR"
	else
		echo "start failed; see $LOGS/monitor.out and $LOGS/ids.out" >&2
		stop_one IDS "$IDS_PID" >/dev/null; stop_one Monitor "$MONITOR_PID" >/dev/null; exit 1
	fi
	;;
stop)
	stop_one IDS "$IDS_PID"
	stop_one Monitor "$MONITOR_PID"
	;;
status)
	for n in IDS Monitor; do
		pf="$RUN/$(echo "$n" | tr A-Z a-z).pid"
		if running "$pf"; then echo "$n: running (pid $(cat "$pf"))"; else echo "$n: not running"; fi
	done
	[[ -f "$LOGS/ids.out" ]] && tail -n 3 "$LOGS/ids.out" | sed 's/^/  ids.out: /'
	;;
*)
	sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac
