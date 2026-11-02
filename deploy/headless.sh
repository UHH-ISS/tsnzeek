#!/usr/bin/env bash
# (C) 2026 Doganalp Ergenc, written with the assistance of Claude
# Run Zeek and the IDS in the background without a terminal window and without installing a service.
#
#   deploy/headless.sh start [-i INTERFACE] [-d LOG_DIR] [-c IDS_CONFIG.json]
#   deploy/headless.sh stop   [-d LOG_DIR]
#   deploy/headless.sh status [-d LOG_DIR]
#
# Defaults: interface $TSNZEEK_INTERFACE (else the first non-loopback one), log directory $TSNZEEK_LOG_DIR
# (else ~/tsnzeek-logs), IDS config $TSNZEEK_CONFIG (else /etc/tsnzeek/ids.json if it exists, else the defaults).
# Capturing needs root: the script uses sudo for Zeek unless you are root or Zeek has been given the capabilities
# (sudo setcap cap_net_raw,cap_net_admin=eip /opt/zeek/bin/zeek).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ZEEK_PREFIX="${ZEEK_PREFIX:-/opt/zeek}"
IFACE="${TSNZEEK_INTERFACE:-}"
LOGS="${TSNZEEK_LOG_DIR:-$HOME/tsnzeek-logs}"
CONFIG="${TSNZEEK_CONFIG:-}"

cmd="${1:-}"; [[ $# -gt 0 ]] && shift
while getopts "i:d:c:" opt; do
	case "$opt" in
		i) IFACE="$OPTARG" ;;
		d) LOGS="$OPTARG" ;;
		c) CONFIG="$OPTARG" ;;
		*) exit 2 ;;
	esac
done

IDS_PID="$LOGS/ids.pid"
ZEEK_PID="$LOGS/zeek.pid"

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
	if running "$IDS_PID" || running "$ZEEK_PID"; then
		echo "already running (deploy/headless.sh status); stop it first" >&2; exit 1
	fi
	[[ -f "$ROOT/build/spicy/tsn.hlto" ]] || { echo "build first: $ROOT/build.sh" >&2; exit 1; }
	[[ -x "$ZEEK_PREFIX/bin/zeek" ]] || { echo "no Zeek in $ZEEK_PREFIX (set ZEEK_PREFIX)" >&2; exit 1; }
	if [[ -z "$IFACE" ]]; then
		IFACE="$(ls /sys/class/net | grep -v '^lo$' | head -1 || true)"
		[[ -n "$IFACE" ]] || { echo "no interface found; use -i" >&2; exit 1; }
	fi
	[[ -d "/sys/class/net/$IFACE" ]] || { echo "no such interface: $IFACE (ip -br link)" >&2; exit 1; }
	mkdir -p "$LOGS"

	ids_args=(--service --alert-log "$LOGS/alerts.log")
	[[ -n "$CONFIG" ]] && ids_args+=(--config "$CONFIG")
	# Only the python command goes to the background (`&` after `&&` would background the whole list, and $! would be a subshell).
	(cd "$ROOT"; PYTHONPATH="$ZEEK_PREFIX/lib/zeek/python" setsid nohup python3 -m ids "${ids_args[@]}" \
		>"$LOGS/ids.out" 2>&1 & echo $! >"$IDS_PID")

	# Zeek writes its logs into the working directory. The wrapper records the pid of Zeek itself (exec keeps it).
	zeek_cmd=(env ZEEK_SPICY_MODULE_PATH="$ROOT/build/spicy" sh -c 'echo $$ >"$0"; exec "$@"' "$ZEEK_PID"
		"$ZEEK_PREFIX/bin/zeek" -C -i "$IFACE" "$ROOT/spicy/scripts" LogAscii::use_json=T TSN::log_flush_interval=1sec)
	if [[ $EUID -ne 0 ]] && getcap "$ZEEK_PREFIX/bin/zeek" 2>/dev/null | grep -q cap_net_raw; then
		(cd "$LOGS" && setsid nohup "${zeek_cmd[@]}" >zeek.out 2>&1 &)
	else
		(cd "$LOGS" && as_root setsid nohup "${zeek_cmd[@]}" >zeek.out 2>&1 &)
	fi
	for _ in $(seq 50); do running "$ZEEK_PID" && break; sleep 0.1; done
	sleep 1
	if running "$ZEEK_PID" && running "$IDS_PID"; then
		echo "started: interface $IFACE, logs and alerts in $LOGS"
		echo "  tail -f $LOGS/alerts.log     stop: deploy/headless.sh stop${LOGS:+ -d $LOGS}"
	else
		echo "start failed; see $LOGS/zeek.out and $LOGS/ids.out" >&2
		stop_one IDS "$IDS_PID" >/dev/null; stop_one Zeek "$ZEEK_PID" >/dev/null; exit 1
	fi
	;;
stop)
	stop_one IDS "$IDS_PID"
	stop_one Zeek "$ZEEK_PID"
	;;
status)
	for n in IDS Zeek; do
		pf="$LOGS/$(echo "$n" | tr A-Z a-z).pid"
		if running "$pf"; then echo "$n: running (pid $(cat "$pf"))"; else echo "$n: not running"; fi
	done
	[[ -f "$LOGS/ids.out" ]] && tail -n 3 "$LOGS/ids.out" | sed 's/^/  ids.out: /'
	;;
*)
	sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac
