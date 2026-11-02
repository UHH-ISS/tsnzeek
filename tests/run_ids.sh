#!/usr/bin/env bash
# End-to-end test of the IDS: Zeek replays tests/pcaps/ids_*.pcap and publishes over Broker, `python3 -m ids`
# analyses it, and the alerts are compared with tests/expected/<case>/alerts.txt. Every alert must also
# come back to Zeek as a Possible_Attack notice.
#
#   tests/run_ids.sh            compare
#   tests/run_ids.sh --update   overwrite the expected alerts
#   tests/run_ids.sh ids_srp    only the named cases
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ZEEK_PREFIX="${ZEEK_PREFIX:-/opt/zeek}"
export PYTHONPATH="$ZEEK_PREFIX/lib/zeek/python:$ROOT${PYTHONPATH:+:$PYTHONPATH}"

update=0
if [[ "${1:-}" == "--update" ]]; then update=1; shift; fi

"$ROOT/build.sh" --no-test >/dev/null

cases=("$@")
if [[ ${#cases[@]} -eq 0 ]]; then
	for f in "$ROOT"/tests/pcaps/ids_*.pcap; do cases+=("$(basename "$f" .pcap)"); done
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
fail=0

for c in "${cases[@]}"; do
	out="$work/$c"
	mkdir -p "$out"
	# Zeek waits for the IDS (wait_for_peer) and exits when the IDS sends ids_done; the timeout is a safety net.
	(cd "$out" && ZEEK_SPICY_MODULE_PATH="$ROOT/build/spicy" timeout 60 "$ZEEK_PREFIX/bin/zeek" -C -D \
		-r "$ROOT/tests/pcaps/$c.pcap" "$ROOT/spicy/scripts" TSN::wait_for_peer=T LogAscii::use_json=T \
		>zeek.out 2>&1) &
	zeek_pid=$!
	for _ in $(seq 100); do (exec 3<>"/dev/tcp/127.0.0.1/9999") 2>/dev/null && break; sleep 0.2; done
	python3 -m ids --offline --idle-exit 2 --config "$ROOT/tests/ids/config.json" 2>"$out/ids.err" \
		| grep -v '^Connected to Zeek$' >"$out/alerts.txt" || true
	wait "$zeek_pid" || { echo "FAIL $c: zeek exited with an error"; head -5 "$out/zeek.out"; fail=1; continue; }

	case_fail=0
	if [[ -s "$out/ids.err" ]]; then echo "FAIL $c: IDS errors"; head -5 "$out/ids.err"; case_fail=1; fi
	# Zeek reports suspend_processing/continue_processing/terminate on stderr; anything else is a problem.
	grep -v -E 'processing (suspended|continued)$|received termination signal$' "$out/zeek.out" >"$out/zeek.rest" || true
	if [[ -s "$out/zeek.rest" ]]; then echo "FAIL $c: unexpected Zeek output"; head -5 "$out/zeek.rest"; case_fail=1; fi

	alerts=$(wc -l <"$out/alerts.txt")
	notices=$(grep -c Possible_Attack "$out/notice.log" 2>/dev/null || true)
	if [[ "$alerts" != "$notices" ]]; then
		echo "FAIL $c: $alerts alerts but $notices notices reached Zeek"; case_fail=1
	fi

	exp="$ROOT/tests/expected/$c/alerts.txt"
	if [[ $update -eq 1 ]]; then
		mkdir -p "$(dirname "$exp")"; cp "$out/alerts.txt" "$exp"
	elif ! diff -u "$exp" "$out/alerts.txt" >"$work/diff.txt" 2>&1; then
		echo "FAIL $c: alerts differ"; head -20 "$work/diff.txt"; case_fail=1
	fi
	if [[ $case_fail -eq 0 ]]; then echo "ok   $c ($alerts alerts)"; else fail=1; fi
done
exit $fail
