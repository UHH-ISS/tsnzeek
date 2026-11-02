#!/usr/bin/env bash
# Run Zeek over every tests/pcaps/*.pcap and compare the resulting logs with tests/expected/.
#
#   tests/run.sh            compare
#   tests/run.sh --update   overwrite the expected logs (review the diff before committing)
#   tests/run.sh frer ...   only run the named cases
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ZEEK_PREFIX="${ZEEK_PREFIX:-/opt/zeek}"
LOGS="cb ptp srp tsn_errors weird notice"

update=0
if [[ "${1:-}" == "--update" ]]; then update=1; shift; fi

"$ROOT/build.sh" --no-test >/dev/null

cases=("$@")
if [[ ${#cases[@]} -eq 0 ]]; then
	for f in "$ROOT"/tests/pcaps/*.pcap; do cases+=("$(basename "$f" .pcap)"); done
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
fail=0

for c in "${cases[@]}"; do
	out="$work/$c"
	case_fail=0
	mkdir -p "$out"
	(cd "$out" && ZEEK_SPICY_MODULE_PATH="$ROOT/build/spicy" "$ZEEK_PREFIX/bin/zeek" -C -D \
		-r "$ROOT/tests/pcaps/$c.pcap" "$ROOT/spicy/scripts" \
		TSN::enable_broker=F LogAscii::use_json=T >stdout.txt 2>stderr.txt) || true
	# Anything Zeek printed to stdout/stderr is a failure signal in itself (script errors, stray prints).
	for std in stdout stderr; do
		if [[ -s "$out/$std.txt" ]]; then
			echo "FAIL $c: unexpected $std output"; head -5 "$out/$std.txt"; case_fail=1
		fi
	done
	exp="$ROOT/tests/expected/$c"
	if [[ $update -eq 1 ]]; then mkdir -p "$exp"; rm -f "$exp"/*.log; fi
	for l in $LOGS; do
		[[ -f "$out/$l.log" ]] || continue
		if [[ $update -eq 1 ]]; then
			cp "$out/$l.log" "$exp/$l.log"
		elif ! diff -u "$exp/$l.log" "$out/$l.log" >"$work/diff.txt" 2>&1; then
			echo "FAIL $c: $l.log differs"; head -20 "$work/diff.txt"; case_fail=1
		fi
	done
	if [[ $update -eq 0 && -d "$exp" ]]; then
		for f in "$exp"/*.log; do
			[[ -f "$out/$(basename "$f")" ]] || { echo "FAIL $c: missing $(basename "$f")"; case_fail=1; }
		done
	fi
	if [[ $case_fail -eq 0 ]]; then echo "ok   $c"; else fail=1; fi
done
exit $fail
