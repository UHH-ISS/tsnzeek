#!/usr/bin/env bash
# Compile the Spicy grammars into build/spicy/tsn.hlto, and run the unit tests after a compilation.
#
#   ./build.sh             compile if a grammar changed, then run tests/unit
#   ./build.sh --no-test   only compile (what the test runners use, so that tests do not start tests)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ZEEK_PREFIX="${ZEEK_PREFIX:-/opt/zeek}"
SRC="$ROOT/spicy/spicy-analyzer"
OUT="$ROOT/build/spicy"

mkdir -p "$OUT"

# Skip the (slow) compilation when no grammar is newer than the output.
if [[ -f "$OUT/tsn.hlto" && -z "$(find "$SRC" -type f \( -name '*.spicy' -o -name '*.evt' \) -newer "$OUT/tsn.hlto")" ]]; then
	echo "up to date $OUT/tsn.hlto"
	exit 0
fi
"$ZEEK_PREFIX/bin/spicyz" -o "$OUT/tsn.hlto" "$SRC"/*.spicy "$SRC/TSN.evt"
echo "built $OUT/tsn.hlto"

[[ "${1:-}" == "--no-test" ]] && exit 0

# A grammar that compiles can still parse wrongly: check right away.
echo "running the unit tests"
status=0
output="$(cd "$ROOT" && python3 -m unittest discover -s tests/unit 2>&1)" || status=$?
echo "$output" | tail -n 15
if [[ $status -ne 0 ]]; then
	echo "build OK, but the unit tests FAILED (python3 -m unittest discover -s tests/unit)" >&2
	exit 1
fi
