#!/usr/bin/env bash
# Compile the Spicy grammars into build/spicy/tsn.hlto.
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
