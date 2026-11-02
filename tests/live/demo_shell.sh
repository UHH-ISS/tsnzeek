#!/usr/bin/env bash
# Shell for a demo window on a Mininet host: `tsn <command>` sends frames from this host's interface.
#   demo_shell.sh <interface>
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
export IFACE="$1" ROOT
export PATH="$ROOT/.venv/bin:$PATH"
tsn() { python "$ROOT/tests/live/send.py" "$@"; }
export -f tsn

printf '\033[1m%s\033[0m  (interface %s)\n\n' "$(hostname)" "$IFACE"
tsn commands
cat <<'BANNER'

Ctrl-C stops a running command; `tsn --help` lists the options. A stream that stops is reported dead
after the timeout. Start legit traffic first, then the attacks.
BANNER
echo
exec bash --norc -i
