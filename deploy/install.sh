#!/usr/bin/env bash
# (C) 2026 Doganalp Ergenc, written with the assistance of Claude
# Install TSNZeek as systemd services (optional; TSNZeek runs without any of this).
#
#   sudo deploy/install.sh              install, enable and start
#   sudo deploy/install.sh --no-start   install only
#   sudo deploy/install.sh --uninstall  stop and remove the units (config and logs stay)
#
# The services run from this checkout (it must stay where it is, built with ./build.sh).
set -euo pipefail

HOME_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ZEEK_PREFIX="${ZEEK_PREFIX:-/opt/zeek}"
UNITS=(tsnzeek-zeek.service tsnzeek-ids.service tsnzeek.target)

[[ $EUID -eq 0 ]] || { echo "run as root: sudo $0 $*" >&2; exit 1; }

if [[ "${1:-}" == "--uninstall" ]]; then
	systemctl disable --now tsnzeek.target 2>/dev/null || true
	for u in "${UNITS[@]}"; do rm -f "/etc/systemd/system/$u"; done
	rm -f /etc/logrotate.d/tsnzeek
	systemctl daemon-reload
	echo "removed; /etc/tsnzeek and /var/log/tsnzeek are kept"
	exit 0
fi

[[ -f "$HOME_DIR/build/spicy/tsn.hlto" ]] || { echo "build first: $HOME_DIR/build.sh" >&2; exit 1; }
[[ -x "$ZEEK_PREFIX/bin/zeek" ]] || { echo "no Zeek in $ZEEK_PREFIX (set ZEEK_PREFIX)" >&2; exit 1; }

id tsnzeek >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin tsnzeek
install -d -o tsnzeek -g tsnzeek -m 0750 /var/log/tsnzeek
install -d -m 0755 /etc/tsnzeek
[[ -f /etc/tsnzeek/tsnzeek.env ]] || install -m 0644 "$HOME_DIR/deploy/tsnzeek.env" /etc/tsnzeek/tsnzeek.env
install -m 0644 "$HOME_DIR/deploy/logrotate.conf" /etc/logrotate.d/tsnzeek
for u in "${UNITS[@]}"; do
	sed -e "s|@TSNZEEK_HOME@|$HOME_DIR|g" -e "s|@ZEEK_PREFIX@|$ZEEK_PREFIX|g" \
		"$HOME_DIR/deploy/systemd/$u" >"/etc/systemd/system/$u"
done
systemctl daemon-reload
systemctl enable tsnzeek.target >/dev/null

if [[ "${1:-}" == "--no-start" ]]; then
	echo "installed; set the interface in /etc/tsnzeek/tsnzeek.env, then: systemctl start tsnzeek.target"
else
	systemctl restart tsnzeek.target
	echo "started; logs in /var/log/tsnzeek, alerts: journalctl -u tsnzeek-ids -f"
fi
