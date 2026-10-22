#!/bin/sh
# Stop and remove moorai-guardd (the systemd service, the socket and the binary). Keeps /etc/moorai
# (the administrator's inputs) and /var/lib/moorai (the device key and any undelivered alerts); remove
# those by hand when the device is retired. MOORAI_GUARDD_STAGE=<dir> works as in install.sh.
set -eu

say() { printf 'moorai-guardd uninstall: %s\n' "$1"; }
die() { printf 'moorai-guardd uninstall: %s\n' "$1" >&2; exit 1; }

STAGE=${MOORAI_GUARDD_STAGE:-}
if [ -n "$STAGE" ]; then
  ROOT=${STAGE%/}
else
  [ "$(id -u)" = 0 ] || die "run this as root (sudo sh uninstall.sh)"
  ROOT=""
fi

plan() {
  if [ -n "$STAGE" ]; then printf 'plan: %s\n' "$*"; return 0; fi
  "$@" || true
}

if [ -n "$STAGE" ] || [ -d /run/systemd/system ]; then
  plan systemctl disable --now moorai-guardd.service moorai-guardd.socket
fi
for d in "$ROOT/usr/lib/systemd/system" "$ROOT/lib/systemd/system"; do
  rm -f "$d/moorai-guardd.service" "$d/moorai-guardd.socket"
done
rm -f "$ROOT/usr/sbin/moorai-guardd"
if [ -n "$STAGE" ] || [ -d /run/systemd/system ]; then
  plan systemctl daemon-reload
fi
say "removed; /etc/moorai and /var/lib/moorai were kept"
