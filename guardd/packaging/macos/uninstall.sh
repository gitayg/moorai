#!/bin/sh
# Stop and remove the moorai-guardd LaunchDaemon and binary. Keeps /etc/moorai (the administrator's
# inputs) and /Library/Application Support/MoorAI/state (the device key and undelivered alerts).
set -eu

LABEL=run.glick.moorai.guardd
die() { printf 'moorai-guardd uninstall: %s\n' "$1" >&2; exit 1; }
[ "$(id -u)" = 0 ] || die "run this as root (sudo sh uninstall.sh)"
launchctl bootout "system/$LABEL" 2>/dev/null || true
rm -f "/Library/LaunchDaemons/$LABEL.plist" /Library/PrivilegedHelperTools/moorai-guardd
pkgutil --forget "$LABEL" >/dev/null 2>&1 || true
printf 'moorai-guardd uninstall: removed; /etc/moorai and the state directory were kept\n'
