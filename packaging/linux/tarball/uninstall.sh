#!/bin/sh
# Remove what install.sh copied. Run `moorai-hook uninstall` as each user first, to take the hook entries
# out of their settings.json. /etc/moorai (the administrator's) is kept.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=${MOORAI_ROOT:-}
if [ -z "$ROOT" ]; then
  [ "$(id -u)" = 0 ] || { echo "moorai uninstall: run this as root, or set MOORAI_ROOT" >&2; exit 1; }
  ROOT=/
fi
ROOT=${ROOT%/}
for f in "$HERE"/root/usr/bin/*; do rm -f "$ROOT/usr/bin/$(basename "$f")"; done
for f in "$HERE"/root/usr/lib/systemd/user/*.service; do rm -f "$ROOT/usr/lib/systemd/user/$(basename "$f")"; done
rm -rf "$ROOT/usr/lib/moorai"
echo "MoorAI removed; /etc/moorai was kept"
