#!/bin/sh
# Install the MoorAI agent from the Linux tarball, for distributions without dpkg (or to a staging root).
#
#   sudo sh install.sh                     # into /
#   MOORAI_ROOT=/tmp/stage sh install.sh   # into a staging root (no root needed)
#
# Copies the same tree the .deb carries (/usr/lib/moorai, /usr/bin/moorai-*, /usr/lib/systemd/user) and
# creates /etc/moorai. Like the .deb it enables nothing; it prints the same next steps.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=${MOORAI_ROOT:-}
if [ -z "$ROOT" ]; then
  [ "$(id -u)" = 0 ] || { echo "moorai install: run this as root, or set MOORAI_ROOT to a staging directory" >&2; exit 1; }
  ROOT=/
fi
ROOT=${ROOT%/}
mkdir -p "$ROOT/usr/lib" "$ROOT/usr/bin" "$ROOT/usr/lib/systemd/user" "$ROOT/etc/moorai"
rm -rf "$ROOT/usr/lib/moorai.new"
cp -RP "$HERE/root/usr/lib/moorai" "$ROOT/usr/lib/moorai.new"
rm -rf "$ROOT/usr/lib/moorai"
mv "$ROOT/usr/lib/moorai.new" "$ROOT/usr/lib/moorai"
for f in "$HERE"/root/usr/bin/*; do
  rm -f "$ROOT/usr/bin/$(basename "$f")"
  cp -P "$f" "$ROOT/usr/bin/"
done
cp "$HERE"/root/usr/lib/systemd/user/*.service "$ROOT/usr/lib/systemd/user/"
chmod 0755 "$ROOT/etc/moorai"
if [ "$ROOT" = "" ] && ! sh /usr/lib/moorai/linux/moorai-node --check; then
  echo "MoorAI: installed, but the hooks need Node.js 18 or newer." >&2
fi
echo "MoorAI installed in ${ROOT:-}/usr/lib/moorai. Register the hooks per user with: moorai-install-hooks"
