#!/bin/sh
# Build an installer package for moorai-guardd from a release binary:
#
#   sh build-pkg.sh /abs/path/to/moorai-guardd out/moorai-guardd.pkg 0.1.0
#
# The payload is exactly what install.sh stages (MOORAI_GUARDD_STAGE), so the pkg and the script lay out
# the same files. scripts/preinstall boots a running daemon out; scripts/postinstall sets ownership and
# modes and bootstraps it. The package is unsigned: signing it needs a Developer ID Installer identity
# (productsign), which this script does not have. Building runs nothing as root and installs nothing.
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
BIN=${1:-}
OUT=${2:-}
VERSION=${3:-0.1.0}
[ -n "$BIN" ] && [ -n "$OUT" ] || { echo "usage: build-pkg.sh /abs/moorai-guardd out.pkg [version]" >&2; exit 1; }
command -v pkgbuild >/dev/null 2>&1 || { echo "build-pkg.sh: pkgbuild is required (macOS)" >&2; exit 1; }

WORK=$(mktemp -d "${TMPDIR:-/tmp}/moorai-guardd-pkg.XXXXXX")
trap 'rm -rf "$WORK"' EXIT
MOORAI_GUARDD_STAGE="$WORK/root" sh "$HERE/install.sh" "$BIN" >/dev/null
# The pkg owns only the helper and its plist; /etc and the log directory are made by postinstall.
rm -rf "$WORK/root/private" "$WORK/root/Library/Logs"
pkgbuild --root "$WORK/root" --scripts "$HERE/scripts" --identifier run.glick.moorai.guardd \
  --version "$VERSION" --install-location / --ownership recommended "$OUT"
