#!/bin/sh
# Install moorai-guardd, the MoorAI privileged helper, as a systemd service (contract §4.3).
#
#   sudo sh install.sh /abs/path/to/moorai-guardd
#
# Lays out /usr/sbin/moorai-guardd (root 0755), /usr/lib/systemd/system/moorai-guardd.{service,socket}
# (root 0644) and /etc/moorai (root 0755), then enables and starts the socket and the service and
# checks that both are active. It never writes /etc/moorai/config.json or secret.json: those are the
# administrator's or MDM's (§4.1). It does tighten an existing /etc/moorai to root 0755 and an existing
# secret.json to root 0600, because the helper refuses anything looser.
#
# MOORAI_GUARDD_STAGE=<dir> lays the same files out under <dir> instead of /, chowns nothing and runs no
# systemctl (the steps it skipped are printed as "plan:" lines). The package builder and the tests use it.
# This variable steers only this installer; the helper itself reads no environment (§10.2).
#
# Exit codes: 0 installed and active; 1 bad input or a failed step; 3 files installed but systemd is
# not running here (a container), so nothing was started.
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
say() { printf 'moorai-guardd install: %s\n' "$1"; }
die() { printf 'moorai-guardd install: %s\n' "$1" >&2; exit 1; }

BIN=${1:-}
[ -n "$BIN" ] || die "usage: install.sh /abs/path/to/moorai-guardd"
case "$BIN" in /*) ;; *) die "the binary path must be absolute: $BIN" ;; esac
[ -f "$BIN" ] && [ -x "$BIN" ] || die "not an executable file: $BIN"

STAGE=${MOORAI_GUARDD_STAGE:-}
if [ -n "$STAGE" ]; then
  ROOT=${STAGE%/}
  OWN=""
else
  [ "$(id -u)" = 0 ] || die "run this as root (sudo sh install.sh ...)"
  ROOT=""
  OWN="-o root -g root"
fi

# A packaged helper must not carry the test-only path injection (contract §10.2, §11.2).
INFO=$("$BIN" --build-info 2>/dev/null || true)
case "$INFO" in
  *"test-injection=false"*) ;;
  *"test-injection=true"*) die "refusing a binary built with test-injection ($INFO)" ;;
  *) die "the binary did not answer --build-info as moorai-guardd does" ;;
esac

UNITS="$ROOT/usr/lib/systemd/system"
# shellcheck disable=SC2086
install -d -m 0755 $OWN "$ROOT/usr/sbin" "$UNITS" "$ROOT/etc/moorai"
# shellcheck disable=SC2086
install -m 0755 $OWN "$BIN" "$ROOT/usr/sbin/moorai-guardd"
for u in moorai-guardd.service moorai-guardd.socket; do
  # shellcheck disable=SC2086
  install -m 0644 $OWN "$HERE/$u" "$UNITS/$u"
done
chmod 0755 "$ROOT/etc/moorai"

plan() {
  if [ -n "$STAGE" ]; then printf 'plan: %s\n' "$*"; return 0; fi
  "$@"
}

if [ -z "$STAGE" ]; then
  chown root:root /etc/moorai
  if [ -e /etc/moorai/secret.json ]; then chown root:root /etc/moorai/secret.json; chmod 0600 /etc/moorai/secret.json; fi
  if [ -e /etc/moorai/config.json ]; then chown root:root /etc/moorai/config.json; chmod 0644 /etc/moorai/config.json; fi
  if [ ! -d /run/systemd/system ]; then
    say "files installed; systemd is not running here, so the service was not started"
    exit 3
  fi
fi

plan systemctl daemon-reload
plan systemctl enable --now moorai-guardd.socket moorai-guardd.service
# An upgrade replaces the binary under a running service; restart picks the new one up.
plan systemctl restart moorai-guardd.service

if [ -z "$STAGE" ]; then
  i=0
  while [ $i -lt 10 ]; do
    if systemctl is-active --quiet moorai-guardd.socket && systemctl is-active --quiet moorai-guardd.service; then
      say "installed: moorai-guardd.socket and moorai-guardd.service are active"
      exit 0
    fi
    i=$((i + 1))
    sleep 1
  done
  systemctl --no-pager status moorai-guardd.socket moorai-guardd.service >&2 || true
  die "the service did not become active"
fi
say "staged under $ROOT"
