#!/bin/sh
# Install moorai-guardd, the MoorAI privileged helper, as a LaunchDaemon (contract §4.3, §13.1 decision 1).
#
#   sudo sh install.sh /abs/path/to/moorai-guardd [--bind [--enroll-secret-file F] [--user-config P]
#                                                   [--server-url U] [--tenant T]]
#   sh install.sh --check            # unprivileged: verify an installed helper (check.sh); sudo for more
#
# --bind also writes the console binding (/etc/moorai/config.json, root-only secret.json) from the enrolled
# user's hook config (bind.sh), for a device without MDM, and after start waits for the helper's
# registration and prints whether the console bound its key (bound = console approval receipts reach
# the hook). Without --bind the binding stays MDM's.
#
# Lays out /Library/PrivilegedHelperTools/moorai-guardd (root:wheel 0755),
# /Library/LaunchDaemons/run.glick.moorai.guardd.plist (root:wheel 0644), /Library/Logs/MoorAI
# (root:admin 0750) and /etc/moorai (root:wheel 0755), then bootstraps the daemon and checks that launchd
# reports it running. It never writes /etc/moorai/config.json or secret.json (MDM's, §4.1); it tightens
# an existing secret.json to root 0600 because the helper refuses anything looser.
#
# MOORAI_GUARDD_STAGE=<dir> lays the files out under <dir>, chowns nothing and runs no launchctl (the
# skipped steps are printed as "plan:" lines). build-pkg.sh and the tests use it. The helper itself reads
# no environment (§10.2).
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
LABEL=run.glick.moorai.guardd
PLIST=/Library/LaunchDaemons/$LABEL.plist
say() { printf 'moorai-guardd install: %s\n' "$1"; }
die() { printf 'moorai-guardd install: %s\n' "$1" >&2; exit 1; }

if [ "${1:-}" = "--check" ]; then
  exec sh "$HERE/check.sh"
fi
BIN=${1:-}
[ -n "$BIN" ] || die "usage: install.sh /abs/path/to/moorai-guardd [--bind ...] | install.sh --check"
shift
BIND=0
if [ "${1:-}" = "--bind" ]; then BIND=1; shift; fi
[ $# -eq 0 ] || [ $BIND -eq 1 ] || die "unknown option: $1 (the binding options follow --bind)"
case "$BIN" in /*) ;; *) die "the binary path must be absolute: $BIN" ;; esac
[ -f "$BIN" ] && [ -x "$BIN" ] || die "not an executable file: $BIN"

STAGE=${MOORAI_GUARDD_STAGE:-}
if [ -n "$STAGE" ]; then
  ROOT=${STAGE%/}
else
  [ "$(id -u)" = 0 ] || die "run this as root (sudo sh install.sh ...)"
  ROOT=""
fi

INFO=$("$BIN" --build-info 2>/dev/null || true)
case "$INFO" in
  *"test-injection=false"*) ;;
  *"test-injection=true"*) die "refusing a binary built with test-injection ($INFO)" ;;
  *) die "the binary did not answer --build-info as moorai-guardd does" ;;
esac

# The binding first: a refused or invalid binding stops the install before anything is replaced or stopped.
if [ $BIND -eq 1 ]; then
  if [ -n "$STAGE" ]; then sh "$HERE/bind.sh" "$ROOT" "" "$@"; else sh "$HERE/bind.sh" "" root:wheel "$@"; fi
fi

# /etc is a symlink to /private/etc on macOS; create the real directory.
mkdir -p "$ROOT/Library/PrivilegedHelperTools" "$ROOT/Library/LaunchDaemons" "$ROOT/Library/Logs/MoorAI" "$ROOT/private/etc/moorai"
cp "$BIN" "$ROOT/Library/PrivilegedHelperTools/moorai-guardd.new"
chmod 0755 "$ROOT/Library/PrivilegedHelperTools/moorai-guardd.new"
mv -f "$ROOT/Library/PrivilegedHelperTools/moorai-guardd.new" "$ROOT/Library/PrivilegedHelperTools/moorai-guardd"
cp "$HERE/$LABEL.plist" "$ROOT$PLIST"
chmod 0644 "$ROOT$PLIST"
chmod 0750 "$ROOT/Library/Logs/MoorAI"
chmod 0755 "$ROOT/private/etc/moorai"

plan() {
  if [ -n "$STAGE" ]; then printf 'plan: %s\n' "$*"; return 0; fi
  "$@"
}

if [ -z "$STAGE" ]; then
  chown root:wheel /Library/PrivilegedHelperTools/moorai-guardd "$PLIST" /private/etc/moorai
  chown root:admin /Library/Logs/MoorAI
  touch /Library/Logs/MoorAI/guardd.log
  chown root:admin /Library/Logs/MoorAI/guardd.log
  chmod 0640 /Library/Logs/MoorAI/guardd.log
  if [ -e /private/etc/moorai/secret.json ]; then chown root:wheel /private/etc/moorai/secret.json; chmod 0600 /private/etc/moorai/secret.json; fi
  if [ -e /private/etc/moorai/config.json ]; then chown root:wheel /private/etc/moorai/config.json; chmod 0644 /private/etc/moorai/config.json; fi
  launchctl bootout "system/$LABEL" 2>/dev/null || true
fi

plan launchctl bootstrap system "$PLIST"
plan launchctl enable "system/$LABEL"
plan launchctl kickstart -k "system/$LABEL"

if [ -z "$STAGE" ]; then
  i=0
  while [ $i -lt 10 ]; do
    if launchctl print "system/$LABEL" 2>/dev/null | grep -q 'state = running'; then
      say "installed: $LABEL is running"
      [ $BIND -eq 1 ] || exit 0
      REG="/Library/Application Support/MoorAI/state/registration.json"
      j=0
      while [ $j -lt 30 ] && [ ! -f "$REG" ]; do j=$((j + 1)); sleep 1; done
      if [ -f "$REG" ]; then
        say "registration: status $(/usr/bin/plutil -extract status raw -o - "$REG" 2>/dev/null || echo unknown), bound $(/usr/bin/plutil -extract bound raw -o - "$REG" 2>/dev/null || echo unknown)"
      else
        say "no registration after 30 s; see /Library/Logs/MoorAI/guardd.log, then: sudo sh $HERE/install.sh --check"
      fi
      exit 0
    fi
    i=$((i + 1))
    sleep 1
  done
  launchctl print "system/$LABEL" >&2 || true
  die "$LABEL did not reach the running state (see /Library/Logs/MoorAI/guardd.log)"
fi
say "staged under $ROOT"
