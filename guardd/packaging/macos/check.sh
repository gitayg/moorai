#!/bin/sh
# Check an installed moorai-guardd on macOS without changing anything (contract §3.1, §4.1-§4.3):
#
#   sh install.sh --check          # as yourself: everything a user can see, and that the key is out of reach
#   sudo sh install.sh --check     # as root: also the device key's own owner and mode, and the registration
#
# Every line is "ok <item>" or "FAIL <item>: <why>"; the exit status is 1 when any line failed. Nothing here
# prints a secret, a key, a token or the console's answer.
#
# MOORAI_GUARDD_STAGE=<dir> checks the tree install.sh staged under <dir>, owned by the user running the
# check instead of root (the tests use it). The helper itself reads no environment (§10.2).
set -u

STAGE=${MOORAI_GUARDD_STAGE:-}
if [ -n "$STAGE" ]; then ROOT=${STAGE%/}; OWNER=$(id -u); else ROOT=""; OWNER=0; fi
ME=$(id -u)
FAILED=0
ok() { printf 'ok %s\n' "$1"; }
fail() { printf 'FAIL %s: %s\n' "$1" "$2"; FAILED=1; }

# owner and permission bits (octal, e.g. 600), or empty when the path cannot be stat'ed.
uid_of() { stat -f '%u' "$1" 2>/dev/null; }
perm_of() { stat -f '%Lp' "$1" 2>/dev/null; }
# true when any of the bits in mask ($2, octal) are set in the permissions of $1.
has_bits() { p=$(perm_of "$1"); [ -n "$p" ] && [ $(( 0$p & 0$2 )) -ne 0 ]; }

# <label> <path> <type: f|d|s> <bits that must be clear, octal> [exact mode]
check() {
  label=$1 path=$ROOT$2 type=$3 clear=$4 exact=${5:-}
  if [ -L "$path" ]; then fail "$label" "is a symbolic link"; return; fi
  case $type in
    f) [ -f "$path" ] || { fail "$label" "missing"; return; } ;;
    d) [ -d "$path" ] || { fail "$label" "missing"; return; } ;;
    s) [ -S "$path" ] || { fail "$label" "missing or not a socket (is the helper running?)"; return; } ;;
  esac
  u=$(uid_of "$path")
  [ "$u" = "$OWNER" ] || { fail "$label" "owned by uid $u, not $OWNER"; return; }
  if has_bits "$path" "$clear"; then fail "$label" "mode $(perm_of "$path") grants more than allowed"; return; fi
  if [ -n "$exact" ] && [ "$(perm_of "$path")" != "$exact" ]; then fail "$label" "mode $(perm_of "$path"), expected $exact"; return; fi
  ok "$label"
}

check "binary /Library/PrivilegedHelperTools/moorai-guardd" /Library/PrivilegedHelperTools/moorai-guardd f 022
check "LaunchDaemon plist" /Library/LaunchDaemons/run.glick.moorai.guardd.plist f 022 644
check "admin directory /etc/moorai" /private/etc/moorai d 022
if [ -e "$ROOT/private/etc/moorai/config.json" ]; then check "machine config /etc/moorai/config.json" /private/etc/moorai/config.json f 022; else fail "machine config /etc/moorai/config.json" "missing (no console binding)"; fi
# secret.json: root only, nobody else may read it (the helper refuses anything looser).
if [ -e "$ROOT/private/etc/moorai/secret.json" ]; then check "secret /etc/moorai/secret.json root-only" /private/etc/moorai/secret.json f 077; else fail "secret /etc/moorai/secret.json" "missing (no install token)"; fi

STATE="/Library/Application Support/MoorAI/state"
check "directory /Library/Application Support/MoorAI" "/Library/Application Support/MoorAI" d 022
check "state directory root-only" "$STATE" d 077 700
# The device key: through the state directory's own mode a user can neither read it nor see its mode. As
# root (or the stage owner) the file itself is checked too.
KEY="$ROOT$STATE/device.key"
if [ "$ME" = "$OWNER" ]; then
  if [ -e "$KEY" ]; then check "device key root-only" "$STATE/device.key" f 077 600; else fail "device key" "missing (has the helper started?)"; fi
else
  if [ ! -d "$ROOT$STATE" ]; then fail "device key" "no state directory (has the helper started?)"
  elif [ -r "$KEY" ] || cat "$KEY" >/dev/null 2>&1; then fail "device key" "readable by uid $ME"
  else ok "device key not readable by uid $ME (state directory is root-only)"; fi
fi

check "run directory /private/var/run/moorai" /private/var/run/moorai d 022 755
check "hook socket root-owned, connectable by users" /private/var/run/moorai/hook.sock s 0 666
check "device.pub root-owned, world-readable" /private/var/run/moorai/device.pub f 022 644

# The registration: the console's answer, root-only. bound=true means the enrolment secret was accepted and
# console receipts can be served to this device.
REG="$ROOT$STATE/registration.json"
if [ "$ME" = "$OWNER" ]; then
  if [ -f "$REG" ]; then
    bound=$(/usr/bin/plutil -extract bound raw -o - "$REG" 2>/dev/null || echo unknown)
    status=$(/usr/bin/plutil -extract status raw -o - "$REG" 2>/dev/null || echo unknown)
    if [ "$bound" = "true" ]; then ok "registered and bound (status $status)"; else fail "registration" "status $status, bound $bound: no console receipts until it is bound (enrolment secret)"; fi
  else
    fail "registration" "none yet (see /Library/Logs/MoorAI/guardd.log)"
  fi
else
  printf 'note registration is root-only: run "sudo sh install.sh --check" to see whether the device is bound\n'
fi
exit $FAILED
