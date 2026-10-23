#!/bin/sh
# Write the console binding moorai-guardd reads (contract §4.1), for an install without MDM. Called by
# `install.sh --bind`; run as root.
#
#   /etc/moorai/config.json  root:wheel 0644  {"serverUrl", "tenant", "helper":"optional"}
#   /etc/moorai/secret.json  root:wheel 0600  {"installToken", "enrollSecret"?}
#
# serverUrl, tenant and installToken come from the enrolled user's hook config (~/.moorai/config.json of
# $SUDO_USER, or --user-config), so the helper signs its policy fetch over the SAME install token the hook
# posts approval requests with: the console serves a receipt only to that token (RAISEME-server
# server/approvals.js receipt gate). --server-url / --tenant override the first two. The one-time enrolment
# secret (console: Devices > Enrolment secrets, or POST /api/devices/enroll-secrets) is read from a file
# (--enroll-secret-file), never from the command line; without it the device registers unbound and the
# console withholds receipts.
#
# An existing config.json or secret.json naming another console, tenant or token is never overwritten
# (MDM owns it); remove it first. Writing config.json makes the device MANAGED for the hook as well
# (cli/config.mjs: the machine file names the console).
#
# Arguments: <root prefix ("" for the real system)> <owner spec (root:wheel, or "" in stage mode)> then
# --user-config P --server-url U --tenant T --enroll-secret-file F (each optional).
set -eu
PREFIX=$1 OWN=$2
shift 2
say() { printf 'moorai-guardd bind: %s\n' "$1"; }
die() { printf 'moorai-guardd bind: %s\n' "$1" >&2; exit 1; }
PLUTIL=/usr/bin/plutil

USER_CONFIG="" URL="" TENANT="" ENROLL_FILE=""
while [ $# -gt 0 ]; do
  case $1 in
    --user-config) USER_CONFIG=${2:-}; shift 2 ;;
    --server-url) URL=${2:-}; shift 2 ;;
    --tenant) TENANT=${2:-}; shift 2 ;;
    --enroll-secret-file) ENROLL_FILE=${2:-}; shift 2 ;;
    *) die "unknown option: $1" ;;
  esac
done

if [ -z "$USER_CONFIG" ]; then
  U=${SUDO_USER:-}
  [ -n "$U" ] || die "no --user-config and no SUDO_USER: run it with sudo as the enrolled user, or pass --user-config"
  case $U in *[!A-Za-z0-9._-]*|"") die "unexpected SUDO_USER" ;; esac
  HOMEDIR=$(/usr/bin/dscl . -read "/Users/$U" NFSHomeDirectory 2>/dev/null | sed -n 's/^NFSHomeDirectory: //p')
  [ -n "$HOMEDIR" ] || die "cannot find the home directory of $U"
  for c in "$HOMEDIR/.moorai/config.json" "$HOMEDIR/.curaiq/config.json" "$HOMEDIR/.raiseme/config.json"; do
    if [ -f "$c" ]; then USER_CONFIG=$c; break; fi
  done
  [ -n "$USER_CONFIG" ] || die "no hook config under $HOMEDIR (enrol the hook first: moorai-hook enroll)"
fi
[ -f "$USER_CONFIG" ] && [ ! -L "$USER_CONFIG" ] || die "not a regular file: $USER_CONFIG"
get() { $PLUTIL -extract "$1" raw -o - "$USER_CONFIG" 2>/dev/null || true; }
[ -n "$URL" ] || URL=$(get serverUrl)
[ -n "$TENANT" ] || TENANT=$(get tenant)
TOKEN=$(get installToken)
URL=${URL%/}

# Values are validated to a character set that needs no JSON escaping.
case $URL in
  https://*) ;;
  http://localhost:*|http://localhost|http://127.0.0.1:*|http://127.0.0.1|http://\[::1\]:*) ;;
  *) die "serverUrl must be https:// (plain http only for localhost): $URL" ;;
esac
case $URL in *[!A-Za-z0-9.:/_~%\[\]-]*) die "serverUrl has unexpected characters" ;; esac
case $TENANT in ""|*[!A-Za-z0-9._:-]*) die "tenant missing or has unexpected characters" ;; esac
[ ${#TENANT} -le 128 ] || die "tenant too long"
case $TOKEN in ""|*[!A-Za-z0-9._~+/=-]*) die "no usable installToken in $USER_CONFIG" ;; esac
ENROLL=""
if [ -n "$ENROLL_FILE" ]; then
  [ -f "$ENROLL_FILE" ] || die "not a file: $ENROLL_FILE"
  ENROLL=$(tr -d ' \t\r\n' < "$ENROLL_FILE")
  printf '%s' "$ENROLL" | grep -Eq '^mes_[0-9a-f]{32}$' || die "the enrolment secret file must hold one mes_ + 32 hex secret"
fi

ETC=$PREFIX/private/etc/moorai
mkdir -p "$ETC"
CFG=$ETC/config.json
SEC=$ETC/secret.json
if [ -e "$CFG" ]; then
  have_url=$($PLUTIL -extract serverUrl raw -o - "$CFG" 2>/dev/null || true)
  have_tenant=$($PLUTIL -extract tenant raw -o - "$CFG" 2>/dev/null || true)
  [ "${have_url%/}" = "$URL" ] && [ "$have_tenant" = "$TENANT" ] || die "$CFG already names another console or tenant (MDM-managed?); remove it first"
  say "config.json already binds $URL tenant $TENANT; kept"
else
  printf '{"serverUrl":"%s","tenant":"%s","helper":"optional"}\n' "$URL" "$TENANT" > "$CFG.new"
  chmod 0644 "$CFG.new"
  [ -z "$OWN" ] || chown "$OWN" "$CFG.new"
  mv -f "$CFG.new" "$CFG"
  say "wrote $CFG (serverUrl $URL, tenant $TENANT)"
fi
if [ -e "$SEC" ]; then
  have_token=$($PLUTIL -extract installToken raw -o - "$SEC" 2>/dev/null || true)
  [ "$have_token" = "$TOKEN" ] || die "$SEC already holds another install token; remove it first"
  if [ -n "$ENROLL" ]; then
    ( umask 077; printf '{"enrollSecret":"%s","installToken":"%s"}\n' "$ENROLL" "$TOKEN" > "$SEC.new" )
  fi
else
  ( umask 077
    if [ -n "$ENROLL" ]; then printf '{"enrollSecret":"%s","installToken":"%s"}\n' "$ENROLL" "$TOKEN" > "$SEC.new"
    else printf '{"installToken":"%s"}\n' "$TOKEN" > "$SEC.new"; fi )
fi
if [ -e "$SEC.new" ]; then
  chmod 0600 "$SEC.new"
  [ -z "$OWN" ] || chown "$OWN" "$SEC.new"
  mv -f "$SEC.new" "$SEC"
  say "wrote $SEC (root-only)"
fi
[ -n "$ENROLL" ] || say "no enrolment secret given: the helper registers UNBOUND and the console withholds approval receipts"
