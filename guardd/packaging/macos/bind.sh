#!/bin/sh
# Write the console binding moorai-guardd reads (contract §4.1), for an install without MDM. Called by
# `install.sh --bind`; run as root.
#
#   /etc/moorai/config.json  root:wheel 0644  {"serverUrl", "tenant", "helper":"optional"}
#   /etc/moorai/secret.json  root:wheel 0600  {"installToken", "enrollSecret"?}
#
# The console and tenant come ONLY from the command line (--server-url, --tenant), never from a user
# file: the user's hook config is writable by the governed agent, and a tampered value would bind this
# root helper, and send the enrolment secret, to another console. The install token is read from the
# enrolled user's hook config (~/.moorai/config.json of $SUDO_USER, or --user-config), because it must be
# the SAME token the hook posts approval requests with: the console serves a receipt only to that token
# (RAISEME-server server/approvals.js receipt gate). That file is accepted only if it and every directory
# above it are owned by that user or root and not writable by group or others (a symbolic link only when
# root owns it, and never the file itself), and it is read AS THAT USER (sudo -u), so a link swapped in
# meanwhile can reach nothing the user could not read anyway. The token is shape-checked.
#
# The binding is printed (console, tenant, the token's SHA-256 fingerprint, never the token) and written
# only after an interactive yes, or with --yes for scripted installs. The one-time enrolment secret
# (console: Devices > Enrolment secrets, or POST /api/devices/enroll-secrets) is read from a file
# (--enroll-secret-file), never from the command line; without it the device registers unbound and the
# console withholds receipts.
#
# An existing config.json or secret.json naming another console, tenant or token is never overwritten
# (MDM owns it); remove it first. Writing config.json makes the device MANAGED for the hook as well
# (cli/config.mjs: the machine file names the console).
#
# Arguments: <root prefix ("" for the real system)> <owner spec (root:wheel, or "" in stage mode)> then
# --server-url U --tenant T (required), --enroll-secret-file F, --user-config P, --yes.
set -eu
PREFIX=$1 OWN=$2
shift 2
say() { printf 'moorai-guardd bind: %s\n' "$1"; }
die() { printf 'moorai-guardd bind: %s\n' "$1" >&2; exit 1; }
PLUTIL=/usr/bin/plutil

USER_CONFIG="" URL="" TENANT="" ENROLL_FILE="" YES=0
while [ $# -gt 0 ]; do
  case $1 in
    --user-config) USER_CONFIG=${2:-}; shift 2 ;;
    --server-url) URL=${2:-}; shift 2 ;;
    --tenant) TENANT=${2:-}; shift 2 ;;
    --enroll-secret-file) ENROLL_FILE=${2:-}; shift 2 ;;
    --yes) YES=1; shift ;;
    *) die "unknown option: $1" ;;
  esac
done
[ -n "$URL" ] && [ -n "$TENANT" ] || die "--server-url and --tenant are required (the console's URL and tenant id, from the console, never from a user file)"
URL=${URL%/}
case $URL in
  https://*) ;;
  http://localhost:*|http://localhost|http://127.0.0.1:*|http://127.0.0.1|http://\[::1\]:*) ;;
  *) die "--server-url must be https:// (plain http only for localhost): $URL" ;;
esac
case $URL in *[!A-Za-z0-9.:/_~%\[\]-]*) die "--server-url has unexpected characters" ;; esac
case ${URL#*://} in ""|/*|*@*) die "--server-url has no host" ;; esac
case $TENANT in ""|*[!A-Za-z0-9._:-]*) die "--tenant must be 1-128 of A-Z a-z 0-9 . _ : -" ;; esac
[ ${#TENANT} -le 128 ] || die "--tenant too long"

# Whose hook config, and which uid may own it.
U=${SUDO_USER:-}
if [ -n "$U" ]; then
  case $U in *[!A-Za-z0-9._-]*) die "unexpected SUDO_USER" ;; esac
  TRUST_UID=$(id -u "$U") || die "unknown SUDO_USER"
else
  TRUST_UID=$(id -u)
fi
if [ -z "$USER_CONFIG" ]; then
  [ -n "$U" ] || die "no --user-config and no SUDO_USER: run it with sudo as the enrolled user, or pass --user-config"
  HOMEDIR=$(/usr/bin/dscl . -read "/Users/$U" NFSHomeDirectory 2>/dev/null | sed -n 's/^NFSHomeDirectory: //p')
  [ -n "$HOMEDIR" ] || die "cannot find the home directory of $U"
  for c in "$HOMEDIR/.moorai/config.json" "$HOMEDIR/.curaiq/config.json" "$HOMEDIR/.raiseme/config.json"; do
    if [ -e "$c" ] || [ -L "$c" ]; then USER_CONFIG=$c; break; fi
  done
  [ -n "$USER_CONFIG" ] || die "no hook config under $HOMEDIR (enrol the hook first: moorai-hook enroll)"
fi
case $USER_CONFIG in /*) ;; *) die "--user-config must be an absolute path" ;; esac

# The ownership walk, from / down to the file (lstat: a component's own owner and mode).
trusted() { # <path> <is-file 0|1>
  u=$(stat -f '%u' "$1" 2>/dev/null) || die "cannot stat $1"
  p=$(stat -f '%Lp' "$1")
  if [ -L "$1" ]; then
    [ "$2" = 0 ] && [ "$u" = 0 ] || die "$1 is a symbolic link (only a root-owned directory link is accepted)"
    return 0
  fi
  [ "$u" = 0 ] || [ "$u" = "$TRUST_UID" ] || die "$1 is owned by uid $u, not root or uid $TRUST_UID"
  [ $(( 0$p & 022 )) -eq 0 ] || die "$1 is writable by group or others (mode $p)"
}
walk=""
rest=${USER_CONFIG#/}
trusted / 0
while [ -n "$rest" ]; do
  part=${rest%%/*}
  case $rest in */*) rest=${rest#*/} ;; *) rest="" ;; esac
  [ -n "$part" ] || continue
  walk="$walk/$part"
  if [ -n "$rest" ]; then trusted "$walk" 0; else trusted "$walk" 1; fi
done
[ -f "$USER_CONFIG" ] || die "not a regular file: $USER_CONFIG"

# Read it as the user who owns it (never with root's reach), into a root-only temporary copy.
TMPD=$(mktemp -d "${TMPDIR:-/tmp}/moorai-bind.XXXXXX")
trap 'rm -rf "$TMPD"' EXIT
chmod 0700 "$TMPD"
if [ "$(id -u)" = 0 ] && [ -n "$U" ]; then
  /usr/bin/sudo -n -u "$U" /bin/cat -- "$USER_CONFIG" > "$TMPD/user.json" || die "cannot read $USER_CONFIG as $U"
else
  /bin/cat -- "$USER_CONFIG" > "$TMPD/user.json" || die "cannot read $USER_CONFIG"
fi
TOKEN=$($PLUTIL -extract installToken raw -o - "$TMPD/user.json" 2>/dev/null || true)
case $TOKEN in ""|*[!A-Za-z0-9._~+/=-]*) die "no usable installToken in $USER_CONFIG" ;; esac
[ ${#TOKEN} -ge 8 ] && [ ${#TOKEN} -le 512 ] || die "the installToken in $USER_CONFIG has an unexpected length"
ENROLL=""
if [ -n "$ENROLL_FILE" ]; then
  [ -f "$ENROLL_FILE" ] || die "not a file: $ENROLL_FILE"
  ENROLL=$(tr -d ' \t\r\n' < "$ENROLL_FILE")
  printf '%s' "$ENROLL" | grep -Eq '^mes_[0-9a-f]{32}$' || die "the enrolment secret file must hold one mes_ + 32 hex secret"
fi

FP=$(printf '%s' "$TOKEN" | /usr/bin/shasum -a 256 | cut -c1-12)
say "console $URL, tenant $TENANT, install token sha256:$FP${ENROLL:+, with a one-time enrolment secret}"
if [ $YES -eq 0 ]; then
  # MOORAI_BIND_TEST_TTY lets a stage-mode test answer the prompt through a pipe; it is ignored for the
  # real system paths.
  if [ -t 0 ] || { [ -n "$PREFIX" ] && [ -n "${MOORAI_BIND_TEST_TTY:-}" ]; }; then
    printf 'Write this binding to /etc/moorai? [y/N] '
    read -r ans || ans=""
    case $ans in y|Y|yes|YES) ;; *) die "not confirmed; nothing written" ;; esac
  else
    die "not interactive: check the console URL and tenant above, then confirm with --yes; nothing written"
  fi
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
