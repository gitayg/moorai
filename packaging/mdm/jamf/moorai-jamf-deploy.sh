#!/bin/bash
# =============================================================================
# MoorAI — Jamf deploy / enroll script (macOS)
#
# Installs the MoorAI agent, registers the on-device Claude Code PreToolUse hooks,
# and writes the per-user enrollment config non-interactively — so a managed Mac
# is governed the moment it checks in, with no user pasting an install token.
#
# WHAT IT DOES (all steps idempotent — safe to re-run on every Jamf check-in):
#   1. Installs the MoorAI CLI agent into MOORAI_HOME (default /usr/local/moorai),
#      either from a Jamf-distributed .pkg/.dmg or via the git installer.
#   2. Writes the MACHINE config /etc/moorai/config.json {serverUrl, tenant} (root:wheel
#      0644). cli/config.mjs reads it first, on every laptop: it is the admin binding, so a
#      user's ~/.moorai/config.json can no longer move the device to another console or
#      tenant, or drop it to coach mode by deleting the token. It never carries the install
#      token: 0644 is readable by every local account, so the token stays where it always
#      was, in the enrolled user's own ~/.moorai/config.json (0600), step 3.
#   3. Writes ~/.moorai/config.json {serverUrl, tenant, installToken} for the logged-in user
#      (0600, owned by that user). On a managed device only its installToken is used.
#      Honest limit: the agent runs as that user and can read the token; keeping it secret
#      needs the privileged helper (trust-anchor design phase 2).
#   4. Runs `<node> <MOORAI_HOME>/cli/moorai-hook.mjs install` as that user, which
#      registers MoorAI's hook entries in ~/.claude/settings.json with node named by
#      absolute path.
#
# CONTENT-FREE: this script only configures the device→console binding. No prompt,
# file, or agent output is collected here; policy still comes from the console
# per-tenant at runtime (<serverUrl>/api/policy?tenant=<tenant>).
#
# JAMF SCRIPT PARAMETERS (Jamf passes $1-$3 automatically; admin values start at $4):
#   $4  SERVER_URL     MoorAI console base URL   (e.g. https://console.moorai.example.com)
#   $5  TENANT         tenant slug               (e.g. acme-corp)
#   $6  INSTALL_TOKEN  per-tenant enroll token   (e.g. it_live_xxxxxxxx)
#   $7  MOORAI_HOME    install dir               (optional; default /usr/local/moorai)
#   $8  PKG_URL        URL of a prebuilt agent tarball/pkg (optional; see INSTALL below)
#
# If $4/$5/$6 are empty, the script falls back to the managed-preferences domain
# `run.glick.moorai` delivered by MoorAI-config.mobileconfig (pre-rebrand profiles
# under `run.glick.curaiq` are still honored as a fallback; recommended: set the
# values once in the profile and leave the script params blank).
# =============================================================================
set -u

# ------------------------------------------------------------------ parameters
SERVER_URL="${4:-}"
TENANT="${5:-}"
INSTALL_TOKEN="${6:-}"
MOORAI_HOME="${7:-/usr/local/moorai}"
PKG_URL="${8:-}"

PROFILE_DOMAIN="run.glick.moorai"          # managed-preferences domain (= app bundle id) from the .mobileconfig
PROFILE_DOMAIN_LEGACY="run.glick.curaiq"   # pre-rebrand bundle id; still honored for un-repushed profiles

log() { /usr/bin/logger -t "MoorAI-deploy" "$1"; echo "MoorAI-deploy: $1"; }
die() { log "ERROR: $1"; exit 1; }

# ---------------------------------------------------- fall back to managed prefs
# When a script param is blank, read the value the configuration profile forced
# into the run.glick.moorai domain. `defaults read <domain> <key>` resolves the
# managed (Forced) value at the system level. Bridge: fleets still shipping the
# pre-rebrand MoorAI-config.mobileconfig push to run.glick.curaiq, so fall back to
# that domain until every profile is re-pushed to the new one.
prof() {
  local v
  v="$(/usr/bin/defaults read "$PROFILE_DOMAIN" "$1" 2>/dev/null)"
  [ -n "$v" ] || v="$(/usr/bin/defaults read "$PROFILE_DOMAIN_LEGACY" "$1" 2>/dev/null)"
  printf '%s' "$v"
}
[ -z "$SERVER_URL" ]    && SERVER_URL="$(prof ServerURL)"
[ -z "$TENANT" ]        && TENANT="$(prof Tenant)"
[ -z "$INSTALL_TOKEN" ] && INSTALL_TOKEN="$(prof InstallToken)"

[ -n "$SERVER_URL" ] || die "SERVER_URL not set (Jamf param \$4 or profile ServerURL)."
[ -n "$TENANT" ]     || die "TENANT not set (Jamf param \$5 or profile Tenant)."
# INSTALL_TOKEN may legitimately be empty for open/unauthenticated consoles.

# --------------------------------------------------- resolve the logged-in user
# Config + hooks are per-user (live under the user's $HOME). Target the console user.
CONSOLE_USER="$(/usr/bin/stat -f%Su /dev/console)"
if [ -z "$CONSOLE_USER" ] || [ "$CONSOLE_USER" = "root" ]; then
  # No user is logged in at the loginwindow. Install the agent system-wide now and
  # let the LaunchAgent / next check-in complete the per-user enroll. For a pure
  # zero-touch flow, scope this policy to run at login, or loop over the users in
  # /Users (see "ALL USERS" note at the bottom of this file).
  log "no console user; installing agent only, per-user enroll deferred."
  DEFER_USER=1
else
  DEFER_USER=0
fi
USER_HOME="$(/usr/bin/dscl . -read "/Users/${CONSOLE_USER}" NFSHomeDirectory 2>/dev/null | awk '{print $2}')"
[ -n "$USER_HOME" ] || USER_HOME="/Users/${CONSOLE_USER}"

# -------------------------------------------------------------- install the app
# INSTALL CHANNEL — choose ONE for your fleet and delete the others:
#
#   (A) Jamf-distributed package  [RECOMMENDED for managed Macs]
#       Build/sign a .pkg or .dmg from the repo (see ../README.md "Signing &
#       notarization"), upload it to Jamf, and deploy it with a *separate* Jamf
#       policy that runs BEFORE this script (policy ordering: package first,
#       script after). In that case leave PKG_URL blank — the agent is already on
#       disk and this script only enrolls + registers hooks.
#
#   (B) Prebuilt tarball fetched from your console/CDN
#       Set $8 PKG_URL to a tarball of the repo (cli/ src/ data/ scripts/ + node_modules).
#
#   (C) Git installer (needs git + node on the Mac; mirrors scripts/install.sh)
#       Used automatically if PKG_URL is blank and MOORAI_HOME has no agent yet.

install_agent() {
  if [ -f "${MOORAI_HOME}/cli/moorai-hook.mjs" ]; then
    log "agent already present at ${MOORAI_HOME}"
    return 0
  fi
  /bin/mkdir -p "$MOORAI_HOME" || die "cannot create ${MOORAI_HOME}"

  if [ -n "$PKG_URL" ]; then
    log "downloading agent tarball from ${PKG_URL}"
    tmp="$(/usr/bin/mktemp -d)"
    /usr/bin/curl -fsSL "$PKG_URL" -o "${tmp}/moorai.tgz" || die "download failed."
    /usr/bin/tar -xzf "${tmp}/moorai.tgz" -C "$MOORAI_HOME" --strip-components=1 || die "extract failed."
    /bin/rm -rf "$tmp"
  else
    command -v git  >/dev/null 2>&1 || die "git required for channel (C); use PKG_URL for an offline fleet."
    command -v node >/dev/null 2>&1 || die "Node.js 18+ required on the Mac."
    log "cloning agent via git installer"
    /usr/bin/git clone --depth 1 "https://github.com/gitayg/moorai.git" "$MOORAI_HOME" \
      || die "git clone failed."
    ( cd "$MOORAI_HOME" && npm ci --omit=dev >/dev/null 2>&1 || npm install --omit=dev >/dev/null 2>&1 ) \
      || die "dependency install failed."
  fi
  /bin/chmod -R a+rX "$MOORAI_HOME"
  log "agent installed at ${MOORAI_HOME}"
}

# ------------------------------------------------- machine-wide trust anchor (/etc/moorai)
# cli/moorai-hook.mjs reads policy.pub, breakglass.pub, offline-posture and policy-lkg.json from
# /etc/moorai as the machine-wide TRUST ANCHOR. readRootOwned() accepts a file there only when
# stat says uid 0 AND the mode has no group/write or other/write bit (mode & 0o022 == 0) — so a
# wrongly-owned or group-writable anchor is silently ignored, and an anchor an ordinary user could
# rewrite would be worth no more than one under ~/.moorai.
#
# UNLIKE WINDOWS, macOS has no forgery precondition to remove here: /etc (-> /private/etc) is
# root:wheel 0755, so an ordinary user cannot create /etc/moorai in the first place. The Windows
# equivalent of this step is load-bearing because C:\ProgramData grants BUILTIN\Users create-file
# rights that every child inherits; this one is normalization — it gives the anchors a correct
# home and REPAIRS a directory an admin deployed with the wrong owner or mode.
#
# Matches what moorai-hook.mjs documents: `install -d -m 0755 -o root /etc/moorai`, anchor files
# 0644 root-owned. 0755/0644 keeps them world-READABLE, which is required: the hook runs as the
# user and has to read them.
ANCHOR_DIR="/etc/moorai"
harden_anchor_dir() {
  if [ "$(/usr/bin/id -u)" -ne 0 ]; then
    log "WARNING: not running as root; leaving ${ANCHOR_DIR} untouched (Jamf policies run as root)."
    return 0
  fi
  /usr/bin/install -d -m 0755 -o root -g wheel "$ANCHOR_DIR" || die "cannot create/harden ${ANCHOR_DIR}"
  # Repair an existing directory deployed with the wrong owner or a too-permissive mode.
  /usr/sbin/chown root:wheel "$ANCHOR_DIR" || die "cannot chown ${ANCHOR_DIR}"
  /bin/chmod 0755 "$ANCHOR_DIR"            || die "cannot chmod ${ANCHOR_DIR}"
  for anchor in policy.pub breakglass.pub offline-posture policy-lkg.json; do
    [ -f "${ANCHOR_DIR}/${anchor}" ] || continue
    /usr/sbin/chown root:wheel "${ANCHOR_DIR}/${anchor}" || die "cannot chown ${ANCHOR_DIR}/${anchor}"
    /bin/chmod 0644 "${ANCHOR_DIR}/${anchor}"            || die "cannot chmod ${ANCHOR_DIR}/${anchor}"
    log "anchor normalized: ${ANCHOR_DIR}/${anchor} (root:wheel 0644)"
  done
  # Fail loudly rather than leave a group/world-writable anchor directory in place: the hook trusts
  # what it finds here, so a writable one is worse than none.
  mode="$(/usr/bin/stat -f%Lp "$ANCHOR_DIR")"
  owner="$(/usr/bin/stat -f%u "$ANCHOR_DIR")"
  [ "$owner" = "0" ] || die "${ANCHOR_DIR} is owned by uid ${owner}, not root."
  # `8#` forces base-8 explicitly: bash reads a bare leading zero as octal but other shells do not,
  # and stat -f%Lp prints no leading zero anyway (e.g. "755"). 8#22 is the g+w / o+w mask that
  # readRootOwned() tests as `st.mode & 0o022`.
  if [ "$(( 8#$mode & 8#22 ))" -ne 0 ]; then
    die "${ANCHOR_DIR} is group- or world-writable (mode ${mode}); the hook would reject every anchor in it."
  fi
  log "trust-anchor directory hardened: ${ANCHOR_DIR} (root:wheel ${mode})"
}

# ------------------------------------------------------- write the machine config
# /etc/moorai/config.json, root:wheel 0644: the admin binding cli/config.mjs reads before any user file
# (and src-tauri admin_config.rs reads for the desktop app). serverUrl and tenant are set, an installToken
# key is REMOVED (the file is world-readable; the token belongs in the user's 0600 file), and every other key an administrator put there ("updates", "mode", egress rules, ...) is kept: plutil edits
# a copy in place (JSON in, JSON out), and the copy is renamed over the original, so a reader never sees a
# half-written file and root never writes through a link planted at that path (the directory is root's).
json_set() { # file key value
  /usr/bin/plutil -replace "$2" -string "$3" "$1" 2>/dev/null \
    || /usr/bin/plutil -insert "$2" -string "$3" "$1" 2>/dev/null
}
write_machine_config() {
  cfg_file="${ANCHOR_DIR}/config.json"
  if [ "$(/usr/bin/id -u)" -ne 0 ]; then return 1; fi
  tmp="$(/usr/bin/mktemp "${ANCHOR_DIR}/.config.json.XXXXXX")" || die "cannot create a temp file in ${ANCHOR_DIR}"
  if [ -f "$cfg_file" ] && [ ! -L "$cfg_file" ] && /usr/bin/plutil -convert json -o "$tmp" "$cfg_file" 2>/dev/null; then :; else printf '{}' > "$tmp"; fi
  # A bare {} is also a valid OpenStep plist, which plutil will not write back; seed a JSON-only form.
  [ "$(/bin/cat "$tmp")" = "{}" ] && printf '{"serverUrl":""}' > "$tmp"
  json_set "$tmp" serverUrl "$SERVER_URL" || { /bin/rm -f "$tmp"; die "cannot set serverUrl in the machine config"; }
  json_set "$tmp" tenant "$TENANT"        || { /bin/rm -f "$tmp"; die "cannot set tenant in the machine config"; }
  /usr/bin/plutil -remove installToken "$tmp" 2>/dev/null || true
  /usr/sbin/chown root:wheel "$tmp" && /bin/chmod 0644 "$tmp" || { /bin/rm -f "$tmp"; die "cannot set owner/mode on the machine config"; }
  /bin/mv -f "$tmp" "$cfg_file" || { /bin/rm -f "$tmp"; die "cannot install ${cfg_file}"; }
  log "wrote machine config ${cfg_file} (root:wheel 0644; serverUrl, tenant; no install token)"
}

# --------------------------------------------------- write per-user enroll config
# The install token's home: the enrolled user's own file, 0600. On a managed device (machine config
# written above) cli/config.mjs takes only installToken from it; serverUrl and tenant are written too, with
# the same values as the machine config, so the file still works if the device is later unmanaged.
write_enroll_config() {
  user="$1"; home="$2"
  cfg_dir="${home}/.moorai"
  cfg_file="${cfg_dir}/config.json"
  # The file carries the install token, so it is private from the moment it exists: umask 077 for the
  # mkdir, and the token goes into a fresh 0600 mktemp file that is renamed over config.json. The
  # rename also means a pre-existing config.json is replaced rather than rewritten in place, so its
  # old mode never applies and root never writes through a symlink left at that path. The subshell
  # keeps the umask from reaching the rest of the script; the chmods below stay as belt-and-braces.
  (
    umask 077
    /bin/mkdir -p "$cfg_dir" || exit 1
    tmp="$(/usr/bin/mktemp "${cfg_dir}/.config.json.XXXXXX")" || exit 1
    /bin/cat > "$tmp" <<JSON || { /bin/rm -f "$tmp"; exit 1; }
{
  "serverUrl": "${SERVER_URL}",
  "tenant": "${TENANT}",
  "installToken": "${INSTALL_TOKEN}"
}
JSON
    /bin/mv -f "$tmp" "$cfg_file" || { /bin/rm -f "$tmp"; exit 1; }
  ) || die "cannot write enroll config ${cfg_file}"
  /usr/sbin/chown -R "${user}" "$cfg_dir"
  /bin/chmod 700 "$cfg_dir"
  /bin/chmod 600 "$cfg_file"
  log "wrote enroll config for ${user} -> ${cfg_file}"
}

# ------------------------------------------------------------- register the hooks
# Runs the hook installer AS the user (launchctl asuser) so it edits that user's
# ~/.claude/settings.json, not root's. Idempotent: moorai-hook.mjs replaces only
# MoorAI's own PreToolUse entries.
register_hooks() {
  user="$1"
  uid="$(/usr/bin/id -u "$user" 2>/dev/null)"
  [ -n "$uid" ] || { log "cannot resolve uid for ${user}; skipping hook registration."; return 0; }
  node_bin="$(command -v node || echo /usr/local/bin/node)"
  /bin/launchctl asuser "$uid" /usr/bin/sudo -u "$user" \
    "$node_bin" "${MOORAI_HOME}/cli/moorai-hook.mjs" install \
    && log "hooks registered for ${user}" \
    || log "hook registration returned non-zero for ${user} (node present? ${node_bin})"
}

# ------------------------------------------------------------------------- main
install_agent
harden_anchor_dir
write_machine_config \
  || log "WARNING: not root; the machine config ${ANCHOR_DIR}/config.json was not written, so this device is NOT managed (its binding is the user-writable ~/.moorai/config.json)."
if [ "$DEFER_USER" -eq 0 ]; then
  write_enroll_config "$CONSOLE_USER" "$USER_HOME"
  register_hooks "$CONSOLE_USER"
fi
log "done. Policy is pulled at runtime from ${SERVER_URL}/api/policy?tenant=${TENANT}"
exit 0

# -----------------------------------------------------------------------------
# ALL USERS (optional): to enroll every existing local user instead of just the
# console user, replace the "main" block above with a loop:
#
#   for uhome in /Users/*; do
#     u="$(basename "$uhome")"
#     case "$u" in Shared|.localized) continue;; esac
#     id "$u" >/dev/null 2>&1 || continue
#     write_enroll_config "$u" "$uhome"
#     register_hooks "$u"
#   done
#
# For brand-new users created after this runs, deploy a LaunchAgent that calls
# `node <MOORAI_HOME>/cli/moorai-hook.mjs install` at each user's first login.
# =============================================================================
