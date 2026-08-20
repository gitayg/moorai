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
#   2. Writes ~/.curaiq/config.json  {serverUrl, tenant, installToken} for the
#      logged-in user — the file cli/config.mjs reads to bind to your console.
#   3. Runs `node <MOORAI_HOME>/cli/moorai-hook.mjs install` as that user, which
#      registers MoorAI's PreToolUse entries in ~/.claude/settings.json.
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
# `run.glick.curaiq` delivered by MoorAI-config.mobileconfig (recommended: set the
# values once in the profile and leave the script params blank).
# =============================================================================
set -u

# ------------------------------------------------------------------ parameters
SERVER_URL="${4:-}"
TENANT="${5:-}"
INSTALL_TOKEN="${6:-}"
MOORAI_HOME="${7:-/usr/local/moorai}"
PKG_URL="${8:-}"

PROFILE_DOMAIN="run.glick.curaiq"   # managed-preferences domain from the .mobileconfig

log() { /usr/bin/logger -t "MoorAI-deploy" "$1"; echo "MoorAI-deploy: $1"; }
die() { log "ERROR: $1"; exit 1; }

# ---------------------------------------------------- fall back to managed prefs
# When a script param is blank, read the value the configuration profile forced
# into the run.glick.curaiq domain. `defaults read <domain> <key>` resolves the
# managed (Forced) value at the system level.
prof() { /usr/bin/defaults read "$PROFILE_DOMAIN" "$1" 2>/dev/null; }
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

# --------------------------------------------------- write per-user enroll config
# JSON shape read by cli/config.mjs: { serverUrl, tenant, installToken }.
# `save_provision` in the Tauri host writes the identical file; we do it here so a
# headless MDM install needs no interactive token paste.
write_enroll_config() {
  user="$1"; home="$2"
  cfg_dir="${home}/.curaiq"
  cfg_file="${cfg_dir}/config.json"
  /bin/mkdir -p "$cfg_dir"
  /usr/bin/tee "$cfg_file" >/dev/null <<JSON
{
  "serverUrl": "${SERVER_URL}",
  "tenant": "${TENANT}",
  "installToken": "${INSTALL_TOKEN}"
}
JSON
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
