#!/bin/bash
# Setup script for a Claude Code cloud environment (claude.ai/code > environment settings > Setup script, or
# the Cloud environments admin page for an organization-shared environment). It "runs when a new cloud
# session starts, before Claude Code launches", as root on Ubuntu 24.04.
#
# Set these as the environment's environment variables:
#   MOORAI_SERVER_URL=https://<your console>
#   MOORAI_TENANT=<tenant>
#   MOORAI_INSTALL_TOKEN=mwt_...      a static workload token: the environment dialog warns that anyone who
#                                     uses the environment can read its variables, and a workload token only
#                                     reaches MoorAI's telemetry and policy-read routes
#   MOORAI_REF=<release tag>          the MoorAI release to install; the clone pins it and the script stops
#                                     without it, so sessions never run the moving main branch
#   MOORAI_COMMIT=<40-hex commit SHA> the commit that tag points to (git ls-remote --tags <repo> <tag>^{});
#                                     the script stops when the clone's HEAD is any other commit
# Network access: Custom, with the console's host in Allowed domains (keep "Also include default list").
# Hook registration: paste the output of `moorai-cloud-setup claude-code-web --print-hooks`
# (claude-code-web-hooks.json) into your organization's server-managed settings, or commit it as the
# repository's .claude/settings.json.
set -euo pipefail
: "${MOORAI_REF:?set MOORAI_REF to a MoorAI release tag}"
: "${MOORAI_COMMIT:?set MOORAI_COMMIT to the full commit SHA that MOORAI_REF points to}"
case "$MOORAI_COMMIT" in
  *[!0-9a-f]*) echo "MOORAI_COMMIT must be a 40-character lowercase commit SHA" >&2; exit 1 ;;
esac
[ "${#MOORAI_COMMIT}" -eq 40 ] || { echo "MOORAI_COMMIT must be a 40-character lowercase commit SHA" >&2; exit 1; }
DIR="${MOORAI_INSTALL_DIR:-/opt/moorai}"
case "$DIR" in
  /*[!/]) ;;
  *) echo "MOORAI_INSTALL_DIR must be an absolute path other than /" >&2; exit 1 ;;
esac
# A checkout an earlier session left behind is never run, and git never runs inside it (its config or hooks
# could run code as root): every session clones the pinned tag fresh next to it, checks the commit, then
# swaps it in. A failed clone or a different commit stops the script before node runs.
mkdir -p "$(dirname "$DIR")"
NEW="$(mktemp -d "${DIR}.new.XXXXXX")"
trap 'rm -rf "$NEW"' EXIT
git clone --quiet --depth 1 --branch "$MOORAI_REF" https://github.com/gitayg/moorai.git "$NEW"
HEAD_SHA="$(git -C "$NEW" rev-parse HEAD)"
if [ "$HEAD_SHA" != "$MOORAI_COMMIT" ]; then
  echo "MoorAI $MOORAI_REF is at $HEAD_SHA, not the pinned $MOORAI_COMMIT; stopping" >&2
  exit 1
fi
rm -rf "$DIR"
mv "$NEW" "$DIR"
trap - EXIT
node "$DIR/cli/moorai-cloud-setup.mjs" claude-code-web --install-dir "$DIR"
