#!/bin/sh
# MoorAI one-line installer (#17) — community edition: the on-device CLI guard + Claude Code hooks.
# Content-free, no account, nothing leaves the machine.
#
#   curl -fsSL https://raw.githubusercontent.com/gitayg/moorai/main/scripts/install.sh | sh
#
# Env overrides:
#   MOORAI_HOME   install dir (default ~/.moorai)
#   MOORAI_REF    git ref to check out (default main)
#   MOORAI_NOHOOK set to 1 to skip registering Claude Code PreToolUse hooks
set -eu

REPO="https://github.com/gitayg/moorai.git"
DEST="${MOORAI_HOME:-$HOME/.moorai}"
REF="${MOORAI_REF:-main}"

say() { printf '\033[1mMoorAI\033[0m %s\n' "$1"; }
die() { printf '\033[31mMoorAI: %s\033[0m\n' "$1" >&2; exit 1; }

command -v git  >/dev/null 2>&1 || die "git is required (install git and re-run)."
command -v node >/dev/null 2>&1 || die "Node.js 18+ is required (install node and re-run)."
command -v npm  >/dev/null 2>&1 || die "npm is required (install npm and re-run)."

NODE_MAJOR="$(node -p 'process.versions.node.split(".")[0]' 2>/dev/null || echo 0)"
[ "$NODE_MAJOR" -ge 18 ] 2>/dev/null || die "Node.js 18+ required (found $(node -v 2>/dev/null))."

if [ -d "$DEST/.git" ]; then
  say "updating $DEST"
  git -C "$DEST" fetch --depth 1 origin "$REF" >/dev/null 2>&1
  git -C "$DEST" checkout -q "$REF"
  git -C "$DEST" reset --hard -q "origin/$REF" 2>/dev/null || git -C "$DEST" reset --hard -q "$REF"
else
  say "cloning into $DEST"
  git clone --depth 1 --branch "$REF" "$REPO" "$DEST" >/dev/null 2>&1 \
    || git clone --depth 1 "$REPO" "$DEST" >/dev/null 2>&1 \
    || die "clone failed."
fi

say "installing dependencies"
( cd "$DEST" && npm ci --omit=dev >/dev/null 2>&1 || npm install --omit=dev >/dev/null 2>&1 ) \
  || die "dependency install failed."

if [ "${MOORAI_NOHOOK:-0}" != "1" ]; then
  say "registering Claude Code PreToolUse hooks"
  ( cd "$DEST" && node cli/moorai-hook.mjs install ) || say "hook registration skipped (run 'node $DEST/cli/moorai-hook.mjs install' later)."
fi

say "installed. Try the on-device guard:"
printf '\n  node %s/cli/moorai-guard.mjs "here is my key sk-ant-api03-... debug this"\n\n' "$DEST"
say "content-free by construction — nothing leaves the machine. Docs: https://github.com/gitayg/moorai"
