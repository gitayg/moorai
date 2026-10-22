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
# Network access: Custom, with the console's host in Allowed domains (keep "Also include default list").
# Hook registration: paste the output of `moorai-cloud-setup claude-code-web --print-hooks`
# (claude-code-web-hooks.json) into your organization's server-managed settings, or commit it as the
# repository's .claude/settings.json.
set -e
git clone --depth 1 https://github.com/gitayg/moorai.git /opt/moorai || true
node /opt/moorai/cli/moorai-cloud-setup.mjs claude-code-web --install-dir /opt/moorai
