#!/usr/bin/env node
// moorai-mcp-check <package> [--json] [--policy file.json | --no-policy] [--tools tools-list.json]
//
// Ten pre-install checks for an MCP server, from registry metadata and published manifests only: the
// package is never downloaded or run (cli/mcp-package/check.mjs). Exit 0 when nothing fails, 1 when a
// check fails, 2 on a usage error.
//
// Policy (egressRules / egressDefault, mcpReputation.feed): --policy reads a local policy JSON; otherwise
// the verified policy this device already holds is read offline, the way moorai-doctor reads it.

import { runMcpCheck } from "./mcp-package/check-cli.mjs";
import { exitWhenDrained } from "./exit-drain.mjs";

// It fetches, so it leaves by draining the loop, not process.exit() (cli/exit-drain.mjs: Windows 0xC0000409).
runMcpCheck().then((code) => exitWhenDrained(code), (e) => { console.error(`moorai-mcp-check: ${e && e.message || e}`); exitWhenDrained(1); });
