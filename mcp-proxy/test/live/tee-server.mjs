#!/usr/bin/env node
// Wire tap for the live-client tests: `node tee-server.mjs <log> -- <cmd> [args...]`.
// Spawns <cmd> as the MCP server and copies every newline-delimited message that arrives on stdin
// (i.e. what the MoorAI stdio guard forwarded to the server) to <log>, one JSON line each, before
// passing it on unchanged. Server stdout/stderr pass through untouched. This is how a test proves a
// real client's initialize / tools/list crossed the guard and reached the real server, and reads the
// clientInfo the client sent.
import { spawn } from "node:child_process";
import { appendFileSync } from "node:fs";

const argv = process.argv.slice(2);
const sep = argv.indexOf("--");
const LOG = argv[0];
const [cmd, ...args] = argv.slice(sep + 1);
const child = spawn(cmd, args, { stdio: ["pipe", "inherit", "inherit"] });
let buf = "";
process.stdin.on("data", (c) => {
  buf += c;
  let nl;
  while ((nl = buf.indexOf("\n")) >= 0) {
    const line = buf.slice(0, nl);
    buf = buf.slice(nl + 1);
    if (line.trim()) { try { appendFileSync(LOG, line + "\n"); } catch { /* tap only */ } }
  }
  child.stdin.write(c);
});
process.stdin.on("end", () => child.stdin.end());
child.on("exit", (code) => process.exit(code ?? 0));
