#!/usr/bin/env node
// Client-side wire tap for the live-client tests: `node client-tap.mjs <log> -- <cmd> [args...]`.
// The mirror image of tee-server.mjs: it sits between the MCP CLIENT and <cmd> (the MoorAI stdio guard)
// and copies every newline-delimited message <cmd> writes to stdout — i.e. exactly what the client
// received — to <log>, one line each, before passing it on unchanged. Used for clients that do not print
// the tool names they were given (`claude mcp list`), so a test can still read the tools/list they got.
import { spawn } from "node:child_process";
import { appendFileSync } from "node:fs";

const argv = process.argv.slice(2);
const sep = argv.indexOf("--");
const LOG = argv[0];
const [cmd, ...args] = argv.slice(sep + 1);
const child = spawn(cmd, args, { stdio: ["pipe", "pipe", "inherit"] });
let buf = "";
child.stdout.on("data", (c) => {
  buf += c;
  let nl;
  while ((nl = buf.indexOf("\n")) >= 0) {
    const line = buf.slice(0, nl);
    buf = buf.slice(nl + 1);
    if (line.trim()) { try { appendFileSync(LOG, line + "\n"); } catch { /* tap only */ } }
  }
  process.stdout.write(c);
});
process.stdin.on("data", (c) => child.stdin.write(c));
process.stdin.on("end", () => child.stdin.end());
child.on("exit", (code) => process.exit(code ?? 0));
