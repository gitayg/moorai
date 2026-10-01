#!/usr/bin/env node
// Merge MoorAI's hook registration into a Claude Code MANAGED settings file (default
// /etc/claude-code/managed-settings.json), for images and CI runners.
//
// Why managed and not ~/.claude/settings.json: in a headless run the repository under test is untrusted,
// and Claude Code's settings reference says of `disableAllHooks`: "Only managed settings can disable
// managed hooks". A user-level registration can be switched off by a project settings file; a managed
// one cannot.
//
// The hooks block is not written down here. It is produced by running MoorAI's own installer
// (`cli/moorai-hook.mjs install`) against a throwaway HOME and reading back what it wrote, so it always
// matches the matcher set of the hook this image ships (the doctor checks it the same way).
//
//   node examples/server/managed-settings.mjs [managed-settings.json]   # run as root in the image
import { mkdtempSync, readFileSync, writeFileSync, mkdirSync, rmSync, renameSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HOOK = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "cli", "moorai-hook.mjs");
const target = process.argv[2] || "/etc/claude-code/managed-settings.json";

const home = mkdtempSync(join(tmpdir(), "moorai-managed-"));
try {
  const r = spawnSync(process.execPath, [HOOK, "install"], { env: { PATH: process.env.PATH, HOME: home, USERPROFILE: home }, encoding: "utf8" });
  if (r.status !== 0) { process.stderr.write(r.stderr || "moorai-hook install failed\n"); process.exit(1); }
  const hooks = JSON.parse(readFileSync(join(home, ".claude", "settings.json"), "utf8")).hooks || {};
  let cur = {};
  try { cur = JSON.parse(readFileSync(target, "utf8")); } catch { /* new file */ }
  const isOurs = (e) => JSON.stringify(e).includes("moorai-hook");
  cur.hooks = cur.hooks || {};
  for (const [event, entries] of Object.entries(hooks)) {
    cur.hooks[event] = [...(Array.isArray(cur.hooks[event]) ? cur.hooks[event] : []).filter((e) => !isOurs(e)), ...entries];
  }
  mkdirSync(dirname(target), { recursive: true });
  const tmp = `${target}.moorai-${process.pid}.tmp`;
  writeFileSync(tmp, JSON.stringify(cur, null, 2) + "\n", { mode: 0o644 });
  renameSync(tmp, target);
  process.stderr.write(`MoorAI hooks registered in ${target} (${Object.keys(hooks).join(", ")})\n`);
} finally { rmSync(home, { recursive: true, force: true }); }
