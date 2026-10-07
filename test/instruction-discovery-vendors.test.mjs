// The instruction files other agents run under are found for fingerprinting (instruction-leak #52) and,
// where they are single files, scanned at session start (the hook's INDEX_SURFACE). Locations are the ones
// test/skill-surface-vendors.test.mjs quotes from each vendor's documentation.
//
//   node --test test/instruction-discovery-vendors.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { discoverInstructionFiles } from "../cli/instruction-fingerprints.mjs";
import { rmTree } from "./fs-cleanup.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

test("fingerprint discovery finds Kiro steering, Amp AGENT.md and Copilot user instructions", () => {
  const home = mkdtempSync(join(tmpdir(), "moorai-idisc-home-"));
  const proj = mkdtempSync(join(tmpdir(), "moorai-idisc-proj-"));
  try {
    const files = [
      join(proj, ".kiro", "steering", "product.md"),
      join(proj, "AGENT.md"),
      join(home, ".kiro", "steering", "team.md"),
      join(home, ".copilot", "instructions", "style.instructions.md")
    ];
    for (const f of files) { mkdirSync(dirname(f), { recursive: true }); writeFileSync(f, "# rules\n"); }
    const found = new Set(discoverInstructionFiles(proj, { home, env: {}, managed: false }));
    for (const f of files) assert.ok(found.has(resolve(f)), `not discovered: ${f.replace(home, "~").replace(proj, "<proj>")}`);
  } finally { rmTree(home); rmTree(proj); }
});

test("session-start scan list includes the documented single-file instruction and settings files", () => {
  const src = readFileSync(join(ROOT, "cli", "moorai-hook.mjs"), "utf8");
  const block = /const INDEX_SURFACE = \[([\s\S]*?)\n\];/.exec(src);
  assert.ok(block, "INDEX_SURFACE not found");
  for (const want of ['["project", "GEMINI.md"]', '["project", "AGENTS.override.md"]', '["project", join(".gemini", "settings.json")]',
    '["project", join(".github", "copilot-instructions.md")]', '["home", join(".gemini", "GEMINI.md")]', '["home", join(".gemini", "settings.json")]']) {
    assert.ok(block[1].includes(want), `INDEX_SURFACE lacks ${want}`);
  }
});

test("the index scan cap never cuts the scan list short (no listed file is silently skipped)", () => {
  const src = readFileSync(join(ROOT, "cli", "moorai-hook.mjs"), "utf8");
  const cap = Number(/const INDEX_MAX_FILES = (\d+);/.exec(src)[1]);
  const entries = (/const INDEX_SURFACE = \[([\s\S]*?)\n\];/.exec(src)[1].match(/\["(?:project|home)"/g) || []).length;
  assert.ok(cap >= entries, `INDEX_MAX_FILES ${cap} < ${entries} INDEX_SURFACE entries: ~/.claude/settings.json and the Gemini home files would never be scanned`);
});
