// The spawn map's lock is bounded: a dangling symlink, an old directory or a live holder's lock at the lock
// path costs at most the wait budget and the record goes without a parent, never a spin that stalls the hook.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, symlinkSync, utimesSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const MOD = pathToFileURL(join(dirname(fileURLToPath(import.meta.url)), "..", "cli", "trace-spawns.mjs")).href;
const LOCK = ".trace-spawns.lock";
const SPAN = "1234567890abcdef";

function run(dir) {
  const code = `const m = await import(${JSON.stringify(MOD)});
    const t0 = Date.now();
    const ok = m.recordSpawn({ sessionId: "s-lock", subagentType: "general-purpose", toolUseId: "tu1", spanId: ${JSON.stringify(SPAN)} }, { dir: ${JSON.stringify(dir)} });
    process.stdout.write(JSON.stringify({ ok, ms: Date.now() - t0 }));`;
  return spawnSync(process.execPath, ["--input-type=module", "-e", code], { encoding: "utf8", timeout: 10000 });
}

test("a dangling symlink at the lock path: the spawn is not recorded and the call returns within the wait budget", { skip: process.platform === "win32" && "symlinks need privileges on Windows" }, () => {
  const dir = mkdtempSync(join(tmpdir(), "trace-spawns-lock-"));
  try {
    symlinkSync(join(dir, "nowhere"), join(dir, LOCK));
    const r = run(dir);
    assert.equal(r.signal, null, `the stamp never returned (killed): ${r.stderr}`);
    const out = JSON.parse(r.stdout);
    assert.equal(out.ok, false);
    assert.ok(out.ms < 2000, `took ${out.ms} ms`);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("an old directory at the lock path: the spawn is not recorded and the call returns within the wait budget", () => {
  const dir = mkdtempSync(join(tmpdir(), "trace-spawns-lock-"));
  try {
    mkdirSync(join(dir, LOCK));
    const old = new Date(Date.now() - 600000);
    utimesSync(join(dir, LOCK), old, old);
    const r = run(dir);
    assert.equal(r.signal, null, `the stamp never returned (killed): ${r.stderr}`);
    const out = JSON.parse(r.stdout);
    assert.equal(out.ok, false);
    assert.ok(out.ms < 2000, `took ${out.ms} ms`);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("no lock in the way: the spawn is recorded", () => {
  const dir = mkdtempSync(join(tmpdir(), "trace-spawns-lock-"));
  try {
    writeFileSync(join(dir, "unrelated"), "");
    const out = JSON.parse(run(dir).stdout);
    assert.equal(out.ok, true);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
