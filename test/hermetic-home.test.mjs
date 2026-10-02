// The unit-test harness keeps tests out of the developer's real home (test/hermetic-env.mjs +
// test/home-guard.mjs). Pinned:
//   1. In-process, os.homedir() and cli/state-dirs.mjs's STATE_DIR resolve under a per-process temp home.
//   2. The two writes that used to land in the real ~/.moorai during `npm run test:unit` —
//      escalation-outcomes.jsonl (data/model-escalation.mjs) and .chain-otel.head.json
//      (cli/record-chain.mjs) — now land in that temp home.
//   3. A child spawned with `{ ...process.env }` inherits the temp home.
//   4. The guard fails a process that writes under the home it started with (or spawns a child into it),
//      names the call, and passes one that writes only under its temp home.
//
//   node --test --import ./test/hermetic-env.mjs test/hermetic-home.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import os from "node:os";
import { existsSync, mkdtempSync, realpathSync } from "node:fs";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { STATE_DIR } from "../cli/state-dirs.mjs";
import { recordEscalationOutcome } from "../data/model-escalation.mjs";
import { nextLink } from "../cli/record-chain.mjs";

const HERMETIC = fileURLToPath(new URL("./hermetic-env.mjs", import.meta.url));
const ESCALATION = new URL("../data/model-escalation.mjs", import.meta.url).href;
const REAL = process.env.MOORAI_TEST_REAL_HOME;
const under = (p, dir) => realpathSync(p).startsWith(realpathSync(dir));

test("in-process: os.homedir() and STATE_DIR are a per-process temp home, not the home the run started with", () => {
  assert.ok(REAL, "hermetic-env must record the home it replaced (run with --import ./test/hermetic-env.mjs)");
  assert.notEqual(os.homedir(), REAL);
  assert.ok(under(os.homedir(), os.tmpdir()), os.homedir());
  assert.equal(STATE_DIR, join(os.homedir(), ".moorai"));
});

test("the escalation outcome log and the OTel chain head land in the temp home", () => {
  recordEscalationOutcome("unavailable", 0, "none");
  nextLink("otel", "0".repeat(64), { tenant: "t" });
  assert.ok(existsSync(join(os.homedir(), ".moorai", "escalation-outcomes.jsonl")));
  assert.ok(existsSync(join(os.homedir(), ".moorai", ".chain-otel.head.json")));
});

test("a child spawned with { ...process.env } inherits the temp home", () => {
  const r = spawnSync(process.execPath, ["-e", "process.stdout.write(require('os').homedir())"], { env: { ...process.env }, encoding: "utf8" });
  assert.equal(r.stdout, os.homedir());
});

// Each case runs a fresh process under the harness with a throwaway STARTING home, so the guard's
// "real home" here is disposable and the developer's is never touched.
function guarded(script) {
  const start = mkdtempSync(join(os.tmpdir(), "moorai-guard-start-"));
  const r = spawnSync(process.execPath, ["--import", HERMETIC, "--input-type=module", "-e", script],
    { env: { ...process.env, HOME: start, USERPROFILE: start }, encoding: "utf8" });
  return { ...r, start };
}

test("guard: a write under the starting home fails the process and names the file", () => {
  const r = guarded(`import { mkdirSync, writeFileSync } from "node:fs";
    const d = process.env.MOORAI_TEST_REAL_HOME + "/.moorai"; mkdirSync(d, { recursive: true }); writeFileSync(d + "/leak.json", "{}");`);
  assert.equal(r.status, 1, r.stderr);
  assert.match(r.stderr, /home-guard: .*REAL home/);
  assert.match(r.stderr, /fs\.writeFileSync\(.*\.moorai[\\/]leak\.json\)/);
});

test("guard: the original leak — a module resolving STATE_DIR from the real HOME at import — is caught", () => {
  // Exactly the pre-fix mechanism: data/model-escalation.mjs (via cli/state-dirs.mjs) imported while
  // HOME is the real home, then an escalation attempt appends its outcome row.
  const r = guarded(`process.env.HOME = process.env.MOORAI_TEST_REAL_HOME;
    const m = await import(${JSON.stringify(ESCALATION)}); m.recordEscalationOutcome("unavailable", 0, "none");`);
  assert.ok(existsSync(join(r.start, ".moorai", "escalation-outcomes.jsonl")), "the write reached the starting home");
  assert.equal(r.status, 1, r.stderr);
  assert.match(r.stderr, /fs\.appendFileSync\(.*\.moorai[\\/]escalation-outcomes\.jsonl\)/);
});

test("guard: a child spawned with HOME at the real home, or with no HOME at all, is caught", () => {
  const withReal = guarded(`import { spawnSync } from "node:child_process";
    spawnSync(process.execPath, ["-e", "0"], { env: { ...process.env, HOME: process.env.MOORAI_TEST_REAL_HOME } });`);
  assert.equal(withReal.status, 1, withReal.stderr);
  assert.match(withReal.stderr, /child_process\.spawnSync\(.*\) with HOME=/);
  const noHome = guarded(`import { spawnSync } from "node:child_process";
    spawnSync(process.execPath, ["-e", "0"], { env: { PATH: process.env.PATH } });`);
  assert.equal(noHome.status, 1, noHome.stderr);
  assert.match(noHome.stderr, /no HOME/);
});

test("guard: a process that writes only under its temp home, and spawns with { ...process.env }, passes", () => {
  const r = guarded(`import { spawnSync } from "node:child_process";
    const m = await import(${JSON.stringify(ESCALATION)}); m.recordEscalationOutcome("unavailable", 0, "none");
    spawnSync(process.execPath, ["-e", "0"], { env: { ...process.env } });`);
  assert.equal(r.status, 0, r.stderr);
  assert.doesNotMatch(r.stderr, /home-guard/);
  assert.ok(!existsSync(join(r.start, ".moorai")), "nothing was created under the starting home");
});
