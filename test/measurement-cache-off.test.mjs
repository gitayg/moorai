// scripts/measure-variance.mjs must call the model on EVERY run. The on-device escalation verdict cache
// (data/escalation-cache.mjs) keys on model + prompt + text and lasts 24 h, so without an off switch runs
// 2..N were answered from run 1's verdicts and the tool reported zero model variability.
//
// A fake Ollama on 127.0.0.1 flips its verdict for a given text on every call (flagged, benign, flagged),
// so a harness that really asks the model each run SEES the spread; one served from a cache does not.
// Temporary HOME, temporary run cache; nothing touches ~/.moorai or test/redteam/variance-cache.json.
//
// The other scorers that route misses through src/semantic.js (--semantic) must not fill or reuse the
// device cache either: each run below must reach the model and leave no ~/.moorai/escalation-cache.json.
//
//   node --test test/measurement-cache-off.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { spawn } from "node:child_process";
import { mkdtempSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname, relative } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const MODEL = "fake-variance-model:latest";

function fakeOllama() {
  const seen = new Map();
  const state = { generate: 0 };
  const srv = http.createServer((req, res) => {
    let b = "";
    req.on("data", (c) => (b += c));
    req.on("end", () => {
      res.setHeader("content-type", "application/json");
      if (req.url === "/api/tags") return res.end(JSON.stringify({ models: [{ name: MODEL, model: MODEL }] }));
      if (req.url === "/api/generate") {
        state.generate++;
        let prompt = "";
        try { prompt = JSON.parse(b).prompt || ""; } catch { /* empty */ }
        const n = (seen.get(prompt) || 0) + 1;
        seen.set(prompt, n);
        return res.end(JSON.stringify({ response: JSON.stringify({ risk: n % 2 === 1, category: "jailbreak", confidence: 0.9 }) }));
      }
      res.statusCode = 404; res.end("{}");
    });
  });
  return { srv, state };
}

function run(args, env, script = "scripts/measure-variance.mjs") {
  return new Promise((resolve) => {
    const p = spawn(process.execPath, [join(ROOT, script), ...args], { cwd: ROOT, env });
    let out = "", err = "";
    p.stdout.on("data", (c) => (out += c));
    p.stderr.on("data", (c) => (err += c));
    p.on("close", (code) => resolve({ code, out, err }));
  });
}

test("measure-variance asks the model on every run (the escalation verdict cache is off for measurement)", { timeout: 120000 }, async () => {
  const { srv, state } = fakeOllama();
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  try {
    const home = mkdtempSync(join(tmpdir(), "moorai-variance-home-"));
    const runCache = join(mkdtempSync(join(tmpdir(), "moorai-variance-runs-")), "runs.json");
    const env = { ...process.env, HOME: home, USERPROFILE: home, MOORAI_LOCAL_HOST: `http://127.0.0.1:${srv.address().port}`, MOORAI_LOCAL_MODEL: MODEL };
    delete env.MOORAI_ESCALATION_CACHE;
    const r = await run(["--runs", "3", "--det-runs", "1", "--fresh", "--json", "--cache", relative(ROOT, runCache)], env);
    assert.equal(r.code, 0, r.err);
    const rep = JSON.parse(r.out);
    const eligible = rep.counts.escalationEligible;
    assert.ok(eligible > 0, "the tune half has deterministic misses to escalate");
    assert.equal(state.generate, 1 + 3 * eligible, "one warm-up call plus one model call per eligible sample per run");
    assert.ok(rep.metrics.modelInducedFp.sd > 0, "a model whose verdict flips between runs must show a spread");
    assert.equal(existsSync(join(home, ".moorai", "escalation-cache.json")), false, "measurement must not fill the device cache");
  } finally {
    srv.close();
  }
});

for (const [script, args] of [
  ["scripts/score-heldout-v2.mjs", ["--semantic", "--json", "--file", "test/redteam/heldout-v2-tune.json"]],
  ["scripts/score-vectors.mjs", ["--semantic", "--json", "--file", "test/redteam/heldout-v2-tune.json"]],
  ["scripts/score-vector24.mjs", ["--vector", "2", "--semantic", "--json"]],
  ["scripts/redteam-eval.mjs", ["--semantic", "--format", "json"]]
]) {
  test(`${script} --semantic reaches the model and leaves the device verdict cache alone`, { timeout: 180000 }, async () => {
    const { srv, state } = fakeOllama();
    await new Promise((r) => srv.listen(0, "127.0.0.1", r));
    try {
      const home = mkdtempSync(join(tmpdir(), "moorai-scorer-home-"));
      const env = { ...process.env, HOME: home, USERPROFILE: home, MOORAI_LOCAL_HOST: `http://127.0.0.1:${srv.address().port}`, MOORAI_LOCAL_MODEL: MODEL };
      delete env.MOORAI_ESCALATION_CACHE;
      const r = await run(args, env, script);
      assert.ok(r.code === 0 || r.code === 1, `exit ${r.code}: ${r.err.slice(-400)}`);
      assert.ok(state.generate > 0, "the scorer must route at least one miss to the model");
      assert.equal(existsSync(join(home, ".moorai", "escalation-cache.json")), false, "measurement must not fill the device cache");
    } finally {
      srv.close();
    }
  });
}
