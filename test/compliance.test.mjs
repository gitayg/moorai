// Compliance-evidence pack tests. Same throwaway-HOME harness as posture.test.mjs: HOME is an
// mkdtempSync dir and the XDG vars are deleted so signals.mjs resolves ~/.moorai under it. We seed the
// real content-free signal files, run the CLI for each framework, and pin two things:
//   1. coverage reflects the seeded evidence — a full-support control keyed to a seeded log reads
//      "covered" with the right count; an unbacked control (empty AIBOM, or by-design none) reads
//      "not-covered".
//   2. NO content leaks — a sentinel value planted in a stray field of a seeded row never appears in
//      any output, human or JSON.
//
//   node --test test/compliance.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const CLI = join(ROOT, "cli", "moorai-compliance.mjs");

// A sentinel that MUST NOT appear in any output. If the CLI ever read a "content" field, this leaks.
const SENTINEL = "SECRET-PROMPT-DO-NOT-LEAK-sk-live-abc123";

function seed(home) {
  const dir = join(home, ".moorai");
  mkdirSync(dir, { recursive: true });
  const jsonl = (name, rows) => writeFileSync(join(dir, name), rows.map((r) => JSON.stringify(r)).join("\n") + "\n");
  const day = 86400000, now = Date.now();

  // exposure-ledger — 2 secret-class exposures (each row carries a stray content field = the sentinel).
  jsonl("exposure-ledger.jsonl", [
    { category: "API key", riskLevel: "Critical", stage: "mcp", tool: "claude", contentHash: "h1", ts: new Date(now - 3 * day).toISOString(), matchText: SENTINEL },
    { category: "Password", riskLevel: "High", stage: "file", tool: "cursor", contentHash: "h2", ts: new Date(now - 1 * day).toISOString(), matchText: SENTINEL }
  ]);
  // action-audit — 3 records, 2 of them High/Critical (= literacy touchpoints).
  jsonl("action-audit.jsonl", [
    { threatId: 1, category: "Prompt Injection", riskLevel: "High", stage: "text", tool: "claude", ts: new Date(now - 5 * day).toISOString(), prompt: SENTINEL },
    { threatId: 2, category: "Info leak", riskLevel: "Critical", stage: "mcp", tool: "claude", ts: new Date(now - 2 * day).toISOString() },
    { threatId: 0, category: "MCP tool call", riskLevel: "Info", stage: "mcp", tool: "hook:x", ts: new Date(now - 1 * day).toISOString() }
  ]);
  // intent-log — 1 human override.
  jsonl("intent-log.jsonl", [
    { categories: ["API key"], justificationHash: "jh1", ts: new Date(now - 1 * day).toISOString(), justification: SENTINEL }
  ]);
  // destinations — 2 observations, 1 denied.
  jsonl("destinations.jsonl", [
    { ts: new Date(now - 2 * day).toISOString(), tool: "claude", kind: "host", name: "api.example.com", decision: "allow" },
    { ts: new Date(now - 1 * day).toISOString(), tool: "claude", kind: "mcp", name: "github", decision: "deny", command: SENTINEL }
  ]);
  // agent-events — 4 behavioral events (epoch-ms ts, as recordAgentEvent writes).
  jsonl("agent-events.jsonl", [
    { ts: now - 4 * day, sig: "Bash|h", ok: true, risk: "Low" },
    { ts: now - 3 * day, sig: "Read|h", ok: true, risk: "Low" },
    { ts: now - 2 * day, sig: "mcp__x|h", ok: false, risk: "High" },
    { ts: now - 1 * day, sig: "Write|h", ok: true, risk: "Medium" }
  ]);
}

function run(home, args) {
  const env = { ...process.env, HOME: home, USERPROFILE: home };
  delete env.XDG_CONFIG_HOME; delete env.XDG_STATE_HOME;
  delete env.MOORAI_RETENTION_DAYS;
  return execFileSync(process.execPath, [CLI, ...args], { encoding: "utf8", env, maxBuffer: 16 * 1024 * 1024 });
}

// Locate a control across the parsed JSON pack.
const ctrl = (pack, fw, id) => pack.frameworks.find((f) => f.framework === fw).controls.find((c) => c.id === id);

function withHome(fn) {
  const home = mkdtempSync(join(tmpdir(), "moorai-compliance-"));
  try { seed(home); return fn(home); } finally { rmSync(home, { recursive: true, force: true }); }
}

test("EU AI Act: seeded signals drive coverage; unbacked controls read not-covered", () => {
  withHome((home) => {
    const pack = JSON.parse(run(home, ["--framework", "eu-ai-act", "--json"]));
    assert.equal(pack.frameworks.length, 1);
    const controls = pack.frameworks[0].controls;
    assert.ok(controls.length >= 5, "the pack must list the framework's controls");

    // Art. 12 record-keeping (full-support, backed by the 3 seeded action-audit rows) → covered.
    const art12 = ctrl(pack, "eu-ai-act", "Art. 12");
    assert.equal(art12.status, "covered");
    assert.equal(art12.metric, 3);

    // Art. 14 human oversight (full-support, backed by the 1 seeded intent row) → covered.
    const art14 = ctrl(pack, "eu-ai-act", "Art. 14");
    assert.equal(art14.status, "covered");
    assert.equal(art14.metric, 1);

    // Art. 4 literacy — only the 2 High/Critical action rows count as touchpoints.
    const art4 = ctrl(pack, "eu-ai-act", "Art. 4");
    assert.equal(art4.status, "covered");
    assert.equal(art4.metric, 2);

    // Art. 26 deployer inventory is AIBOM-backed; the throwaway HOME has no AI config → not-covered.
    const art26 = ctrl(pack, "eu-ai-act", "Art. 26");
    assert.equal(art26.status, "not-covered");
    assert.equal(art26.metric, 0);

    // Art. 10 training-data governance is none-support by design → always not-covered.
    const art10 = ctrl(pack, "eu-ai-act", "Art. 10");
    assert.equal(art10.support, "none");
    assert.equal(art10.status, "not-covered");
  });
});

test("NIST AI RMF: exposure + behavior full-support controls covered from seeded logs", () => {
  withHome((home) => {
    const pack = JSON.parse(run(home, ["--framework", "nist-ai-rmf", "--json"]));
    const measure27 = ctrl(pack, "nist-ai-rmf", "MEASURE 2.7"); // exposure, full
    assert.equal(measure27.status, "covered");
    assert.equal(measure27.metric, 2);
    const measure26 = ctrl(pack, "nist-ai-rmf", "MEASURE 2.6"); // behavior, full
    assert.equal(measure26.status, "covered");
    assert.equal(measure26.metric, 4);
    const map11 = ctrl(pack, "nist-ai-rmf", "MAP 1.1"); // none
    assert.equal(map11.status, "not-covered");
  });
});

test("ISO 42001: egress + partial-support suppliers control reflect seeded/absent evidence", () => {
  withHome((home) => {
    const pack = JSON.parse(run(home, ["--framework", "iso-42001", "--json"]));
    const egress = ctrl(pack, "iso-42001", "A.7.4"); // destinations, partial → partial (has 2 rows)
    assert.equal(egress.status, "partial");
    assert.equal(egress.metric, 2);
    const suppliers = ctrl(pack, "iso-42001", "A.10.2"); // suppliers via AIBOM, empty HOME → not-covered
    assert.equal(suppliers.status, "not-covered");
  });
});

test("--framework all emits all three packs with per-framework summaries", () => {
  withHome((home) => {
    const pack = JSON.parse(run(home, ["--framework", "all", "--json"]));
    assert.deepEqual(pack.frameworks.map((f) => f.framework), ["eu-ai-act", "nist-ai-rmf", "iso-42001"]);
    for (const fw of pack.frameworks) {
      assert.equal(fw.summary.total, fw.controls.length);
      assert.equal(fw.summary.covered + fw.summary.partial + fw.summary.notCovered, fw.controls.length);
    }
  });
});

test("no content leaks — sentinel absent from JSON and human output for every framework", () => {
  withHome((home) => {
    for (const fw of ["eu-ai-act", "nist-ai-rmf", "iso-42001", "all"]) {
      const j = run(home, ["--framework", fw, "--json"]);
      const h = run(home, ["--framework", fw]);
      assert.ok(!j.includes(SENTINEL), `sentinel leaked into ${fw} --json`);
      assert.ok(!h.includes(SENTINEL), `sentinel leaked into ${fw} human output`);
    }
  });
});

test("human output is readable and shows a coverage summary", () => {
  withHome((home) => {
    const out = run(home, ["--framework", "eu-ai-act"]);
    assert.match(out, /EU AI Act/);
    assert.match(out, /covered/);
    assert.match(out, /Art\. 12 — Record-keeping/);
    assert.match(out, /COVERED|NOT COVERED|PARTIAL/);
  });
});
