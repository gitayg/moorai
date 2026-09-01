// STIX 2.1 export tests. Two things are pinned:
//   1. STRUCTURE — the bundle is a well-formed STIX 2.1 bundle: type "bundle", a deterministic
//      bundle--<uuid> id, every object carries spec_version 2.1 and a well-formed type--<uuid> id,
//      indicators carry a pattern/pattern_type, and the note's object_refs resolve to real objects.
//   2. CONTENT-FREE — a sentinel planted in a stray field of every source row NEVER appears in the
//      bundle, because the exporter reads a strict allowlist and never spreads the row.
//
//   node --test test/stix.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import { buildStixBundle, collectFindings, stixFromEvidence, uuidv5, SPEC_VERSION } from "../cli/moorai-stix.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const CLI = join(ROOT, "cli", "moorai-compliance.mjs");
const SENTINEL = "SECRET-PROMPT-DO-NOT-LEAK-sk-live-abc123";

const ID_RE = /^[a-z0-9-]+--[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

// Content-free evidence with a stray content field on EVERY row — exactly what the real logs never
// carry, planted here so any accidental row-spread is caught.
function evidence() {
  const now = Date.now(), day = 86400000;
  return {
    ledger: [{ category: "API key", riskLevel: "Critical", stage: "mcp", tool: "claude", decision: "deny", contentHash: "h2:aaaa1111bbbb2222", tenant: "acme", ts: new Date(now - day).toISOString(), matchText: SENTINEL }],
    actions: [{ category: "Prompt Injection", riskLevel: "High", stage: "text", tool: "cursor", contentHash: "h2:cccc3333dddd4444", ts: new Date(now - 2 * day).toISOString(), prompt: SENTINEL }],
    agentEvents: [{ ts: now - 3 * day, sig: `Bash|h2:eeee5555ffff6666`, ok: false, risk: "High", rawCommand: SENTINEL }],
    intent: [{ categories: ["API key"], justificationHash: "h2:1234abcd5678ef90", stage: "mcp", tool: "claude", ts: new Date(now - 4 * day).toISOString(), justification: SENTINEL }],
    destinations: [{ ts: new Date(now - 5 * day).toISOString(), tool: "claude", kind: "mcp", decision: "allow", contentHash: "h2:9999000011112222", command: SENTINEL }]
  };
}

function assertStructural(bundle) {
  assert.equal(bundle.type, "bundle");
  assert.match(bundle.id, ID_RE, `bundle id ${bundle.id}`);
  assert.ok(Array.isArray(bundle.objects));
  const ids = new Set();
  for (const o of bundle.objects) {
    assert.equal(o.spec_version, SPEC_VERSION, `${o.type} spec_version`);
    assert.match(o.id, ID_RE, `object id ${o.id}`);
    assert.ok(o.id.startsWith(o.type + "--"), `${o.id} id prefix must match type ${o.type}`);
    ids.add(o.id);
    if (o.type === "indicator") {
      assert.equal(o.pattern_type, "stix");
      assert.ok(typeof o.pattern === "string" && o.pattern.length > 0, "indicator needs a pattern");
      assert.ok(o.valid_from, "indicator needs valid_from");
    }
  }
  const note = bundle.objects.find((o) => o.type === "note");
  if (note) {
    assert.ok(Array.isArray(note.object_refs) && note.object_refs.length > 0);
    for (const ref of note.object_refs) assert.ok(ids.has(ref), `note object_ref ${ref} must resolve`);
  }
}

test("STRUCTURE: a well-formed STIX 2.1 bundle from evidence", () => {
  const bundle = stixFromEvidence(evidence(), { now: 1_700_000_000_000 });
  assertStructural(bundle);
  // one x-moorai-finding per source row.
  const findings = bundle.objects.filter((o) => o.type === "x-moorai-finding");
  assert.equal(findings.length, 5);
  // findings that carry a usable one-way hash also get an indicator keyed on that hash.
  assert.ok(bundle.objects.some((o) => o.type === "indicator"));
});

test("MAPPING: content-free fields map onto x_moorai_ properties; risk from riskLevel", () => {
  const bundle = buildStixBundle(collectFindings(evidence()), { now: 1 });
  const f = bundle.objects.find((o) => o.type === "x-moorai-finding" && o.x_moorai_source === "exposure-ledger");
  assert.equal(f.x_moorai_category, "API key");
  assert.equal(f.x_moorai_risk, "Critical");
  assert.equal(f.x_moorai_decision, "deny");
  assert.equal(f.x_moorai_content_hash, "h2:aaaa1111bbbb2222");
  const ind = bundle.objects.find((o) => o.type === "indicator" && o.pattern.includes("h2:aaaa1111bbbb2222"));
  assert.ok(ind, "the ledger finding's hash must appear in an indicator pattern");
  assert.match(ind.pattern, /^\[x-moorai-finding:x_moorai_content_hash = 'h2:aaaa1111bbbb2222'\]$/);
});

test("NO_KEY hashes produce no indicator (nothing to key an IOC on)", () => {
  const bundle = buildStixBundle([{ source: "action-audit", category: "x", riskLevel: "Low", contentHash: "h2:nokey", ts: 1 }], { now: 1 });
  assert.ok(bundle.objects.some((o) => o.type === "x-moorai-finding"));
  assert.ok(!bundle.objects.some((o) => o.type === "indicator"), "h2:nokey must not yield an indicator");
});

test("DETERMINISM: re-export of the same evidence is byte-identical", () => {
  const ev = evidence();
  const a = JSON.stringify(stixFromEvidence(ev, { now: 42 }));
  const b = JSON.stringify(stixFromEvidence(ev, { now: 42 }));
  assert.equal(a, b);
  // ids are derived from content-free fields, so they are stable regardless of the clock.
  const c = stixFromEvidence(ev, { now: 999 });
  assert.deepEqual(
    stixFromEvidence(ev, { now: 42 }).objects.map((o) => o.id),
    c.objects.map((o) => o.id)
  );
});

test("CONTENT-FREE: the sentinel never reaches the bundle (rows are allowlisted, not spread)", () => {
  const wire = JSON.stringify(stixFromEvidence(evidence(), { now: 1 }));
  assert.ok(!wire.includes(SENTINEL), "a stray content field leaked into the STIX bundle");
});

test("empty evidence still yields a valid, empty bundle", () => {
  const bundle = buildStixBundle([], {});
  assert.equal(bundle.type, "bundle");
  assert.match(bundle.id, ID_RE);
  assert.deepEqual(bundle.objects, []);
});

test("uuidv5 is deterministic and version-5 shaped", () => {
  assert.equal(uuidv5("x"), uuidv5("x"));
  assert.notEqual(uuidv5("x"), uuidv5("y"));
  assert.match(`t--${uuidv5("x")}`, ID_RE);
});

// ---- end-to-end through the compliance CLI's --format stix, with a seeded throwaway HOME ----
function seedHome() {
  const home = mkdtempSync(join(tmpdir(), "moorai-stix-"));
  const dir = join(home, ".moorai");
  mkdirSync(dir, { recursive: true });
  const jsonl = (name, rows) => writeFileSync(join(dir, name), rows.map((r) => JSON.stringify(r)).join("\n") + "\n");
  const now = Date.now();
  jsonl("exposure-ledger.jsonl", [{ category: "API key", riskLevel: "Critical", stage: "mcp", tool: "claude", contentHash: "h2:deadbeefdeadbeef", ts: new Date(now).toISOString(), matchText: SENTINEL }]);
  jsonl("action-audit.jsonl", [{ category: "Info leak", riskLevel: "High", stage: "text", tool: "claude", ts: new Date(now).toISOString(), prompt: SENTINEL }]);
  return home;
}

test("E2E: moorai-compliance --format stix emits a valid, content-free bundle", () => {
  const home = seedHome();
  try {
    const env = { ...process.env, HOME: home, USERPROFILE: home };
    delete env.XDG_CONFIG_HOME; delete env.XDG_STATE_HOME; delete env.MOORAI_RETENTION_DAYS;
    const out = execFileSync(process.execPath, [CLI, "--format", "stix"], { encoding: "utf8", env, maxBuffer: 16 * 1024 * 1024 });
    const bundle = JSON.parse(out);
    assertStructural(bundle);
    assert.ok(bundle.objects.some((o) => o.type === "x-moorai-finding"));
    assert.ok(!out.includes(SENTINEL), "sentinel leaked through the compliance --format stix path");
  } finally { rmSync(home, { recursive: true, force: true }); }
});
