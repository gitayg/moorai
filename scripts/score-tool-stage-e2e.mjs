#!/usr/bin/env node
// END-TO-END reachability of AMTSO vector 3 through the SHIPPED tool stage.
//
//   node scripts/score-tool-stage-e2e.mjs                  # text report
//   node scripts/score-tool-stage-e2e.mjs --json
//   node scripts/score-tool-stage-e2e.mjs --misses         # every attack still not reached, and why
//   node scripts/score-tool-stage-e2e.mjs --shadow-replay  # + the cross-server shadowing measurement
//
// WHY THIS EXISTS ALONGSIDE scripts/score-vectors.mjs. That scorer calls the LIBRARY —
// `engine.scan(sample.text, "tool")` — which answers "do the rules match?". It cannot answer the
// question that actually matters, and its own STAGE_REACHABILITY table said so:
//
//     tool: { reachable: false, via: "NO shipped caller. mcp-proxy/moorai-mcp-guard.mjs scans
//             tools/call ARGUMENTS only and passes tools/list through verbatim, so tool
//             DESCRIPTIONS and SCHEMAS are never scanned in production" }
//
// This harness answers the product question instead. It spawns the REAL proxy
// (mcp-proxy/moorai-mcp-guard.mjs) against a REAL child MCP server, has that server advertise the
// corpus samples as genuine `tools/list` responses, and counts a sample as reached ONLY when a
// content-free alert for that tool arrives at a real HTTP alert sink at stage "tool". Nothing is
// imported from the engine to decide that; the verdict comes off the wire.
//
// The library verdict is computed too, but only as a CONTRAST: a sample the library catches and the
// wire does not is a wiring loss, and is reported as one.
//
// HONEST SCOPE, stated up front:
//   * Only the 50 stage-"tool" samples (38 attacks + 12 benign) go through this harness. The
//     file/index/output samples were already reachable through cli/moorai-hook.mjs and
//     cli/moorai-guard.mjs and are reported unchanged, not re-measured here.
//   * Tool names are made unique per sample so an alert can be attributed to the sample that caused
//     it. The harness asserts this rename does not change the library verdict for any sample, and
//     fails loudly if it ever does.
//   * The default run measures the ONE-SHOT text scan only, and its headline number counts only
//     that. Cross-call detection needs a BEFORE, which a single-snapshot corpus does not have.
//     --shadow-replay adds the one cross-call case the corpus CAN supply honestly (see below);
//     capability expansion and delayed behaviour change are proven end-to-end against an explicit
//     before/after pair in test/mcp-tool-stage.test.mjs instead of against an invented predecessor.
//
// Content-free: emits sample ids, sub-techniques, threat ids and booleans. Never a sample's text.

import { readFileSync, writeFileSync, mkdtempSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { spawn } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import { dirname, join } from "node:path";
import http from "node:http";
import { DETECTORS } from "../data/detectors.js";
import { CONTENT_RULES } from "../data/content-rules.js";
import { DetectionEngine } from "../src/engine.js";
import { toolScanText } from "../mcp-proxy/tool-scan.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const GUARD = join(ROOT, "mcp-proxy", "moorai-mcp-guard.mjs");
const FAKE = join(ROOT, "mcp-proxy", "test-fake-mcp-server.mjs");
const CORPUS = join(ROOT, "test/redteam/vector3-supply-chain.json");
const TOOLS_PER_LIST = 20; // a realistic server's list size, and comfortably inside CAPS.maxTools

// The corpus stores a tool descriptor as TEXT with real newlines inside its JSON strings, which is
// not valid JSON. Re-escape the control characters (preserving them exactly) so it parses back into
// the object an MCP server would actually put on the wire.
const CTRL = new RegExp("[\\u0000-\\u001f]", "g");
export function looseParse(t) {
  return JSON.parse(String(t).replace(CTRL, (c) => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0")));
}

function safeName(id) { return "s_" + String(id).replace(/[^A-Za-z0-9_]/g, "_"); }

async function startSink() {
  const alerts = [];
  const server = http.createServer((req, res) => {
    if (req.url === "/api/alerts" && req.method === "POST") {
      let b = ""; req.on("data", (c) => (b += c));
      req.on("end", () => { try { alerts.push(JSON.parse(b)); } catch { /* ignore */ } res.writeHead(200); res.end("{}"); });
      return;
    }
    res.writeHead(503); res.end(""); // no policy: the DEFAULT posture, which is what we want measured
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  return { alerts, url: `http://127.0.0.1:${server.address().port}`, close: () => new Promise((r) => server.close(r)) };
}

async function driveProxy(home, url, batches, serverLabel = "amtso-vector3") {
  const env = { ...process.env, HOME: home, USERPROFILE: home, MoorAI_SERVER: url, MoorAI_TENANT: "amtso", FAKE_TOOLS_FILE: join(home, "tools.json") };
  delete env.XDG_CONFIG_HOME; delete env.XDG_STATE_HOME;
  writeFileSync(join(home, "tools.json"), JSON.stringify(batches));
  const child = spawn(process.execPath, [GUARD, "--server", serverLabel, "--", process.execPath, FAKE], { cwd: ROOT, stdio: ["pipe", "pipe", "pipe"], env });
  child.stderr.on("data", () => {});
  const seen = new Set();
  let pending = "";
  child.stdout.on("data", (c) => {
    pending += c.toString();
    let nl;
    while ((nl = pending.indexOf("\n")) >= 0) {
      const line = pending.slice(0, nl); pending = pending.slice(nl + 1);
      try { const m = JSON.parse(line); if (m.id != null) seen.add(m.id); } catch { /* partial */ }
    }
  });
  for (let i = 0; i < batches.length; i++) {
    child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id: i + 1, method: "tools/list", params: {} }) + "\n");
    const deadline = Date.now() + 20000;
    while (!seen.has(i + 1) && Date.now() < deadline) await new Promise((r) => setTimeout(r, 20));
    await new Promise((r) => setTimeout(r, 350)); // the observation is deliberately off the forwarding path
  }
  await new Promise((r) => setTimeout(r, 1200));
  try { child.stdin.end(); } catch { /* ignore */ }
  try { child.kill(); } catch { /* ignore */ }
  await new Promise((r) => setTimeout(r, 150));
}

// --shadow-replay. The ONLY cross-call sub-technique that can be measured from a single-snapshot
// corpus without inventing anything: tool-name shadowing IS "the same name, advertised by a second
// server", so the corpus sample supplies both halves and the harness only supplies the second server.
//
// Capability expansion and delayed behaviour change are deliberately NOT replayed here. Their BEFORE
// does not exist in the corpus, and a predecessor I author is a predecessor that differs by
// construction — the measurement would be of my own fixture, not of the product. Those two are
// proven end-to-end in test/mcp-tool-stage.test.mjs against an explicit before/after pair instead.
async function shadowReplay(samples) {
  const sink = await startSink();
  const home = mkdtempSync(join(tmpdir(), "moorai-v3shadow-"));
  mkdirSync(join(home, ".curaiq"), { recursive: true });
  writeFileSync(join(home, ".curaiq", "config.json"), JSON.stringify({ serverUrl: sink.url, tenant: "amtso", installToken: "tok" }));

  const wire = [];
  for (const s of samples) {
    try { wire.push({ ...looseParse(s.text), name: safeName(s.id) }); } catch { /* counted as a parse failure above */ }
  }
  const batches = [];
  for (let i = 0; i < wire.length; i += TOOLS_PER_LIST) batches.push(wire.slice(i, i + TOOLS_PER_LIST));

  await driveProxy(home, sink.url, batches, "corporate-mail"); // first sighting: no signal expected
  const firstPass = sink.alerts.length;
  await driveProxy(home, sink.url, batches, "helper-utils");   // a SECOND server claims the same names

  const shadowed = new Set();
  for (const a of sink.alerts.slice(firstPass)) {
    if (a.stage === "tool" && /shadow/i.test(a.category || "")) shadowed.add(String(a.tool || "").replace(/^desktop:/, ""));
  }
  await sink.close();
  rmSync(home, { recursive: true, force: true });
  return samples.filter((s) => shadowed.has(safeName(s.id))).map((s) => s.id);
}

async function run() {
  const args = process.argv.slice(2);
  const asJson = args.includes("--json");
  const showMisses = args.includes("--misses");
  const doShadow = args.includes("--shadow-replay");

  const corpus = JSON.parse(readFileSync(CORPUS, "utf8"));
  const all = [...corpus.attacks.map((s) => ({ ...s, shouldDetect: s.shouldDetect !== false })), ...(corpus.benign || []).map((s) => ({ ...s, shouldDetect: false }))];
  const toolSamples = all.filter((s) => (s.stage || "prompt") === "tool");

  const threats = JSON.parse(readFileSync(join(ROOT, "data/threats.json"), "utf8"));
  const engine = new DetectionEngine(threats, DETECTORS, CONTENT_RULES);

  // Build the wire tools, and verify the rename is verdict-neutral before trusting any number.
  const rows = [];
  const renameDrift = [];
  const wire = [];
  for (const s of toolSamples) {
    let obj = null, parseError = null;
    try { obj = looseParse(s.text); } catch (e) { parseError = e.message; }
    const libraryText = engine.scan(s.text, "tool").map((f) => f.detectorId).sort().join(",");
    let composed = "", renamed = "";
    if (obj) {
      composed = engine.scan(toolScanText(obj), "tool").map((f) => f.detectorId).sort().join(",");
      const r = { ...obj, name: safeName(s.id) };
      renamed = engine.scan(toolScanText(r), "tool").map((f) => f.detectorId).sort().join(",");
      if (renamed !== composed) renameDrift.push(s.id);
      wire.push(r);
    }
    rows.push({
      id: s.id, subTechnique: s.subTechnique || s.family, shouldDetect: s.shouldDetect,
      wireName: obj ? safeName(s.id) : null,
      parseError,
      libraryDetected: libraryText.length > 0,
      libraryDetectors: libraryText ? libraryText.split(",") : [],
      composedDetected: composed.length > 0,
      e2eDetected: false, e2eThreats: []
    });
  }

  const sink = await startSink();
  const home = mkdtempSync(join(tmpdir(), "moorai-v3e2e-"));
  mkdirSync(join(home, ".curaiq"), { recursive: true });
  writeFileSync(join(home, ".curaiq", "config.json"), JSON.stringify({ serverUrl: sink.url, tenant: "amtso", installToken: "tok" }));

  const batches = [];
  for (let i = 0; i < wire.length; i += TOOLS_PER_LIST) batches.push(wire.slice(i, i + TOOLS_PER_LIST));
  await driveProxy(home, sink.url, batches);
  await sink.close();

  const byTool = new Map();
  for (const a of sink.alerts) {
    if (a.stage !== "tool") continue;
    const n = String(a.tool || "").replace(/^desktop:/, "");
    if (!byTool.has(n)) byTool.set(n, []);
    byTool.get(n).push(a);
  }
  for (const r of rows) {
    const hits = r.wireName ? byTool.get(r.wireName) || [] : [];
    r.e2eDetected = hits.length > 0;
    r.e2eThreats = [...new Set(hits.map((h) => h.threatId))];
  }

  // Content-free check on the live wire, not on intent: nothing posted may echo a sample's text.
  const blob = JSON.stringify(sink.alerts);
  const leaks = [];
  for (const s of toolSamples) {
    for (const frag of String(s.text).split(/[\s"{}:,]+/).filter((w) => w.length >= 12)) {
      if (blob.includes(frag)) { leaks.push({ id: s.id, len: frag.length }); break; }
    }
  }
  rmSync(home, { recursive: true, force: true });

  const shadowSamples = toolSamples.filter((s) => s.shouldDetect && (s.subTechnique || s.family) === "tool-name-shadowing");
  const shadowReached = doShadow ? await shadowReplay(shadowSamples) : null;

  const atk = rows.filter((r) => r.shouldDetect);
  const ben = rows.filter((r) => !r.shouldDetect);
  const nonToolAttacks = all.filter((s) => s.shouldDetect && (s.stage || "prompt") !== "tool").length;
  const out = {
    corpus: "test/redteam/vector3-supply-chain.json",
    totalAttacks: all.filter((s) => s.shouldDetect).length,
    toolStageAttacks: atk.length,
    toolStageBenign: ben.length,
    nonToolAttacks,
    before: { toolStageReachable: 0, note: "grep -rn 'decideText([^)]*\"tool\"' cli/ -> zero. No shipped caller fed the tool stage." },
    after: {
      libraryDetectable: atk.filter((r) => r.libraryDetected).length,
      reachedEndToEnd: atk.filter((r) => r.e2eDetected).length,
      wiringLoss: atk.filter((r) => r.libraryDetected && !r.e2eDetected).map((r) => r.id),
      falsePositivesEndToEnd: ben.filter((r) => r.e2eDetected).map((r) => r.id)
    },
    shadowReplay: shadowReached && {
      samples: shadowSamples.length,
      flaggedOnSecondServer: shadowReached.length,
      ids: shadowReached,
      newlyReachable: shadowReached.filter((id) => !rows.find((r) => r.id === id).e2eDetected)
    },
    parseFailures: rows.filter((r) => r.parseError).map((r) => ({ id: r.id, parseError: r.parseError })),
    renameDrift,
    contentLeaks: leaks,
    stillUnreachable: atk.filter((r) => !r.e2eDetected).map((r) => ({ id: r.id, subTechnique: r.subTechnique, libraryDetected: r.libraryDetected })),
    bySubTechnique: [...new Set(atk.map((r) => r.subTechnique))].sort().map((k) => {
      const g = atk.filter((r) => r.subTechnique === k);
      return { subTechnique: k, attacks: g.length, library: g.filter((r) => r.libraryDetected).length, e2e: g.filter((r) => r.e2eDetected).length };
    })
  };

  if (asJson) { console.log(JSON.stringify(out, null, 2)); return; }

  console.log(`\n=== AMTSO vector 3 — tool stage, measured END-TO-END through mcp-proxy/moorai-mcp-guard.mjs ===`);
  console.log(`corpus: ${out.corpus}   attacks: ${out.totalAttacks} (tool stage ${out.toolStageAttacks}, other stages ${out.nonToolAttacks})\n`);
  console.log(`  BEFORE  tool-stage attacks reachable from any shipped harness   0 / ${out.toolStageAttacks}`);
  console.log(`  AFTER   detectable by the rules (library API)                  ${String(out.after.libraryDetectable).padStart(2)} / ${out.toolStageAttacks}`);
  console.log(`  AFTER   ALERTED on the wire through the real proxy             ${String(out.after.reachedEndToEnd).padStart(2)} / ${out.toolStageAttacks}`);
  console.log(`  wiring loss (rules match, product silent)                      ${out.after.wiringLoss.length}${out.after.wiringLoss.length ? " -> " + out.after.wiringLoss.join(", ") : ""}`);
  console.log(`  false positives on benign tool metadata (end-to-end)           ${out.after.falsePositivesEndToEnd.length} / ${out.toolStageBenign}`);
  console.log(`  corpus samples that would not parse as a tool descriptor       ${out.parseFailures.length}`);
  console.log(`  rename-neutrality violations (harness validity)                ${out.renameDrift.length}`);
  console.log(`  content leaked into the alert stream                           ${out.contentLeaks.length}`);
  if (out.shadowReplay) {
    console.log(`\n  --shadow-replay (the same corpus tool advertised by a SECOND server):`);
    console.log(`    flagged as shadowing on the second sighting                  ${out.shadowReplay.flaggedOnSecondServer} / ${out.shadowReplay.samples}`);
    console.log(`    of those, NOT already caught by the one-shot text scan       ${out.shadowReplay.newlyReachable.length}${out.shadowReplay.newlyReachable.length ? " -> " + out.shadowReplay.newlyReachable.join(", ") : ""}`);
  }
  console.log(`\n  per sub-technique (attacks / library / end-to-end):`);
  for (const g of out.bySubTechnique) console.log(`    ${g.subTechnique.padEnd(30)} ${String(g.attacks).padStart(3)}   ${String(g.library).padStart(3)}   ${String(g.e2e).padStart(3)}`);
  if (showMisses) {
    console.log(`\n  still unreachable (${out.stillUnreachable.length}):`);
    for (const m of out.stillUnreachable) console.log(`    ${m.id.padEnd(18)} ${m.subTechnique.padEnd(30)} ${m.libraryDetected ? "RULES MATCH — wiring loss" : "no rule matches this sample"}`);
  }
  console.log("");
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) run();
