// Per-file runner:  node --test --import ./test/hermetic-env.mjs test/model-scan-posture.test.mjs
//
// The static model scan OFF the hook path: the model-download detector (#76, report-only, Bash only),
// the download queue the hook writes, the drain that scans a settled download, the opt-in store
// inventory, the content-free heartbeat field and alerts, and the end-to-end hand-off through the real
// hook and its detached `modelscan` worker. Fixtures are synthetic; no network beyond a loopback console
// stand-in; nothing is downloaded.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, utimesSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import http from "node:http";
import { generateKeyPairSync, sign as edSign } from "node:crypto";
import { DETECTORS } from "../data/detectors.js";
import { CONTENT_RULES } from "../data/content-rules.js";
import { DetectionEngine } from "../src/engine.js";
import { modelDownloads } from "../data/model-download.js";
import { downloadTargets, queueModelDownload, readQueue, modelScanDue, QUEUE_FILE, SETTLE_MS } from "../cli/model-scan-queue.mjs";
import { modelScanPosture, modelScanPolicy, MODEL_SCAN_STATE } from "../cli/model-scan-posture.mjs";
import { scanModelFile, sha256File } from "../cli/model-scan.mjs";
import { inventoryPosture } from "../cli/agent-posture.mjs";
import { policyCanonical, policyDigest, POLICY_SIG_VERSION, publicKeyId } from "../cli/hook-core.mjs";
import { PICKLES, torchZip, ggufModel, SSTI_TEMPLATE, CLEAN_TEMPLATE } from "./model-scan-fixtures.mjs";
import { rmTree } from "./fs-cleanup.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const HOOK = join(ROOT, "cli", "moorai-hook.mjs");
const threats = JSON.parse(readFileSync(join(ROOT, "data/threats.json"), "utf8"));
const engine = new DetectionEngine(threats, DETECTORS, CONTENT_RULES);
const det = DETECTORS.find((d) => d.detectorId === "model-download");
const fires = (text, ctx = { shell: "sh" }) => !!engine._matchDetector(text, det, ctx);
function sandbox(t) { const d = mkdtempSync(join(tmpdir(), "moorai-model-posture-")); t.after(() => rmTree(d)); return d; }
function put(p, buf) { mkdirSync(dirname(p), { recursive: true }); writeFileSync(p, buf); return p; }
const ago = (p, ms) => { const s = (Date.now() - ms) / 1000; utimesSync(p, s, s); };

// ---- the detector ----
const POSITIVE = [
  "ollama pull llama3.2",
  "OLLAMA_HOST=127.0.0.1 ollama pull qwen2.5:7b",
  "huggingface-cli download TheBloke/Llama-2-7B-GGUF llama-2-7b.Q4_K_M.gguf --local-dir ./models",
  "hf download openai-community/gpt2",
  "cd repo && git lfs pull",
  "git clone https://huggingface.co/microsoft/phi-2",
  "curl -L -o model.pt https://example.com/files/model.pt",
  "curl -LO https://example.com/w/pytorch_model.bin",
  "wget https://huggingface.co/x/y/resolve/main/model.safetensors?download=true",
  "wget -P ~/models https://example.com/m.gguf",
  "curl -L https://example.com/clf.pkl -o /tmp/clf.pkl"
];
const NEGATIVE = [
  "ollama list", "ollama run llama3", "ollama push me/model", "huggingface-cli login", "hf upload me/m ./m",
  "git clone https://github.com/org/repo", "git lfs install", "curl https://example.com/index.html",
  "curl https://example.com/model.pt", // to stdout: no file lands under a name
  "curl -o - https://example.com/model.pt | sha256sum",
  "wget https://example.com/readme.md", "echo 'run ollama pull llama3 later'"
];
for (const c of POSITIVE) test(`model-download fires: ${c}`, () => assert.ok(fires(c), c));
for (const c of NEGATIVE) test(`model-download silent: ${c}`, () => assert.ok(!fires(c), c));
test("model-download: only on a shell command; yields to model-unsafe-load; maps to #76 report-only", () => {
  assert.ok(!fires("ollama pull llama3", {}), "a prompt mentioning the command is not a download");
  assert.ok(!fires("ollama pull llama3", { shell: "ps" }));
  assert.ok(!fires("wget https://x.example/m.pt && python -c \"import torch; torch.load('m.pt', weights_only=False)\""), "the load detector owns that finding");
  assert.equal(det.threatId, 76);
  assert.equal(det.mode, "notify");
  const t76 = threats.threats.find((t) => t.id === 76);
  assert.equal(t76.atlas, "AML.T0011.000");
  const f = engine.scan("ollama pull llama3", "prompt", { shell: "sh" }).find((x) => x.threat.id === 76);
  assert.equal(f.detectorId, "model-download");
});

// ---- targets and the queue ----
test("downloadTargets resolves each kind against cwd, home and the store variables", () => {
  const home = "/h", cwd = "/w";
  const env = { OLLAMA_MODELS: "/srv/ollama" };
  const t = (c, e = env) => downloadTargets(c, { cwd, home, env: e, platform: "darwin" }).map((x) => x.path);
  assert.deepEqual(t("ollama pull llama3"), ["/srv/ollama"]);
  assert.deepEqual(t("ollama pull llama3", {}), ["/h/.ollama/models"]);
  assert.deepEqual(t("hf download a/b"), ["/h/.cache/huggingface/hub"]);
  assert.deepEqual(t("hf download a/b", { HF_HOME: "/hfh" }), ["/hfh/hub"]);
  assert.deepEqual(t("huggingface-cli download a/b --local-dir=out"), ["/w/out"]);
  assert.deepEqual(t("git -C /r lfs pull"), ["/r"]);
  assert.deepEqual(t("git clone https://hf.co/org/m.git"), ["/w/m"]);
  assert.deepEqual(t("curl -L -o ~/m/x.pt https://e.example/x.pt"), ["/h/m/x.pt"]);
  assert.deepEqual(t("curl -LO --output-dir d https://e.example/a/y.gguf"), ["/w/d/y.gguf"]);
  assert.deepEqual(t("wget -O z.onnx https://e.example/z.onnx"), ["/w/z.onnx"]);
  assert.deepEqual(modelDownloads("curl https://e.example/x.pt"), []);
});
test("queue: the hook appends targets; the worker is due only after the settle time and at most once per retry window", (t) => {
  const st = sandbox(t);
  assert.equal(modelScanDue({ stateDir: st }), false, "no queue: one stat and no spawn");
  const now = Date.now();
  assert.equal(queueModelDownload("curl -L -o m.pt https://e.example/m.pt", { cwd: "/w", stateDir: st, now }), 1);
  assert.equal(queueModelDownload("ls -la", { cwd: "/w", stateDir: st, now }), 0);
  assert.deepEqual(readQueue(st).map((x) => [x.kind, x.path, x.isFile]), [["curl-model", "/w/m.pt", true]]);
  assert.equal(modelScanDue({ stateDir: st, now: now + 1000 }), false, "not settled yet");
  assert.equal(modelScanDue({ stateDir: st, now: now + SETTLE_MS + 1 }), true);
  assert.equal(modelScanDue({ stateDir: st, now: now + SETTLE_MS + 2 }), false, "spawned moments ago");
});

// ---- the drain ----
function queued(st, path, { isFile = true, age = 2 * SETTLE_MS } = {}) {
  mkdirSync(st, { recursive: true });
  writeFileSync(join(st, QUEUE_FILE), JSON.stringify({ items: [{ kind: "curl-model", path, isFile, ts: Date.now() - age }] }));
}
test("drain: a settled malicious download raises one content-free #76 alert; the queue entry is removed; the second run is silent", (t) => {
  const d = sandbox(t), st = join(d, ".moorai");
  const p = put(join(d, "proj", "evil.pt"), torchZip(PICKLES.osSystem));
  ago(p, 2 * SETTLE_MS);
  queued(st, p);
  const r = modelScanPosture({ policy: null, home: d, stateDir: st });
  assert.ok(r);
  assert.equal(r.field.inventory, "off");
  assert.equal(r.field.scanned, 1);
  assert.equal(r.field.unsafe, 1);
  assert.equal(r.field.byFormat["pytorch-zip"], 1);
  assert.equal(r.field.byClass["dangerous-import"], 1);
  assert.equal(r.alerts.length, 1);
  const a = r.alerts[0];
  assert.equal(a.threatId, 76);
  assert.equal(a.reasonCode, "MODEL_FILE_UNSAFE");
  assert.equal(a.riskLevel, "Critical");
  assert.equal(a.tool, "download:model-scan");
  assert.equal(a.modelFile.sha256, sha256File(p));
  assert.deepEqual(a.modelFile.classes, ["dangerous-import"]);
  const wire = JSON.stringify([r.field, r.alerts]);
  assert.ok(!wire.includes(d) && !wire.includes("evil") && !wire.includes("os.system"), "no path, file name or detail leaves");
  r.commit([]);
  assert.deepEqual(readQueue(st), []);
  assert.ok(!readFileSync(join(st, MODEL_SCAN_STATE), "utf8").includes("evil.pt"), "the local memory keys by hash, not by path");
  queued(st, p);
  const r2 = modelScanPosture({ policy: null, home: d, stateDir: st });
  assert.equal(r2.alerts.length, 0, "alerted once per file content");
  assert.equal(r2.field.unsafe, 1, "still counted");
});
test("drain: a download still being written is kept for later; a failed alert post is raised again", (t) => {
  const d = sandbox(t), st = join(d, ".moorai");
  const p = put(join(d, "m.pt"), torchZip(PICKLES.osSystem));
  queued(st, p);
  const r = modelScanPosture({ home: d, stateDir: st });
  assert.equal(r.field.scanned, 0);
  assert.equal(r.field.pendingDownloads, 1);
  r.commit([]);
  assert.equal(readQueue(st).length, 1);
  ago(p, 2 * SETTLE_MS);
  const r2 = modelScanPosture({ home: d, stateDir: st });
  assert.equal(r2.alerts.length, 1);
  r2.commit(r2.alerts);
  queued(st, p);
  assert.equal(modelScanPosture({ home: d, stateDir: st }).alerts.length, 1, "the console never accepted it");
});
test("drain: a partial Hugging Face download (*.incomplete) holds the entry even when other files settled", (t) => {
  const d = sandbox(t), st = join(d, ".moorai");
  const dir = join(d, "hub");
  const done = put(join(dir, "models--a--b", "snapshots", "r", "model.safetensors"), PICKLES.osSystem);
  const part = put(join(dir, "models--a--b", "blobs", "abc.incomplete"), Buffer.alloc(8));
  ago(done, 2 * SETTLE_MS); ago(part, 2 * SETTLE_MS);
  queued(st, dir, { isFile: false });
  const r = modelScanPosture({ home: d, stateDir: st });
  assert.equal(r.field.scanned, 0);
  assert.equal(r.field.pendingDownloads, 1);
});
test("policy: downloads off ignores the queue; allowHashes makes a file 'allowed' with no alert; the per-run budget leaves the rest pending", (t) => {
  const d = sandbox(t), st = join(d, ".moorai");
  const p = put(join(d, "m.pt"), torchZip(PICKLES.osSystem));
  ago(p, 2 * SETTLE_MS);
  queued(st, p);
  assert.equal(modelScanPosture({ policy: { modelScan: { downloads: "off" } }, home: d, stateDir: st }), null);
  const h = sha256File(p);
  const r = modelScanPosture({ policy: { modelScan: { allowHashes: [h.toUpperCase(), "not-a-hash"] } }, home: d, stateDir: st });
  assert.equal(r.field.allowed, 1);
  assert.equal(r.alerts.length, 0);
  const st2 = join(d, ".m2");
  queued(st2, p);
  const tiny = modelScanPosture({ policy: { modelScan: { maxGiBPerRun: 1e-9 } }, home: d, stateDir: st2 });
  assert.equal(tiny.field.pending, 1);
  assert.equal(tiny.field.pendingDownloads, 1);
  assert.equal(modelScanPolicy({ modelScan: { inventory: "yes" } }).inventory, "off", "only the exact word opts in");
});

// ---- the store inventory ----
test("inventory (opt-in): scans the model stores, remembers unchanged files, and adds modelFiles to inventoryPosture only when it ran", async (t) => {
  const d = sandbox(t), st = join(d, ".moorai");
  put(join(d, ".ollama", "models", "blobs", "sha256-aaa"), ggufModel(SSTI_TEMPLATE));
  put(join(d, ".ollama", "models", "blobs", "sha256-bbb"), ggufModel(CLEAN_TEMPLATE));
  put(join(d, ".ollama", "models", "manifests", "registry.ollama.ai", "library", "x", "latest"), "{}");
  put(join(d, ".lmstudio", "models", "pub", "m", "m.safetensors"), PICKLES.benignDict);
  let calls = 0;
  const spy = (p, o) => { calls++; return scanModelFile(p, o); };
  const policy = { modelScan: { inventory: "scan" } };
  const r = modelScanPosture({ policy, home: d, env: {}, platform: "darwin", stateDir: st, scan: spy });
  assert.equal(r.field.inventory, "scan");
  assert.equal(r.field.stores, 2);
  assert.equal(r.field.scanned, 3);
  assert.equal(r.field.unsafe, 1);
  assert.equal(r.field.byFormat.gguf, 2);
  assert.equal(r.alerts.length, 1);
  assert.equal(r.alerts[0].tool, "inventory:model-scan");
  r.commit([]);
  calls = 0;
  const again = modelScanPosture({ policy, home: d, env: {}, platform: "darwin", stateDir: st, scan: spy });
  assert.equal(calls, 0, "unchanged files are not re-read");
  assert.equal(again.field.unsafe, 1);
  assert.equal(again.alerts.length, 0);
  assert.equal(modelScanPosture({ policy: null, home: d, stateDir: st }), null, "inventory off and no queue: nothing runs");

  const opts = { home: d, stateDir: join(d, ".moorai-inv"), sample: () => ({ sockets: [], source: "test" }), resolve: false, decoys: false };
  const off = await inventoryPosture({ ...opts, policy: null });
  assert.ok(!("modelFiles" in off.fields));
  const on = await inventoryPosture({ ...opts, policy });
  assert.equal(on.fields.modelFiles.unsafe, 1);
  assert.ok(on.alerts.some((a) => a.reasonCode === "MODEL_FILE_UNSAFE"));
  assert.ok(existsSync(join(d, ".moorai-inv", MODEL_SCAN_STATE)), "committed with the rest of the inventory memory");
});

// ---- end to end: the real hook, its detached worker, a stand-in console ----
const TENANT = "model-scan";
const key = generateKeyPairSync("ed25519");
function signed(policy) {
  const iat = new Date().toISOString();
  const sig = edSign(null, Buffer.from(policyCanonical({ v: POLICY_SIG_VERSION, tenant: TENANT, iat, digest: policyDigest(policy) })), key.privateKey).toString("base64");
  return JSON.stringify({ ...policy, policySig: { v: POLICY_SIG_VERSION, alg: "ed25519", tenant: TENANT, iat, sig } });
}
const PUBKEY = JSON.stringify({ tenant: TENANT, alg: "ed25519", publicKey: publicKeyId(key.publicKey) });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function until(fn, ms = 15000) { const end = Date.now() + ms; while (Date.now() < end) { if (fn()) return true; await sleep(50); } return false; }
async function consoleStub(t, policy) {
  const alerts = [], beats = [];
  const srv = http.createServer((req, res) => {
    let b = "";
    req.on("data", (c) => (b += c));
    req.on("end", () => {
      if (req.url === "/api/agent-posture") { beats.push(Date.now()); res.writeHead(201); return res.end("{}"); }
      if (req.method === "POST" && req.url === "/api/alerts") { try { alerts.push(JSON.parse(b)); } catch { /* batch */ } res.writeHead(201); return res.end("{}"); }
      if (req.url.startsWith("/api/policy/pubkey")) { res.writeHead(200, { "Content-Type": "application/json" }); return res.end(PUBKEY); }
      if (req.url.startsWith("/api/policy")) { res.writeHead(200, { "Content-Type": "application/json" }); return res.end(policy); }
      res.writeHead(201); res.end("{}");
    });
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  t.after(() => new Promise((r) => srv.close(r)));
  return { url: `http://127.0.0.1:${srv.address().port}`, alerts, beats };
}
function runHook(home, input) {
  return new Promise((res, rej) => {
    const c = spawn(process.execPath, [HOOK], { cwd: home, env: { PATH: process.env.PATH || "/usr/bin:/bin", HOME: home, USERPROFILE: home }, stdio: ["pipe", "pipe", "pipe"] });
    let out = "", err = "";
    c.stdout.on("data", (x) => (out += x));
    c.stderr.on("data", (x) => (err += x));
    c.on("error", rej);
    c.on("close", (code) => (code === 0 ? res(out) : rej(new Error(`hook exit ${code}: ${err}`))));
    c.stdin.end(JSON.stringify(input));
  });
}
test("end to end: the hook reports a model download (#76) and queues it without scanning; a later event's worker scans the file and alerts", async (t) => {
  const c = await consoleStub(t, signed({ captureTier: "content-free" }));
  const home = sandbox(t);
  const st = join(home, ".moorai");
  mkdirSync(st, { recursive: true });
  writeFileSync(join(st, "config.json"), JSON.stringify({ serverUrl: c.url, tenant: TENANT, installToken: "tok-model-scan" }));
  const proj = join(home, "proj");
  mkdirSync(proj, { recursive: true });
  const out = await runHook(home, { hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "curl -L -o evil.pt https://models.example/evil.pt" }, session_id: "s-ms", cwd: proj });
  assert.ok(!/"permissionDecision":"deny"/.test(out), "report-only: the download is not blocked");
  assert.ok(await until(() => c.alerts.some((a) => a.threatId === 76)), "the #76 report reached the console");
  const q = readQueue(st);
  assert.deepEqual(q.map((x) => x.path), [join(proj, "evil.pt")]);
  assert.ok(!existsSync(join(st, MODEL_SCAN_STATE)), "nothing was scanned on PreToolUse");
  // The day's posture beat (spawned by that first event) also drains the queue. Let it finish first, so
  // what scans the file below can only be the modelscan worker the next event spawns.
  assert.ok(await until(() => c.beats.length > 0 && existsSync(join(st, "inventory-detectors.json"))), "the day's posture beat finished");
  // The download lands (simulated), and both it and the queue entry are past the settle time.
  const p = put(join(proj, "evil.pt"), torchZip(PICKLES.osSystem));
  ago(p, 2 * SETTLE_MS);
  writeFileSync(join(st, QUEUE_FILE), JSON.stringify({ items: q.map((x) => ({ ...x, ts: Date.now() - 2 * SETTLE_MS })) }));
  await runHook(home, { hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "ls" }, session_id: "s-ms", cwd: proj });
  assert.ok(await until(() => c.alerts.some((a) => a.reasonCode === "MODEL_FILE_UNSAFE")), "the detached worker scanned the download and alerted");
  const a = c.alerts.find((x) => x.reasonCode === "MODEL_FILE_UNSAFE");
  assert.equal(a.threatId, 76);
  assert.equal(a.modelFile.sha256, sha256File(p));
  assert.ok(!JSON.stringify(a).includes("evil.pt"));
  assert.ok(await until(() => readQueue(st).length === 0), "the queue entry is gone");
});
