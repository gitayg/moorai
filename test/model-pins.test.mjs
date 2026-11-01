// Per-file runner:  node --test --import ./test/hermetic-env.mjs test/model-pins.test.mjs
//
// Model provenance pinning (cli/model-pins.mjs, cli/model-pins-targets.mjs, cli/model-pins-hook.mjs): the
// pin policy and who may set it, the not-approved verdict next to the static verdicts, the background scan
// paths (queue and store), the hook's load check by mode, and one load form end to end through the real
// hook. Fixtures are synthetic; nothing is downloaded.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, utimesSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import http from "node:http";
import { generateKeyPairSync, sign as edSign, createHash } from "node:crypto";
import { resolveModelPins, applyPins, approvalOf, fileIdentity, readPinCache, PIN_CACHE_FILE } from "../cli/model-pins.mjs";
import { modelLoadTargets, ollamaBlobs } from "../cli/model-pins-targets.mjs";
import { modelPinCheck } from "../cli/model-pins-hook.mjs";
import { modelScanPosture } from "../cli/model-scan-posture.mjs";
import { readQueue, QUEUE_FILE, SETTLE_MS } from "../cli/model-scan-queue.mjs";
import { scanModelFile, sha256File } from "../cli/model-scan.mjs";
import { run as scanCli } from "../cli/model-scan-cli.mjs";
import { policyCanonical, policyDigest, POLICY_SIG_VERSION, publicKeyId } from "../cli/hook-core.mjs";
import { PICKLES, torchZip, ggufModel, CLEAN_TEMPLATE } from "./model-scan-fixtures.mjs";
import { rmTree } from "./fs-cleanup.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const HOOK = join(ROOT, "cli", "moorai-hook.mjs");
function sandbox(t) { const d = mkdtempSync(join(tmpdir(), "moorai-model-pins-")); t.after(() => rmTree(d)); return d; }
function put(p, buf) { mkdirSync(dirname(p), { recursive: true }); writeFileSync(p, buf); return p; }
const ago = (p, ms) => { const s = (Date.now() - ms) / 1000; utimesSync(p, s, s); };
const sha = (buf) => createHash("sha256").update(buf).digest("hex");
const GOOD = ggufModel(CLEAN_TEMPLATE);
const OTHER = Buffer.concat([ggufModel(CLEAN_TEMPLATE), Buffer.from("different weights")]);
const EVIL = torchZip(PICKLES.osSystem);
const quiet = { warn: () => {} };

// ---- the policy: who may set it, and how it fails ----
test("policy: off by default; admin binding wins wholesale over the signed policy; pins alone mean report", () => {
  assert.equal(resolveModelPins(null, { admin: null, ...quiet }).mode, "off");
  assert.equal(resolveModelPins({ captureTier: "content-free" }, quiet).mode, "off");
  const pol = { modelPinMode: "block", modelPins: [{ sha256: "a".repeat(64), name: "approved" }] };
  const r = resolveModelPins(pol, quiet);
  assert.deepEqual([r.mode, r.source, r.invalid, [...r.pins.keys()]], ["block", "policy", false, ["a".repeat(64)]]);
  const adm = resolveModelPins(pol, { admin: { modelPinMode: "ask", modelPins: [{ sha256: "b".repeat(64) }] }, ...quiet });
  assert.deepEqual([adm.mode, adm.source, [...adm.pins.keys()]], ["ask", "admin", ["b".repeat(64)]], "the admin list is not widened by the policy's");
  assert.equal(resolveModelPins({ modelPins: [{ sha256: "c".repeat(64) }] }, quiet).mode, "report");
  assert.ok(resolveModelPins({ modelPinMode: "report", modelPins: [{ sha256: `sha256:${"D".repeat(64)}` }] }, quiet).pins.has("d".repeat(64)), "sha256: prefix and case are normalised");
});

test("policy: an invalid pin policy fails closed", () => {
  const warns = [];
  const w = { warn: (m) => warns.push(m) };
  for (const bad of ["Block", "enforce", "", 1, null, true]) {
    const r = resolveModelPins({ modelPinMode: bad, modelPins: [{ sha256: "a".repeat(64) }] }, w);
    assert.deepEqual([r.mode, r.invalid], ["block", true], `mode ${JSON.stringify(bad)}`);
  }
  const notList = resolveModelPins({ modelPinMode: "block", modelPins: { sha256: "a".repeat(64) } }, w);
  assert.deepEqual([notList.mode, notList.pins.size, notList.invalid], ["block", 0, true], "a non-list pins nothing");
  const badEntries = resolveModelPins({ modelPinMode: "ask", modelPins: [{ sha256: "xyz" }, "a".repeat(64), { sha: "a".repeat(64) }, { sha256: "e".repeat(64) }] }, w);
  assert.deepEqual([badEntries.mode, [...badEntries.pins.keys()], badEntries.invalid], ["ask", ["e".repeat(64)], true], "a malformed entry is skipped, never a match");
  assert.equal(approvalOf("a".repeat(64), badEntries), "not-approved");
  assert.ok(warns.length && warns.every((m) => !m.includes("a".repeat(64)) && !m.includes("enforce")), "warnings name the key, never the value");
});

// ---- the verdict ----
test("verdict: a pinned file passes; an unpinned one is not-approved; a pinned unsafe file stays unsafe; no hash is unverified", (t) => {
  const d = sandbox(t);
  const good = put(join(d, "good.gguf"), GOOD), other = put(join(d, "other.gguf"), OTHER), evil = put(join(d, "evil.pt"), EVIL);
  const cfg = resolveModelPins({ modelPinMode: "block", modelPins: [{ sha256: sha(GOOD) }, { sha256: sha(EVIL) }] }, quiet);
  const g = applyPins(scanModelFile(good), cfg);
  assert.deepEqual([g.verdict, g.pin], ["clean", "pinned"]);
  const o = applyPins(scanModelFile(other), cfg);
  assert.deepEqual([o.verdict, o.pin], ["not-approved", "not-approved"]);
  const e = applyPins(scanModelFile(evil), cfg);
  assert.deepEqual([e.verdict, e.pin], ["unsafe", "pinned"], "a pin never overrides a static finding");
  const e2 = applyPins(scanModelFile(evil), resolveModelPins({ modelPinMode: "block", modelPins: [] }, quiet));
  assert.deepEqual([e2.verdict, e2.pin], ["unsafe", "not-approved"], "unsafe is not replaced by not-approved");
  const big = applyPins({ verdict: "unscanned", sha256: null }, cfg);
  assert.deepEqual([big.verdict, big.pin], ["not-approved", "unverified"]);
  const off = applyPins(scanModelFile(other), resolveModelPins(null, quiet));
  assert.deepEqual([off.verdict, off.pin], ["clean", undefined], "pinning off changes nothing");
});

test("CLI: --pin and the policy file's modelPins; NOT-APPROVED exits 1; a pinned unsafe file prints UNSAFE", (t) => {
  const d = sandbox(t);
  const good = put(join(d, "m", "good.gguf"), GOOD);
  put(join(d, "m", "other.gguf"), OTHER);
  const evil = put(join(d, "e", "evil.pt"), EVIL);
  const cap = () => { let s = ""; return { out: (x) => (s += x), err: (x) => (s += x), text: () => s }; };
  let c = cap();
  assert.equal(scanCli([good, "--pin", sha(GOOD)], c), 0);
  assert.match(c.text(), /\(pinned\)/);
  c = cap();
  assert.equal(scanCli([join(d, "m"), "--pin", sha(GOOD)], c), 1);
  assert.match(c.text(), /NOT-APPROVED/);
  assert.match(c.text(), /1 not approved/);
  const polFile = put(join(d, "pol.json"), JSON.stringify({ modelPinMode: "block", modelPins: [{ sha256: sha(EVIL) }] }));
  c = cap();
  assert.equal(scanCli([evil, "--policy", polFile], c), 1);
  assert.match(c.text(), /^UNSAFE/m);
  assert.equal(scanCli([good, "--pin", "nothex"], cap()), 2);
});

// ---- the background paths: the download queue and the store scan ----
function queued(st, items) { mkdirSync(st, { recursive: true }); writeFileSync(join(st, QUEUE_FILE), JSON.stringify({ items })); }
test("queue: an unpinned download raises one MODEL_NOT_APPROVED alert with the hash prefix only; a pinned one none; a pinned unsafe one stays MODEL_FILE_UNSAFE", (t) => {
  const d = sandbox(t), st = join(d, ".moorai");
  const good = put(join(d, "dl", "good.gguf"), GOOD), other = put(join(d, "dl2", "other.gguf"), OTHER), evil = put(join(d, "dl3", "evil.pt"), EVIL);
  for (const p of [good, other, evil]) ago(p, 2 * SETTLE_MS);
  const ts = Date.now() - 2 * SETTLE_MS;
  queued(st, [good, other, evil].map((path) => ({ kind: "curl-model", path, isFile: true, ts })));
  const policy = { modelPinMode: "block", modelPins: [{ sha256: sha(GOOD) }, { sha256: sha(EVIL) }] };
  const r = modelScanPosture({ policy, home: d, stateDir: st, admin: null });
  assert.equal(r.field.pinMode, "block");
  assert.equal(r.field["not-approved"], 1);
  assert.equal(r.field.unsafe, 1);
  assert.equal(r.field.clean, 1);
  const na = r.alerts.filter((a) => a.reasonCode === "MODEL_NOT_APPROVED");
  assert.equal(na.length, 1);
  assert.equal(na[0].threatId, 76);
  assert.equal(na[0].modelFile.hashPrefix, sha(OTHER).slice(0, 12));
  assert.equal(na[0].modelFile.pinned, false);
  assert.equal(na[0].modelFile.format, "gguf");
  const wire = JSON.stringify(na);
  assert.ok(!wire.includes(sha(OTHER)) && !wire.includes(d) && !wire.includes("other"), "no full hash, path or name");
  const un = r.alerts.find((a) => a.reasonCode === "MODEL_FILE_UNSAFE");
  assert.equal(un.modelFile.pinned, true, "pinned and still unsafe");
  r.commit([]);
  assert.deepEqual(readQueue(st), []);
  // The scan filled the hook's hash cache, keyed by identity, not by path.
  const cache = readPinCache(st);
  assert.equal(cache[fileIdentity(other).key], sha(OTHER));
  assert.ok(!readFileSync(join(st, PIN_CACHE_FILE), "utf8").includes("other.gguf"));
  queued(st, [{ kind: "curl-model", path: other, isFile: true, ts }]);
  const r2 = modelScanPosture({ policy, home: d, stateDir: st, admin: null });
  assert.equal(r2.alerts.filter((a) => a.reasonCode === "MODEL_NOT_APPROVED").length, 0, "once per file content");
});

test("queue: a pin-verify item (a load the hook could not hash) is hashed fresh, even over a remembered verdict", (t) => {
  const d = sandbox(t), st = join(d, ".moorai");
  const p = put(join(d, "big.gguf"), GOOD);
  ago(p, 2 * SETTLE_MS);
  const ts = Date.now();
  queued(st, [{ kind: "curl-model", path: p, isFile: true, ts: ts - 2 * SETTLE_MS }]);
  modelScanPosture({ policy: null, home: d, stateDir: st, admin: null }).commit([]);
  rmTree(join(st, PIN_CACHE_FILE));
  let scans = 0;
  queued(st, [{ kind: "pin-verify", path: p, isFile: true, ts }]);
  const r = modelScanPosture({ policy: { modelPinMode: "ask", modelPins: [{ sha256: sha(GOOD) }] }, home: d, stateDir: st, admin: null, scan: (path, o) => { scans++; return scanModelFile(path, o); } });
  assert.equal(scans, 1, "not taken from model-scan-state");
  assert.equal(r.field.clean, 1);
  r.commit([]);
  assert.equal(readPinCache(st)[fileIdentity(p).key], sha(GOOD));
  assert.deepEqual(readQueue(st), []);
});

test("store scan: pins apply to the opt-in inventory of the model stores", (t) => {
  const d = sandbox(t), st = join(d, ".moorai");
  const store = join(d, "store");
  put(join(store, "a.gguf"), GOOD);
  put(join(store, "b.gguf"), OTHER);
  const r = modelScanPosture({ policy: { modelScan: { inventory: "scan" }, modelPinMode: "report", modelPins: [{ sha256: sha(GOOD) }] }, home: d, stateDir: st, admin: null, stores: [{ dir: store }] });
  assert.equal(r.field.clean, 1);
  assert.equal(r.field["not-approved"], 1);
  assert.equal(r.alerts.filter((a) => a.reasonCode === "MODEL_NOT_APPROVED" && a.tool === "inventory:model-scan").length, 1);
});

// ---- the hook check ----
const block = (pins) => ({ modelPinMode: "block", modelPins: pins.map((s) => ({ sha256: s })) });
test("hook check: the load forms it names", (t) => {
  const d = sandbox(t), cwd = join(d, "proj");
  put(join(cwd, "m.gguf"), GOOD);
  put(join(cwd, "Modelfile"), "# base\nFROM ./m.gguf\nPARAMETER temperature 0.2\n");
  mkdirSync(join(cwd, "weights"), { recursive: true });
  const k = (cmd) => modelLoadTargets(cmd, { cwd, home: d, env: {} }).map((x) => [x.kind, x.path]);
  assert.deepEqual(k("llama-server -m m.gguf --port 8080"), [["llama.cpp", join(cwd, "m.gguf")]]);
  assert.deepEqual(k("./build/bin/llama-cli --model=/opt/x.gguf -mg 1 -p hi"), [["llama.cpp", "/opt/x.gguf"]], "-mg is not -m");
  assert.deepEqual(k("ollama create mine -f Modelfile"), [["ollama-create", join(cwd, "m.gguf")]]);
  assert.deepEqual(k("vllm serve ./weights --port 8000"), [["vllm", join(cwd, "weights")]]);
  assert.deepEqual(k("vllm serve Qwen/Qwen2.5-7B-Instruct"), [["vllm", null]], "a hub id cannot be named: unresolved");
  assert.deepEqual(k("vllm serve --port 8000 ./weights"), [["vllm", null]], "a model after a flag is not guessed");
  assert.deepEqual(k("vllm serve --port 8000 --model ./weights"), [["vllm", join(cwd, "weights")]]);
  assert.deepEqual(k(`python -c "import torch; m = torch.load('/data/ckpt.pt', weights_only=True)"`), [["python:torch.load", "/data/ckpt.pt"]]);
  assert.deepEqual(k(`python -c "from transformers import AutoModel; AutoModel.from_pretrained('gpt2')"`), [], "a hub id from from_pretrained is not checked");
  for (const neg of ["ls -la", "echo llama-server -m x.gguf is how you run it", "ollama list", "ollama pull llama3", "cat Modelfile"]) assert.deepEqual(k(neg), [], neg);
});

test("hook check: a model directory is checked file by file; one the walk cannot finish is unverified", (t) => {
  const d = sandbox(t), st = join(d, ".moorai"), cwd = join(d, "proj");
  put(join(cwd, "w", "a.safetensors"), GOOD);
  put(join(cwd, "w", "b.safetensors"), OTHER);
  const base = { cwd, stateDir: st, home: d, env: {}, admin: null, command: "vllm serve ./w" };
  assert.equal(modelPinCheck({ ...base, policy: block([sha(GOOD), sha(OTHER)]) }).decision, "allow");
  assert.equal(modelPinCheck({ ...base, policy: block([sha(GOOD)]) }).decision, "deny", "one unpinned shard is enough");
  for (let i = 0; i < 70; i++) put(join(cwd, "many", `s${String(i).padStart(2, "0")}.safetensors`), GOOD);
  const r = modelPinCheck({ ...base, command: "vllm serve ./many", policy: block([sha(GOOD)]) });
  assert.equal(r.decision, "deny", "past the 64-file walk: not every file was checked");
});

test("hook check: a pinned file passes; an unpinned one is reported, asked or blocked by mode", (t) => {
  const d = sandbox(t), st = join(d, ".moorai"), cwd = join(d, "proj");
  put(join(cwd, "good.gguf"), GOOD);
  put(join(cwd, "other.gguf"), OTHER);
  const base = { cwd, stateDir: st, home: d, env: {}, admin: null };
  assert.equal(modelPinCheck({ ...base, command: "llama-server -m good.gguf", policy: null }), null, "pinning off: nothing");
  const ok = modelPinCheck({ ...base, command: "llama-server -m good.gguf", policy: block([sha(GOOD)]) });
  assert.deepEqual([ok.decision, ok.alerts.length, ok.files[0].approval], ["allow", 0, "pinned"]);
  for (const [mode, decision, outcome] of [["report", "allow", "reported"], ["ask", "ask", "asked"], ["block", "deny", "blocked"]]) {
    const r = modelPinCheck({ ...base, command: "llama-server -m other.gguf", policy: { modelPinMode: mode, modelPins: [{ sha256: sha(GOOD) }] } });
    assert.equal(r.decision, decision, mode);
    assert.equal(r.alerts.length, 1, `${mode}: alerted, never silent`);
    const a = r.alerts[0];
    assert.deepEqual([a.reasonCode, a.threatId, a.modelLoad.kind, a.modelLoad.format, a.modelLoad.pinned, a.modelLoad.verified, a.modelLoad.hashPrefix, a.modelLoad.outcome],
      ["MODEL_NOT_APPROVED", 76, "llama.cpp", "gguf", false, true, sha(OTHER).slice(0, 12), outcome]);
    assert.ok(!JSON.stringify(a).includes(sha(OTHER)) && !JSON.stringify(a).includes("other.gguf") && !JSON.stringify(a).includes(d));
  }
  const inv = modelPinCheck({ ...base, command: "llama-server -m good.gguf", policy: { modelPinMode: "bogus", modelPins: { x: 1 } } });
  assert.equal(inv.decision, "deny", "an invalid pin policy fails closed on the hook path too");
});

test("hook check: a file past the hash budget is unverified (asked / denied), queued, then decided from the cache; a changed file is re-hashed", (t) => {
  const d = sandbox(t), st = join(d, ".moorai"), cwd = join(d, "proj");
  const p = put(join(cwd, "good.gguf"), GOOD);
  const base = { cwd, stateDir: st, home: d, env: {}, admin: null, command: "llama-server -m good.gguf" };
  const b = modelPinCheck({ ...base, policy: block([sha(GOOD)]), budget: 16 });
  assert.equal(b.decision, "deny", "block: not hashed in time is not approved");
  assert.equal(b.alerts[0].modelLoad.verified, false);
  assert.equal(b.alerts[0].modelLoad.hashPrefix, null);
  assert.equal(modelPinCheck({ ...base, policy: { modelPinMode: "ask", modelPins: [{ sha256: sha(GOOD) }] }, budget: 16 }).decision, "ask");
  const rep = modelPinCheck({ ...base, policy: { modelPinMode: "report", modelPins: [{ sha256: sha(GOOD) }] }, budget: 16 });
  assert.deepEqual([rep.decision, rep.alerts.length], ["allow", 1], "report: allowed with an alert, never silently");
  assert.deepEqual(readQueue(st).map((x) => [x.kind, x.path]), [["pin-verify", p]], "queued once for the background hash");
  // The background scan hashes it; the next check is decided from the cache with no hash on the hook path.
  const T = Math.floor((Date.now() - 2 * SETTLE_MS) / 1000);
  utimesSync(p, T, T);
  modelScanPosture({ policy: block([sha(GOOD)]), home: d, stateDir: st, admin: null }).commit([]);
  let hashed = 0;
  const cached = modelPinCheck({ ...base, policy: block([sha(GOOD)]), budget: 16, hash: (x) => { hashed++; return sha256File(x); } });
  assert.deepEqual([cached.decision, hashed], ["allow", 0]);
  // The same path rewritten with other bytes (same size, mtime put back): its ctime moved, so the cache misses.
  const st0 = fileIdentity(p);
  const swapped = Buffer.from(GOOD);
  swapped[swapped.length - 1] ^= 0xff;
  writeFileSync(p, swapped);
  utimesSync(p, T, T);
  assert.notEqual(fileIdentity(p).key, st0.key, "same path, size, inode and mtime: only the ctime tells");
  const after = modelPinCheck({ ...base, policy: block([sha(GOOD)]) });
  assert.equal(after.decision, "deny", "the swapped file is hashed again and is not the pinned one");
});

test("hook check: an Ollama blob is checked by its own hash, never by its name alone", (t) => {
  const d = sandbox(t), st = join(d, ".moorai"), cwd = join(d, "proj");
  mkdirSync(cwd, { recursive: true });
  const store = join(d, ".ollama", "models");
  const blob = put(join(store, "blobs", `sha256-${sha(GOOD)}`), GOOD);
  put(join(store, "manifests", "registry.ollama.ai", "library", "tiny", "latest"), JSON.stringify({ layers: [{ mediaType: "application/vnd.ollama.image.model", digest: `sha256:${sha(GOOD)}` }, { mediaType: "application/vnd.ollama.image.template", digest: `sha256:${"0".repeat(64)}` }] }));
  assert.deepEqual(ollamaBlobs("tiny", { home: d, env: {} }), [{ path: blob, claimed: sha(GOOD) }]);
  const base = { cwd, stateDir: st, home: d, env: {}, admin: null };
  assert.equal(modelPinCheck({ ...base, command: "ollama run tiny", policy: block([sha(GOOD)]) }).decision, "allow");
  assert.equal(modelPinCheck({ ...base, command: "ollama run tiny:latest 'hi'", policy: block([sha(OTHER)]) }).decision, "deny");
  assert.equal(modelPinCheck({ ...base, command: "ollama run notpulled", policy: block([sha(GOOD)]) }).decision, "deny", "a model not in the store cannot be named: unverified");
  assert.equal(modelPinCheck({ ...base, command: "ollama run --verbose tiny", policy: block([sha(OTHER)]) }).decision, "deny", "a boolean flag before the model");
  assert.equal(modelPinCheck({ ...base, command: "ollama run --keepalive 5m tiny", policy: block([sha(GOOD)]) }).decision, "allow");
  // The blob replaced in place keeps its pinned name; its content no longer matches.
  writeFileSync(blob, OTHER);
  const r = modelPinCheck({ ...base, command: "ollama run tiny", policy: block([sha(GOOD), sha(OTHER)]) });
  assert.equal(r.decision, "deny");
  assert.equal(r.alerts[0].modelLoad.nameMismatch, true);
});

// ---- end to end: one load form through the real hook, a signed policy from a stand-in console ----
const TENANT = "model-pins";
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
  const alerts = [];
  const srv = http.createServer((req, res) => {
    let b = "";
    req.on("data", (c) => (b += c));
    req.on("end", () => {
      if (req.method === "POST" && req.url === "/api/alerts") { try { alerts.push(JSON.parse(b)); } catch { /* batch */ } res.writeHead(201); return res.end("{}"); }
      if (req.url.startsWith("/api/policy/pubkey")) { res.writeHead(200, { "Content-Type": "application/json" }); return res.end(PUBKEY); }
      if (req.url.startsWith("/api/policy")) { res.writeHead(200, { "Content-Type": "application/json" }); return res.end(policy); }
      res.writeHead(201); res.end("{}");
    });
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  t.after(() => new Promise((r) => srv.close(r)));
  return { url: `http://127.0.0.1:${srv.address().port}`, alerts };
}
function runHook(home, input) {
  return new Promise((res, rej) => {
    const c = spawn(process.execPath, [HOOK], { cwd: home, env: { PATH: process.env.PATH || "/usr/bin:/bin", HOME: home, USERPROFILE: home }, stdio: ["pipe", "pipe", "pipe"] });
    let out = "", err = "";
    c.stdout.on("data", (x) => (out += x));
    c.stderr.on("data", (x) => (err += x));
    c.on("error", rej);
    c.on("close", (code) => (code === 0 || code === 2 ? res(out) : rej(new Error(`hook exit ${code}: ${err}`))));
    c.stdin.end(JSON.stringify(input));
  });
}
test("end to end: block denies an unpinned llama-server load, allows the pinned one, and user-writable state cannot add a pin", async (t) => {
  const c = await consoleStub(t, signed({ captureTier: "content-free", modelPinMode: "block", modelPins: [{ sha256: sha(GOOD), name: "approved" }] }));
  const home = sandbox(t);
  const st = join(home, ".moorai");
  mkdirSync(st, { recursive: true });
  // The user's own config and a planted policy cache both claim the unpinned file is approved.
  writeFileSync(join(st, "config.json"), JSON.stringify({ serverUrl: c.url, tenant: TENANT, installToken: "tok-model-pins", modelPinMode: "off", modelPins: [{ sha256: sha(OTHER) }] }));
  const proj = join(home, "proj");
  put(join(proj, "good.gguf"), GOOD);
  put(join(proj, "other.gguf"), OTHER);
  const deny = await runHook(home, { hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "llama-server -m other.gguf --port 8080" }, session_id: "s-mp", cwd: proj });
  assert.match(deny, /"permissionDecision":"deny"/);
  assert.match(deny, /approved list/);
  assert.ok(await until(() => c.alerts.some((a) => a.reasonCode === "MODEL_NOT_APPROVED")), "the content-free alert reached the console");
  const a = c.alerts.find((x) => x.reasonCode === "MODEL_NOT_APPROVED");
  assert.equal(a.modelLoad.hashPrefix, sha(OTHER).slice(0, 12));
  assert.ok(!JSON.stringify(a).includes("other.gguf") && !JSON.stringify(a).includes(sha(OTHER)));
  const allow = await runHook(home, { hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "llama-server -m good.gguf --port 8080" }, session_id: "s-mp", cwd: proj });
  assert.ok(!/"permissionDecision":"(deny|ask)"/.test(allow), allow);
  assert.ok(existsSync(join(st, PIN_CACHE_FILE)), "the hook remembered the hashes it computed");
  // The detached modelscan worker gets the pins too: a queued, settled download that is not pinned. The day's
  // posture beat (spawned by the first event) also drains the queue, so it finishes first.
  assert.ok(await until(() => existsSync(join(st, "inventory-detectors.json"))), "the day's posture beat finished");
  const dl = put(join(proj, "dl", "fresh.gguf"), Buffer.concat([GOOD, Buffer.from("downloaded")]));
  ago(dl, 2 * SETTLE_MS);
  writeFileSync(join(st, QUEUE_FILE), JSON.stringify({ items: [{ kind: "curl-model", path: dl, isFile: true, ts: Date.now() - 2 * SETTLE_MS }] }));
  await runHook(home, { hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "ls" }, session_id: "s-mp", cwd: proj });
  assert.ok(await until(() => c.alerts.some((x) => x.reasonCode === "MODEL_NOT_APPROVED" && x.tool === "download:model-scan")), "the worker applied the signed policy's pins");
});
