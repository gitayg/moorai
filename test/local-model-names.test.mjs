// Local models whose NAME says their safety training was removed (cli/local-model-names.mjs): the token
// list and how a name is split into words, the per-runtime directory walks and Ollama's loopback
// /api/tags, the content-free record the AIBOM carries, and the time / entry bounds. Every runtime and
// directory tree here is fake; the only socket is an in-process server on 127.0.0.1.
//
//   node --test test/local-model-names.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import {
  SAFETY_REMOVED_TOKENS, MODEL_SOURCES, LIMITS, nameWords, safetyRemovedByName, modelDirs,
  scanModelNames, summarizeModelSafety, fetchOllamaTagsLoopback, localModelSafety
} from "../cli/local-model-names.mjs";
import { rmTree } from "./fs-cleanup.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const AIBOM = join(ROOT, "cli", "moorai-aibom.mjs");

// ---- the token list ----

test("tokens: exactly the justified list, each with a reason and a public example", () => {
  assert.deepEqual(SAFETY_REMOVED_TOKENS.map((t) => t.token).sort(),
    ["abliterated", "decensored", "heretic", "jailbroken", "obliterated", "unaligned", "uncensored"]);
  for (const t of SAFETY_REMOVED_TOKENS) {
    assert.ok(typeof t.why === "string" && t.why.length > 20, `${t.token}: why`);
    assert.ok(typeof t.example === "string" && t.example.includes("/"), `${t.token}: an org/name example`);
    assert.ok(safetyRemovedByName(t.example), `${t.token}: its own example matches`);
  }
});

// Real Hugging Face / Ollama names (hub search, 2026-10-08), plus constructed case / separator / boundary variants.
const POSITIVE = [
  "huihui-ai/Huihui-Qwen3.8-27B-abliterated-GGUF",
  "failspy/llama-3-70B-Instruct-abliterated",
  "Meta-Llama-3.1-8B-Instruct-ABLITERATED",
  "huihui_ai/qwen3-abliterated:8b",
  "OBLITERATUS/Qwen3.8-27B-OBLITERATED",
  "JonathanColetti/Qwen3.8-27B-Uncensored-GGUF",
  "llama2-uncensored:7b",
  "Orenguteng/Llama-3.1-8B-Lexi-Uncensored-V2",
  "dealignai/Ornith-1.5-9B-UNCENSORED-GGUF",
  "mradermacher/gemma-4-12B-it-heretic_decensored-i1-GGUF",
  "Riyan200324200324/Qwen3-Next-80B-A3B-Instruct-Decensored-i1-GGUF",
  "bartowski/LLAMA-3_8B_Unaligned_BETA-GGUF",
  "mradermacher/Unaligned-Thinker-PHI-4-i1-GGUF",
  "cooperleong00/Meta-Llama-3-8B-Instruct-Jailbroken",
  "CCSU-ML/Qwen3-8B-Jailbroken.Q6_K.gguf",
  "AEON-7/Qwen3.6-35B-A3B-heretic-NVFP4",
  "llmfan46/gemma-4-31B-it-uncensored-heretic-GGUF",
  "hf.co/mradermacher/Qwen3-8B-Jailbroken-GGUF:Q4_K_M",
  "Qwen3-8B Uncensored Q4_K_M.gguf",
  "WizardLMUncensored",          // camelCase boundary
  "qwen3abliterated-8b"          // letter/digit boundary
];

test("match: case and separator variants of every token match", () => {
  for (const n of POSITIVE) assert.equal(safetyRemovedByName(n), true, n);
});

// Names that contain a token's letters, or a near word, and must NOT match.
const BENIGN_REAL = [
  "jackhhao/jailbreak-classifier",                       // a jailbreak DETECTOR — why "jailbreak" is not a token
  "madhurjindal/Jailbreak-Detector-Large",
  "rogue-security/prompt-injection-jailbreak-sentinel-v2",
  "meta-llama/Llama-Guard-3-8B",
  "meta-llama/Prompt-Guard-86M",
  "GuardrailsAI/prompt-saturation-attack-detector",      // why "guardrails" / "no-guardrails" is not a token
  "mozilla-ai/llamafile-guardrails",
  "reallexi/lexi-coder-v4.3",                            // why "lexi" alone is not a token
  "EleutherAI/deep-ignorance-unfiltered",                // "unfiltered" pretraining DATA in a safety study
  "Falconsai/nsfw_image_detection",                      // a content classifier
  "unitary/toxic-bert",
  "HuggingFaceH4/zephyr-7b-beta",
  "princeton-nlp/Llama-3-Instruct-8B-SimPO",
  "sentence-transformers/all-MiniLM-L6-v2",
  "llama3:latest", "qwen2.5-coder:32b", "deepseek-r1:8b"
];
// A token as part of a longer word: the hubs' names are separated by - _ . / : or a case change, so a
// token glued to other letters is a different word (constructed names, shaped like real ones).
const BENIGN_SUBSTRING = ["acme/heretical-poetry-7b", "x/Realigned-Llama-8B", "x/aligned-7b", "x/censored-filter-v1", "x/ablit-test", "x/obliteratedness-probe", "x/uncensoredx"];

test("no match: real benign names and a token inside a longer word", () => {
  for (const n of [...BENIGN_REAL, ...BENIGN_SUBSTRING]) assert.equal(safetyRemovedByName(n), false, n);
});

test("known false negative, pinned: a token glued to lower-case letters is not split", () => {
  assert.equal(safetyRemovedByName("llamauncensored"), false);
  assert.deepEqual(nameWords("Qwen3-8B-Jailbroken.Q6_K"), ["qwen", "3", "8", "b", "jailbroken", "q", "6", "k"]);
});

test("match: non-strings, empty and over-long names never match and never throw", () => {
  for (const v of [null, undefined, 42, {}, "", "a".repeat(10000) + "-uncensored"]) assert.equal(safetyRemovedByName(v), false, String(v).slice(0, 20));
});

// ---- fake directory trees ----
// A tree is nested objects; a file is null. opendir() returns a lazy reader like fs.opendirSync's Dir.
function fakeFs(tree, stats = { opens: 0, reads: 0 }) {
  const get = (p) => { let n = tree; for (const x of p.split("/").filter(Boolean)) { if (!n || typeof n !== "object" || !(x in n)) return undefined; n = n[x]; } return n; };
  return {
    stats,
    opendir(p) {
      const n = get(p);
      if (!n || typeof n !== "object") { const e = new Error(`ENOENT ${p}`); e.code = "ENOENT"; throw e; }
      stats.opens++;
      const keys = Object.keys(n); let i = 0;
      return {
        readSync() { stats.reads++; if (i >= keys.length) return null; const k = keys[i++], v = n[k]; return { name: k, isDirectory: () => v !== null, isFile: () => v === null, isSymbolicLink: () => false }; },
        closeSync() {}
      };
    }
  };
}
const at = (path, leaf) => path.split("/").filter(Boolean).reduceRight((acc, k) => ({ [k]: acc }), leaf);
const merge = (...ts) => { const out = {}; const m = (a, b) => { for (const [k, v] of Object.entries(b)) a[k] = v && typeof v === "object" && a[k] && typeof a[k] === "object" ? (m(a[k], v), a[k]) : v; }; for (const t of ts) m(out, t); return out; };

const HOME = "/home/dev";
const LINUX_TREE = () => merge(
  at(`${HOME}/.ollama/models/manifests/registry.ollama.ai/library`, { llama3: { latest: null }, "llama2-uncensored": { "7b": null } }),
  at(`${HOME}/.ollama/models/manifests/registry.ollama.ai/huihui_ai`, { "qwen3-abliterated": { "8b": null, "14b": null } }),
  at(`${HOME}/.ollama/models/manifests/hf.co/mradermacher`, { "Qwen3-8B-Jailbroken-GGUF": { Q4_K_M: null } }),
  at(`${HOME}/.lmstudio/models`, {
    "lmstudio-community": { "Qwen3-8B-GGUF": { "Qwen3-8B-Q4_K_M.gguf": null } },
    bartowski: { "LLAMA-3_8B_Unaligned_BETA-GGUF": { "LLAMA-3_8B_Unaligned_BETA-Q4_K_M.gguf": null } },
    "secret-team": { "acme-internal-7b-GGUF": { "acme-internal-7b-uncensored-q4.gguf": null } }
  }),
  at(`${HOME}/.local/share/Jan/data/llamacpp/models`, { "huihui-ai": { "Huihui-Qwen3.5-27B-abliterated": { "model.gguf": null, "model.yml": null } }, Menlo: { "Jan-nano-gguf": { "model.gguf": null } } }),
  at(`${HOME}/.local/share/nomic.ai/GPT4All`, { "Meta-Llama-3-8B-Instruct.Q4_0.gguf": null, "localdocs_v2.db": null }),
  at(`${HOME}/.cache/llama.cpp`, { "bartowski_Llama-3.2-1B-Instruct-GGUF_Llama-3.2-1B-Instruct-Q4_K_M.gguf": null, "models--OBLITERATUS--Qwen3.8-27B-OBLITERATED": { snapshots: {} } }),
  at(`${HOME}/.cache/huggingface/hub`, {
    "models--huihui-ai--Huihui-Qwen3.8-27B-abliterated-GGUF": { blobs: {}, snapshots: {} },
    "models--meta-llama--Llama-Guard-3-8B": { snapshots: {} },
    "models--jackhhao--jailbreak-classifier": { snapshots: {} },
    "models--gpt2": { snapshots: {} },
    "datasets--unalignment--toxic-dpo-v0.2": {},
    "blobs": {}, "CACHEDIR.TAG": null
  })
);
const scan = (tree, extra = {}) => scanModelNames({ platform: "linux", env: {}, home: HOME, fsx: fakeFs(tree), ...extra });
const counts = (rec) => Object.fromEntries((rec?.sources || []).map((s) => [s.runtime, [s.models, s.safetyRemovedByName]]));

test("directories: per-OS defaults and the runtimes' own env overrides", () => {
  const dirs = (platform, env, home) => modelDirs({ platform, env, home }).map((d) => `${d.runtime}:${d.dir}`);
  const lin = dirs("linux", {}, HOME);
  for (const want of [`ollama:${HOME}/.ollama/models/manifests`, "ollama:/usr/share/ollama/.ollama/models/manifests", `lmstudio:${HOME}/.lmstudio/models`,
    `lmstudio:${HOME}/.cache/lm-studio/models`, `jan:${HOME}/.local/share/Jan/data/llamacpp/models`, `jan:${HOME}/.local/share/Jan/data/mlx/models`,
    `gpt4all:${HOME}/.local/share/nomic.ai/GPT4All`, `llama.cpp:${HOME}/.cache/llama.cpp`, `huggingface:${HOME}/.cache/huggingface/hub`]) assert.ok(lin.includes(want), want);
  const mac = dirs("darwin", {}, "/Users/dev");
  for (const want of ["jan:/Users/dev/Library/Application Support/Jan/data/llamacpp/models", "gpt4all:/Users/dev/Library/Application Support/nomic.ai/GPT4All", "llama.cpp:/Users/dev/Library/Caches/llama.cpp"]) assert.ok(mac.includes(want), want);
  const env = dirs("linux", { OLLAMA_MODELS: "/srv/ollama", HF_HUB_CACHE: "/srv/hf", LLAMA_CACHE: "/srv/llama" }, HOME);
  for (const want of ["ollama:/srv/ollama/manifests", "huggingface:/srv/hf", "llama.cpp:/srv/llama"]) assert.ok(env.includes(want), want);
  assert.ok(dirs("linux", { HF_HOME: "/srv/hfhome" }, HOME).includes("huggingface:/srv/hfhome/hub"));
  for (const d of modelDirs({ platform: "linux", env: {}, home: HOME })) assert.ok(MODEL_SOURCES.includes(d.runtime), d.runtime);
});

test("scan: every runtime's tree gives its model count and its safety-removed-by-name count", () => {
  const s = scan(LINUX_TREE());
  const rec = summarizeModelSafety(s);
  assert.deepEqual(counts(rec), {
    ollama: [5, 4],        // llama3, llama2-uncensored, qwen3-abliterated:8b and :14b, hf.co …Jailbroken
    lmstudio: [3, 2],      // Unaligned repo; acme repo matched by its FILE name; lmstudio-community clean
    jan: [2, 1],
    gpt4all: [1, 0],       // the .db is not a model
    "llama.cpp": [2, 1],   // a flat .gguf and an HF-layout repo
    huggingface: [4, 1]    // datasets--, blobs and CACHEDIR.TAG are not models; jailbreak-classifier and Llama-Guard do not match
  });
  assert.equal(rec.count, 9);
  assert.equal(rec.safetyRemovedByName, true);
  assert.equal(rec.basis, "name");
  assert.equal(rec.truncated, false);
  assert.equal(rec.timedOut, false);
});

test("scan: nothing installed gives no sources, a false boolean and a zero count", () => {
  const rec = summarizeModelSafety(scan({}));
  assert.deepEqual(rec, { basis: "name", safetyRemovedByName: false, count: 0, sources: [], truncated: false, timedOut: false });
});

test("ollama: names from loopback /api/tags join the on-disk manifests, each model counted once", async () => {
  const seen = [];
  const rec = await localModelSafety({ platform: "linux", env: {}, home: HOME, fsx: fakeFs(LINUX_TREE()),
    ollamaTags: async (o) => { seen.push(o); return { names: ["llama3:latest", "huihui_ai/qwen3-abliterated:8b", "dolphin-mixtral:8x7b", "nidumai/nidum-gemma-3-4b-it-uncensored:q4_k_m"], truncated: false }; } });
  assert.deepEqual(counts(rec).ollama, [7, 5], "two api-only models added; the two on disk not double-counted");
  assert.equal(seen.length, 1);
  assert.ok(seen[0].timeoutMs > 0 && seen[0].timeoutMs <= LIMITS.httpTimeoutMs);
});

test("ollama: an unreachable or failing /api/tags leaves the disk count and never throws", async () => {
  for (const fail of [async () => null, async () => { throw new Error("ECONNREFUSED"); }]) {
    const rec = await localModelSafety({ platform: "linux", env: {}, home: HOME, fsx: fakeFs(LINUX_TREE()), ollamaTags: fail });
    assert.deepEqual(counts(rec).ollama, [5, 4]);
  }
});

// ---- the content-free guarantee ----
const ALLOWED_KEYS = new Set(["basis", "safetyRemovedByName", "count", "sources", "runtime", "models", "truncated", "timedOut"]);
function assertContentFree(rec, where) {
  const walk = (v, path) => {
    if (Array.isArray(v)) return v.forEach((x, i) => walk(x, `${path}[${i}]`));
    if (v && typeof v === "object") { for (const [k, x] of Object.entries(v)) { assert.ok(ALLOWED_KEYS.has(k), `${where}: unexpected key ${path}.${k}`); walk(x, `${path}.${k}`); } return; }
    if (typeof v === "string") assert.ok(v === "name" || MODEL_SOURCES.includes(v), `${where}: free string ${path}=${v}`);
    else assert.ok(typeof v === "number" || typeof v === "boolean", `${where}: ${path} is ${typeof v}`);
  };
  walk(rec, "rec");
  const json = JSON.stringify(rec);
  for (const leak of ["huihui", "qwen", "Qwen", "abliterated", "uncensored", "jailbroken", "Jailbroken", "Unaligned", "OBLITERATED", "mradermacher", "bartowski", "secret", "acme", "lmstudio-community",
    "meta-llama", "jackhhao", "/home", "dev/", ".gguf", "manifests", "models--", "Q4_K_M", "registry.ollama.ai", "hf.co", ":8b", "sha256", "nidumai"]) assert.ok(!json.includes(leak), `${where}: ${leak} leaked`);
}

test("content-free: the record carries only fixed keys, runtime ids, counts and booleans — never a name, path, org or hash", async () => {
  assertContentFree(summarizeModelSafety(scan(LINUX_TREE())), "scan");
  const rec = await localModelSafety({ platform: "linux", env: {}, home: HOME, fsx: fakeFs(LINUX_TREE()),
    ollamaTags: async () => ({ names: ["nidumai/nidum-gemma-3-4b-it-uncensored:q4_k_m", "x/y@sha256:abcdef"], truncated: false }) });
  assertContentFree(rec, "localModelSafety");
});

// ---- bounds ----

test("bound: total directory entries read stop at maxEntries and the record says truncated", () => {
  const many = {}; for (let i = 0; i < 20000; i++) many[`models--org${i}--m${i}`] = {};
  const fsx = fakeFs(at(`${HOME}/.cache/huggingface/hub`, many));
  const s = scanModelNames({ platform: "linux", env: {}, home: HOME, fsx, maxPerDir: 100000 });
  assert.ok(fsx.stats.reads <= LIMITS.maxEntries + 1, `read ${fsx.stats.reads} entries`);
  assert.equal(s.truncated, true);
  assert.equal(summarizeModelSafety(s).truncated, true);
});

test("bound: one directory is read at most maxPerDir entries deep", () => {
  const many = {}; for (let i = 0; i < 3000; i++) many[`model-${i}.gguf`] = null;
  const fsx = fakeFs(at(`${HOME}/.local/share/nomic.ai/GPT4All`, many));
  const s = scanModelNames({ platform: "linux", env: {}, home: HOME, fsx });
  assert.ok(fsx.stats.reads <= LIMITS.maxPerDir + 1, `read ${fsx.stats.reads}`);
  assert.equal(counts(summarizeModelSafety(s)).gpt4all[0], LIMITS.maxPerDir);
  assert.equal(s.truncated, true);
});

test("bound: the walk stops at the deadline and the record says timedOut", () => {
  let t = 0;
  const fsx = fakeFs(LINUX_TREE());
  const s = scanModelNames({ platform: "linux", env: {}, home: HOME, fsx, now: () => (t += 5), deadlineMs: 40 });
  assert.equal(s.timedOut, true);
  assert.ok(fsx.stats.reads <= 10, `read ${fsx.stats.reads} entries after the deadline`);
  assert.equal(summarizeModelSafety(s).timedOut, true);
});

test("bound: /api/tags gets only the time left, and is skipped once the deadline has passed", async () => {
  let t = 0, calls = 0, got = null;
  await localModelSafety({ platform: "linux", env: {}, home: HOME, fsx: fakeFs({}), now: () => (t += 1), deadlineMs: 300,
    ollamaTags: async (o) => { calls++; got = o.timeoutMs; return null; } });
  assert.equal(calls, 1);
  assert.ok(got <= 300, `timeout ${got}`);
  t = 0; calls = 0;
  const rec = await localModelSafety({ platform: "linux", env: {}, home: HOME, fsx: fakeFs(LINUX_TREE()), now: () => (t += 50), deadlineMs: 40,
    ollamaTags: async () => { calls++; return { names: ["x-uncensored:1b"], truncated: false }; } });
  assert.equal(calls, 0);
  assert.equal(rec.timedOut, true);
});

// ---- Ollama /api/tags over loopback (an in-process server on 127.0.0.1) ----
// The probe raced against a 2 s sentinel, so a broken timeout fails the test instead of hanging it.
const HUNG = Symbol("still waiting after 2 s");
const within2s = (p) => Promise.race([p, new Promise((r) => setTimeout(() => r(HUNG), 2000).unref())]);
async function withServer(handler, fn) {
  const reqs = [];
  const srv = createServer((req, res) => { reqs.push({ method: req.method, url: req.url, host: req.socket.localAddress }); handler(req, res); });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  try { return await fn(srv.address().port, reqs); } finally { srv.closeAllConnections?.(); await new Promise((r) => srv.close(r)); }
}

test("loopback: GET /api/tags on 127.0.0.1 returns the names; OLLAMA_HOST is not followed", async () => {
  const prev = process.env.OLLAMA_HOST;
  process.env.OLLAMA_HOST = "http://203.0.113.9:11434";
  try {
    await withServer((req, res) => { res.writeHead(200, { "content-type": "application/json" }); res.end(JSON.stringify({ models: [{ name: "llama3:latest", digest: "sha256:aa" }, { name: "huihui_ai/qwen3-abliterated:8b" }, { name: 7 }, { model: "x" }] })); }, async (port, reqs) => {
      const r = await fetchOllamaTagsLoopback({ port });
      assert.deepEqual(r, { names: ["llama3:latest", "huihui_ai/qwen3-abliterated:8b"], truncated: false });
      assert.deepEqual(reqs.map((x) => [x.method, x.url, x.host]), [["GET", "/api/tags", "127.0.0.1"]]);
    });
  } finally { if (prev === undefined) delete process.env.OLLAMA_HOST; else process.env.OLLAMA_HOST = prev; }
});

test("loopback: a server that never answers is abandoned at the timeout", async () => {
  await withServer(() => { /* never respond */ }, async (port) => {
    const t0 = Date.now();
    const r = await within2s(fetchOllamaTagsLoopback({ port, timeoutMs: 300 }));
    assert.notEqual(r, HUNG, "the probe was still open after 2 s");
    assert.equal(r, null);
    assert.ok(Date.now() - t0 < 1500, `took ${Date.now() - t0} ms`);
  });
});

test("loopback: a slow drip that never finishes is abandoned at the timeout (the timer is total, not idle)", async () => {
  await withServer((req, res) => { res.writeHead(200); const iv = setInterval(() => res.write(" "), 50); res.on("close", () => clearInterval(iv)); }, async (port) => {
    const t0 = Date.now();
    const r = await within2s(fetchOllamaTagsLoopback({ port, timeoutMs: 300 }));
    assert.notEqual(r, HUNG, "the probe was still open after 2 s");
    assert.equal(r, null);
    assert.ok(Date.now() - t0 < 1500, `took ${Date.now() - t0} ms`);
  });
});

test("loopback: a response over maxBytes, a non-200 and non-JSON all give null", async () => {
  await withServer((req, res) => { res.writeHead(200); res.end(JSON.stringify({ models: [{ name: "x".repeat(2 * 1024 * 1024) }] })); }, async (port) => {
    assert.equal(await fetchOllamaTagsLoopback({ port }), null);
  });
  await withServer((req, res) => { res.writeHead(404); res.end("{}"); }, async (port) => assert.equal(await fetchOllamaTagsLoopback({ port }), null));
  await withServer((req, res) => { res.writeHead(200); res.end("not json"); }, async (port) => assert.equal(await fetchOllamaTagsLoopback({ port }), null));
});

test("loopback: more than httpMaxModels names are capped and flagged", async () => {
  const models = Array.from({ length: LIMITS.httpMaxModels + 50 }, (_, i) => ({ name: `m${i}:latest` }));
  await withServer((req, res) => { res.writeHead(200); res.end(JSON.stringify({ models })); }, async (port) => {
    const r = await fetchOllamaTagsLoopback({ port });
    assert.equal(r.names.length, LIMITS.httpMaxModels);
    assert.equal(r.truncated, true);
  });
});

test("loopback: nothing listening gives null", async () => {
  const port = await withServer(() => {}, async (p) => p); // closed again: nothing listens there now
  assert.equal(await fetchOllamaTagsLoopback({ port, timeoutMs: 500 }), null);
});

// ---- the AIBOM CLI end to end ----

test("CLI: the AIBOM carries the content-free block and summary count; Markdown states it is name-based", () => {
  const home = mkdtempSync(join(tmpdir(), "moorai-modelnames-"));
  try {
    mkdirSync(join(home, ".ollama/models/manifests/registry.ollama.ai/huihui_ai/qwen3-abliterated"), { recursive: true });
    writeFileSync(join(home, ".ollama/models/manifests/registry.ollama.ai/huihui_ai/qwen3-abliterated/8b"), "{}");
    for (const r of ["models--secretorg--Acme-Internal-8B-Uncensored", "models--meta-llama--Llama-Guard-3-8B"]) mkdirSync(join(home, ".cache/huggingface/hub", r, "snapshots"), { recursive: true });
    const fixture = join(home, "probe.json");
    writeFileSync(fixture, JSON.stringify({ lsof: "", ps: "", "ollama-api-tags": JSON.stringify({ models: [{ name: "nidumai/nidum-gemma-3-4b-it-uncensored:q4_k_m" }, { name: "llama3:latest" }] }) }));
    const env = { ...process.env, HOME: home, USERPROFILE: home, MOORAI_AIBOM_PROBE_FIXTURE: fixture, MOORAI_AIBOM_PLATFORM: "linux" };
    for (const k of ["MOORAI_AIBOM_JSON", "OLLAMA_MODELS", "HF_HOME", "HF_HUB_CACHE", "LLAMA_CACHE", "XDG_CACHE_HOME"]) delete env[k];
    const out = execFileSync(process.execPath, [AIBOM], { env, encoding: "utf8" });
    const d = JSON.parse(out);
    assertContentFree(d.localModelSafety, "CLI");
    assert.deepEqual(counts(d.localModelSafety), { ollama: [3, 2], huggingface: [2, 1] });
    assert.equal(d.localModelSafety.safetyRemovedByName, true);
    assert.equal(d.summary.localModelsSafetyRemovedByName, 3);
    for (const leak of ["secretorg", "Acme-Internal", "nidum", "qwen3-abliterated"]) assert.ok(!out.includes(leak), `${leak} anywhere in the AIBOM`);
    const md = execFileSync(process.execPath, [AIBOM, "--format", "md"], { env, encoding: "utf8" });
    assert.match(md, /## Local models with safety training removed \(by name\)/);
    assert.match(md, /name only/i);
    assert.match(md, /does not prove or disprove a backdoor/i);
    assert.match(md, /\| ollama \| 3 \| 2 \|/);
  } finally { rmTree(home); }
});
