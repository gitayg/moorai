#!/usr/bin/env node
// Sets up the REAL official vector-store MCP servers in a throwaway directory and runs the opt-in live test
// test/index-real-vector-mcp.test.mjs against them (MoorAI's index stage through the stdio proxy and the
// HTTP gateway).
//
//   node scripts/real-vector-mcp.mjs [setup|test|all] [--dir <dir>] [--break report|unwired]
//
//   setup   two uv venvs (Python 3.12, no Python download) with the pinned servers, and their default
//           embedding model (all-MiniLM-L6-v2) fetched from Hugging Face. Idempotent.
//   test    MOORAI_LIVE_VECTOR=1 MOORAI_REALVEC_DIR=<dir> node --test test/index-real-vector-mcp.test.mjs,
//           then checks that no server is left running.
//   all     (default) setup, then test.
//   --dir   default $MOORAI_REALVEC_DIR, else <tmpdir>/moorai-realvec
//   --break falsification: the block policies are sent as indexScanAction "report", or with the
//           heuristic off and no indexTools; the block tests must go red.
//
// Network: PyPI (packages) and Hugging Face (models) during setup only. Chroma's own default model URL
// (an S3 bucket) is NOT used: the same all-MiniLM-L6-v2 ONNX export is fetched from Hugging Face
// (sentence-transformers/all-MiniLM-L6-v2) into the cache path Chroma checks first. At test time every
// server runs with HF_HUB_OFFLINE=1, ANONYMIZED_TELEMETRY=False and, on macOS, under sandbox-exec with
// outbound IP denied except localhost. No API key and no cloud service is involved.
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, copyFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
export const PINS = { chroma: "chroma-mcp==0.2.6", qdrant: "mcp-server-qdrant==0.8.1" };
const ST_REPO = "sentence-transformers/all-MiniLM-L6-v2";
const ST_FILES = ["onnx/model.onnx", "config.json", "special_tokens_map.json", "tokenizer_config.json", "tokenizer.json", "vocab.txt"];

const argv = process.argv.slice(2);
const opt = (name) => { const i = argv.indexOf(name); return i >= 0 ? argv[i + 1] : undefined; };
const mode = argv.find((a) => ["setup", "test", "all"].includes(a)) || "all";
const DIR = opt("--dir") || process.env.MOORAI_REALVEC_DIR || join(tmpdir(), "moorai-realvec");
const BREAK = opt("--break") || "";

function run(cmd, args, env = {}, { cwd = DIR, capture = false } = {}) {
  process.stderr.write(`$ ${cmd} ${args.join(" ")}\n`);
  const r = spawnSync(cmd, args, { cwd, env: { ...process.env, ...env }, stdio: capture ? ["ignore", "pipe", "inherit"] : "inherit", encoding: "utf8" });
  if (r.status !== 0) { process.stderr.write(`failed (${r.status ?? r.signal}): ${cmd} ${args.join(" ")}\n`); process.exit(1); }
  return r.stdout;
}

function setup() {
  if (spawnSync("uv", ["--version"]).status !== 0) { process.stderr.write("uv is required (https://docs.astral.sh/uv/)\n"); process.exit(1); }
  mkdirSync(DIR, { recursive: true });
  const uvEnv = { UV_CACHE_DIR: join(DIR, "uv-cache") };
  for (const [name, pin] of Object.entries(PINS)) {
    const venv = join(DIR, `${name}-env`);
    if (!existsSync(join(venv, "bin", "python"))) run("uv", ["venv", "--no-python-downloads", "-p", "3.12", venv], uvEnv);
    run("uv", ["pip", "install", "--no-python-downloads", pin], { ...uvEnv, VIRTUAL_ENV: venv });
  }
  const hf = { HF_HOME: join(DIR, "models", "hf"), HF_HUB_DISABLE_TELEMETRY: "1" };
  // Qdrant: fastembed's default model, downloaded by fastembed itself (Hugging Face: Qdrant/all-MiniLM-L6-v2-onnx).
  run(join(DIR, "qdrant-env", "bin", "python"), ["-c", "from fastembed import TextEmbedding; m = TextEmbedding('sentence-transformers/all-MiniLM-L6-v2'); print('fastembed dim', len(list(m.passage_embed(['x']))[0]))"],
    { ...hf, FASTEMBED_CACHE_PATH: join(DIR, "models", "fastembed") });
  // Chroma: the default embedding function's files, into the directory it checks before downloading.
  const onnx = join(DIR, "home", ".cache", "chroma", "onnx_models", "all-MiniLM-L6-v2", "onnx");
  const st = join(DIR, "models", "st-minilm");
  if (!ST_FILES.every((f) => existsSync(join(onnx, f.replace(/^onnx\//, ""))))) {
    run(join(DIR, "chroma-env", "bin", "hf"), ["download", ST_REPO, ...ST_FILES, "--local-dir", st], hf);
    mkdirSync(onnx, { recursive: true });
    for (const f of ST_FILES) copyFileSync(join(st, f), join(onnx, f.replace(/^onnx\//, "")));
  }
  for (const name of Object.keys(PINS)) {
    const freeze = run("uv", ["pip", "freeze"], { ...uvEnv, VIRTUAL_ENV: join(DIR, `${name}-env`) }, { capture: true });
    process.stdout.write(`${name}-env: ${freeze.split("\n").filter((l) => /^(chroma-mcp|chromadb|mcp-server-qdrant|qdrant-client|fastembed|fastmcp|mcp|onnxruntime)==/.test(l)).join(" ")}\n`);
  }
  run("du", ["-sh", join(DIR, "uv-cache"), join(DIR, "chroma-env"), join(DIR, "qdrant-env"), join(DIR, "models")]);
}

const leftovers = () => (spawnSync("/bin/ps", ["-axo", "pid=,command="], { encoding: "utf8" }).stdout || "")
  .split("\n").filter((l) => l.includes(DIR) && /chroma-mcp|mcp-server-qdrant/.test(l));

function test() {
  const env = { MOORAI_LIVE_VECTOR: "1", MOORAI_REALVEC_DIR: DIR, ...(BREAK ? { MOORAI_LIVE_VECTOR_BREAK: BREAK } : {}) };
  const r = spawnSync(process.execPath, ["--test", "--import", "./test/hermetic-env.mjs", "test/index-real-vector-mcp.test.mjs"], { cwd: ROOT, env: { ...process.env, ...env }, stdio: "inherit" });
  const left = leftovers();
  process.stdout.write(`servers still running after the test: ${left.length}${left.length ? "\n" + left.join("\n") : ""}\n`);
  return r.status === 0 && left.length === 0 ? 0 : 1;
}

if (mode === "setup" || mode === "all") setup();
process.exit(mode === "setup" ? 0 : test());
