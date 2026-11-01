// The model files one shell command loads or serves, for the provenance pin check (cli/model-pins-hook.mjs).
// It reuses the two recognisers #76 already has: the statement splitter and token helpers of
// data/model-download.js, and the model-load calls of data/model-load.js (each in code position).
//
//   llama.cpp   llama-server / llama-cli / llama-run / … / llamafile  -m | --model | -md | --model-draft <file>
//   vLLM        vllm serve <path | hub id> (or --model)          a hub id: unresolved (the file is fetched)
//   Ollama      ollama run <model>                               the model layer blob its manifest names
//               ollama create <name> [-f <Modelfile>]            the Modelfile's FROM: a path, or a model
//                                                                in the store (its manifest's blob)
//   Python      torch.load / pickle / joblib / dill / read_pickle / np.load / load_model / from_pretrained
//               with a local path as its first string argument (a hub id from from_pretrained is not
//               checked: the same call loads tokenizers and configs)
//
// → [{ kind, path: string | null, isFile, claimed?: sha256 }]. path null: the command loads a model this
// device cannot name yet (an Ollama model not in the store, a vLLM hub id); the caller treats it as
// unverified. claimed: the sha256 an Ollama manifest names for the blob (checked against the file's own
// hash, never trusted on its own).
import { readFileSync, statSync, existsSync } from "node:fs";
import { join, resolve, dirname, isAbsolute } from "node:path";
import { homedir } from "node:os";
import { statements, tokens, commandIndex, baseName } from "../data/model-download.js";
import { modelLoadCalls } from "../data/model-load.js";
import { storeDir } from "./model-scan-queue.mjs";

export const LOAD_PREFILTER = /llama|vllm|ollama|torch\.load|pickle|joblib|dill|read_pickle|np\.load|numpy\.load|load_model|from_pretrained/;
const LLAMA_CPP = new Set(["llama-server", "llama-cli", "llama-run", "llama-simple", "llama-simple-chat", "llama-bench", "llama-mtmd-cli", "llama-perplexity", "llama-embedding", "llama-quantize", "llamafile"]);
const MODEL_FLAGS = new Set(["-m", "--model", "-md", "--model-draft"]);
const PY_PATH_CALLS = /^(?:torch\.load|c?[Pp]ickle\.loads?|_pickle\.loads?|joblib\.load|dill\.loads?|cloudpickle\.loads?|read_pickle|np\.load|numpy\.load|load_model|from_pretrained)$/;
const MODELFILE_MAX = 64 * 1024;
const OLLAMA_LAYERS = new Set(["application/vnd.ollama.image.model", "application/vnd.ollama.image.adapter", "application/vnd.ollama.image.projector"]);

const expandHome = (p, home) => (p === "~" ? home : p.startsWith("~/") ? join(home, p.slice(2)) : p);
const pathLike = (v) => /^(?:\/|\.{1,2}\/|~\/|~$|[A-Za-z]:[\\/])/.test(v);
const isDir = (p) => { try { return statSync(p).isDirectory(); } catch { return false; } };

function local(v, base, home) {
  if (!v) return null;
  const p = expandHome(v, home);
  const abs = isAbsolute(p) ? p : resolve(base, p);
  return pathLike(v) || existsSync(abs) ? abs : null;
}

// An Ollama model name → the blobs its manifest names. → [{ path, claimed }] or null (no manifest).
export function ollamaBlobs(name, { home = homedir(), env = process.env, platform = process.platform } = {}) {
  const root = storeDir("ollama", { home, env, platform });
  if (!root || typeof name !== "string" || !name || name.length > 300 || name.includes("..")) return null;
  let ref = name, tag = "latest";
  const at = ref.lastIndexOf(":");
  if (at > ref.lastIndexOf("/")) { tag = ref.slice(at + 1); ref = ref.slice(0, at); }
  const parts = ref.split("/").filter(Boolean);
  if (!parts.length || parts.length > 3 || !tag) return null;
  const [host, ns, model] = parts.length === 3 ? parts : parts.length === 2 ? ["registry.ollama.ai", ...parts] : ["registry.ollama.ai", "library", parts[0]];
  let man;
  try { man = JSON.parse(readFileSync(join(root, "manifests", host, ns, model, tag), "utf8")); } catch { return null; }
  const out = [];
  for (const l of Array.isArray(man && man.layers) ? man.layers : []) {
    if (!l || !OLLAMA_LAYERS.has(l.mediaType)) continue;
    const m = /^sha256:([0-9a-f]{64})$/.exec(String(l.digest || ""));
    if (m) out.push({ path: join(root, "blobs", `sha256-${m[1]}`), claimed: m[1] });
  }
  return out;
}

function modelfileFrom(file) {
  let text;
  try { const st = statSync(file); if (!st.isFile() || st.size > MODELFILE_MAX) return null; text = readFileSync(file, "utf8"); } catch { return null; }
  const m = /^[ \t]*FROM[ \t]+("[^"\n]+"|'[^'\n]+'|\S+)/im.exec(text);
  return m ? m[1].replace(/^["']|["']$/g, "") : null;
}

function ollamaTargets(kind, name, opts, out) {
  const blobs = ollamaBlobs(name, opts);
  if (!blobs || !blobs.length) { out.push({ kind, path: null, isFile: true }); return; }
  for (const b of blobs) out.push({ kind, path: b.path, isFile: true, claimed: b.claimed });
}

// The first word that is not a flag; a flag in `valued` takes the next word as its value.
function firstPositional(args, valued = new Set()) {
  for (let k = 0; k < args.length; k++) {
    const t = args[k];
    if (t.startsWith("-")) { if (valued.has(t)) k++; continue; }
    return t;
  }
  return null;
}
const OLLAMA_RUN_VALUED = new Set(["--format", "--keepalive"]);

function shellTargets(statement, { cwd, home, env, platform }, out) {
  const toks = tokens(statement);
  if (!toks.length) return;
  const i = commandIndex(toks);
  const cmd = baseName(toks[i]);
  const args = toks.slice(i + 1);
  if (LLAMA_CPP.has(cmd)) {
    for (let k = 0; k < args.length; k++) {
      const t = args[k];
      let v = null;
      if (MODEL_FLAGS.has(t) && k + 1 < args.length) v = args[++k];
      else { const eq = /^(--model|--model-draft)=(.+)$/.exec(t); if (eq) v = eq[2]; }
      if (v) { const p = expandHome(v, home); out.push({ kind: "llama.cpp", path: isAbsolute(p) ? p : resolve(cwd, p), isFile: true }); }
    }
    return;
  }
  if (cmd === "vllm" && args[0] === "serve") {
    const rest = args.slice(1);
    // The model is the word right after "serve", or --model; anything else cannot be read safely (vLLM flags
    // mix booleans and values), so it is unresolved, not guessed.
    let v = rest[0] && !rest[0].startsWith("-") ? rest[0] : null;
    for (let k = 0; k < rest.length && !v; k++) { if (rest[k] === "--model" && k + 1 < rest.length) v = rest[k + 1]; else if (rest[k].startsWith("--model=")) v = rest[k].slice(8); }
    if (!v) { out.push({ kind: "vllm", path: null, isFile: true }); return; }
    const p = local(v, cwd, home);
    out.push({ kind: "vllm", path: p, isFile: p ? !isDir(p) : true });
    return;
  }
  if (cmd === "ollama" && args[0] === "run" && args[1]) {
    const name = firstPositional(args.slice(1), OLLAMA_RUN_VALUED);
    if (name) ollamaTargets("ollama-run", name, { home, env, platform }, out);
    else out.push({ kind: "ollama-run", path: null, isFile: true });
    return;
  }
  if (cmd === "ollama" && args[0] === "create") {
    let mf = null;
    for (let k = 1; k < args.length; k++) { if ((args[k] === "-f" || args[k] === "--file") && k + 1 < args.length) mf = args[k + 1]; else if (args[k].startsWith("--file=")) mf = args[k].slice(7); }
    const file = mf ? resolve(cwd, expandHome(mf, home)) : join(cwd, "Modelfile");
    const from = modelfileFrom(file);
    if (!from) { out.push({ kind: "ollama-create", path: null, isFile: true }); return; }
    const p = local(from, dirname(file), home);
    if (p) out.push({ kind: "ollama-create", path: p, isFile: !isDir(p) });
    else ollamaTargets("ollama-create", from, { home, env, platform }, out);
  }
}

function pythonTargets(text, { cwd, home }, out) {
  for (const c of modelLoadCalls(text)) {
    if (!PY_PATH_CALLS.test(c.name)) continue;
    const m = /^\s*(?:open\s*\(\s*)?(?:f|filepath|pretrained_model_name_or_path|path|file)?\s*=?\s*(['"])([^'"\n]{1,1000})\1/.exec(c.args);
    if (!m) continue;
    const p = local(m[2], cwd, home);
    if (p) out.push({ kind: `python:${c.name.replace(/^c?[Pp]ickle\./, "pickle.").replace(/^numpy\./, "np.")}`, path: p, isFile: !isDir(p) });
  }
}

export function modelLoadTargets(command, { cwd = process.cwd(), home = homedir(), env = process.env, platform = process.platform } = {}) {
  const out = [];
  if (typeof command !== "string" || command.length > 200_000 || !LOAD_PREFILTER.test(command)) return out;
  const opts = { cwd: cwd || process.cwd(), home, env, platform };
  for (const s of statements(command)) shellTargets(s, opts, out);
  pythonTargets(command, opts, out);
  const seen = new Set();
  return out.filter((t) => { const k = `${t.kind}|${t.path}`; if (seen.has(k)) return false; seen.add(k); return true; }).slice(0, 32);
}
