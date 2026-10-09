// Local models whose NAME says their safety training was removed — a content-free governance signal for
// the AIBOM (cli/moorai-aibom.mjs). It reads model NAMES that local runtimes keep on this device, in
// memory only, matches them against a short token list, and emits nothing but per-runtime counts and a
// boolean. A name, path, org, tag or digest never leaves this module.
//
// What this is NOT: it says nothing about the weights. A model renamed to look benign is not caught, a
// model whose name carries a token may be harmless, and a backdoored fine-tune (a hidden trigger in
// otherwise normal weights) has no tell in its name at all. It neither proves nor disproves a backdoor.
//
// Where names come from (no network egress; the one socket is 127.0.0.1):
//   ollama       <models>/manifests/<registry>/<namespace>/<model>/<tag>, models = $OLLAMA_MODELS or the
//                per-OS default — docs.ollama.com/faq "Where are models stored?": "macOS: ~/.ollama/models",
//                "Linux: /usr/share/ollama/.ollama/models", "Windows: C:\Users\%username%\.ollama\models";
//                plus GET http://127.0.0.1:11434/api/tags ("List Local Models": { models: [{ name, … }] }),
//                which also covers a server whose OLLAMA_MODELS this process cannot see. The host is fixed
//                to 127.0.0.1: OLLAMA_HOST is never followed, so the probe cannot be pointed off the device.
//   lmstudio     ~/.lmstudio/models/<publisher>/<model>/<file>.gguf — lmstudio.ai/docs/app/advanced/import-model:
//                "publisher/model/model-file.gguf"; ~/.cache/lm-studio/models is the pre-0.3 location.
//   jan          <data>/llamacpp/models and <data>/mlx/models, "<org>/<repo>/" — jan.ai/docs/desktop/data-folder;
//                <data> = "%APPDATA%/Jan/data", "~/Library/Application Support/Jan/data", "~/.local/share/Jan/data".
//   gpt4all      model files in docs.gpt4all.io/gpt4all_desktop/settings.html's default download path:
//                "C:\Users\{username}\AppData\Local\nomic.ai\GPT4All", "/Users/{username}/Library/Application
//                Support/nomic.ai/GPT4All/", "/home/{username}/.local/share/nomic.ai/GPT4All".
//   llama.cpp    `-hf` download cache: $LLAMA_CACHE, else %LOCALAPPDATA% / ~/Library/Caches / $XDG_CACHE_HOME
//                or ~/.cache, + "llama.cpp" (ggml-org/llama.cpp common/common.cpp fs_get_cache_directory).
//                Both flat *.gguf files and Hugging Face cache-layout repos are counted.
//   huggingface  $HF_HUB_CACHE, else $HF_HOME/hub, else ~/.cache/huggingface/hub (huggingface_hub
//                manage-cache guide); a repo is "models--<org>--<name>" (datasets--, spaces-- are not models).
//
// Bounds: one deadline for the whole collection (default 2 s, the HTTP call gets only the time left),
// at most LIMITS.maxEntries directory entries in total and LIMITS.maxPerDir from any one directory, a
// fixed walk depth per runtime (no recursion), and for /api/tags a total (not idle) timeout, a byte cap
// and a model cap. Directories are read lazily (fs.opendirSync), so a huge one costs only what is read.
import { opendirSync } from "node:fs";
import { request } from "node:http";
import { homedir } from "node:os";
import { join } from "node:path";

// Each token is a whole WORD of the name (see nameWords): a token glued to other letters is a different
// word. Justified from public model-hub naming (Hugging Face model search, sorted by downloads, 2026-10-08).
export const SAFETY_REMOVED_TOKENS = Object.freeze([
  { token: "abliterated", example: "huihui-ai/Huihui-Qwen3.8-27B-abliterated-GGUF",
    why: "Abliteration projects the refusal direction out of the weights; per huggingface.co/blog/mlabonne/abliteration the model 'loses its ability to refuse requests'. The suffix names the result (failspy/llama-3-70B-Instruct-abliterated; the top hit had 2.1M downloads)." },
  { token: "obliterated", example: "OBLITERATUS/Qwen3.8-27B-OBLITERATED",
    why: "Same technique, other spelling: the OBLITERATUS model cards say 'Abliteration removes refusal behavior'; mradermacher and mlx-community republish them under the same suffix." },
  { token: "uncensored", example: "JonathanColetti/Qwen3.8-27B-Uncensored-GGUF",
    why: "The community's oldest label for a refusal-free fine-tune (llama2-uncensored, the Lexi-Uncensored family); the five most-downloaded hits each had about 2M downloads. Lexi models always carry it, so 'lexi' is not needed as a token." },
  { token: "decensored", example: "mradermacher/gemma-4-12B-it-heretic_decensored-i1-GGUF",
    why: "Used for the same outcome by newer releases (…-Decensored-i1-GGUF, …heretic_decensored…); every hit was a refusal-removed model." },
  { token: "unaligned", example: "bartowski/LLAMA-3_8B_Unaligned_BETA-GGUF",
    why: "Names a model trained away from its alignment (LLAMA-3_8B_Unaligned, Unaligned-Thinker); 'aligned' alone is a different word and does not match." },
  { token: "jailbroken", example: "cooperleong00/Meta-Llama-3-8B-Instruct-Jailbroken",
    why: "Names a model fine-tuned to comply (…-Instruct-Jailbroken and its GGUF republishes). 'jailbreak' is NOT a token: its top hits are detectors (jackhhao/jailbreak-classifier, madhurjindal/Jailbreak-Detector)." },
  { token: "heretic", example: "AEON-7/Qwen3.6-35B-A3B-heretic-NVFP4",
    why: "Output of p-e-w/heretic, 'Fully automatic censorship removal for language models'; its releases carry the tool's name (…-heretic, …-Heretic-Uncensored), with hits up to 2M downloads." }
]);
// Considered and left out: "jailbreak" and "guardrails" (their hub hits are safety classifiers),
// "no-guardrails" (no hub usage found), "lexi" (reallexi/lexi-coder is an ordinary coder; Lexi
// uncensored models also say "Uncensored"), "unfiltered" (EleutherAI/deep-ignorance-unfiltered means
// unfiltered PRETRAINING DATA in a safety study), "nsfw" (content classifiers), "dolphin" (an uncensored
// family by its model card, but the name does not say so).
const TOKENS = new Set(SAFETY_REMOVED_TOKENS.map((t) => t.token));

export const MODEL_SOURCES = Object.freeze(["ollama", "lmstudio", "jan", "gpt4all", "llama.cpp", "huggingface"]);
export const LIMITS = Object.freeze({ deadlineMs: 2000, maxEntries: 5000, maxPerDir: 1000, httpTimeoutMs: 1000, httpMaxBytes: 1024 * 1024, httpMaxModels: 1000, maxNameLength: 256 });
const OLLAMA_PORT = 11434;

// Words of a name: split at every non-alphanumeric character (- _ . / : space …), at a lower→upper case
// change, between an acronym and the next word ("LMUncensored" → LM Uncensored) and at a letter↔digit
// change, then lower-cased. "Qwen3-8B-Jailbroken.Q6_K" → qwen 3 8 b jailbroken q 6 k.
export function nameWords(name) {
  if (typeof name !== "string" || !name || name.length > LIMITS.maxNameLength) return [];
  return name.replace(/([a-z])(?=[A-Z])/g, "$1 ").replace(/([A-Z])(?=[A-Z][a-z])/g, "$1 ").replace(/([A-Za-z])(?=[0-9])/g, "$1 ").replace(/([0-9])(?=[A-Za-z])/g, "$1 ")
    .toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
}

export function safetyRemovedByName(name) {
  return nameWords(name).some((w) => TOKENS.has(w));
}

// → [{ runtime, kind, dir }] for this OS. kind says how the directory is laid out (see WALKS).
export function modelDirs({ platform = process.platform, env = process.env, home = homedir() } = {}) {
  const win = platform === "win32", mac = platform === "darwin";
  const localAppData = env.LOCALAPPDATA || join(home, "AppData", "Local");
  const appData = env.APPDATA || join(home, "AppData", "Roaming");
  const xdgCache = env.XDG_CACHE_HOME || join(home, ".cache");
  const out = [];
  const add = (runtime, kind, dir) => { if (dir && !out.some((d) => d.runtime === runtime && d.dir === dir)) out.push({ runtime, kind, dir }); };
  for (const m of [env.OLLAMA_MODELS, join(home, ".ollama", "models"), !win && !mac && "/usr/share/ollama/.ollama/models"]) if (m) add("ollama", "ollama-manifests", join(m, "manifests"));
  add("lmstudio", "publisher-repo", join(home, ".lmstudio", "models"));
  add("lmstudio", "publisher-repo", join(home, ".cache", "lm-studio", "models"));
  const jan = win ? join(appData, "Jan", "data") : mac ? join(home, "Library", "Application Support", "Jan", "data") : join(home, ".local", "share", "Jan", "data");
  add("jan", "publisher-repo", join(jan, "llamacpp", "models"));
  add("jan", "publisher-repo", join(jan, "mlx", "models"));
  add("gpt4all", "model-files", win ? join(localAppData, "nomic.ai", "GPT4All") : mac ? join(home, "Library", "Application Support", "nomic.ai", "GPT4All") : join(home, ".local", "share", "nomic.ai", "GPT4All"));
  add("llama.cpp", "files-and-hf", env.LLAMA_CACHE || (win ? join(localAppData, "llama.cpp") : mac ? join(home, "Library", "Caches", "llama.cpp") : join(xdgCache, "llama.cpp")));
  add("huggingface", "hf-cache", env.HF_HUB_CACHE || (env.HF_HOME ? join(env.HF_HOME, "hub") : join(xdgCache, "huggingface", "hub")));
  return out;
}

const MODEL_FILE = /\.(gguf|llamafile)$/i;
const hfRepo = (entry) => { const m = /^models--(.+)$/.exec(entry); return m ? m[1].split("--").join("/") : null; };

// The collection: { byRuntime: Map<runtime, Map<modelName, matched>>, entries, truncated, timedOut }.
// Names stay in this in-memory map; summarizeModelSafety() reduces it to counts.
export function scanModelNames({ platform = process.platform, env = process.env, home = homedir(), fsx = { opendir: opendirSync },
  now = Date.now, deadline, deadlineMs = LIMITS.deadlineMs, maxEntries = LIMITS.maxEntries, maxPerDir = LIMITS.maxPerDir } = {}) {
  const stopAt = deadline ?? now() + deadlineMs;
  const st = { byRuntime: new Map(), entries: 0, truncated: false, timedOut: false };
  const stopped = () => st.timedOut || st.entries >= maxEntries;
  // Lazily list one directory → [{ name, dir: bool }], within every bound. Unreadable → [].
  const list = (dir) => {
    if (st.timedOut) return [];
    if (st.entries >= maxEntries) { st.truncated = true; return []; }
    let d;
    try { d = fsx.opendir(dir); } catch { return []; }
    const out = [];
    try {
      for (;;) {
        if (now() > stopAt) { st.timedOut = true; break; }
        if (st.entries >= maxEntries || out.length >= maxPerDir) { st.truncated = true; break; }
        const e = d.readSync();
        st.entries++;
        if (!e) break;
        if (typeof e.name !== "string" || e.name.startsWith(".")) continue;
        out.push({ name: e.name, dir: e.isDirectory() || (e.isSymbolicLink?.() ?? false) });
      }
    } catch { /* unreadable mid-way: keep what was read */ } finally { try { d.closeSync(); } catch { /* already closed */ } }
    return out;
  };
  const add = (runtime, name, matched = safetyRemovedByName(name)) => {
    if (!name || name.length > LIMITS.maxNameLength) return;
    let m = st.byRuntime.get(runtime);
    if (!m) { m = new Map(); st.byRuntime.set(runtime, m); }
    m.set(name, (m.get(name) || false) || matched);
  };
  const WALKS = {
    "ollama-manifests": (runtime, root) => {
      for (const reg of list(root)) if (reg.dir) for (const ns of list(join(root, reg.name))) if (ns.dir)
        for (const model of list(join(root, reg.name, ns.name))) if (model.dir)
          for (const tag of list(join(root, reg.name, ns.name, model.name))) if (!tag.dir) {
            const base = reg.name === "registry.ollama.ai" ? (ns.name === "library" ? model.name : `${ns.name}/${model.name}`) : `${reg.name}/${ns.name}/${model.name}`;
            add(runtime, `${base}:${tag.name}`);
          }
    },
    "publisher-repo": (runtime, root) => {
      for (const pub of list(root)) if (pub.dir) for (const repo of list(join(root, pub.name))) if (repo.dir) {
        const name = `${pub.name}/${repo.name}`;
        add(runtime, name, safetyRemovedByName(name) || list(join(root, pub.name, repo.name)).some((f) => !f.dir && safetyRemovedByName(f.name)));
      }
    },
    "model-files": (runtime, root) => { for (const f of list(root)) if (!f.dir && MODEL_FILE.test(f.name)) add(runtime, f.name); },
    "files-and-hf": (runtime, root) => {
      for (const f of list(root)) { if (!f.dir && MODEL_FILE.test(f.name)) add(runtime, f.name); else if (f.dir && hfRepo(f.name)) add(runtime, hfRepo(f.name)); }
    },
    "hf-cache": (runtime, root) => { for (const f of list(root)) if (f.dir && hfRepo(f.name)) add(runtime, hfRepo(f.name)); }
  };
  for (const d of modelDirs({ platform, env, home })) {
    if (stopped()) break;
    try { WALKS[d.kind](d.runtime, d.dir); } catch { /* fail-open per runtime */ }
  }
  st.addNames = (runtime, names) => { for (const n of names) if (typeof n === "string") add(runtime, n); };
  return st;
}

// The content-free record: fixed keys, runtime ids from MODEL_SOURCES, counts and booleans only.
export function summarizeModelSafety(st) {
  if (!st || !(st.byRuntime instanceof Map)) return null;
  const sources = [];
  for (const runtime of MODEL_SOURCES) {
    const m = st.byRuntime.get(runtime);
    if (!m || !m.size) continue;
    sources.push({ runtime, models: m.size, safetyRemovedByName: [...m.values()].filter(Boolean).length });
  }
  const count = sources.reduce((s, x) => s + x.safetyRemovedByName, 0);
  return { basis: "name", safetyRemovedByName: count > 0, count, sources, truncated: !!st.truncated, timedOut: !!st.timedOut };
}

// An /api/tags body → { names, truncated } or null when it is not { models: [...] }.
export function parseOllamaTags(text, maxModels = LIMITS.httpMaxModels) {
  let j;
  try { j = JSON.parse(String(text)); } catch { return null; }
  const models = j && Array.isArray(j.models) ? j.models : null;
  if (!models) return null;
  const names = models.map((m) => (m && typeof m.name === "string" ? m.name : null)).filter(Boolean);
  return { names: names.slice(0, maxModels), truncated: names.length > maxModels };
}

// GET http://127.0.0.1:<port>/api/tags → { names, truncated } or null (refused, timed out, too big, not
// 200, not JSON). The timer is TOTAL, so a server that drips bytes cannot hold the probe open.
export function fetchOllamaTagsLoopback({ port = OLLAMA_PORT, timeoutMs = LIMITS.httpTimeoutMs, maxBytes = LIMITS.httpMaxBytes, maxModels = LIMITS.httpMaxModels } = {}) {
  return new Promise((resolve) => {
    let done = false, size = 0;
    const chunks = [];
    const finish = (v) => { if (done) return; done = true; clearTimeout(timer); try { req.destroy(); } catch { /* gone */ } resolve(v); };
    const req = request({ host: "127.0.0.1", port, path: "/api/tags", method: "GET", agent: false, headers: { accept: "application/json" } }, (res) => {
      if (res.statusCode !== 200) { res.resume(); return finish(null); }
      res.on("data", (c) => { size += c.length; if (size > maxBytes) return finish(null); chunks.push(c); });
      res.on("end", () => finish(parseOllamaTags(Buffer.concat(chunks).toString("utf8"), maxModels)));
      res.on("error", () => finish(null));
    });
    const timer = setTimeout(() => finish(null), Math.max(1, timeoutMs));
    req.on("error", () => finish(null));
    req.end();
  });
}

// The whole collector: directory walks, then /api/tags with whatever time is left. Fail-open: any part
// that cannot run contributes nothing; the record is always returned.
export async function localModelSafety({ ollamaTags = fetchOllamaTagsLoopback, now = Date.now, deadlineMs = LIMITS.deadlineMs, ...opts } = {}) {
  const deadline = now() + deadlineMs;
  let st;
  try { st = scanModelNames({ ...opts, now, deadline }); } catch { st = { byRuntime: new Map(), entries: 0, truncated: false, timedOut: false, addNames() {} }; }
  const left = deadline - now();
  if (left <= 0) st.timedOut = true;
  else {
    try {
      const r = await ollamaTags({ timeoutMs: Math.min(LIMITS.httpTimeoutMs, left) });
      if (r && Array.isArray(r.names)) { st.addNames("ollama", r.names); if (r.truncated) st.truncated = true; }
    } catch { /* unreachable: nothing added */ }
  }
  return summarizeModelSafety(st);
}
