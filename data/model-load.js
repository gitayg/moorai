// Unsafe AI model loading — the load step through which a malicious model file runs its code
// (ATLAS AML.T0011.000 Unsafe AI Artifacts: "An unsafe artifact may exploit deserialization ... to
// execute code on the host", and "functionality intentionally supported by an AI runtime").
//
// code-insecure-deser (#61) already fires on any `pickle.load(` in code the agent WRITES. What it does
// not see: the same calls in a COMMAND the agent runs (`python -c`, a heredoc), the other pickle-backed
// loaders (joblib, dill, cloudpickle, pandas.read_pickle, numpy allow_pickle=True), torch.load with its
// safety switch turned off, Keras safe_mode=False, and remote code a model hub ships alongside the
// weights (trust_remote_code=True / --trust-remote-code).
//
// Each call is judged on its OWN arguments, and only when it sits in code position:
//   torch.load        weights_only=False -> fire; weights_only=True -> silent; no argument -> fire only
//                     when the source is untrusted. PyTorch >= 2.6 defaults to weights_only=True, so a
//                     bare torch.load of your own checkpoint is not the risk; the explicit False (often
//                     added to silence the 2.6 change) and an older runtime loading a download are.
//   pickle / joblib / dill / cloudpickle / read_pickle -> fire when the source is untrusted: a URL, a
//                     network read, a hub download, a temp or Downloads path. (A local file in the
//                     project is code-insecure-deser's finding on written code, and not re-raised here.)
//   np.load allow_pickle=True, load_model safe_mode=False, *trust_remote_code=True -> fire.
// "Code position": the call opens a statement (start of line, after `;`, inside `python -c "…"`), or is
// the value of an assignment, argument, return, with or await. Prose — "never call torch.load(path)",
// "Is joblib.load('x') safe?", `pickle.load(f)` in backticks — is not code and stays silent.
// Content-free: the caller gets a boolean.

const MAX = 200_000;
const MAX_CALLS = 400;

const CALL = /\b(torch\.load|c?[Pp]ickle\.loads?|_pickle\.loads?|joblib\.load|dill\.loads?|cloudpickle\.loads?|read_pickle|np\.load|numpy\.load|load_model|from_pretrained|pipeline|load_dataset)\s{0,4}\(/g;
const PICKLE_FAMILY = /^(?:c?[Pp]ickle\.loads?|_pickle\.loads?|joblib\.load|dill\.loads?|cloudpickle\.loads?|read_pickle)$/;
const UNTRUSTED = /https?:\/\/|\burlopen\s{0,4}\(|\brequests\.(?:get|post)\s{0,4}\(|\bhttpx\.get\s{0,4}\(|\burlretrieve\s{0,4}\(|\bhf_hub_download\s{0,4}\(|\bcached_download\s{0,4}\(|\/tmp\/|\/var\/tmp\/|\/dev\/shm\/|[\\\/]Downloads?[\\\/]|(?:^|["'\s(])downloads?[\\\/]|\$TMPDIR|%TEMP%|\$env:TEMP|\.cache[\\\/]huggingface/i;
const REMOTE_CODE_CLI = /^[ \t]{0,8}(?:[A-Z_][A-Z0-9_]{0,40}=\S{0,200}[ \t]{1,4}){0,4}(?:sudo[ \t]{1,4})?(?:vllm|lm_eval|lm-eval|python[\d.]{0,4}|uv|accelerate|torchrun|deepspeed|text-generation-launcher|sglang|optimum-cli|mlx_lm\.\w{1,20}|llamafactory-cli|axolotl|tgi)\b[^\n]{0,2000}?(?<![\w-])--trust[-_]remote[-_]code(?![\w-])(?![ \t]{0,4}=?[ \t]{0,4}(?:false|0)\b)/im;

// Where the statement holding the call begins: the last newline, `;`, or opening `-c "` before it.
function statementPrefix(text, start) {
  const window = text.slice(Math.max(0, start - 400), start);
  let cut = Math.max(window.lastIndexOf("\n"), window.lastIndexOf(";"));
  for (const m of window.matchAll(/-c\s{0,4}["']/g)) cut = Math.max(cut, m.index + m[0].length - 1);
  return window.slice(cut + 1);
}

function inCodePosition(text, start) {
  if (start > 0 && text[start - 1] === "`") return false;
  const p = statementPrefix(text, start).trim();
  if (!p) return true;
  return /(?:[=(,\[{:]|\breturn|\bawait|\byield|\bwith|\bin|\bassert|\bprint\s{0,4}\()$/.test(p) && !/`[^`]{0,200}$/.test(p);
}

// The call's argument text: up to the matching `)`, bounded.
function argsOf(text, open) {
  let depth = 0;
  const end = Math.min(text.length, open + 600);
  for (let i = open; i < end; i++) {
    const ch = text[i];
    if (ch === "(") depth++;
    else if (ch === ")" && --depth === 0) return text.slice(open + 1, i);
  }
  return text.slice(open + 1, end).split("\n")[0];
}

function callUnsafe(name, args) {
  if (name === "torch.load") {
    if (/\bweights_only\s{0,4}=\s{0,4}False\b/.test(args)) return true;
    if (/\bweights_only\s{0,4}=\s{0,4}True\b/.test(args)) return false;
    return UNTRUSTED.test(args);
  }
  if (PICKLE_FAMILY.test(name)) return UNTRUSTED.test(args);
  if (name === "np.load" || name === "numpy.load") return /\ballow_pickle\s{0,4}=\s{0,4}True\b/.test(args);
  if (name === "load_model") return /\bsafe_mode\s{0,4}=\s{0,4}False\b/.test(args);
  return /\btrust_remote_code\s{0,4}=\s{0,4}True\b/.test(args);
}

function scanUnsafeModelLoad(text) {
  if (typeof text !== "string" || text.length > MAX) return false;
  CALL.lastIndex = 0;
  let m, n = 0;
  while ((m = CALL.exec(text)) !== null && n++ < MAX_CALLS) {
    let start = m.index;
    while (start > 0 && start > m.index - 120 && /[\w.]/.test(text[start - 1])) start--;
    if (!inCodePosition(text, start)) continue;
    if (callUnsafe(m[1], argsOf(text, m.index + m[0].length - 1))) return true;
  }
  return REMOTE_CODE_CLI.test(text);
}

// Memoised on the last text, for the reason data/obfuscation-signal.js gives: _matchDetector re-invokes
// refine() once per prefilter occurrence.
let lastText = null, lastHit = false;
export function unsafeModelLoadHit(text) {
  if (text === lastText) return lastHit;
  lastText = text;
  lastHit = scanUnsafeModelLoad(text);
  return lastHit;
}
