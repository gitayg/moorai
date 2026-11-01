// AI model downloads in one shell command, for the model-download detector (#76, report-only) and for
// the queue that hands the downloaded files to the static model scanner (cli/model-scan-queue.mjs).
// Nothing is scanned on the hook path: the hook only records what the command will fetch, and the
// detached worker scans it after the download has settled.
//
// Recognised (one statement at a time; statements split on newline, ";", "&&", "||" and "|"):
//   ollama pull <model>                                  target: the Ollama model store
//   huggingface-cli download / hf download <repo> …      target: --local-dir, else --cache-dir, else the
//                                                        Hugging Face hub cache
//   git lfs pull                                         target: the repository (cwd, or git -C <dir>)
//   git clone <huggingface.co | hf.co URL> [dir]         target: the clone directory (LFS fetches weights)
//   curl / wget of a URL whose path ends in a model extension (.pt .pth .bin .ckpt .pkl .pickle .joblib
//   .gguf .safetensors .onnx .h5 .keras)                 target: -o / --output / -O / --output-dir (curl),
//                                                        -O / --output-document / -P (wget), else the URL's
//                                                        file name in the working directory
// → [{ kind, target: { file?: string, dir?: string, store?: "ollama" | "hf-cache" } }]. Paths are as
// written (relative paths resolve against the agent's cwd in the queue). Content-free for the detector:
// it only gets a boolean.
const MAX = 200_000;
const MAX_STATEMENTS = 400;
export const MODEL_FILE_EXT = /\.(?:pt|pth|bin|ckpt|pkl|pickle|joblib|gguf|safetensors|onnx|h5|keras)$/i;
const HF_HOST = /^https?:\/\/(?:[\w-]{1,40}\.)?(?:huggingface\.co|hf\.co)\//i;

export const unquote = (t) => String(t || "").replace(/^["']|["']$/g, "");
export const tokens = (segment) => (segment.match(/"[^"]{0,2000}"|'[^']{0,2000}'|\S{1,2000}/g) || []).slice(0, 200).map(unquote);
export function commandIndex(toks) {
  let i = 0;
  while (i < toks.length && (/^[A-Za-z_]\w{0,40}=/.test(toks[i]) || /^(?:sudo|env|time|nohup|command|exec)$/.test(toks[i]))) i++;
  return i;
}
export const baseName = (t) => String(t || "").split(/[\\/]/).pop().toLowerCase().replace(/\.exe$/, "");
// The value of a flag: "--flag value", "--flag=value", "-f value", "-fvalue" (short flags only).
export function flagValue(toks, names) {
  for (let k = 0; k < toks.length; k++) {
    const t = toks[k];
    for (const n of names) {
      if (t === n && k + 1 < toks.length) return toks[k + 1];
      if (n.startsWith("--") && t.startsWith(`${n}=`)) return t.slice(n.length + 1);
      if (!n.startsWith("--") && n.length === 2 && t.startsWith(n) && t.length > 2 && !t.startsWith("--")) return t.slice(2);
    }
  }
  return null;
}
function urlPathName(u) {
  try { const p = new URL(u).pathname; return decodeURIComponent(p.split("/").pop() || ""); } catch { return ""; }
}

function hfDownload(toks, i) {
  const local = flagValue(toks, ["--local-dir"]);
  if (local) return { dir: local };
  const cache = flagValue(toks, ["--cache-dir"]);
  if (cache) return { dir: cache };
  return { store: "hf-cache" };
}

function fetcher(cmd, toks, i) {
  const urls = toks.slice(i + 1).filter((t) => /^https?:\/\//i.test(t));
  const model = urls.find((u) => MODEL_FILE_EXT.test(urlPathName(u)));
  if (!model) return null;
  const name = urlPathName(model).split(/[\\/]/).pop();
  if (cmd === "curl") {
    const out = flagValue(toks, ["-o", "--output"]);
    if (out && out !== "-") return { file: out };
    if (out === "-") return null; // streamed to stdout: nothing lands on disk under a name
    const dir = flagValue(toks, ["--output-dir"]);
    if (toks.some((t) => t === "-O" || t === "--remote-name" || /^-[A-Za-z]{0,10}O[A-Za-z]{0,10}$/.test(t))) return { file: dir ? `${dir}/${name}` : name };
    return null; // curl without -o / -O writes to stdout
  }
  const out = flagValue(toks, ["-O", "--output-document"]);
  if (out === "-") return null;
  if (out) return { file: out };
  const dir = flagValue(toks, ["-P", "--directory-prefix"]);
  return { file: dir ? `${dir}/${name}` : name };
}

// One shell command's statements, split as modelDownloads splits them (also used by cli/model-pins-targets.mjs).
export const statements = (text) => text.split(/\n|;|&&|\|\||\|/).slice(0, MAX_STATEMENTS);

export function modelDownloads(text) {
  if (typeof text !== "string" || text.length > MAX) return [];
  if (!/ollama|huggingface|\bhf\b|\blfs\b|hf\.co|curl|wget/i.test(text)) return [];
  const out = [];
  for (const statement of statements(text)) {
    const toks = tokens(statement);
    if (!toks.length) continue;
    const i = commandIndex(toks);
    const cmd = baseName(toks[i]);
    const sub = String(toks[i + 1] || "").toLowerCase();
    if (cmd === "ollama" && sub === "pull" && toks[i + 2]) out.push({ kind: "ollama-pull", target: { store: "ollama" } });
    else if ((cmd === "huggingface-cli" || cmd === "hf") && sub === "download" && toks[i + 2]) out.push({ kind: "hf-download", target: hfDownload(toks, i) });
    else if (cmd === "git") {
      const c = flagValue(toks.slice(i + 1, i + 3), ["-C"]);
      const rest = toks.slice(i + 1 + (c ? 2 : 0));
      if (rest[0] === "lfs" && rest[1] === "pull") out.push({ kind: "git-lfs-pull", target: { dir: c || "." } });
      else if (rest[0] === "clone") {
        const args = rest.slice(1).filter((t) => !t.startsWith("-"));
        if (args[0] && HF_HOST.test(args[0])) out.push({ kind: "hf-clone", target: { dir: args[1] || urlPathName(args[0]).replace(/\.git$/, "") || "." } });
      }
    } else if (cmd === "curl" || cmd === "wget") {
      const t = fetcher(cmd, toks, i);
      if (t) out.push({ kind: `${cmd}-model`, target: t });
    }
  }
  return out;
}

// Memoised on the last text: _matchDetector re-invokes refine() once per prefilter occurrence.
let lastText = null, lastHit = false;
export function modelDownloadHit(text) {
  if (text === lastText) return lastHit;
  lastText = text;
  lastHit = modelDownloads(text).length > 0;
  return lastHit;
}
