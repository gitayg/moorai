// AML.T0035 — AI Artifact Collection: "Adversaries may collect AI artifacts for Exfiltration ... AI
// artifacts include models and datasets". On a developer machine those are the weights and datasets on
// disk — *.safetensors, *.gguf, *.onnx, *.pt, the Hugging Face cache, the Ollama and LM Studio stores —
// and the collection act is packaging or copying them for removal.
//
// Downloading a model, listing the cache, running inference, and cleaning up are ordinary and silent.
// This fires on one command string (a Bash call) when:
//   1. HUB UPLOAD — `huggingface-cli upload`, `hf upload`, `ollama push`, `git push` to huggingface.co /
//      hf.co, or the huggingface_hub upload API from `python -c` / a heredoc. A model hub is the one sink
//      built for model-sized uploads, so the verb alone is the signal;
//   2. ARTIFACT INTO A SINK — a model/dataset path in the source position of an outbound command
//      (OUTBOUND_UPLOAD from data/outbound-upload.js — curl -F/-T/-d, wget --post-file, nc, Invoke-RestMethod —
//      plus scp/rsync/sftp to a remote spec, aws s3 / gsutil / azcopy / rclone to a remote), or piped
//      into one (`tar cz ~/.ollama/models | curl -T - …`);
//   3. STAGING — an archive or copy whose inputs are artifacts and whose output lands in a temp
//      directory (tar/zip/7z/Compress-Archive/cp/rsync -> /tmp, /var/tmp, /dev/shm, $TMPDIR, %TEMP%);
//      or anywhere, when a LATER statement of the same command ships that output (the file-tie the
//      clipboard-to-sink statement forms use for a clipboard read).
// Loopback targets are not a sink (a local inference server is not egress). Content-free: a boolean.
import { OUTBOUND_UPLOAD } from "./outbound-upload.js";

const MAX = 200_000;
const MAX_STATEMENTS = 400;

const ARTIFACT_EXT = /\.(?:safetensors|gguf|ggml|ggmlv3|onnx|pt|pth|ckpt|h5|keras|tflite|mlmodel|mlpackage|pkl|joblib)$/i;
const ARTIFACT_DIR = /(?:^|[\\\/])(?:\.cache[\\\/](?:huggingface|torch|lm-studio)|\.ollama(?:[\\\/]models)?|\.lmstudio(?:[\\\/]models)?|models--[\w.-]{1,120})(?:[\\\/]|$)|^~?[\\\/]?\.ollama$/i;
const TEMP = /^(?:\/tmp|\/var\/tmp|\/private\/tmp|\/dev\/shm|\$TMPDIR|\$\{TMPDIR\}|%TEMP%|%TMP%|\$env:TEMP|\$env:TMP|C:\\Windows\\Temp)(?:[\\\/]|$)/i;
const LOOPBACK = /^(?:localhost|127(?:\.\d{1,3}){3}|0\.0\.0\.0|\[::1\]|::1)$/i;
const REMOTE_SPEC = /^(?:[\w.-]{1,64}@)?[\w.-]{2,253}:(?![\\\/]{2})/;
const HF_URL = /\bhttps?:\/\/(?:[\w-]{1,40}\.)?(?:huggingface\.co|hf\.co)\//i;
const HUB_API = /\b(?:upload_(?:file|folder|large_folder)|create_commit|push_to_hub)\s{0,4}\(/;
const FILTER = /^(?:gzip|xz|zstd|bzip2|base64|openssl|gpg|age|pv|cat|tee|split)$/;
const PY_INLINE = /\bpython[\d.]{0,4}\b[^\n]{0,60}?(?:\s-c\s|<<|\s-\s)/;

const unquote = (t) => t.replace(/^["']|["']$/g, "");
// A token's path part: `file=@x`, `@x`, `-Path=x` and `--x=y` all name x / y.
function pathOf(tok) {
  let t = unquote(tok);
  t = t.replace(/^[\w-]{0,40}=@?/, "").replace(/^@/, "");
  return unquote(t);
}
function isArtifact(tok) {
  const p = pathOf(tok);
  if (!p || /:\/\//.test(p)) return false;
  return ARTIFACT_EXT.test(p.replace(/[\\\/]+$/, "")) || ARTIFACT_DIR.test(p);
}

function tokens(segment) {
  return (segment.match(/"[^"]{0,2000}"|'[^']{0,2000}'|\S{1,2000}/g) || []).slice(0, 200);
}
// The command word: past env assignments, sudo/env/time/nohup/command.
function commandIndex(toks) {
  let i = 0;
  while (i < toks.length && (/^[A-Za-z_][\w]{0,40}=/.test(toks[i]) || /^(?:sudo|env|time|nohup|command|exec)$/.test(toks[i]))) i++;
  return i;
}
const baseName = (t) => unquote(t || "").split(/[\\\/]/).pop().toLowerCase();
const positional = (toks, from) => toks.slice(from).filter((t) => !/^-/.test(t) && !/^[<>|&]/.test(t));

function loopbackOnly(segment) {
  const hosts = [...segment.matchAll(/\b(?:https?|ftp):\/\/(?:[^\s\/@'"]{0,200}@)?(\[[0-9a-f:]{2,39}\]|[^\s\/:'"?#]{1,253})/gi)].map((m) => m[1]);
  if (hosts.length) return hosts.every((h) => LOOPBACK.test(h));
  return /(?<![\w.-])(?:localhost|127(?:\.\d{1,3}){3}|0\.0\.0\.0)(?::\d{1,5})?(?![\w.-])/i.test(segment);
}

function hubUpload(toks, segment) {
  const i = commandIndex(toks);
  const cmd = baseName(toks[i]), sub = unquote(toks[i + 1] || "").toLowerCase();
  if ((cmd === "huggingface-cli" || cmd === "hf") && sub === "upload") return true;
  if ((cmd === "huggingface-cli" || cmd === "hf") && sub === "upload-large-folder") return true;
  if (cmd === "ollama" && sub === "push") return true;
  if (cmd === "git" && sub === "push" && HF_URL.test(segment)) return true;
  return false;
}

// An outbound command whose DESTINATION is off the device; returns the tokens in source position.
function sinkSources(toks, segment) {
  const i = commandIndex(toks);
  const cmd = baseName(toks[i]);
  const args = positional(toks, i + 1);
  const last = unquote(args[args.length - 1] || "");
  if (cmd === "scp" || cmd === "rsync" || cmd === "sftp") return REMOTE_SPEC.test(last) && !/^[A-Za-z]:[\\\/]/.test(last) ? args.slice(0, -1) : null;
  if (cmd === "aws" && unquote(toks[i + 1] || "") === "s3") return /^s3:\/\//i.test(last) ? args.slice(2, -1) : null;
  if (cmd === "gsutil") return /^gs:\/\//i.test(last) ? args.slice(1, -1) : null;
  if (cmd === "azcopy") return /^https:\/\/[\w-]{1,63}\.blob\.core\.windows\.net\//i.test(last) ? args.slice(1, -1) : null;
  if (cmd === "rclone") return REMOTE_SPEC.test(last) && !/^[A-Za-z]:[\\\/]/.test(last) ? args.slice(1, -1) : null;
  if (cmd === "az" && /\bstorage\s{1,4}blob\s{1,4}upload/.test(segment)) return toks.slice(i + 1);
  for (const r of OUTBOUND_UPLOAD) if (r.test(segment) && !loopbackOnly(segment)) return toks.slice(i + 1);
  return null;
}

// An archive or copy: { inputs, output } or null. output is null when the archive streams to stdout.
function staging(toks, segment) {
  const i = commandIndex(toks);
  const cmd = baseName(toks[i]);
  const redirect = segment.match(/(?<![0-9<>&])>{1,2}\s{0,4}(\S{1,500})/);
  const redirectOut = redirect ? unquote(redirect[1]) : null;
  if (cmd === "tar" || cmd === "bsdtar" || cmd === "gtar") {
    const flags = unquote(toks[i + 1] || "");
    if (!/^-{0,1}[A-Za-z]{0,12}c/.test(flags) && !toks.includes("--create")) return null;
    let out = redirectOut;
    const fIdx = toks.findIndex((t, k) => k > i && (/^-{0,1}[A-Za-z]{0,12}f$/.test(t) && /c/.test(flags + t) || t === "-f" || t === "--file"));
    if (fIdx > 0 && toks[fIdx + 1]) out = unquote(toks[fIdx + 1]);
    const eq = toks.find((t) => /^--file=/.test(t));
    if (eq) out = unquote(eq.slice(7));
    return { inputs: toks.slice(i + 1), output: out === "-" ? null : out };
  }
  if (cmd === "zip") { const p = positional(toks, i + 1); return p.length ? { inputs: p.slice(1), output: unquote(p[0]) } : null; }
  if (cmd === "7z" || cmd === "7za" || cmd === "7zz") {
    const p = positional(toks, i + 1);
    return p[0] === "a" && p[1] ? { inputs: p.slice(2), output: unquote(p[1]) } : null;
  }
  if (/^compress-archive$/i.test(cmd)) {
    const d = toks.findIndex((t) => /^-DestinationPath$/i.test(t));
    return { inputs: toks.slice(i + 1), output: d > 0 && toks[d + 1] ? unquote(toks[d + 1]) : null };
  }
  if (cmd === "cp" || cmd === "mv" || cmd === "ditto" || cmd === "rsync" || /^copy-item$/i.test(cmd)) {
    const p = positional(toks, i + 1);
    return p.length >= 2 ? { inputs: p.slice(0, -1), output: unquote(p[p.length - 1]) } : null;
  }
  if ((cmd === "gzip" || cmd === "zstd" || cmd === "xz" || cmd === "cat" || cmd === "base64" || cmd === "split") && redirectOut) {
    return { inputs: toks.slice(i + 1), output: redirectOut };
  }
  if (cmd === "gzip" || cmd === "zstd" || cmd === "xz" || cmd === "cat" || cmd === "base64") return { inputs: toks.slice(i + 1), output: null };
  return null;
}

function scanModelCollection(text) {
  if (typeof text !== "string" || text.length > MAX) return false;
  if (HUB_API.test(text) && PY_INLINE.test(text)) return true;
  const statements = text.split(/\n|;|&&|\|\|/).slice(0, MAX_STATEMENTS);
  const tainted = new Set();
  for (const statement of statements) {
    const segments = statement.split("|").slice(0, 20);
    let streaming = false;
    for (const segment of segments) {
      const toks = tokens(segment);
      if (!toks.length) continue;
      if (hubUpload(toks, segment)) return true;
      const src = sinkSources(toks, segment);
      if (src) {
        if (streaming) return true;
        if (src.some((t) => isArtifact(t) || tainted.has(pathOf(t)))) return true;
      }
      const st = staging(toks, segment);
      if (st && st.inputs.some(isArtifact)) {
        if (st.output === null) { streaming = true; continue; }
        if (TEMP.test(st.output)) return true;
        tainted.add(st.output);
      }
      // A filter between the archive and the sink (gzip, base64, openssl, …) keeps the stream.
      if (streaming && FILTER.test(baseName(toks[commandIndex(toks)]))) continue;
      streaming = false;
    }
  }
  return false;
}

// Memoised on the last text, for the reason data/obfuscation-signal.js gives: _matchDetector re-invokes
// refine() once per prefilter occurrence.
let lastText = null, lastHit = false;
export function modelCollectionHit(text) {
  if (text === lastText) return lastHit;
  lastText = text;
  lastHit = scanModelCollection(text);
  return lastHit;
}
