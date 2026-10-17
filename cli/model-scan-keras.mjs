// Keras model configs: .keras (a zip with config.json) and legacy HDF5 .h5 (the model_config attribute).
//
// A Lambda layer serializes the Python function it wraps. Keras 3 writes
// { "class_name": "Lambda", "config": { "function": { "class_name": "__lambda__", "config": { "code":
// "<base64 marshal>" } } } }; tf.keras 2 writes "function": ["<base64 marshal>", defaults, closure] with
// "function_type": "lambda". Loading either runs that bytecode (Keras 3 refuses it unless
// safe_mode=False; tf.keras 2 does not ask).
//   lambda-code       critical  a Lambda layer carrying serialized bytecode
//   lambda-function   medium    a Lambda layer naming a function by module and name
//   dangerous-import  critical  a serialized object whose module/name is on the pickle deny list
//                               (cli/model-scan-pickle.mjs classifyGlobal), e.g. module "os"
//   custom-object     low       a serialized object from a module outside keras / tensorflow
//   lambda-layer      high      HDF5 only: a Lambda class name was found in the bytes but no
//                               model_config JSON could be parsed around it
//   no-config         low       HDF5 only: no model_config JSON in the bytes searched (a weights-only file)
//
// HDF5 WITHOUT AN HDF5 LIBRARY. h5py stores the model_config attribute as a JSON string, and Keras
// writes it before the weights, so it sits near the start of the file. This reader does a bounded byte
// search (the first KERAS_LIMITS.maxScanBytes) for `{"class_name"`, extracts the balanced JSON object
// there and parses it. A config stored compressed or past the scanned prefix is not seen; that is a
// documented limit of the heuristic.
import { safeDetail } from "./model-scan-bytes.mjs";
import { classifyGlobal } from "./model-scan-pickle.mjs";
import { zipEntries, readEntry } from "./model-scan-zip.mjs";

export const KERAS_LIMITS = Object.freeze({ maxConfig: 32 * 1024 * 1024, maxNodes: 2_000_000, maxDepth: 200, maxScanBytes: 256 * 1024 * 1024, maxHits: 16 });
const HDF5_SIG = Buffer.from([0x89, 0x48, 0x44, 0x46, 0x0d, 0x0a, 0x1a, 0x0a]);
const KERAS_MODULE = /^(?:keras|tf_keras|tensorflow|tf)(?:\.|$)/;

export function looksLikeHdf5(src) {
  for (const off of [0, 512, 1024, 2048, 4096]) {
    if (off + 8 > src.size) break;
    if (src.read(off, 8).equals(HDF5_SIG)) return true;
  }
  return false;
}

function collector() {
  const findings = [];
  const add = (cls, severity, detail) => {
    const f = findings.find((x) => x.class === cls);
    if (f) { f.count++; if (detail && f.details.length < 20 && !f.details.includes(safeDetail(detail))) f.details.push(safeDetail(detail)); }
    else findings.push({ class: cls, severity, count: 1, details: detail ? [safeDetail(detail)] : [] });
  };
  return { findings, add };
}

// Walks a parsed Keras config. Iterative, bounded by node count and depth.
export function kerasConfigChecks(root, add, limits = KERAS_LIMITS) {
  const stack = [[root, 0]];
  let nodes = 0;
  while (stack.length) {
    const [v, depth] = stack.pop();
    if (++nodes > limits.maxNodes || depth > limits.maxDepth) { add("too-large", "medium", "config past the walk budget"); return; }
    if (!v || typeof v !== "object") continue;
    if (Array.isArray(v)) { for (const x of v) stack.push([x, depth + 1]); continue; }
    if (v.class_name === "Lambda" && v.config && typeof v.config === "object") {
      const fn = v.config.function;
      const code = (fn && typeof fn === "object" && !Array.isArray(fn) && fn.class_name === "__lambda__" && fn.config && typeof fn.config.code === "string")
        || (Array.isArray(fn) && typeof fn[0] === "string")
        || v.config.function_type === "lambda";
      if (code) add("lambda-code", "critical", `Lambda layer ${safeDetail(v.config.name || "")}`);
      else add("lambda-function", "medium", `Lambda layer ${safeDetail(v.config.name || "")}`);
      if (typeof v.config.module === "string" && typeof fn === "string") {
        const k = classifyGlobal(v.config.module, fn);
        if (k === "dangerous") add("dangerous-import", "critical", `${v.config.module}.${fn}`);
      }
    }
    if (typeof v.module === "string" && v.module && typeof v.class_name === "string") {
      const name = v.class_name === "function" && typeof v.config === "string" ? v.config : v.class_name;
      const k = classifyGlobal(v.module, name);
      if (k === "dangerous") add("dangerous-import", "critical", `${v.module}.${name}`);
      else if (!KERAS_MODULE.test(v.module) && v.module !== "builtins") add("custom-object", "low", `${v.module}.${name}`);
    }
    for (const x of Object.values(v)) if (x && typeof x === "object") stack.push([x, depth + 1]);
  }
}

export function scanKerasZip(src, limits = KERAS_LIMITS) {
  const { findings, add } = collector();
  let entries;
  try { entries = zipEntries(src); } catch (e) { add("malformed", "medium", e.message || "unreadable zip"); return { findings }; }
  const cfg = entries.find((e) => e.name === "config.json");
  if (!cfg) { add("malformed", "medium", "no config.json in the .keras archive"); return { findings }; }
  let buf;
  try { buf = readEntry(src, cfg, limits.maxConfig); } catch (e) { add("malformed", "medium", e.message || "config.json unreadable"); return { findings }; }
  if (!buf) { add("too-large", "medium", "config.json past the size cap"); return { findings }; }
  let obj;
  try { obj = JSON.parse(buf.toString("utf8")); } catch { add("malformed", "medium", "config.json is not JSON"); return { findings }; }
  kerasConfigChecks(obj, add, limits);
  return { findings };
}

// The balanced JSON object starting at buf[start] ("{"), honouring strings. → string | null
export function balancedJson(buf, start, max) {
  let depth = 0, inStr = false, esc = false;
  const end = Math.min(buf.length, start + max);
  for (let i = start; i < end; i++) {
    const b = buf[i];
    if (inStr) { if (esc) esc = false; else if (b === 0x5c) esc = true; else if (b === 0x22) inStr = false; continue; }
    if (b === 0x22) inStr = true;
    else if (b === 0x7b) depth++;
    else if (b === 0x7d && --depth === 0) return buf.toString("utf8", start, i + 1);
  }
  return null;
}

const LAMBDA_BYTES = [Buffer.from('"class_name": "Lambda"'), Buffer.from('"class_name":"Lambda"')];
const CONFIG_START = Buffer.from('{"class_name"');

export function scanHdf5(src, limits = KERAS_LIMITS) {
  const { findings, add } = collector();
  if (!looksLikeHdf5(src)) add("malformed", "medium", "no HDF5 signature");
  const scan = Math.min(src.size, limits.maxScanBytes);
  const CHUNK = 4 * 1024 * 1024, OVERLAP = 64;
  let parsed = false, lambdaBytes = false, hits = 0;
  for (let pos = 0; pos < scan && hits < limits.maxHits && !parsed; pos += CHUNK - OVERLAP) {
    const len = Math.min(CHUNK, scan - pos);
    const chunk = src.read(pos, len);
    if (!lambdaBytes && LAMBDA_BYTES.some((p) => chunk.indexOf(p) >= 0)) lambdaBytes = true;
    let at = chunk.indexOf(CONFIG_START);
    while (at >= 0 && hits < limits.maxHits && !parsed) {
      hits++;
      const abs = pos + at;
      const window = src.read(abs, Math.min(limits.maxConfig, src.size - abs));
      const text = balancedJson(window, 0, limits.maxConfig);
      if (text) {
        let obj = null;
        try { obj = JSON.parse(text); } catch { obj = null; }
        if (obj && typeof obj === "object" && obj.config) { kerasConfigChecks(obj, add, limits); parsed = true; }
      }
      at = chunk.indexOf(CONFIG_START, at + 1);
    }
    if (len < CHUNK) break;
  }
  if (!parsed && lambdaBytes) add("lambda-layer", "high", "Lambda class name in the bytes; config not parsed");
  if (!parsed && !lambdaBytes) add("no-config", "low", src.size > scan ? "no model_config in the scanned prefix" : "no model_config found");
  return { findings, parsedConfig: parsed };
}
