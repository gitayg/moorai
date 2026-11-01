// ONNX and TensorFlow SavedModel scanning with a minimal protobuf walker (wire types 0, 1, 2, 5;
// encoding.md at protobuf.dev). Only the few message paths that name an operator or an external file
// are followed; every other field, the tensor bytes included, is skipped by length without being read.
//
// ONNX (onnx/onnx.proto3): ModelProto.opset_import(8) / graph(7) / functions(25);
// GraphProto.node(1) / initializer(5) / sparse_initializer(15); NodeProto.op_type(4) / domain(7) /
// attribute(5) → AttributeProto.t(5) / g(6) / tensors(10) / graphs(11) / sparse_tensor(22) /
// sparse_tensors(23); TensorProto.external_data(13) → StringStringEntryProto key(1) value(2);
// FunctionProto.node(7) / domain(10).
//   custom-op-domain       medium  a node or opset in a domain that is neither standard ONNX nor a
//                                  model-local function: running it needs a custom-op library
//                                  (native code) registered with the runtime
//   runtime-contrib-domain low     ONNX Runtime's own contrib domains (com.microsoft*), org.pytorch.aten
//   external-data-escape   high    an external-data location that is absolute, a URL, or climbs out of
//                                  the model's folder with ".."
// HEURISTIC: this reads the graph's declarations; it does not resolve what a custom op library would do.
//
// TensorFlow SavedModel (tensorflow/core/protobuf/saved_model.proto, meta_graph.proto,
// framework/graph.proto, node_def.proto, function.proto): SavedModel.meta_graphs(2) →
// MetaGraphDef.graph_def(2) → GraphDef.node(1) / library(2) → FunctionDefLibrary.function(1) →
// FunctionDef.node_def(3); NodeDef.op(2).
//   tf-python-op           high    PyFunc, PyFuncStateless, EagerPyFunc (call back into Python)
//   tf-file-op             medium  ops that read, write or list files: ReadFile, WriteFile, MatchingFiles,
//                                  WholeFileReader(V2), DatasetToTFRecord, CreateSummaryFileWriter,
//                                  ImmutableConst. SaveV2 / RestoreV2 / MergeV2Checkpoints are the
//                                  checkpoint machinery every SavedModel carries and are not flagged.
// HEURISTIC: op names only; an op's attributes (which file, which callback) are not evaluated.
import { isAbsolute, resolve, relative, sep } from "node:path";
import { Cursor, ScanMalformed, ScanTruncated, safeDetail } from "./model-scan-bytes.mjs";

export const PROTO_LIMITS = Object.freeze({ maxDepth: 32, maxNodes: 5_000_000, maxString: 4096 });

const STANDARD_DOMAINS = new Set(["", "ai.onnx", "ai.onnx.ml", "ai.onnx.training", "ai.onnx.preview.training", "ai.onnx.preview"]);
const RUNTIME_DOMAIN = /^(?:com\.microsoft(?:\.[\w.]{1,40})?|com\.ms\.internal\.nhwc|org\.pytorch\.aten)$/;
const TF_PYTHON = new Set(["PyFunc", "PyFuncStateless", "EagerPyFunc"]);
const TF_FILE = new Set(["ReadFile", "WriteFile", "MatchingFiles", "WholeFileReader", "WholeFileReaderV2", "DatasetToTFRecord", "ExperimentalDatasetToTFRecord", "CreateSummaryFileWriter", "ImmutableConst"]);

function collector() {
  const findings = [];
  const add = (cls, severity, detail) => {
    const f = findings.find((x) => x.class === cls);
    if (f) { f.count++; if (detail && f.details.length < 20 && !f.details.includes(safeDetail(detail))) f.details.push(safeDetail(detail)); }
    else findings.push({ class: cls, severity, count: 1, details: detail ? [safeDetail(detail)] : [] });
  };
  return { findings, add };
}

// Calls on[field](cursorOverTheField) for each length-delimited field listed; skips everything else.
function walk(src, start, end, on, ctx, depth) {
  if (depth > ctx.limits.maxDepth) throw new ScanMalformed("message nesting too deep");
  const c = new Cursor(src, start, end);
  while (c.left > 0) {
    if (++ctx.nodes > ctx.limits.maxNodes) throw new ScanMalformed("field budget reached");
    const tag = c.varint();
    const field = Math.floor(tag / 8), wire = tag % 8;
    if (field === 0) throw new ScanMalformed("field number 0");
    if (wire === 0) { const v = c.varint(); if (on.varint && on.varint[field]) on.varint[field](v); continue; }
    if (wire === 1) { c.skip(8); continue; }
    if (wire === 5) { c.skip(4); continue; }
    if (wire !== 2) throw new ScanMalformed(`unsupported wire type ${wire}`);
    const len = c.varint();
    if (len > c.left) throw new ScanTruncated();
    const fstart = c.pos;
    c.skip(len);
    if (on[field]) on[field](fstart, fstart + len, depth + 1);
  }
}
const str = (src, s, e, ctx) => src.read(s, Math.min(e - s, ctx.limits.maxString)).toString("utf8");

// ---- ONNX ----
export function externalLocationEscapes(loc, dir) {
  const l = String(loc || "");
  if (!l) return false;
  if (/^[a-z][a-z0-9+.-]{1,20}:\/\//i.test(l) || /^file:/i.test(l)) return true;
  if (l.startsWith("/") || l.startsWith("\\") || l.startsWith("~") || /^[A-Za-z]:/.test(l) || isAbsolute(l)) return true;
  if (l.split(/[\\/]+/).includes("..")) return true;
  if (dir) { const rel = relative(dir, resolve(dir, l)); if (rel.startsWith("..") || isAbsolute(rel) || rel.split(sep).includes("..")) return true; }
  return false;
}

export function scanOnnx(src, { dir = null, limits = PROTO_LIMITS } = {}) {
  const { findings, add } = collector();
  const ctx = { limits, nodes: 0 };
  const used = new Set(), local = new Set();
  let nodes = 0;
  const tensor = (s, e, d) => walk(src, s, e, {
    13: (ks, ke, kd) => {
      let key = null, value = null;
      walk(src, ks, ke, { 1: (a, b) => { key = str(src, a, b, ctx); }, 2: (a, b) => { value = str(src, a, b, ctx); } }, ctx, kd);
      if (key === "location" && externalLocationEscapes(value, dir)) add("external-data-escape", "high", "external data outside the model folder");
    }
  }, ctx, d);
  const sparse = (s, e, d) => walk(src, s, e, { 1: tensor, 2: tensor }, ctx, d);
  let graph;
  const attribute = (s, e, d) => walk(src, s, e, { 5: tensor, 6: (a, b, dd) => graph(a, b, dd), 10: tensor, 11: (a, b, dd) => graph(a, b, dd), 22: sparse, 23: sparse }, ctx, d);
  const node = (s, e, d) => {
    nodes++;
    let domain = "";
    walk(src, s, e, { 7: (a, b) => { domain = str(src, a, b, ctx); }, 5: attribute }, ctx, d);
    used.add(domain);
  };
  graph = (s, e, d) => walk(src, s, e, { 1: node, 5: tensor, 15: sparse }, ctx, d);
  const opset = (s, e, d) => { let domain = ""; walk(src, s, e, { 1: (a, b) => { domain = str(src, a, b, ctx); } }, ctx, d); used.add(domain); };
  const fn = (s, e, d) => walk(src, s, e, { 7: node, 9: opset, 10: (a, b) => { local.add(str(src, a, b, ctx)); } }, ctx, d);
  let sawGraph = false;
  try {
    walk(src, 0, src.size, { 7: (s, e, d) => { sawGraph = true; graph(s, e, d); }, 8: opset, 25: fn }, ctx, 0);
    if (!sawGraph) add("malformed", "medium", "no graph in the model");
  } catch (e) {
    if (e instanceof ScanTruncated) add("malformed", "medium", "truncated protobuf");
    else if (e instanceof ScanMalformed) add("malformed", "medium", e.message);
    else throw e;
  }
  for (const d of used) {
    if (STANDARD_DOMAINS.has(d) || local.has(d)) continue;
    if (RUNTIME_DOMAIN.test(d)) add("runtime-contrib-domain", "low", d);
    else add("custom-op-domain", "medium", d);
  }
  return { findings, nodes };
}

// ---- TensorFlow SavedModel ----
export function scanSavedModel(src, limits = PROTO_LIMITS) {
  const { findings, add } = collector();
  const ctx = { limits, nodes: 0 };
  const ops = new Set();
  let metaGraphs = 0, nodes = 0;
  const nodeDef = (s, e, d) => { nodes++; walk(src, s, e, { 2: (a, b) => { ops.add(str(src, a, b, ctx)); } }, ctx, d); };
  const fnDef = (s, e, d) => walk(src, s, e, { 3: nodeDef }, ctx, d);
  const library = (s, e, d) => walk(src, s, e, { 1: fnDef }, ctx, d);
  const graphDef = (s, e, d) => walk(src, s, e, { 1: nodeDef, 2: library }, ctx, d);
  const metaGraph = (s, e, d) => { metaGraphs++; walk(src, s, e, { 2: graphDef }, ctx, d); };
  try {
    walk(src, 0, src.size, { 2: metaGraph }, ctx, 0);
    if (!metaGraphs) add("malformed", "medium", "no meta graphs in saved_model.pb");
  } catch (e) {
    if (e instanceof ScanTruncated) add("malformed", "medium", "truncated protobuf");
    else if (e instanceof ScanMalformed) add("malformed", "medium", e.message);
    else throw e;
  }
  for (const op of ops) {
    if (TF_PYTHON.has(op)) add("tf-python-op", "high", op);
    else if (TF_FILE.has(op)) add("tf-file-op", "medium", op);
  }
  return { findings, metaGraphs, nodes };
}
