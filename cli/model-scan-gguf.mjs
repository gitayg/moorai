// GGUF header and metadata reader (Ollama, LM Studio, llama.cpp model files). Layout from the GGUF
// specification (github.com/ggml-org/ggml docs/gguf.md):
//   uint32 magic "GGUF" · uint32 version · uint64 tensor_count · uint64 metadata_kv_count
//   then metadata_kv_count × { gguf_string key, uint32 value_type, value }
//   gguf_string = uint64 length + UTF-8 bytes (version 1: uint32 length, and uint32 counts)
//   value types 0 u8 · 1 i8 · 2 u16 · 3 i16 · 4 u32 · 5 i32 · 6 f32 · 7 bool · 8 string · 9 array
//               (uint32 type, uint64 count, values) · 10 u64 · 11 i64 · 12 f64
// Only the metadata is read; tensor data is never touched. The chat template(s) go through
// cli/model-scan-template.mjs; other string values get the instruction and hidden-text checks.
//
// Metadata oddities: duplicate-key (medium: which copy a loader keeps differs), bad-key (low: not
// ASCII printable), template-not-string (medium), unknown-version (medium), and malformed (medium)
// for a bad magic, an unknown value type, an implausible count or a truncated header.
import { Cursor, ScanMalformed, ScanTruncated, safeDetail } from "./model-scan-bytes.mjs";
import { templateChecks, textChecks } from "./model-scan-template.mjs";

export const GGUF_LIMITS = Object.freeze({ maxKv: 100_000, maxTensors: 10_000_000, maxKeyLen: 65_535, maxTemplate: 1024 * 1024, maxText: 64 * 1024, maxArrayDepth: 4 });
const FIXED = { 0: 1, 1: 1, 2: 2, 3: 2, 4: 4, 5: 4, 6: 4, 7: 1, 10: 8, 11: 8, 12: 8 };

export const looksLikeGguf = (head) => !!head && head.length >= 4 && head.toString("latin1", 0, 4) === "GGUF";

// → { findings: [{ class, severity, count, details }], version, tensors, kv, templates }
export function scanGguf(src, limits = GGUF_LIMITS) {
  const counts = new Map();
  const add = (cls, severity, detail) => {
    let c = counts.get(cls);
    if (!c) counts.set(cls, (c = { severity, count: 0, details: new Set() }));
    c.count++;
    if (detail && c.details.size < 20) c.details.add(safeDetail(detail));
  };
  let version = null, tensors = 0, kv = 0, templates = 0;
  try {
    const c = new Cursor(src);
    if (c.bytes(4).toString("latin1") !== "GGUF") throw new ScanMalformed("bad magic");
    version = c.u32();
    if (version < 1 || version > 3) { add("unknown-version", "medium", `version ${version}`); throw new ScanMalformed("unsupported version"); }
    const v1 = version === 1;
    const count = () => (v1 ? c.u32() : c.u64());
    tensors = count();
    kv = count();
    if (tensors > limits.maxTensors) throw new ScanMalformed("implausible tensor count");
    if (kv > limits.maxKv) throw new ScanMalformed("implausible metadata count");
    const strLen = () => { const n = v1 ? c.u32() : c.u64(); if (n > c.left) throw new ScanTruncated(); return n; };
    const readStr = (cap) => { const n = strLen(); const take = Math.min(n, cap); const b = c.bytes(take); c.skip(n - take); return { s: b.toString("utf8"), truncated: n > cap }; };
    const skipValue = (type, depth) => {
      if (FIXED[type] != null) { c.skip(FIXED[type]); return; }
      if (type === 8) { c.skip(strLen()); return; }
      if (type === 9) {
        if (depth >= limits.maxArrayDepth) throw new ScanMalformed("array nesting too deep");
        const et = c.u32(), n = count();
        if (FIXED[et] != null) { if (n * FIXED[et] > c.left) throw new ScanTruncated(); c.skip(n * FIXED[et]); return; }
        if (et !== 8 && et !== 9) throw new ScanMalformed(`unknown array element type ${et}`);
        if (n * (et === 8 ? (v1 ? 4 : 8) : 12) > c.left) throw new ScanTruncated();
        for (let i = 0; i < n; i++) skipValue(et, depth + 1);
        return;
      }
      throw new ScanMalformed(`unknown value type ${type}`);
    };
    const seen = new Set();
    for (let i = 0; i < kv; i++) {
      const kn = strLen();
      if (kn > limits.maxKeyLen) throw new ScanMalformed("key too long");
      const key = c.bytes(kn).toString("utf8");
      if (seen.has(key)) add("duplicate-key", "medium", key);
      seen.add(key);
      if (!/^[\x21-\x7e]+$/.test(key)) add("bad-key", "low", "non-printable or non-ASCII key");
      const type = c.u32();
      const isTemplate = key === "tokenizer.chat_template" || key.startsWith("tokenizer.chat_template.");
      if (isTemplate && type !== 8) { add("template-not-string", "medium", key); skipValue(type, 0); continue; }
      if (type === 8) {
        const { s, truncated } = readStr(isTemplate ? limits.maxTemplate : limits.maxText);
        if (isTemplate) { templates++; templateChecks(s, add, { truncated }); }
        else if (!key.startsWith("tokenizer.ggml.")) textChecks(s, add, "metadata");
        continue;
      }
      // tokenizer.chat_templates (an array of template names) and the token arrays are skipped.
      skipValue(type, 0);
    }
  } catch (e) {
    if (e instanceof ScanTruncated) add("malformed", "medium", "truncated GGUF header or metadata");
    else if (e instanceof ScanMalformed) add("malformed", "medium", e.message);
    else throw e;
  }
  const findings = [...counts.entries()].map(([cls, x]) => ({ class: cls, severity: x.severity, count: x.count, details: [...x.details] }));
  return { findings, version, tensors, kv, templates };
}
