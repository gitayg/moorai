// The inline files a model request carries, per API, for the cloud file scan (cli/file-scan.mjs). Every
// turn is read, any role, since a conversation re-sends its earlier files (the scan's cache answers those).
//   anthropic          messages[].content[] {type: "image" | "document", source: {type: "base64", media_type,
//                      data}}, also inside a tool_result's content[] (platform.claude.com/docs/en/build-with-claude/vision,
//                      …/pdf-support). A document whose source is text or content blocks is text, scanned as text.
//   openai-chat        messages[].content[] (any role, a `tool` message's included) {type: "image_url", image_url:
//                      {url: "data:<mt>;base64,…"}}, {type: "file", file: {file_data: "data:<mt>;base64,…", filename}},
//                      {type: "input_audio", input_audio: {data, format}} (github.com/openai/openai-openapi).
//   openai-responses   input[] message content[] {type: "input_image", image_url: data URL}, {type: "input_file",
//                      file_data: data URL, filename}; also a function_call_output whose output is a list of them.
//   gemini             contents[].parts[] and systemInstruction.parts[] inlineData {mimeType, data}
//                      (ai.google.dev/api/caching#Blob), and the parts nested in a functionResponse.parts[].
//   ollama             messages[].images[] (/api/chat) and images[] (/api/generate): base64 strings, no media type.
//                      Also a computer_call_output's screenshot (output.image_url).
// REFERENCES (no content in the request to scan): a URL (image_url / file_url https://…, an Anthropic url source,
// Gemini fileData.fileUri) or a provider file id (OpenAI file_id, Anthropic source.type "file") is listed in `refs`;
// the caller alerts and applies onUnknown. A file_data / image_url value that is neither a data: URL nor a
// reference (raw base64, a non-string) is unscannable.
//
// DUAL SPELLINGS. Gemini's REST API is proto3 JSON, whose parsers accept both the lowerCamelCase and the
// original snake_case field name (inlineData / inline_data, mimeType / mime_type, functionResponse /
// function_response, systemInstruction / system_instruction). Which one an upstream reads when both are sent
// is not documented, so both are scanned, and when they differ the request is `ambiguous` (the caller refuses
// it: it could be read differently than it was checked). The other APIs' fields have one spelling.
//
// STRICT BASE64. A lenient decoder (Buffer.from(s, "base64")) skips characters outside the alphabet and stray
// padding, so the bytes scanned could differ from the bytes the provider decodes. Each blob is validated first
// (strictBase64): whitespace removed; the standard alphabet, plus the URL-safe one only where the API documents it
// (proto3 JSON `bytes`: "Either standard or URL-safe base64 encoding with/without paddings are accepted" —
// Gemini; padding is still required here, which can only make a valid blob unscannable, never a bad one
// clean), never both in one value; padding only at the end; a length that is a multiple of 4; and the decoded
// bytes must re-encode to exactly the same text. A blob that fails is `unscannable`: the caller treats it as
// not scanned (onUnknown and its fail mode decide), never as clean. A data: URL that is not base64 is
// percent-decoded; one that does not decode is unscannable.
//
// ANY JSON BODY (kind "any"). The whole body is walked, whatever the path, and every object is tested against every
// API's file shapes above: an Anthropic image / document block, an OpenAI image_url / file / input_audio part, a
// Responses input_image / input_file / computer_call_output, a Gemini inlineData / fileData part, an Ollama `images`
// array of strings. So a sibling endpoint (count_tokens, countTokens, input_tokens, a batch, an unknown route) or a
// file nested anywhere is found. Bounded: ANY_DEPTH levels and ANY_NODES objects; past either, unscannable.
//
// -> { parts: [{ where, mediaType, bytes, filename? }], over, unscannable: [{ where, mediaType, raw }], refs:
// [{ where, ref }], ambiguous: [where] } — at most MAX_PARTS of each; `over` counts the rest, which the caller treats
// as not scanned.
import { createHash } from "node:crypto";
export const MAX_PARTS = 32;

const isObj = (v) => Boolean(v) && typeof v === "object" && !Array.isArray(v);
const arr = (v) => (Array.isArray(v) ? v : []);
const MAX_DEPTH = 16;
export const ANY_DEPTH = 64;
export const ANY_NODES = 200000;

export function strictBase64(s, { urlSafe = false } = {}) {
  if (typeof s !== "string") return null;
  const t = s.replace(/[\t\n\r ]/g, "");
  if (!t.length || t.length % 4) return null;
  const std = /^[A-Za-z0-9+/]*={0,2}$/.test(t);
  const url = urlSafe && /^[A-Za-z0-9\-_]*={0,2}$/.test(t);
  if (!std && !url) return null;
  const bytes = Buffer.from(t, std ? "base64" : "base64url");
  let again = bytes.toString("base64");
  if (!std) again = again.replace(/\+/g, "-").replace(/\//g, "_");
  return again === t ? bytes : null;
}

// data:[<media type>][;params][;base64],<data>
function fromDataUrl(s) {
  if (typeof s !== "string" || !/^data:/i.test(s)) return null;
  const comma = s.indexOf(",");
  if (comma < 0) return { mediaType: "", bytes: null, raw: s };
  const meta = s.slice(5, comma).split(";");
  const mediaType = (meta[0] || "text/plain").trim().toLowerCase();
  const isB64 = meta.slice(1).some((p) => p.trim().toLowerCase() === "base64");
  const payload = s.slice(comma + 1);
  if (isB64) return { mediaType, bytes: strictBase64(payload), raw: payload };
  try { return { mediaType, bytes: Buffer.from(decodeURIComponent(payload), "utf8"), raw: payload }; } catch { return { mediaType, bytes: null, raw: payload }; }
}

// Canonical text of a JSON value to tell two spellings' values apart: keys in lowerCamelCase (as proto3 JSON
// reads either spelling), sorted.
const camel = (k) => k.replace(/_([a-z0-9])/g, (_, c) => c.toUpperCase());
function canon(v) {
  if (Array.isArray(v)) return `[${v.map(canon).join(",")}]`;
  if (isObj(v)) return `{${Object.keys(v).map((k) => [camel(k), k]).sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0)).map(([c, k]) => `${JSON.stringify(c)}:${canon(v[k])}`).join(",")}}`;
  return JSON.stringify(v);
}

export function fileParts(kind, body) {
  const parts = [], unscannable = [], ambiguous = [], refs = [];
  let over = 0;
  const add = (where, mediaType, bytes, filename, raw) => {
    const mt = String(mediaType || "application/octet-stream").toLowerCase().slice(0, 128);
    if (bytes === null) {
      if (unscannable.length >= MAX_PARTS) { over++; return; }
      unscannable.push({ where, mediaType: mt, raw: typeof raw === "string" ? raw : "" });
      return;
    }
    if (!bytes.length) return;
    if (parts.length >= MAX_PARTS) { over++; return; }
    parts.push({ where, mediaType: mt, bytes, ...(typeof filename === "string" ? { filename: filename.slice(0, 128) } : {}) });
  };
  const ref = (where, value) => {
    if (value === undefined || value === null || value === "") return;
    if (refs.length >= MAX_PARTS) { over++; return; }
    refs.push({ where, ref: typeof value === "string" ? value.slice(0, 2048) : JSON.stringify(value).slice(0, 2048) });
  };
  // A field that takes a data: URL: decoded; a URL is a reference; anything else present is unscannable.
  const dataField = (where, value, filename) => {
    if (value === undefined || value === null || value === "") return;
    if (typeof value === "string" && /^data:/i.test(value)) { const d = fromDataUrl(value); add(where, d.mediaType, d.bytes, filename, d.raw); return; }
    if (typeof value === "string" && /^(?:https?|gs):\/\//i.test(value)) { ref(`${where}:url`, value); return; }
    add(where, "", null, filename, typeof value === "string" ? value : "");
  };
  // A base64 field: a non-empty string strictly decoded; any other non-empty value is unscannable.
  const b64 = (where, mediaType, s, filename, opts) => {
    if (typeof s === "string" && s.length) add(where, mediaType, strictBase64(s, opts), filename, s);
    else if (s !== undefined && s !== null && s !== "") add(where, mediaType, null, filename, "");
  };
  // Both spellings of a field: every present value, and `ambiguous` when two are present and differ.
  const both = (o, a, b, where) => {
    const vals = [o[a], o[b]].filter((v) => v !== undefined);
    if (vals.length === 2 && canon(vals[0]) !== canon(vals[1])) ambiguous.push(where);
    return vals;
  };
  // Past MAX_DEPTH nothing is read further: the place is recorded unscannable (onUnknown and the fail mode decide),
  // never skipped as if it held no file.
  const deep = (where) => add(where, "", null, undefined, "");
  if (kind === "any") {
    let nodes = 0, stopped = false;
    const visit = (v, depth) => {
      if (stopped || v === null || typeof v !== "object") return;
      if (depth > ANY_DEPTH || ++nodes > ANY_NODES) { stopped = true; deep("any:limit"); return; }
      if (Array.isArray(v)) { for (const x of v) visit(x, depth + 1); return; }
      const t = v.type;
      if ((t === "image" || t === "document") && isObj(v.source)) {
        if (v.source.type === "base64") b64(`any:${t}`, v.source.media_type, v.source.data);
        else if (v.source.type === "url") ref(`any:${t}:url`, v.source.url);
        else if (v.source.type === "file") ref(`any:${t}:file`, v.source.file_id);
      } else if (t === "image_url") dataField("any:image_url", isObj(v.image_url) ? v.image_url.url : v.image_url);
      else if (t === "file" && isObj(v.file)) { dataField("any:file", v.file.file_data, v.file.filename); ref("any:file:id", v.file.file_id); }
      else if (t === "input_audio" && isObj(v.input_audio)) b64("any:input_audio", `audio/${String(v.input_audio.format || "unknown").replace(/[^a-z0-9.+-]/gi, "")}`, v.input_audio.data);
      else if (t === "input_image") { dataField("any:input_image", v.image_url); ref("any:input_image:id", v.file_id); }
      else if (t === "input_file") { dataField("any:input_file", v.file_data, v.filename); ref("any:input_file:id", v.file_id); ref("any:input_file:url", v.file_url); }
      else if (t === "computer_call_output" && isObj(v.output)) { dataField("any:computer_screenshot", v.output.image_url); ref("any:computer_screenshot:id", v.output.file_id); }
      for (const d of both(v, "inlineData", "inline_data", "any:inlineData")) {
        if (!isObj(d)) continue;
        const [mt] = both(d, "mimeType", "mime_type", "any:mimeType");
        b64("any:inlineData", mt, d.data, undefined, { urlSafe: true });
      }
      for (const fd of both(v, "fileData", "file_data", "any:fileData")) if (isObj(fd)) for (const u of both(fd, "fileUri", "file_uri", "any:fileUri")) ref("any:fileData", u);
      if (Array.isArray(v.images) && v.images.length && v.images.every((x) => typeof x === "string")) for (const s of v.images) b64("any:images", "image/unknown", s);
      for (const k of Object.keys(v)) visit(v[k], depth + 1);
    };
    visit(body, 0);
    return { parts, over, unscannable, refs, ambiguous };
  }
  if (!isObj(body)) return { parts, over, unscannable, refs, ambiguous };

  if (kind === "anthropic") {
    const block = (b, depth) => {
      if (!isObj(b)) return;
      if (depth > MAX_DEPTH) { deep("anthropic:depth"); return; }
      if ((b.type === "image" || b.type === "document") && isObj(b.source) && b.source.type === "base64") b64(`anthropic:${b.type}`, b.source.media_type, b.source.data);
      else if ((b.type === "image" || b.type === "document") && isObj(b.source) && b.source.type === "url") ref(`anthropic:${b.type}:url`, b.source.url);
      else if ((b.type === "image" || b.type === "document") && isObj(b.source) && b.source.type === "file") ref(`anthropic:${b.type}:file`, b.source.file_id);
      else if (b.type === "tool_result") for (const c of arr(b.content)) block(c, depth + 1);
    };
    for (const m of arr(body.messages)) if (isObj(m)) for (const b of arr(m.content)) block(b, 0);
  } else if (kind === "openai-chat") {
    for (const m of arr(body.messages)) {
      if (!isObj(m)) continue;
      for (const p of arr(m.content)) {
        if (!isObj(p)) continue;
        if (p.type === "image_url") dataField("openai:image_url", isObj(p.image_url) ? p.image_url.url : p.image_url);
        else if (p.type === "file" && isObj(p.file)) { dataField("openai:file", p.file.file_data, p.file.filename); ref("openai:file:id", p.file.file_id); }
        else if (p.type === "input_audio" && isObj(p.input_audio)) b64("openai:input_audio", `audio/${String(p.input_audio.format || "unknown").replace(/[^a-z0-9.+-]/gi, "")}`, p.input_audio.data);
      }
    }
  } else if (kind === "openai-responses") {
    const part = (p) => {
      if (!isObj(p)) return;
      if (p.type === "input_image") { dataField("responses:input_image", p.image_url); ref("responses:input_image:id", p.file_id); }
      else if (p.type === "input_file") { dataField("responses:input_file", p.file_data, p.filename); ref("responses:input_file:id", p.file_id); ref("responses:input_file:url", p.file_url); }
    };
    for (const it of arr(body.input)) {
      if (!isObj(it)) continue;
      if (it.type === "computer_call_output") { if (isObj(it.output)) { dataField("responses:computer_screenshot", it.output.image_url); ref("responses:computer_screenshot:id", it.output.file_id); } continue; }
      if (it.type === "function_call_output" || it.type === "custom_tool_call_output") { for (const p of arr(it.output)) part(p); continue; }
      for (const p of arr(it.content)) part(p);
    }
  } else if (kind === "gemini") {
    const walk = (list, depth) => {
      if (depth > MAX_DEPTH) { if (arr(list).length) deep("gemini:depth"); return; }
      for (const p of arr(list)) {
        if (!isObj(p)) continue;
        for (const d of both(p, "inlineData", "inline_data", "gemini:inlineData")) {
          if (!isObj(d)) continue;
          const [mt] = both(d, "mimeType", "mime_type", "gemini:mimeType");
          b64("gemini:inlineData", mt, d.data, undefined, { urlSafe: true });
        }
        for (const fd of both(p, "fileData", "file_data", "gemini:fileData")) if (isObj(fd)) for (const u of both(fd, "fileUri", "file_uri", "gemini:fileUri")) ref("gemini:fileData", u);
        for (const fr of both(p, "functionResponse", "function_response", "gemini:functionResponse")) if (isObj(fr)) walk(fr.parts, depth + 1);
      }
    };
    for (const si of both(body, "systemInstruction", "system_instruction", "gemini:systemInstruction")) if (isObj(si)) walk(si.parts, 0);
    for (const c of arr(body.contents)) if (isObj(c)) walk(c.parts, 0);
  } else if (kind === "ollama") {
    for (const s of arr(body.images)) b64("ollama:images", "image/unknown", s);
    for (const m of arr(body.messages)) if (isObj(m)) for (const s of arr(m.images)) b64("ollama:images", "image/unknown", s);
  }
  return { parts, over, unscannable, refs, ambiguous };
}

// Two results as one, a file found by both counted once (by its bytes; an unscannable value or a reference by its
// text), under the same caps.
export function mergeFileParts(...list) {
  const out = { parts: [], over: 0, unscannable: [], refs: [], ambiguous: [] };
  const seen = new Set();
  const key = { parts: (x) => `p:${createHash("sha256").update(x.bytes).digest("hex")}`, unscannable: (x) => `u:${x.raw}:${x.raw ? "" : x.where}`, refs: (x) => `r:${x.ref}` };
  for (const f of list) {
    out.over += f.over || 0;
    for (const k of ["parts", "unscannable", "refs"]) for (const x of f[k] || []) {
      const id = key[k](x);
      if (seen.has(id)) continue;
      seen.add(id);
      if (out[k].length >= MAX_PARTS) out.over++; else out[k].push(x);
    }
    for (const a of f.ambiguous || []) if (!out.ambiguous.includes(a)) out.ambiguous.push(a);
  }
  return out;
}

// Anthropic Message Batches (POST …/v1/messages/batches): {requests: [{custom_id, params: <a Messages request>}]};
// every request's params read as a Messages body, merged under the same caps.
export function batchFileParts(body) {
  const out = { parts: [], over: 0, unscannable: [], refs: [], ambiguous: [] };
  for (const r of arr(isObj(body) ? body.requests : null)) {
    if (!isObj(r)) continue;
    const f = fileParts("anthropic", r.params);
    out.over += f.over;
    for (const k of ["parts", "unscannable", "refs"]) for (const x of f[k]) { if (out[k].length >= MAX_PARTS) out.over++; else out[k].push(x); }
    out.ambiguous.push(...f.ambiguous);
  }
  return out;
}
