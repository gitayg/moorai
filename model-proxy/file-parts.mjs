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
// NOT read (no content in the request to scan): a URL (image_url https://…, Gemini fileData.fileUri), a
// provider file id (Anthropic source.type "file", OpenAI file_id), an Anthropic url source.
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
// -> { parts: [{ where, mediaType, bytes, filename? }], over, unscannable: [{ where, mediaType, raw }], ambiguous:
// [where] } — at most MAX_PARTS parts; `over` counts the rest, which the caller treats as not scanned.
export const MAX_PARTS = 32;

const isObj = (v) => Boolean(v) && typeof v === "object" && !Array.isArray(v);
const arr = (v) => (Array.isArray(v) ? v : []);
const MAX_DEPTH = 16;

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
  const parts = [], unscannable = [], ambiguous = [];
  let over = 0;
  const add = (where, mediaType, bytes, filename, raw) => {
    const mt = String(mediaType || "application/octet-stream").toLowerCase().slice(0, 128);
    if (bytes === null) { unscannable.push({ where, mediaType: mt, raw: typeof raw === "string" ? raw : "" }); return; }
    if (!bytes.length) return;
    if (parts.length >= MAX_PARTS) { over++; return; }
    parts.push({ where, mediaType: mt, bytes, ...(typeof filename === "string" ? { filename: filename.slice(0, 128) } : {}) });
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
  if (!isObj(body)) return { parts, over, unscannable, ambiguous };

  if (kind === "anthropic") {
    const block = (b, depth) => {
      if (!isObj(b) || depth > MAX_DEPTH) return;
      if ((b.type === "image" || b.type === "document") && isObj(b.source) && b.source.type === "base64") b64(`anthropic:${b.type}`, b.source.media_type, b.source.data);
      else if (b.type === "tool_result") for (const c of arr(b.content)) block(c, depth + 1);
    };
    for (const m of arr(body.messages)) if (isObj(m)) for (const b of arr(m.content)) block(b, 0);
  } else if (kind === "openai-chat") {
    for (const m of arr(body.messages)) {
      if (!isObj(m)) continue;
      for (const p of arr(m.content)) {
        if (!isObj(p)) continue;
        if (p.type === "image_url" && isObj(p.image_url)) { const d = fromDataUrl(p.image_url.url); if (d) add("openai:image_url", d.mediaType, d.bytes, undefined, d.raw); }
        else if (p.type === "file" && isObj(p.file)) { const d = fromDataUrl(p.file.file_data); if (d) add("openai:file", d.mediaType, d.bytes, p.file.filename, d.raw); }
        else if (p.type === "input_audio" && isObj(p.input_audio)) b64("openai:input_audio", `audio/${String(p.input_audio.format || "unknown").replace(/[^a-z0-9.+-]/gi, "")}`, p.input_audio.data);
      }
    }
  } else if (kind === "openai-responses") {
    const part = (p) => {
      if (!isObj(p)) return;
      if (p.type === "input_image") { const d = fromDataUrl(p.image_url); if (d) add("responses:input_image", d.mediaType, d.bytes, undefined, d.raw); }
      else if (p.type === "input_file") { const d = fromDataUrl(p.file_data); if (d) add("responses:input_file", d.mediaType, d.bytes, p.filename, d.raw); }
    };
    for (const it of arr(body.input)) {
      if (!isObj(it)) continue;
      if (it.type === "function_call_output" || it.type === "custom_tool_call_output") { for (const p of arr(it.output)) part(p); continue; }
      for (const p of arr(it.content)) part(p);
    }
  } else if (kind === "gemini") {
    const walk = (list, depth) => {
      if (depth > MAX_DEPTH) return;
      for (const p of arr(list)) {
        if (!isObj(p)) continue;
        for (const d of both(p, "inlineData", "inline_data", "gemini:inlineData")) {
          if (!isObj(d)) continue;
          const [mt] = both(d, "mimeType", "mime_type", "gemini:mimeType");
          b64("gemini:inlineData", mt, d.data, undefined, { urlSafe: true });
        }
        for (const fr of both(p, "functionResponse", "function_response", "gemini:functionResponse")) if (isObj(fr)) walk(fr.parts, depth + 1);
      }
    };
    for (const si of both(body, "systemInstruction", "system_instruction", "gemini:systemInstruction")) if (isObj(si)) walk(si.parts, 0);
    for (const c of arr(body.contents)) if (isObj(c)) walk(c.parts, 0);
  } else if (kind === "ollama") {
    for (const s of arr(body.images)) b64("ollama:images", "image/unknown", s);
    for (const m of arr(body.messages)) if (isObj(m)) for (const s of arr(m.images)) b64("ollama:images", "image/unknown", s);
  }
  return { parts, over, unscannable, ambiguous };
}
