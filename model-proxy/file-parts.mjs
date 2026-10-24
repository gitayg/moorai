// The inline files a model request carries, per API, for the cloud file scan (cli/file-scan.mjs). Every
// turn is read, any role, since a conversation re-sends its earlier files (the scan's cache answers those).
//   anthropic          messages[].content[] {type: "image" | "document", source: {type: "base64", media_type,
//                      data}}, also inside a tool_result's content[] (platform.claude.com/docs/en/build-with-claude/vision,
//                      …/pdf-support). A document whose source is text or content blocks is text, scanned as text.
//   openai-chat        messages[].content[] {type: "image_url", image_url: {url: "data:<mt>;base64,…"}},
//                      {type: "file", file: {file_data: "data:<mt>;base64,…", filename}}, {type: "input_audio",
//                      input_audio: {data, format}} (github.com/openai/openai-openapi).
//   openai-responses   input[] message content[] {type: "input_image", image_url: data URL}, {type: "input_file",
//                      file_data: data URL, filename}; also a function_call_output whose output is a list of them.
//   gemini             contents[].parts[] and systemInstruction.parts[] inlineData / inline_data {mimeType |
//                      mime_type, data} (ai.google.dev/api/caching#Blob).
//   ollama             messages[].images[] (/api/chat) and images[] (/api/generate): base64 strings, no media type.
// NOT read (no content in the request to scan): a URL (image_url https://…, Gemini fileData.fileUri), a
// provider file id (Anthropic source.type "file", OpenAI file_id), an Anthropic url source.
//
// -> { parts: [{ where, mediaType, bytes, filename? }], over } — at most MAX_PARTS parts; `over` counts the
// rest, which the caller treats as not scanned (its fail mode decides).
export const MAX_PARTS = 32;

const isObj = (v) => Boolean(v) && typeof v === "object" && !Array.isArray(v);
const arr = (v) => (Array.isArray(v) ? v : []);
// data:[<media type>][;params][;base64],<data>
function fromDataUrl(s) {
  if (typeof s !== "string" || !/^data:/i.test(s)) return null;
  const comma = s.indexOf(",");
  if (comma < 0) return null;
  const meta = s.slice(5, comma).split(";");
  const mediaType = (meta[0] || "text/plain").trim().toLowerCase();
  const isB64 = meta.slice(1).some((p) => p.trim().toLowerCase() === "base64");
  const payload = s.slice(comma + 1);
  if (isB64) return { mediaType, bytes: Buffer.from(payload, "base64") };
  try { return { mediaType, bytes: Buffer.from(decodeURIComponent(payload), "utf8") }; } catch { return { mediaType, bytes: Buffer.from(payload, "utf8") }; }
}
const b64 = (s) => (typeof s === "string" && s.length ? Buffer.from(s, "base64") : null);

export function fileParts(kind, body) {
  const parts = [];
  let over = 0;
  const add = (where, mediaType, bytes, filename) => {
    if (!bytes || !bytes.length) return;
    if (parts.length >= MAX_PARTS) { over++; return; }
    parts.push({ where, mediaType: String(mediaType || "application/octet-stream").toLowerCase().slice(0, 128), bytes, ...(typeof filename === "string" ? { filename: filename.slice(0, 128) } : {}) });
  };
  if (!isObj(body)) return { parts, over };

  if (kind === "anthropic") {
    const block = (b) => {
      if (!isObj(b)) return;
      if ((b.type === "image" || b.type === "document") && isObj(b.source) && b.source.type === "base64") add(`anthropic:${b.type}`, b.source.media_type, b64(b.source.data));
      else if (b.type === "tool_result") for (const c of arr(b.content)) block(c);
    };
    for (const m of arr(body.messages)) if (isObj(m)) for (const b of arr(m.content)) block(b);
  } else if (kind === "openai-chat") {
    for (const m of arr(body.messages)) {
      if (!isObj(m)) continue;
      for (const p of arr(m.content)) {
        if (!isObj(p)) continue;
        if (p.type === "image_url" && isObj(p.image_url)) { const d = fromDataUrl(p.image_url.url); if (d) add("openai:image_url", d.mediaType, d.bytes); }
        else if (p.type === "file" && isObj(p.file)) { const d = fromDataUrl(p.file.file_data); if (d) add("openai:file", d.mediaType, d.bytes, p.file.filename); }
        else if (p.type === "input_audio" && isObj(p.input_audio)) add("openai:input_audio", `audio/${String(p.input_audio.format || "unknown").replace(/[^a-z0-9.+-]/gi, "")}`, b64(p.input_audio.data));
      }
    }
  } else if (kind === "openai-responses") {
    const part = (p) => {
      if (!isObj(p)) return;
      if (p.type === "input_image") { const d = fromDataUrl(p.image_url); if (d) add("responses:input_image", d.mediaType, d.bytes); }
      else if (p.type === "input_file") { const d = fromDataUrl(p.file_data); if (d) add("responses:input_file", d.mediaType, d.bytes, p.filename); }
    };
    for (const it of arr(body.input)) {
      if (!isObj(it)) continue;
      if (it.type === "function_call_output" || it.type === "custom_tool_call_output") { for (const p of arr(it.output)) part(p); continue; }
      for (const p of arr(it.content)) part(p);
    }
  } else if (kind === "gemini") {
    const partsOf = (c) => arr(isObj(c) ? c.parts : null);
    for (const p of [...partsOf(body.systemInstruction || body.system_instruction), ...arr(body.contents).flatMap(partsOf)]) {
      if (!isObj(p)) continue;
      const d = isObj(p.inlineData) ? p.inlineData : isObj(p.inline_data) ? p.inline_data : null;
      if (d) add("gemini:inlineData", d.mimeType || d.mime_type, b64(d.data));
    }
  } else if (kind === "ollama") {
    for (const s of arr(body.images)) add("ollama:images", "image/unknown", b64(s));
    for (const m of arr(body.messages)) if (isObj(m)) for (const s of arr(m.images)) add("ollama:images", "image/unknown", b64(s));
  }
  return { parts, over };
}
