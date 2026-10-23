// JSON.parse for a body or event the proxy will re-serialize (a masked reply, text-guard.mjs, server.mjs): a
// number whose value would not print back as its source text — an integer past 2^53 (a snowflake id in a
// function call's arguments beside the masked text), a float with more digits than a double keeps — is kept as
// JSON.rawJSON(source), so JSON.stringify writes the provider's digits unchanged. A safe integer stays a number
// (an `index` field reads as before). Uses the reviver's source text (V8 JSON.parse source access, Node 22+);
// where the runtime has none, a plain JSON.parse. Returns null for text that is not JSON.
const RAW = typeof JSON.rawJSON === "function";
const keep = (key, value, ctx) => (typeof value === "number" && ctx && typeof ctx.source === "string" && !Number.isSafeInteger(value) && String(value) !== ctx.source ? JSON.rawJSON(ctx.source) : value);
export function parseLossless(text) {
  try { return JSON.parse(text, RAW ? keep : undefined); } catch { return null; }
}
