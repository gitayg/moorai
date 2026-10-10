// Placeholder credentials, shared by the model proxy and the HTTP MCP gateway. The agent holds a placeholder
// (`moorai-ph:<name>`); a host-only bindings file maps it to where the real secret is read from, the one
// route + upstream it may be sent to, the header it goes in and its scheme. The component swaps the secret
// in only on that route, and refuses a placeholder anywhere else.
//
//   { "bindings": { "moorai-ph:anthropic-prod": { "secret": { "env": "ANTHROPIC_API_KEY" },
//       "route": "/anthropic", "upstream": "https://api.anthropic.com", "header": "x-api-key" } } }
//
// Secret sources: { "env": NAME } or { "file": PATH } (a Kubernetes secret mount). A literal value in the
// bindings file is refused: the file would then be a second copy of the key, and it is the file operators
// keep in config management and print when debugging. A file source gives the same result with a mode-0600
// file of its own.
//
// Never in an error, a log line or a report: a secret value. Placeholder names and env var names are not
// secrets and may appear.
import { readFileSync, statSync } from "node:fs";
import { Buffer } from "node:buffer";

export const PLACEHOLDER_PREFIX = "moorai-ph:";
const NAME_RE = /^moorai-ph:[A-Za-z0-9._-]{1,64}$/;
// Any header value or query string carrying this is treated as a placeholder use (`%3A` is the encoded colon).
const MARK_RE = /moorai-ph(?::|%3a)/i;
// `[scheme ]moorai-ph:name`, nothing else in the value.
const VALUE_RE = /^(?:([A-Za-z][A-Za-z0-9._~+-]*) )?(moorai-ph:[A-Za-z0-9._-]{1,64})$/;
const HEADER_RE = /^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,64}$/;
const SCHEME_RE = /^[A-Za-z][A-Za-z0-9._~+-]{0,31}$/;
// Headers that carry a credential when a client sends one. A request with any of these (or a bound header)
// holding something other than a placeholder is "a raw credential" once bindings are configured.
export const CREDENTIAL_HEADERS = Object.freeze(["authorization", "x-api-key", "api-key", "x-goog-api-key"]);
export const MIN_SECRET = 8;
export const MAX_SECRET = 4096;
const MAX_BINDINGS = 256;
const KEYS = new Set(["secret", "route", "upstream", "header", "scheme"]);

// The file must not be writable by anyone but its owner, and (POSIX) owned by this user or root. Windows
// mode bits are synthesized from the read-only attribute, not the ACL, so nothing is checked there.
export function checkFileSafe(path, what, { platform = process.platform, uid = process.getuid?.(), stat = statSync } = {}) {
  let st;
  try { st = stat(path); } catch (e) { throw new Error(`${what} ${path} cannot be read (${e.code || "error"})`); }
  if (!st.isFile()) throw new Error(`${what} ${path} is not a regular file`);
  if (platform === "win32") return;
  if (st.mode & 0o022) throw new Error(`${what} ${path} is group- or world-writable (mode ${(st.mode & 0o777).toString(8)}); chmod go-w it`);
  if (uid != null && st.uid !== uid && st.uid !== 0) throw new Error(`${what} ${path} is owned by another user (uid ${st.uid}); it must be owned by this user (uid ${uid}) or root`);
}

const normPrefix = (p) => { const s = String(p || ""); return s === "/" ? "" : s.replace(/\/+$/, ""); };
// origin + path without a trailing slash: the form a binding's upstream and a route's upstream are compared in.
const baseOf = (u) => `${u.origin}${u.pathname.replace(/\/+$/, "")}`;

function readSecret(name, src, env, opts) {
  if (typeof src === "string" || (src && Object.hasOwn(src, "value"))) throw new Error(`binding ${name}: a literal secret is refused; use { "env": NAME } or { "file": PATH }`);
  if (!src || typeof src !== "object" || Array.isArray(src)) throw new Error(`binding ${name}: "secret" must be { "env": NAME } or { "file": PATH }`);
  const keys = Object.keys(src);
  if (keys.length !== 1 || !["env", "file"].includes(keys[0])) throw new Error(`binding ${name}: "secret" must have exactly one of "env" or "file"`);
  let raw;
  if (keys[0] === "env") {
    const v = String(src.env || "");
    if (!/^[A-Za-z_][A-Za-z0-9_]{0,127}$/.test(v)) throw new Error(`binding ${name}: "secret.env" is not an environment variable name`);
    raw = env[v];
    if (raw == null || raw === "") throw new Error(`binding ${name}: environment variable ${v} is not set`);
  } else {
    const p = String(src.file || "");
    if (!p) throw new Error(`binding ${name}: "secret.file" is empty`);
    checkFileSafe(p, `binding ${name}: secret file`, opts);
    try { raw = readFileSync(p, "utf8"); } catch (e) { throw new Error(`binding ${name}: secret file ${p} cannot be read (${e.code || "error"})`); }
  }
  const v = String(raw).trim();
  if (v.length < MIN_SECRET) throw new Error(`binding ${name}: the secret is shorter than ${MIN_SECRET} characters`);
  if (v.length > MAX_SECRET) throw new Error(`binding ${name}: the secret is longer than ${MAX_SECRET} characters`);
  if (!/^[\x20-\x7e]+$/.test(v)) throw new Error(`binding ${name}: the secret has a character a header cannot carry (control or non-ASCII)`);
  if (MARK_RE.test(v)) throw new Error(`binding ${name}: the secret is itself a placeholder`);
  return v;
}

// file → { bindings: Map<placeholder, binding>, secrets: string[], headers: Set } — or throws. `routes` is
// [{ prefix, base }] as the component resolves requests (prefix "/x", base an absolute URL); `reserved` the
// headers the component strips or owns (a secret put there would never arrive, or would be taken as the
// component's own token).
export function loadBindings(file, { env = process.env, routes, reserved = new Set(), fileOpts } = {}) {
  checkFileSafe(file, "credentials file", fileOpts);
  let doc;
  try { doc = JSON.parse(readFileSync(file, "utf8")); } catch (e) { throw new Error(e.code ? `credentials file ${file} cannot be read (${e.code})` : `credentials file ${file} is not valid JSON`); }
  const entries = doc && typeof doc === "object" && doc.bindings && typeof doc.bindings === "object" && !Array.isArray(doc.bindings) ? Object.entries(doc.bindings) : null;
  if (!entries) throw new Error(`credentials file ${file}: expected { "bindings": { "moorai-ph:<name>": { … } } }`);
  if (!entries.length) throw new Error(`credentials file ${file} has no bindings`);
  if (entries.length > MAX_BINDINGS) throw new Error(`credentials file ${file} has more than ${MAX_BINDINGS} bindings`);
  const byPrefix = new Map(routes.map((r) => [normPrefix(r.prefix), r]));
  const bindings = new Map();
  for (const [name, b] of entries) {
    if (!NAME_RE.test(name)) throw new Error(`binding name must be ${PLACEHOLDER_PREFIX}<letters, digits, . _ ->, at most 64 after the prefix`);
    if (!b || typeof b !== "object" || Array.isArray(b)) throw new Error(`binding ${name} is not an object`);
    for (const k of Object.keys(b)) if (!KEYS.has(k)) throw new Error(`binding ${name}: unknown key "${k}"`);
    const prefix = normPrefix(b.route);
    if (typeof b.route !== "string" || !b.route.startsWith("/")) throw new Error(`binding ${name}: "route" must be a route path such as /anthropic`);
    const route = byPrefix.get(prefix);
    if (!route) throw new Error(`binding ${name}: route ${b.route} is not one of this component's routes`);
    let up;
    try { up = new URL(String(b.upstream || "")); } catch { throw new Error(`binding ${name}: "upstream" is not a URL`); }
    if (up.protocol !== "https:" && up.protocol !== "http:") throw new Error(`binding ${name}: "upstream" must be http(s)`);
    if (up.username || up.password || up.search || up.hash) throw new Error(`binding ${name}: "upstream" must not carry credentials, a query or a fragment`);
    if (baseOf(up) !== baseOf(new URL(route.base))) throw new Error(`binding ${name}: upstream does not match route ${b.route}'s upstream exactly`);
    const header = String(b.header || "").toLowerCase();
    if (!HEADER_RE.test(header)) throw new Error(`binding ${name}: "header" is not a header name`);
    if (reserved.has(header)) throw new Error(`binding ${name}: header ${header} is stripped or owned by this component`);
    const scheme = b.scheme == null || b.scheme === "" ? "" : String(b.scheme);
    if (scheme && !SCHEME_RE.test(scheme)) throw new Error(`binding ${name}: "scheme" is not an auth scheme token`);
    const secret = readSecret(name, b.secret, env, fileOpts);
    bindings.set(name, { name, prefix, upstream: up, base: baseOf(up), header, scheme, secret });
  }
  const secrets = [...new Set([...bindings.values()].map((b) => b.secret))];
  return { bindings, secrets, headers: new Set([...CREDENTIAL_HEADERS, ...[...bindings.values()].map((b) => b.header)]) };
}

// Every `key` parameter of a query string ("?a=1&key=…"); [] for none or an unparseable one.
export const CREDENTIAL_QUERY_PARAM = "key";
function queryKeys(query) {
  try { return new URLSearchParams(String(query || "").replace(/^\?/, "")).getAll(CREDENTIAL_QUERY_PARAM); } catch { return []; }
}

// The request-side gate. check(rawHeaders, query, prefix, target URL) →
//   { error: { status, message, raw? } }   refuse, content-free (raw: a raw credential under --require-placeholders)
//   { swaps: Map<header, value>, raw: boolean }
// rawHeaders is Node's req.rawHeaders: the only place a case-variant duplicate is visible (Node keeps the
// first Authorization and silently drops the rest; it joins two x-api-key values with ", ").
export function createGate(loaded, { requirePlaceholders = false } = {}) {
  const { bindings, headers: credHeaders } = loaded;
  return function check(rawHeaders, query, prefix, target) {
    const seen = new Map();
    for (let i = 0; i + 1 < rawHeaders.length; i += 2) {
      const k = String(rawHeaders[i]).toLowerCase(), v = String(rawHeaders[i + 1]);
      const e = seen.get(k);
      if (e) { e.n++; e.mark ||= MARK_RE.test(v); } else seen.set(k, { n: 1, v, mark: MARK_RE.test(v) });
    }
    for (const [k, e] of seen) if (e.n > 1 && (e.mark || credHeaders.has(k))) return { error: { status: 400, message: "a credential header appears more than once (in any letter case); refused" } };
    if (MARK_RE.test(String(query || ""))) return { error: { status: 400, message: "a credential placeholder in the URL is never swapped; send it in the header it is bound to" } };
    const swaps = new Map();
    // The Gemini API's query-string auth (`?key=<API key>`) carries a credential exactly as a header does.
    let raw = queryKeys(query).some((v) => v.trim() !== "");
    for (const [k, e] of seen) {
      if (!e.mark) { if (credHeaders.has(k) && e.v.trim() !== "") raw = true; continue; }
      const m = VALUE_RE.exec(e.v.trim());
      const b = m && bindings.get(m[2]);
      if (!b) return { error: { status: 401, message: "unknown or malformed credential placeholder" } };
      if (b.header !== k) return { error: { status: 403, message: "this credential placeholder is not bound to this header" } };
      if (b.prefix !== normPrefix(prefix) || !(target instanceof URL) || target.origin !== b.upstream.origin || !(`${target.pathname}/`.startsWith(`${b.base.slice(b.upstream.origin.length)}/`))) {
        return { error: { status: 403, message: "this credential placeholder is not bound to this route" } };
      }
      const given = m[1] || "";
      if (given.toLowerCase() !== b.scheme.toLowerCase()) return { error: { status: 401, message: "unknown or malformed credential placeholder" } };
      swaps.set(k, b.scheme ? `${b.scheme} ${b.secret}` : b.secret);
    }
    if (raw && requirePlaceholders) return { error: { status: 401, message: "this endpoint accepts only credential placeholders; a raw credential was refused", raw: true } };
    return { swaps, raw };
  };
}
