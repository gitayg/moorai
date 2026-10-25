// #65 — secret-shaped values in content the agent just read (a Read, a Bash result, an MCP result), for
// the session's tracked set (cli/secret-taint.mjs). Two passes, both reusing existing parsers, in this order:
//   credential values  every KEY=value line of a credential-like source (a .env, cloud or package-manager
//                      credentials file, an `env` / `printenv` dump), through the store parser and
//                      isSecretish; then the entropy-gated named-assignment detectors (`FOO_TOKEN=…` with a
//                      high-entropy value), an Azure AccountKey and a database URL's password
//   provider tokens    the prefix-anchored #39 detectors (data/secrets-patterns.js) and the JWT shape
// Each pass reads the whole text, up to LEARN_TOTAL characters, in line-aligned chunks of LEARN_CHUNK, so
// provider-shaped junk ahead of a credential line can never crowd the credential out.
// TRUNCATION is reported, never silent: `truncated` is set when text past LEARN_TOTAL went unread, or when
// MAX_PER_RESULT values were collected and another one was still pending. The caller hands it to the
// tracker, which holds the session as unverified until now + TTL (secretEgress.unverified decides).
// Returns values in memory only; the caller fingerprints and drops them.
import { SECRET_DETECTORS, looksLikeAssignedSecret } from "../data/secrets-patterns.js";
import { parseEnv, isSecretish } from "./secret-egress.mjs";
import { inboundText } from "./inbound.mjs";

// Well above the tracker's per-call quota, so a result past this bound always also overflows the quota.
export const MAX_PER_RESULT = 4096;
// The total bound matches the egress raw-scan cap (cli/secret-match.mjs MAX_RAW, 16 MiB).
export const LEARN_TOTAL = 16 << 20;
export const LEARN_CHUNK = 262144;
// A chunk cut with no newline in its second half overlaps the next one by this much, past any learnable
// value (isSecretish: at most 512 characters; a database URL: user and password at most 256 each).
const LEARN_OVERLAP = 2048;

const PROVIDER_IDS = new Set(["secret-github", "secret-gitlab", "secret-slack", "secret-stripe", "secret-aws-akia", "secret-google-api", "secret-openai-anthropic", "secret-npm", "secret-pypi", "secret-sendgrid", "secret-twilio"]);
const ASSIGN_IDS = new Set(["secret-named-assignment", "secret-generic-assignment", "secret-aws-secret"]);
const glob = (re) => new RegExp(re.source, re.flags.includes("g") ? re.flags : re.flags + "g");
const PROVIDER = SECRET_DETECTORS.filter((d) => PROVIDER_IDS.has(d.detectorId)).flatMap((d) => d.patterns.map(glob));
const ASSIGN = SECRET_DETECTORS.filter((d) => ASSIGN_IDS.has(d.detectorId)).flatMap((d) => d.patterns.map(glob));
const JWT = /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\b/g;
const AZURE = /AccountKey=([A-Za-z0-9\/+]{40,}={0,2})/gi;
const DB_URL = /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/[^:@\s/]{1,256}:([^@\s/]{1,256})@/gi;
const unquote = (v) => String(v).replace(/^[\s"']+|[\s"',;]+$/g, "");

// A file whose lines are credentials: dotenv (not a committed template), cloud / package-manager / git
// credential files, gh's hosts.yml, docker and kube configs, Terraform variable files, secrets.* files.
export function isCredentialPath(p) {
  const s = String(p || "").replace(/\\/g, "/");
  if (!s || s.length > 4096) return false;
  const base = s.slice(s.lastIndexOf("/") + 1).toLowerCase();
  if (/^\.env(\..+)?$/.test(base)) return !/^\.env\.(example|sample|template)$/.test(base);
  if (["credentials", ".npmrc", ".netrc", "_netrc", ".pypirc", ".git-credentials", ".pgpass", ".dockercfg", ".boto", ".s3cfg", ".htpasswd"].includes(base)) return true;
  if (/\.tfvars$/.test(base) || /^secrets?\.(env|ya?ml|json|toml|txt|ini|properties)$/.test(base)) return true;
  return /(^|\/)\.config\/gh\/hosts\.yml$|(^|\/)\.docker\/config\.json$|(^|\/)\.kube\/config$/i.test(s);
}

// A shell command that dumps the environment (`env`, `printenv`, `set`, `export -p`, PowerShell `Get-ChildItem env:`).
export function isEnvDump(command) {
  return /(^|[;&|(]\s*)(?:env|printenv|set|export\s+-p)\s*(?:$|[;&|)>])|\b(?:gci|dir|ls|Get-ChildItem)\s+env:/i.test(String(command || ""));
}

// The chunks of `t`: line-aligned where a newline falls in a chunk's second half, else cut hard with an
// overlap (a value cut by a hard cut is read whole by the next chunk; duplicates collapse in the Set).
function* chunksOf(t) {
  for (let i = 0; i < t.length;) {
    const end = Math.min(t.length, i + LEARN_CHUNK);
    if (end === t.length) { yield t.slice(i); return; }
    // Searched within the chunk only: an unbounded lastIndexOf on newline-free text is quadratic.
    const c = t.slice(i, end), nl = c.lastIndexOf("\n");
    if (nl >= LEARN_CHUNK >> 1) { yield c.slice(0, nl + 1); i += nl + 1; }
    else { yield c; i = end - LEARN_OVERLAP; }
  }
}
const PLACEHOLDER_PW = /^(?:<[^<>]*>|\$\{[^}]*\}|\$[A-Za-z_]\w*|\{\{[^}]*\}\}|%[sd]|\*+|x{3,}|\.{3,}|\[[^\]]*\])$/i;

// Secret-shaped values in `text`. `kv`: the text comes from a credential-like source, so every KEY=value
// line counts. → { values (at most MAX_PER_RESULT, credential values first), truncated }.
export function learnableSecrets(text, { kv = false } = {}) {
  const s = String(text || "");
  const out = new Set();
  let truncated = s.length > LEARN_TOTAL, full = false;
  if (!s) return { values: [], truncated: false };
  const t = truncated ? s.slice(0, LEARN_TOTAL) : s;
  const add = (v) => {
    const u = unquote(v);
    if (out.has(u) || !isSecretish(u)) return;
    if (out.size >= MAX_PER_RESULT) { truncated = full = true; return; }
    out.add(u);
  };
  const credential = (c) => {
    if (kv) for (const v of parseEnv(c.replace(/^([^=\n:]+):\s/gm, "$1= "))) { add(v); if (full) return; }
    for (const re of ASSIGN) {
      re.lastIndex = 0;
      for (const m of c.matchAll(re)) { const v = unquote(String(m[0]).replace(/^[^:=]*[:=]\s*/, "")); if (looksLikeAssignedSecret(v)) add(v); if (full) return; }
    }
    for (const m of c.matchAll(AZURE)) { add(m[1]); if (full) return; }
    for (const m of c.matchAll(DB_URL)) { if (!PLACEHOLDER_PW.test(m[1])) add(m[1]); if (full) return; }
  };
  const provider = (c) => {
    for (const re of PROVIDER) { re.lastIndex = 0; for (const m of c.matchAll(re)) { add(m[0]); if (full) return; } }
    for (const m of c.matchAll(JWT)) { add(m[0]); if (full) return; }
  };
  for (const pass of [credential, provider]) {
    for (const c of chunksOf(t)) { pass(c); if (full) break; }
    if (full) break;
  }
  return { values: [...out], truncated };
}

// The text to learn from in a tool result, read past the scan surfaces' own caps (the 64 KB result scan
// text, a 256 KiB file head): a string as is, or every string value of an object, one per line (image and
// binary `data` / `blob` fields skipped, as the result scan does), JSON escapes decoded as every inbound
// surface decodes them. → { text, truncated } (more than LEARN_TOTAL characters, LEARN_DEPTH levels or
// LEARN_NODES objects: the rest went unread).
const LEARN_DEPTH = 32, LEARN_NODES = 1 << 20;
const BINARY_KEYS = new Set(["data", "blob"]);
export function learnSource(value) {
  if (typeof value === "string") return { text: inboundText(value, LEARN_TOTAL), truncated: value.length > LEARN_TOTAL };
  if (!value || typeof value !== "object") return { text: "", truncated: false };
  const parts = [];
  const b = { chars: LEARN_TOTAL, nodes: LEARN_NODES, truncated: false };
  const walk = (node, depth) => {
    if (b.truncated) return;
    if (depth > LEARN_DEPTH || --b.nodes < 0) { b.truncated = true; return; }
    for (const [k, v] of Array.isArray(node) ? node.entries() : Object.entries(node)) {
      if (b.truncated) return;
      if (typeof v === "string") {
        if (!v || BINARY_KEYS.has(k)) continue;
        if (v.length + 1 > b.chars) { parts.push(v.slice(0, b.chars)); b.truncated = true; return; }
        b.chars -= v.length + 1;
        parts.push(v);
      } else if (v && typeof v === "object") walk(v, depth + 1);
    }
  };
  walk(value, 0);
  return { text: inboundText(parts.join("\n"), LEARN_TOTAL), truncated: b.truncated };
}
