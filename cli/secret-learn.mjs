// #65 — secret-shaped values in content the agent just read (a Read, a Bash result, an MCP result), for
// the session's tracked set (cli/secret-taint.mjs). Two sources, both reusing existing parsers:
//   provider tokens  the prefix-anchored #39 detectors (data/secrets-patterns.js) run over the whole text,
//                    plus the entropy-gated named-assignment detectors (`FOO_TOKEN=…` with a high-entropy
//                    value) and the JWT shape; a database URL contributes its password
//   KEY=value lines  every line of a credential-like source (a .env, cloud or package-manager credentials
//                    file, an `env` / `printenv` dump), through the store parser and isSecretish
// Returns values in memory only; the caller fingerprints and drops them.
import { SECRET_DETECTORS, looksLikeAssignedSecret } from "../data/secrets-patterns.js";
import { parseEnv, isSecretish } from "./secret-egress.mjs";

// Well above the tracker's per-call quota, so a result past this bound always also overflows the quota.
export const MAX_PER_RESULT = 4096;
const SCAN_CAP = 262144;

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

// Secret-shaped values in `text`. `kv`: the text comes from a credential-like source, so every KEY=value
// line counts. At most MAX_PER_RESULT values, first seen first.
export function learnableSecrets(text, { kv = false } = {}) {
  const t = String(text || "").slice(0, SCAN_CAP);
  const out = new Set();
  const add = (v) => { const u = unquote(v); if (out.size < MAX_PER_RESULT && isSecretish(u)) out.add(u); };
  if (!t) return [];
  for (const re of PROVIDER) { re.lastIndex = 0; for (const m of t.matchAll(re)) add(m[0]); }
  for (const m of t.matchAll(JWT)) add(m[0]);
  for (const m of t.matchAll(AZURE)) add(m[1]);
  for (const m of t.matchAll(DB_URL)) if (!/^(?:<[^<>]*>|\$\{[^}]*\}|\$[A-Za-z_]\w*|\{\{[^}]*\}\}|%[sd]|\*+|x{3,}|\.{3,}|\[[^\]]*\])$/i.test(m[1])) add(m[1]);
  for (const re of ASSIGN) {
    re.lastIndex = 0;
    for (const m of t.matchAll(re)) { const v = unquote(String(m[0]).replace(/^[^:=]*[:=]\s*/, "")); if (looksLikeAssignedSecret(v)) add(v); }
  }
  if (kv) for (const v of parseEnv(t.replace(/^([^=\n:]+):\s/gm, "$1= "))) add(v);
  return [...out];
}
