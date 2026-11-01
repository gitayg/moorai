// Trust boundary changed without a threat-model update (#85): does a write ADD a trust-boundary change?
// Judged on the difference between the file before and after the write (cli/oversight-signals.mjs
// beforeAfter), never on a mention: a README, a test, a fixture or a comment that names a host, a route or a
// package is not a finding, and neither is something that was already there.
//
// Signals (content-free enums; only these leave this module, never a name, host, key, path or value):
//   new-dependency       a manifest gains a dependency it did not declare (package.json dependencies,
//                        optionalDependencies, peerDependencies; requirements*.txt; pyproject [project] and
//                        poetry dependencies; go.mod require; Cargo.toml dependencies and build-dependencies;
//                        Gemfile gem; pom.xml dependency; gradle implementation / api / compileOnly /
//                        runtimeOnly). A version bump of a declared dependency is not new, and dev / test
//                        dependencies (devDependencies, dev-dependencies, test scope, testImplementation,
//                        poetry dev / test groups) are not counted.
//   new-egress-host      an http(s) URL in runtime code or config for a host the file did not name before.
//                        Loopback, the reserved example / test / invalid / localhost names and XML / JSON
//                        schema namespace hosts are ignored, as are comments and $schema / xmlns lines.
//   new-credential-path  runtime code newly reads a secret-looking env var (data/credential-env-names.js:
//                        the fixed list or the credential name shape), names a credential file
//                        (data/cred-alternatives.js kinds; certificates and public keys excluded) or starts
//                        loading dotenv; or a real .env file gains a key (.env.example and friends do not count).
//   new-route            more HTTP route or handler registrations than before (express / koa / fastify /
//                        hono / gin / echo style app.get / router.post, fastify route objects, Flask / FastAPI
//                        decorators, Django urlpatterns in urls.py, Go http.HandleFunc / Handle, Spring
//                        *Mapping, ASP.NET Map* and [Http*], Rails routes.rb, Next.js route handlers). Counted,
//                        not keyed, so renaming a route is not a new one.
//   analysis-incomplete  the write was not read whole: before or after over MAX (1 MiB), or the write adds a
//                        line over LINE_MAX (4 KiB) to a file judged line by line (every kind but package.json
//                        and pom.xml, which are parsed whole). Never cut and judged clean: it is recorded like a
//                        signal and counted at Stop (cli/boundary-stop.mjs), as #84's budget fails closed.
//
// Path handling (cli/oversight-signals.mjs pathClasses): only "code" is judged — docs, fixtures, examples,
// tests, CI tooling and UI component files are not; a path is judged when the path as written or its real
// target is runtime code. Manifests are judged by name in the same classes (requirements*.txt is a manifest,
// not a doc). Linear time: every pattern below is free of overlapping quantifiers, no line-anchored pattern lets
// \s span a newline ([ \t] instead), identifier runs are bounded, lines over LINE_MAX are blanked before any
// pattern sees them, and input is capped at MAX. These run on agent-written content inside PreToolUse, where a
// slow scan would time the hook out.
import { pathClasses } from "./oversight-signals.mjs";
import { CREDENTIAL_ENV_NAMES, CREDENTIAL_ENV_SHAPE } from "../data/credential-env-names.js";
import { CRED_ALTERNATIVES } from "../data/cred-alternatives.js";

export const BOUNDARY_SIGNALS = Object.freeze(["new-dependency", "new-egress-host", "new-credential-path", "new-route", "analysis-incomplete"]);
export const BOUNDARY_INCOMPLETE = "analysis-incomplete";
const MAX = 1_048_576;
export const LINE_MAX = 4096;
// The text with every line over LINE_MAX blanked (its line break kept), and the set of those lines.
function capLines(text) {
  const long = new Set();
  const lines = text.split("\n");
  for (let i = 0; i < lines.length; i++) if (lines[i].length > LINE_MAX) { long.add(lines[i]); lines[i] = ""; }
  return { text: long.size ? lines.join("\n") : text, long };
}
const isObj = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const str = (v) => (typeof v === "string" ? v.slice(0, MAX) : "");
const baseOf = (p) => { const s = String(p || "").replace(/\\/g, "/"); return s.slice(s.lastIndexOf("/") + 1); };
const minus = (a, b) => [...a].filter((x) => !b.has(x));

// ---- scope ----
const REQS = /^requirements[\w.-]*\.txt$/i;
const MANIFESTS = { "package.json": "npm", "pyproject.toml": "pyproject", "go.mod": "go", "cargo.toml": "cargo", "gemfile": "gem", "pom.xml": "maven", "build.gradle": "gradle", "build.gradle.kts": "gradle" };
function manifestKind(path) {
  const b = baseOf(path);
  if (REQS.test(b)) return "pip";
  return MANIFESTS[b.toLowerCase()] || null;
}
// The path to judge: as written when that is runtime code, else its real target when that is, else null.
// A requirements file is classed as a manifest, not as a .txt doc.
function judgedPath(path, cwd) {
  const asManifest = (p) => String(p || "").replace(/(requirements[\w.-]*)\.txt$/i, "$1.pip");
  try {
    const hit = pathClasses(asManifest(path), cwd).find((c) => c.cls === "code");
    if (!hit) return null;
    return hit.rel === pathClasses(asManifest(path), cwd)[0].rel ? path : hit.rel.replace(/(requirements[\w.-]*)\.pip$/i, "$1.txt");
  } catch { return null; }
}
const LOCKFILE = /^(?:package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|poetry\.lock|pipfile\.lock|cargo\.lock|go\.sum|gemfile\.lock|composer\.lock|bun\.lockb?)$/i;
const SOURCE_EXT = /\.(?:[cm]?js|[cm]?ts|py|rb|go|java|kt|kts|scala|rs|cs|php|swift|sh|bash|zsh|ps1|ya?ml|json|toml|ini|cfg|conf|properties|tf|hcl)$/i;
const ENV_FILE = /^\.env(?:\.[\w.-]+)?$/i;
const ENV_TEMPLATE = /\.(?:example|sample|template|dist|defaults?|tpl)$/i;

// ---- comments out, strings kept ----
const HASH_EXT = /\.(?:py|rb|sh|bash|zsh|ps1|ya?ml|toml|ini|cfg|conf|properties|tf|hcl|r|pl|ex|exs)$|(?:^|\/)(?:gemfile|rakefile|dockerfile|\.env[\w.-]*)$/i;
const SLASH_EXT = /\.(?:[cm]?js|[cm]?ts|go|java|kt|kts|scala|rs|cs|swift|c|cc|cpp|h|hpp|m|dart|php|tf|hcl|json5?)$/i;
// One pass over the text. Per line: a quote scanner ('", and ` across lines) that cuts at a comment opener
// outside a string. Python triple-quoted strings that open a statement (docstrings) are dropped.
export function codeText(text, path = "") {
  const hash = HASH_EXT.test(path), slash = SLASH_EXT.test(path), py = /\.py$/i.test(path);
  const out = [];
  let block = false, tick = false, doc = null;
  for (const line of str(text).split(/\r?\n/)) {
    let s = line, o = "";
    if (doc) { const i = s.indexOf(doc); if (i < 0) { out.push(""); continue; } s = s.slice(i + 3); doc = null; }
    if (py) {
      const t = s.trim();
      if (/^[rbuRBU]{0,2}(?:"""|''')/.test(t)) {
        const q = t.includes('"""') ? '"""' : "'''";
        const rest = t.slice(t.indexOf(q) + 3);
        if (!rest.includes(q)) doc = q;
        out.push(""); continue;
      }
    }
    let q = tick ? "`" : null;
    for (let i = 0; i < s.length; i++) {
      const c = s[i];
      if (block) { if (c === "*" && s[i + 1] === "/") { block = false; i++; } continue; }
      if (q) {
        o += c;
        if (c === "\\") { if (i + 1 < s.length) o += s[++i]; continue; }
        if (c === q) q = null;
        continue;
      }
      if (slash && c === "/" && s[i + 1] === "/") break;
      if (slash && c === "/" && s[i + 1] === "*") { block = true; i++; continue; }
      if (hash && c === "#" && (i === 0 || /\s/.test(s[i - 1]))) break;
      if (c === '"' || c === "'" || (slash && c === "`")) q = c;
      o += c;
    }
    tick = q === "`";
    out.push(o);
  }
  return out.join("\n");
}

// ---- new-dependency ----
const pep503 = (n) => n.toLowerCase().replace(/[-_.]+/g, "-");
const PEP508_NAME = /^\s*([A-Za-z0-9][A-Za-z0-9._-]*)/;
function npmDeps(text) {
  let j;
  try { j = JSON.parse(text); } catch { return null; }
  if (!isObj(j)) return null;
  const out = new Set();
  for (const k of ["dependencies", "optionalDependencies", "peerDependencies"]) if (isObj(j[k])) for (const n of Object.keys(j[k])) out.add(n.toLowerCase());
  return out;
}
function pipDeps(text) {
  const out = new Set();
  for (const raw of text.split(/\r?\n/)) {
    const l = raw.replace(/(?:^|\s)#.*$/, "").trim();
    if (!l || l.startsWith("-")) continue;
    const egg = /#egg=([A-Za-z0-9._-]+)/.exec(raw);
    if (egg) { out.add(pep503(egg[1])); continue; }
    if (/^[a-z+]+:\/\//i.test(l) || /^[./]/.test(l)) { out.add(l); continue; }
    const m = PEP508_NAME.exec(l);
    if (m) out.add(pep503(m[1]));
  }
  return out;
}
const DEV_GROUP = /^(?:dev|develop|development|test|tests|testing|lint|docs?|typing)$/i;
function pyprojectDeps(text) {
  const out = new Set();
  let table = "", inArray = false, arrayCounts = false;
  const strings = (l) => { const r = []; const re = /"([^"\n]*)"|'([^'\n]*)'/g; let m; while ((m = re.exec(l))) r.push(m[1] ?? m[2]); return r; };
  const addSpec = (s) => { const m = PEP508_NAME.exec(s); if (m) out.add(pep503(m[1])); };
  for (const raw of text.split(/\r?\n/)) {
    const l = raw.replace(/(?:^|\s)#.*$/, "");
    const t = l.trim();
    if (inArray) {
      if (arrayCounts) strings(t).forEach(addSpec);
      if (t.includes("]")) inArray = false;
      continue;
    }
    const h = /^\[([^\]]*)\]$/.exec(t);
    if (h) { table = h[1].trim().replace(/["']/g, ""); continue; }
    const poetryGroup = /^tool\.poetry\.group\.([^.]+)\.dependencies$/.exec(table);
    const poetry = table === "tool.poetry.dependencies" || (poetryGroup && !DEV_GROUP.test(poetryGroup[1]));
    if (poetry) { const k = /^([A-Za-z0-9][A-Za-z0-9._-]*)\s*=/.exec(t); if (k && k[1].toLowerCase() !== "python") out.add(pep503(k[1])); continue; }
    const arr = /^([A-Za-z0-9._-]+)\s*=\s*\[(.*)$/.exec(t);
    if (!arr) continue;
    arrayCounts = (table === "project" && arr[1] === "dependencies") || (table === "project.optional-dependencies" && !DEV_GROUP.test(arr[1]));
    if (arrayCounts) strings(arr[2]).forEach(addSpec);
    if (!arr[2].includes("]")) inArray = true;
  }
  return out;
}
function goDeps(text) {
  const out = new Set();
  let block = false;
  for (const raw of text.split(/\r?\n/)) {
    const t = raw.replace(/\/\/.*$/, "").trim();
    if (block) { if (t.startsWith(")")) { block = false; continue; } const m = /^(\S+)\s+v\S+/.exec(t); if (m) out.add(m[1].toLowerCase()); continue; }
    if (/^require\s*\($/.test(t)) { block = true; continue; }
    const m = /^require\s+(\S+)\s+v\S+/.exec(t);
    if (m) out.add(m[1].toLowerCase());
  }
  return out;
}
function cargoDeps(text) {
  const out = new Set();
  let counts = false;
  for (const raw of text.split(/\r?\n/)) {
    const t = raw.replace(/(?:^|\s)#.*$/, "").trim();
    const h = /^\[([^\]]*)\]$/.exec(t);
    if (h) {
      const name = h[1].trim();
      const dotted = /^(?:(?:workspace|target\.[^\]]+?)\.)?(dependencies|build-dependencies)\.([A-Za-z0-9_-]+)$/.exec(name);
      if (dotted) { out.add(dotted[2].toLowerCase()); counts = false; continue; }
      counts = /^(?:(?:workspace|target\..+)\.)?(?:dependencies|build-dependencies)$/.test(name);
      continue;
    }
    if (!counts) continue;
    const k = /^([A-Za-z0-9_-]+)\s*=/.exec(t);
    if (k) out.add(k[1].toLowerCase());
  }
  return out;
}
function gemDeps(text) {
  const out = new Set();
  const re = /^[ \t]*gem[ \t]+["']([^"'\n]+)["']/gm;
  let m;
  while ((m = re.exec(text))) out.add(m[1].toLowerCase());
  return out;
}
function mavenDeps(text) {
  const out = new Set();
  const chunks = text.split("<dependency>");
  for (let i = 1; i < chunks.length; i++) {
    const c = chunks[i].split("</dependency>")[0];
    const g = /<groupId>\s*([^<\s]+)\s*<\/groupId>/.exec(c), a = /<artifactId>\s*([^<\s]+)\s*<\/artifactId>/.exec(c), s = /<scope>\s*([^<\s]+)\s*<\/scope>/.exec(c);
    if (!a || (s && /^test$/i.test(s[1]))) continue;
    out.add(`${g ? g[1] : ""}:${a[1]}`.toLowerCase());
  }
  return out;
}
const GRADLE = /^[ \t]*(?:implementation|api|compileOnly|runtimeOnly|annotationProcessor|kapt|ksp|compile|runtime)[ \t]*(?:\([ \t]*)?["']([^"':\s]+):([^"':\s]+)(?::[^"'\s]*)?["']/gm;
function gradleDeps(text) {
  const out = new Set();
  let m;
  GRADLE.lastIndex = 0;
  while ((m = GRADLE.exec(text))) out.add(`${m[1]}:${m[2]}`.toLowerCase());
  return out;
}
const DEP_READERS = { npm: npmDeps, pip: pipDeps, pyproject: pyprojectDeps, go: goDeps, cargo: cargoDeps, gem: gemDeps, maven: mavenDeps, gradle: gradleDeps };
// Parsed whole (JSON.parse, and a split-based XML reader with non-overlapping patterns); the rest line by line.
const WHOLE = new Set(["npm", "maven"]);
// The dependency names a manifest of `kind` declares, or null when the text cannot be read as one. A line-read
// manifest is read with its lines over LINE_MAX blanked (a name on such a line is not seen).
export function manifestDeps(kind, text) {
  const r = DEP_READERS[kind];
  if (!r) return null;
  try { const t = str(text); return r(WHOLE.has(kind) ? t : capLines(t).text); } catch { return null; }
}
function newDependency(kind, before, after) {
  const a = manifestDeps(kind, after);
  if (!a || !a.size) return false;
  const b = before ? manifestDeps(kind, before) : new Set();
  if (!b) return false;
  return minus(a, b).length > 0;
}

// ---- new-egress-host ----
const URL_RE = /\bhttps?:\/\/(\[[0-9A-Fa-f:.]{2,45}\]|[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63}){0,20})/g;
const IGNORED_HOST = /^(?:localhost|127(?:\.\d{1,3}){3}|0\.0\.0\.0|\[::1?\]|\[0:0:0:0:0:0:0:1\])$|(?:^|\.)(?:localhost|local|test|example|invalid|internal\.?example)$|(?:^|\.)example\.(?:com|net|org)$|(?:^|\.)(?:w3\.org|json-schema\.org|json\.schemastore\.org|schemas\.xmlsoap\.org|purl\.org|xmlns\.com|schema\.org|schemas\.microsoft\.com|schemas\.android\.com|maven\.apache\.org|www\.apache\.org)$/i;
const SCHEMA_LINE = /\$schema|\bxmlns\b|xsi:schemaLocation|\$id"\s*:/;
function hosts(text) {
  const out = new Set();
  for (const line of text.split("\n")) {
    if (SCHEMA_LINE.test(line)) continue;
    URL_RE.lastIndex = 0;
    let m;
    while ((m = URL_RE.exec(line))) {
      const h = m[1].toLowerCase().replace(/\.$/, "");
      if (!h.includes(".") && !h.startsWith("[")) continue;
      if (IGNORED_HOST.test(h)) continue;
      out.add(h);
    }
  }
  return out;
}

// ---- new-credential-path ----
const ENV_REFS = [
  /\bprocess\.env\.([A-Za-z_][A-Za-z0-9_]*)/g,
  /\bprocess\.env\[\s*["'`]([A-Za-z_][A-Za-z0-9_]*)["'`]\s*\]/g,
  /\bimport\.meta\.env\.([A-Za-z_][A-Za-z0-9_]*)/g,
  /\bDeno\.env\.get\(\s*["']([A-Za-z_][A-Za-z0-9_]*)["']/g,
  /\bos\.environ(?:\.get)?\s*[[(]\s*["']([A-Za-z_][A-Za-z0-9_]*)["']/g,
  /\b(?:getenv|Getenv|LookupEnv|getEnv|GetEnv)\s*\(\s*["']([A-Za-z_][A-Za-z0-9_]*)["']/g,
  /\bENV(?:\.fetch\(\s*|\[\s*)["']([A-Za-z_][A-Za-z0-9_]*)["']/g,
  /\benv::var(?:_os)?\(\s*"([A-Za-z_][A-Za-z0-9_]*)"/g,
  /\bGetEnvironmentVariable\(\s*"([A-Za-z_][A-Za-z0-9_]*)"/g,
  /\$env:([A-Za-z_][A-Za-z0-9_]*)/gi
];
const DESTRUCTURE = /\{([^{}\n]{1,400})\}\s*=\s*process\.env\b/g;
const DOTENV = /\brequire\(\s*["']dotenv["']\s*\)|["']dotenv\/config["']|\bfrom\s+["']dotenv["']|\bload_dotenv\s*\(|\bfrom\s+dotenv\s+import\b|\bDotenv\.load\b|\bgodotenv\.Load\b|\bdotenv::dotenv\b/;
// The repo's credential names and shape, plus *_KEY names that are keys by name (SECRET_KEY, SIGNING_KEY).
const KEY_SHAPE = /(?:SECRET|SIGNING|ENCRYPTION|MASTER|PRIVATE|SERVICE_ACCOUNT)_KEY$/i;
const secretName = (n) => Object.prototype.hasOwnProperty.call(CREDENTIAL_ENV_NAMES, n) || CREDENTIAL_ENV_SHAPE.test(n) || KEY_SHAPE.test(n);
const LITERAL = /"((?:\\.|[^"\\\n]){1,400})"|'((?:\\.|[^'\\\n]){1,400})'|`((?:\\.|[^`\\\n]){1,400})`/g;
const NOT_SECRET = /\.(?:pub|crt|cer)\b/i;
const CERT_PEM = /(?:^|[/\\\s])(?:ca|certs?|certificate|chain|fullchain|public|pubkey|cacert|ca-bundle|bundle)[\w-]*\.pem$/i;
function credentialRefs(text) {
  const out = new Set();
  for (const re of ENV_REFS) { re.lastIndex = 0; let m; while ((m = re.exec(text))) if (secretName(m[1])) out.add(`env:${m[1]}`); }
  DESTRUCTURE.lastIndex = 0;
  let d;
  while ((d = DESTRUCTURE.exec(text))) for (const part of d[1].split(",")) { const n = part.split(/[:=]/)[0].trim(); if (/^[A-Za-z_]\w*$/.test(n) && secretName(n)) out.add(`env:${n}`); }
  if (DOTENV.test(text)) out.add("dotenv");
  LITERAL.lastIndex = 0;
  let m;
  while ((m = LITERAL.exec(text))) {
    const lit = m[1] ?? m[2] ?? m[3];
    if (NOT_SECRET.test(lit) || CERT_PEM.test(lit)) continue;
    for (const c of CRED_ALTERNATIVES) if (c.kind !== "gcloud" || /[/\\]/.test(lit)) { if (c.re.test(lit)) { out.add(`file:${c.kind}:${lit}`); break; } }
  }
  return out;
}
function envKeys(text) {
  const out = new Set();
  const re = /^[ \t]*(?:export[ \t]+)?([A-Za-z_][A-Za-z0-9_]*)[ \t]*=/gm;
  let m;
  while ((m = re.exec(text))) out.add(m[1]);
  return out;
}

// ---- new-route ----
// An identifier start: not preceded by an identifier character (\b would also start inside a$b$c).
const JS_ROUTE = /(?<![\w$])(?:app|server|srv|fastify|api|router|routes|route|r|e|g|mux|v\d|[A-Za-z_$][\w$]{0,63}(?:Router|Routes|App|Api))\s*\.\s*(?:get|post|put|patch|delete|del|all|options|head|use|route|GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD|Any|Handle|HandleFunc)\s*\(\s*["'`](?:[A-Z]{3,7} )?\//g;
const ROUTE_OBJ = /\.route\(\s*\{[^{}]{0,400}?\burl\s*:\s*["'`]\//g;
const GO_HANDLE = /\bhttp\s*\.\s*Handle(?:Func)?\s*\(\s*"/g;
const PY_DECORATOR = /@\s*[A-Za-z_][\w.]*\.(?:route|get|post|put|patch|delete|websocket|api_route|head|options)\s*\(\s*[rbuf]{0,2}["']/g;
const DJANGO = /\b(?:path|re_path|url)\s*\(\s*[rbuf]{0,2}["']/g;
const SPRING = /@(?:Get|Post|Put|Delete|Patch|Request)Mapping\b/g;
const DOTNET = /\.\s*Map(?:Get|Post|Put|Delete|Patch|Methods)\s*\(\s*"|\[\s*(?:Http(?:Get|Post|Put|Delete|Patch)|Route)\b/g;
const RAILS = /^[ \t]*(?:get|post|put|patch|delete|match|resources?|root|mount)\b[ \t]*[:"'(]|^[ \t]*root[ \t]+to:/gm;
const NEXT_HANDLER = /\bexport\s+(?:async\s+)?(?:function|const)\s+(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b/g;
const count = (re, text) => { re.lastIndex = 0; let n = 0; while (re.exec(text)) n++; return n; };
function routeCount(text, path) {
  const b = baseOf(path).toLowerCase();
  const p = String(path || "").replace(/\\/g, "/");
  let n = count(JS_ROUTE, text) + count(ROUTE_OBJ, text) + count(GO_HANDLE, text) + count(PY_DECORATOR, text) + count(SPRING, text) + count(DOTNET, text);
  if (b === "urls.py") n += count(DJANGO, text);
  if (b === "routes.rb") n += count(RAILS, text);
  if (/(?:^|\/)app\/(?:.*\/)?route\.[cm]?[jt]s$|(?:^|\/)pages\/api\//.test(p)) n += count(NEXT_HANDLER, text);
  return n;
}

// ---- the judgment ----
export function boundaryEditSignals({ path: written = "", before = null, after = "", cwd = "" } = {}) {
  try {
    if (typeof after !== "string" || !written) return [];
    const path = judgedPath(written, cwd);
    if (!path) return [];
    const base = baseOf(path);
    const kind = manifestKind(path);
    const env = !kind && ENV_FILE.test(base);
    if (!kind && !env && (LOCKFILE.test(base) || !SOURCE_EXT.test(base))) return [];
    if (after.length > MAX || (typeof before === "string" && before.length > MAX)) return [BOUNDARY_INCOMPLETE];
    if (after === (typeof before === "string" ? before : "")) return [];
    const out = new Set();
    let b = typeof before === "string" ? before : "", a = after;
    if (!WHOLE.has(kind)) {
      const cb = capLines(b), ca2 = capLines(a);
      if (minus(ca2.long, cb.long).length) out.add(BOUNDARY_INCOMPLETE);
      b = cb.text; a = ca2.text;
    }
    if (kind) { if (newDependency(kind, b, a)) out.add("new-dependency"); return BOUNDARY_SIGNALS.filter((s) => out.has(s)); }
    if (env) {
      if (!ENV_TEMPLATE.test(base) && minus(envKeys(a), envKeys(b)).length) out.add("new-credential-path");
      if (minus(hosts(codeText(a, path)), hosts(codeText(b, path))).length) out.add("new-egress-host");
      return BOUNDARY_SIGNALS.filter((s) => out.has(s));
    }
    const ca = codeText(a, path), cb = codeText(b, path);
    if (minus(hosts(ca), hosts(cb)).length) out.add("new-egress-host");
    if (minus(credentialRefs(ca), credentialRefs(cb)).length) out.add("new-credential-path");
    if (routeCount(ca, path) > routeCount(cb, path)) out.add("new-route");
    return BOUNDARY_SIGNALS.filter((s) => out.has(s));
  } catch { return []; }
}
