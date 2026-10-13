// Which program a script host (node, bun, deno, python) runs, read from its argv with that runtime's own
// option grammar, and the Windows CommandLine → argv split. Used by cli/ai-api-callers.mjs only.
//
// mainProgram(argv, kind) → one of
//   { script, at }              argv[at] is the main script; deno adds noConfig, python adds nothing more
//   { module, safePath }        python -m <module>; safePath when -I or -P keeps the cwd off sys.path
//   { spec }                    a package spec (npm:, jsr:, a URL), not a file: what it loads is decided by
//                               the registry, lockfile and the working directory's config, not the argv
//   { loads: <reason> }         the command line runs code other than one main script file
//   { unparseable: <reason> }   an option this grammar does not list, or a value form it cannot place
// Every option is on an allowlist: an option that is not listed is unparseable, so the classifier never
// guesses whether it consumes the next argument. Value options are accepted only in the `--opt=value` form
// where the runtime's own handling of the spaced form differs (MEASURED, node 22: `--max-old-space-size 100
// a.js` is refused by V8, `--title t a.js` consumes `t`). Option names fold `_` to `-` as node does.

const fold = (name) => (name.startsWith("--") ? `--${name.slice(2).replace(/_/g, "-")}` : name);

// ---- node: node [options] [script | -e code | -] [--] [arguments] ----
const NODE_FLAGS = new Set(["--no-warnings", "--no-deprecation", "--throw-deprecation", "--trace-deprecation", "--pending-deprecation",
  "--trace-warnings", "--trace-uncaught", "--trace-exit", "--enable-source-maps", "--expose-gc", "--no-addons", "--abort-on-uncaught-exception",
  "--use-openssl-ca", "--use-system-ca", "--use-bundled-ca", "--openssl-legacy-provider", "--tls-min-v1.2", "--tls-min-v1.3", "--tls-max-v1.2",
  "--tls-max-v1.3", "--zero-fill-buffers", "--no-network-family-autoselection", "--experimental-vm-modules", "--no-experimental-fetch"]);
const NODE_EQ = new Set(["--max-old-space-size", "--max-semi-space-size", "--stack-size", "--stack-trace-limit", "--unhandled-rejections",
  "--dns-result-order", "--title", "--disable-warning", "--max-http-header-size", "--network-family-autoselection-attempt-timeout", "--disable-proto"]);
function nodeLoads(n) {
  if (n === "-r" || n === "--require") return "preload";
  if (n === "--import") return "import";
  if (n === "--loader" || n === "--experimental-loader") return "loader";
  if (n === "-e" || n === "--eval" || n === "-p" || n === "--print") return "inline";
  if (n === "-i" || n === "--interactive") return "repl";
  if (n === "--env-file" || n === "--env-file-if-exists") return "env-file"; // an env file can set NODE_OPTIONS (MEASURED: --require ran)
  if (n === "--experimental-config-file" || n === "--experimental-default-config-file") return "config-file";
  if (n === "--snapshot-blob" || n === "--build-snapshot" || n === "--build-snapshot-config") return "snapshot";
  if (n === "--run" || n === "--test" || n === "--watch" || n === "--watch-path") return "runner";
  if (n === "--preserve-symlinks" || n === "--preserve-symlinks-main") return "symlinks"; // dependencies resolve from the link's folder
  if (n === "-C" || n === "--conditions") return "conditions";
  if (n.startsWith("--inspect") || n.startsWith("--debug")) return "inspector"; // a debugger client can run code in it
  return "";
}
function nodeMain(a) {
  for (let i = 1; i < a.length; i++) {
    const t = a[i];
    if (t === "--") return i + 1 < a.length ? { script: a[i + 1], at: i + 1 } : { loads: "stdin" };
    if (t === "-") return { loads: "stdin" };
    if (!t.startsWith("-")) return { script: t, at: i };
    const eq = t.indexOf("="), name = fold(eq < 0 ? t : t.slice(0, eq));
    const why = nodeLoads(name);
    if (why) return { loads: why };
    if (eq < 0 ? NODE_FLAGS.has(name) : NODE_EQ.has(name)) continue;
    return { unparseable: `node option ${name}` };
  }
  return { loads: "stdin" };
}

// ---- bun: bun [run] [options] <file> [arguments] ----
const BUN_FLAGS = new Set(["--bun", "--smol", "--silent", "--no-install", "--prefer-offline", "--no-deprecation", "--no-clear-screen"]);
function bunLoads(n) {
  if (n === "-r" || n === "--preload" || n === "--require" || n === "--import") return "preload";
  if (n === "-e" || n === "--eval" || n === "-p" || n === "--print") return "inline";
  if (n === "-c" || n === "--config" || n === "--cwd") return "config-file"; // a bunfig.toml can preload
  if (n === "--env-file") return "env-file";
  if (n === "-i" || n === "--install") return "auto-install";
  if (n === "--hot" || n === "--watch") return "runner";
  if (n.startsWith("--inspect")) return "inspector";
  return "";
}
function bunMain(a) {
  let sawRun = false;
  for (let i = 1; i < a.length; i++) {
    const t = a[i];
    if (t === "-") return { loads: "stdin" };
    if (t === "--") return { unparseable: "bun --" };
    if (!t.startsWith("-")) {
      if (t === "run" && !sawRun) { sawRun = true; continue; }
      if (t === "x" || t === "exec" || t === "repl") return { loads: `bun ${t}` };
      return { script: t, at: i };
    }
    const eq = t.indexOf("="), name = fold(eq < 0 ? t : t.slice(0, eq));
    const why = bunLoads(name);
    if (why) return { loads: why };
    if (eq < 0 && BUN_FLAGS.has(name)) continue;
    return { unparseable: `bun option ${name}` };
  }
  return { loads: "stdin" };
}

// ---- deno: deno [run] [options] <script> [arguments] ----
const DENO_FLAGS = new Set(["-A", "--allow-all", "-q", "--quiet", "--no-config", "--no-prompt", "--no-check", "--cached-only", "--no-lock",
  "--no-remote", "--no-npm", "-R", "-W", "-N", "-E", "-S"]);
const DENO_EQ = new Set(["--v8-flags", "--seed", "--log-level"]);
const DENO_PERM = /^--(allow|deny)-(read|write|net|env|sys|run|ffi|import|hrtime|scripts)$/;
const DENO_SUB = new Set(["eval", "repl", "x", "task", "serve", "test", "bench", "compile", "install", "add", "jupyter", "lsp", "upgrade"]);
function denoLoads(n) {
  if (n === "--preload" || n === "--require" || n === "--import") return "preload";
  if (n === "-c" || n === "--config" || n === "--import-map") return "config-file";
  if (n === "--env-file" || n === "--env") return "env-file";
  if (n === "--node-modules-dir" || n === "--vendor") return "local-modules";
  if (n === "--watch" || n === "--watch-hmr" || n === "--hmr") return "runner";
  if (n.startsWith("--inspect")) return "inspector";
  return "";
}
function denoMain(a) {
  let sawRun = false, noConfig = false;
  for (let i = 1; i < a.length; i++) {
    const t = a[i];
    if (t === "-") return { loads: "stdin" };
    if (t === "--") return { unparseable: "deno --" };
    if (!t.startsWith("-")) {
      if (t === "run" && !sawRun) { sawRun = true; continue; }
      if (!sawRun && DENO_SUB.has(t)) return { loads: `deno ${t}` };
      if (/^(npm|jsr|https?|file|data|blob):/i.test(t)) return { spec: t };
      return { script: t, at: i, noConfig };
    }
    const eq = t.indexOf("="), name = fold(eq < 0 ? t : t.slice(0, eq));
    const why = denoLoads(name);
    if (why) return { loads: why };
    if (name === "--no-config" && eq < 0) { noConfig = true; continue; }
    if (DENO_PERM.test(name) || (/^--unstable(-[a-z-]+)?$/.test(name) && eq < 0)) continue;
    if (eq < 0 ? DENO_FLAGS.has(name) : DENO_EQ.has(name)) continue;
    return { unparseable: `deno option ${name}` };
  }
  return { loads: "stdin" };
}

// ---- python: python [-bBdEhiIOPqRsSuvVWx?] [-c cmd | -m mod | script | -] [args] ----
// Short options cluster (-Bu, -Im mod, -Wd); c, m, W and X take the rest of the token or the next argument.
const PY_FLAGS = "bBdEIOPqRsSuvx";
const PY_X = /^(utf8(=[01])?|dev|importtime(=\d)?|faulthandler|tracemalloc(=\d+)?|no_debug_ranges|frozen_modules=(on|off)|warn_default_encoding|int_max_str_digits=\d+|cpu_count=(\d+|default)|gil=[01]|showrefcount|perf|perf_jit)$/;
// -W action:message:category:module:lineno. A dotted category is imported to resolve it (MEASURED: python 3.9,
// `-W ignore::evilcat.W` imported evilcat from PYTHONPATH), so only a bare category name is plain.
const pyWarnOk = (v) => !/\./.test(String(v).split(":")[2] || "");
function pythonMain(a) {
  let safePath = false;
  for (let i = 1; i < a.length; i++) {
    const t = a[i];
    if (t === "-") return { loads: "stdin" };
    if (t.startsWith("--")) {
      const eq = t.indexOf("="), name = eq < 0 ? t : t.slice(0, eq);
      if (name === "--check-hash-based-pycs") { if (eq < 0) i++; continue; }
      return { unparseable: `python option ${name}` };
    }
    if (!t.startsWith("-")) return { script: t, at: i };
    for (let j = 1; j < t.length; j++) {
      const c = t[j];
      if (c === "c") return { loads: "inline" };
      if (c === "i") return { loads: "repl" };
      if (c === "m" || c === "W" || c === "X") {
        let v = t.slice(j + 1);
        if (!v) { if (i + 1 >= a.length) return { unparseable: `python -${c} without a value` }; v = a[++i]; }
        if (c === "m") return { module: v, safePath };
        if (c === "W" && !pyWarnOk(v)) return { loads: "warning-category-import" };
        if (c === "X" && !PY_X.test(v)) return { unparseable: `python -X ${v.split("=")[0]}` };
        break;
      }
      if (PY_FLAGS.includes(c)) { if (c === "I" || c === "P") safePath = true; continue; }
      return { unparseable: `python option -${c}` };
    }
  }
  return { loads: "stdin" };
}

export function mainProgram(argv, kind) {
  const a = Array.isArray(argv) ? argv.map(String) : [];
  if (!a.length) return { unparseable: "empty argv" };
  if (kind === "node") return nodeMain(a);
  if (kind === "bun") return bunMain(a);
  if (kind === "deno") return denoMain(a);
  if (kind === "python") return pythonMain(a);
  return { unparseable: `script host ${kind}` };
}

// ---- Windows CommandLine → argv, by CommandLineToArgvW's rules ----
// argv[0] (the program) ends at the next quote if it starts with one, else at the first blank; no escapes.
// After it: 2n backslashes + quote → n backslashes and the quote toggles quoting; 2n+1 backslashes + quote →
// n backslashes and a literal quote; other backslashes are literal (Wine's shell32 implementation of the
// same function). Its separate rule for consecutive quotes is never reached: those are refused below.
// node, python, bun and deno do NOT call CommandLineToArgvW: they split with the C runtime or their own code,
// which disagrees with it on a doubled quote ("") and on a quote inside or right after argv[0]. A command line
// that has any of those, or an unclosed quote, is unparseable (null) instead of read one of two ways.
export function winArgv(s) {
  const t = String(s ?? "");
  let i = 0;
  while (t[i] === " " || t[i] === "\t") i++;
  let prog = "";
  if (t[i] === "\"") {
    const end = t.indexOf("\"", i + 1);
    if (end < 0) return null;
    prog = t.slice(i + 1, end);
    i = end + 1;
    if (i < t.length && t[i] !== " " && t[i] !== "\t") return null;
  } else {
    while (i < t.length && t[i] !== " " && t[i] !== "\t") { if (t[i] === "\"") return null; prog += t[i++]; }
  }
  const out = [prog];
  const rest = t.slice(i);
  if (/""/.test(rest.replace(/\\\\/g, "").replace(/\\"/g, ""))) return null;
  let cur = "", inArg = false, quoted = false, bs = 0;
  for (let k = 0; k < rest.length; k++) {
    const c = rest[k];
    if ((c === " " || c === "\t") && !quoted) { if (inArg) { out.push(cur + "\\".repeat(bs)); cur = ""; inArg = false; } bs = 0; continue; }
    inArg = true;
    if (c === "\\") { bs++; continue; }
    if (c === "\"") {
      cur += "\\".repeat(Math.floor(bs / 2));
      if (bs % 2) cur += "\""; else quoted = !quoted;
      bs = 0;
      continue;
    }
    cur += "\\".repeat(bs) + c;
    bs = 0;
  }
  if (quoted) return null;
  if (inArg) out.push(cur + "\\".repeat(bs));
  return out;
}
