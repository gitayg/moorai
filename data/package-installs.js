// The registry packages a shell command installs or runs, and the remote scripts it pipes into a shell, read
// the way the shell runs it (data/shell-parse.js, the reader data/agent-launch.js and data/net-exec.js use).
// A package counts only where the shell would run the installer: the command word of a segment (after env
// assignments and wrappers such as sudo, env, xargs), inside `sh -c` / `bash -c` / `pwsh -Command` /
// `cmd /c` / `eval`, or a heredoc fed to a shell. A name in an argument (`echo pip install x`, `grep`) is data.
//
// Read: npm / cnpm / pnpm / yarn / bun install and add (any scope, global or not), npx / bunx / pnpx /
// `npm exec` / `pnpm dlx` / `yarn dlx` / `bun x`; pip / pip3 / `python -m pip` install, pipx install / run,
// uv add, `uv pip install`, `uv tool install` / `uv tool run`, uvx (and its --from / --with), poetry add,
// pdm add. A fetched script run by a shell: curl / wget / Invoke-WebRequest / Invoke-RestMethod piped into a
// shell or iex, or `bash <(curl …)`.
//
// Each package → { ecosystem: "npm" | "pypi", name, version } where version is the exact version the spec
// pins (`x@1.2.3`, `x==1.2.3`, `x@1.2.3` for uv / poetry) and null otherwise (no version, a range, a
// dist-tag such as `latest`). A requirements file (`-r`), a lockfile install (`npm ci`, `uv sync`), a path,
// a URL or a git spec names no registry package here. Each script → { ecosystem: "url", name: host/path }.
//
// Bounded by the reader's caps (command length, segments, nesting depth). Never throws.
import { splitShell, commandOf, SHELLS, PWSH, MAX_CMD, MAX_DEPTH } from "./shell-parse.js";

const EXACT_SEMVER = /^v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const EXACT_PEP440 = /^v?\d+(?:\.\d+)*(?:(?:a|b|rc|\.post|\.dev)\d+)*(?:\+[0-9a-z.]+)?$/i;
const NPM_INSTALL = new Set(["install", "i", "in", "ins", "inst", "insta", "instal", "isnt", "isnta", "isntal", "isntall", "add"]);
const FETCHERS = new Set(["curl", "wget", "wget2", "invoke-webrequest", "invoke-restmethod"]);
const PIPS = /^pip[0-9.]*$/;
const PYTHONS = /^(?:python[0-9.]*|py)$/;
const NOT_REGISTRY = /^(?:git\+|git:|https?:|file:|github:|gitlab:|bitbucket:|link:|workspace:|portal:|\.{0,2}[/\\]|~)/i;

// Option values each family takes (the next word is the value, not a package).
const NPM_VALUED = new Set(["--registry", "--prefix", "-w", "--workspace", "--tag", "--cache", "--userconfig", "-C", "--dir", "--filter", "--cwd", "--modules-folder", "--network-timeout", "-p", "--package", "--call", "-c"]);
const PIP_VALUED = new Set(["-r", "--requirement", "-c", "--constraint", "-i", "--index-url", "--extra-index-url", "-e", "--editable", "-t", "--target", "--prefix", "--root", "--python", "-f", "--find-links", "--platform", "--python-version", "--implementation", "--abi", "--src", "--upgrade-strategy", "--progress-bar", "--log", "--cache-dir", "--trusted-host", "--proxy", "--timeout", "--retries", "--report", "--group", "--suffix", "--pip-args", "--spec", "--index", "--default-index", "-p", "--project", "--directory", "--optional", "--extra", "--dev-group", "-G", "--source", "--from", "--with", "--with-requirements", "--with-editable", "--constraints", "--overrides", "--refresh-package", "--reinstall-package", "--upgrade-package", "-P", "--branch", "--tag", "--rev", "--marker", "--package"]);

const positional = (args, valued) => {
  const out = [];
  for (let i = 0; i < args.length; i++) {
    const t = args[i];
    if (t === "--") { out.push(...args.slice(i + 1)); break; }
    if (t.startsWith("-")) { if (!t.includes("=") && valued.has(t)) i++; continue; }
    out.push(t);
  }
  return out;
};
// Values of one option (`--with x`, `--with=x`).
const optionValues = (args, names) => {
  const out = [];
  for (let i = 0; i < args.length; i++) {
    const t = args[i];
    if (t === "--") break;
    const eq = t.indexOf("=");
    if (eq > 0 && names.includes(t.slice(0, eq))) out.push(t.slice(eq + 1));
    else if (names.includes(t) && args[i + 1] != null) { out.push(args[i + 1]); i++; }
  }
  return out;
};

// `name`, `name@1.2.3`, `@scope/name@^1`, `alias@npm:real@1.2.3` → { name, version|null }, or null.
export function npmSpec(tok) {
  let s = String(tok || "").trim().replace(/^npm:/i, "");
  if (!s || NOT_REGISTRY.test(s) || s.includes("$")) return null;
  const at = s.indexOf("@", 1);
  let name = at > 0 ? s.slice(0, at) : s, spec = at > 0 ? s.slice(at + 1) : "";
  if (/^npm:/i.test(spec)) return npmSpec(spec);
  if (/^[^@]+\/[^/]/.test(name) && !name.startsWith("@")) return null; // owner/repo is a GitHub shorthand
  name = name.toLowerCase();
  if (!/^(?:@[a-z0-9][\w.-]*\/)?[a-z0-9][\w.-]*$/.test(name)) return null;
  const exact = spec.replace(/^=\s*/, "");
  return { ecosystem: "npm", name, version: exact && EXACT_SEMVER.test(exact) ? exact.replace(/^v/, "") : null };
}

// `name`, `name==1.2.3`, `name[extra]==1.2.3`, `name@1.2.3` (uv / poetry) → { name, version|null }, or null.
export function pypiSpec(tok) {
  const s = String(tok || "").trim();
  if (!s || NOT_REGISTRY.test(s) || s.includes("$") || /\.(?:whl|tar\.gz|zip|txt)$/i.test(s)) return null;
  const m = /^([A-Za-z0-9][A-Za-z0-9._-]{0,213})(?:\[[^\]]{0,256}\])?(.*)$/.exec(s);
  if (!m) return null;
  const tail = m[2].trim();
  if (tail && !/^[<>!~=@;,]/.test(tail)) return null;
  const pin = /^(?:===?|@)\s*([^\s,;]+)$/.exec(tail);
  // A pin PEP 440 allows but this pattern does not (an epoch `0!1.2`, `===`, leading zeros, a `.*` wildcard) is
  // passed on as written: normVersion puts it in normal form, or marks it so a listed package fails closed.
  const v = pin ? (EXACT_PEP440.test(pin[1]) ? pin[1].replace(/^v/i, "") : pin[1]) : null;
  return { ecosystem: "pypi", name: m[1].toLowerCase(), version: v };
}

// One segment's packages and runner target, or a command string it runs elsewhere ({ run }).
function segmentPackages(cw, rest) {
  const b = cw.binary, r0 = rest[0], r1 = rest[1];
  const npm = (toks) => toks.map(npmSpec).filter(Boolean);
  const pypi = (toks) => toks.map(pypiSpec).filter(Boolean);
  // npx-style runners: the -p / --package values, else the first positional word is the package.
  const npmRun = (args) => { const p = optionValues(args, ["-p", "--package"]); return npm(p.length ? p : positional(args, NPM_VALUED).slice(0, 1)); };
  if (b === "npx" || b === "bunx" || b === "pnpx") return npmRun(rest);
  if ((b === "npm" && (r0 === "exec" || r0 === "x")) || ((b === "pnpm" || b === "yarn") && r0 === "dlx") || (b === "bun" && r0 === "x")) return npmRun(rest.slice(1));
  if (b === "npm" || b === "cnpm" || b === "pnpm" || b === "bun") return NPM_INSTALL.has(r0) || r0 === "a" ? npm(positional(rest.slice(1), NPM_VALUED)) : [];
  if (b === "yarn") return r0 === "add" ? npm(positional(rest.slice(1), NPM_VALUED)) : r0 === "global" && r1 === "add" ? npm(positional(rest.slice(2), NPM_VALUED)) : [];
  // uvx / uv tool run / pipx run: --from names the package (else the first word), --with adds packages.
  const pyRun = (args) => { const from = optionValues(args, ["--from", "--spec"]); return pypi([...(from.length ? from : positional(args, PIP_VALUED).slice(0, 1)), ...optionValues(args, ["--with"])]); };
  if (b === "uvx") return pyRun(rest);
  if (b === "uv" && r0 === "tool" && r1 === "run") return pyRun(rest.slice(2));
  if (b === "pipx" && r0 === "run") return pyRun(rest.slice(1));
  if (PIPS.test(b) || b === "pipx") return r0 === "install" ? pypi(positional(rest.slice(1), PIP_VALUED)) : [];
  if (PYTHONS.test(b)) { const mi = rest.indexOf("-m"); return mi >= 0 && PIPS.test(rest[mi + 1] || "") && rest[mi + 2] === "install" ? pypi(positional(rest.slice(mi + 3), PIP_VALUED)) : []; }
  if (b === "uv") {
    if (r0 === "add") return pypi([...positional(rest.slice(1), PIP_VALUED), ...optionValues(rest.slice(1), ["--with"])]);
    if ((r0 === "pip" || r0 === "tool") && r1 === "install") return pypi([...positional(rest.slice(2), PIP_VALUED), ...optionValues(rest.slice(2), ["--with"])]);
    return [];
  }
  if (b === "poetry" || b === "pdm") return r0 === "add" ? pypi(positional(rest.slice(1), PIP_VALUED)) : [];
  return [];
}

function scriptUrl(t) {
  const m = /^(?:https?:\/\/)?([^/?#\s"']{1,253})(\/[^?#\s"']{0,1024})?/i.exec(String(t || ""));
  if (!m || !/\./.test(m[1]) || /^-/.test(t)) return null;
  const host = m[1].toLowerCase().replace(/^www\./, "").replace(/:\d+$/, "");
  return `${host}${(m[2] || "").replace(/\/+$/, "")}`;
}
const runsStdin = (cw) => !!cw && (SHELLS.has(cw.binary) || PWSH.has(cw.binary) || cw.binary === "iex" || cw.binary === "invoke-expression");

function walk(cmd, ps, depth, out, budget) {
  if (depth > MAX_DEPTH || budget.n <= 0) return;
  const segs = splitShell(String(cmd || "").slice(0, MAX_CMD), ps, 0, { segs: [], heredocs: [], nscope: 0 }).segs;
  const items = segs.map((seg) => { const cw = commandOf(seg.tokens, seg.ps); return { seg, cw, rest: cw ? seg.tokens.slice(cw.at + 1) : [] }; });
  for (let k = 0; k < items.length && budget.n-- > 0; k++) {
    const { seg, cw, rest } = items[k];
    if (!cw) continue;
    const b = cw.binary;
    const prev = items[k - 1], next = items[k + 1];
    const body = seg.heredoc != null ? seg.heredoc : prev && prev.seg.sep === "|" && prev.seg.heredoc != null ? prev.seg.heredoc : null;
    if (body != null && runsStdin(cw)) walk(body, PWSH.has(b) || b === "iex" || b === "invoke-expression", depth + 1, out, budget);
    if (FETCHERS.has(b)) {
      // A fetched script counts once a shell runs it: piped into a shell or iex, or `bash <(curl …)`.
      if ((seg.sep === "|" && next && runsStdin(next.cw)) || (prev && prev.seg.sep === "(" && runsStdin(prev.cw))) {
        // A word with a scheme first; else the first word that is not the value of an option before it.
        const pick = rest.find((t) => /^https?:\/\//i.test(t)) || rest.find((t, i) => !t.startsWith("-") && !(i > 0 && /^-/.test(rest[i - 1]) && !rest[i - 1].includes("=")));
        const u = pick ? scriptUrl(pick) : null;
        if (u) out.scripts.push({ ecosystem: "url", name: u });
      }
      continue;
    }
    if (SHELLS.has(b)) { const ci = rest.findIndex((t) => /^-[a-z]*c[a-z]*$/.test(t)); if (ci >= 0 && rest[ci + 1] != null) walk(rest[ci + 1], false, depth + 1, out, budget); continue; }
    if (PWSH.has(b)) { const ci = rest.findIndex((t) => /^-c(?:ommand)?$/i.test(t)); if (ci >= 0) walk(rest.slice(ci + 1).join(" "), true, depth + 1, out, budget); continue; }
    if (b === "cmd") { const ci = rest.findIndex((t) => /^\/[ck]$/i.test(t)); if (ci >= 0) walk(rest.slice(ci + 1).join(" "), false, depth + 1, out, budget); continue; }
    if (b === "eval" || b === "iex" || b === "invoke-expression") { if (rest.length) walk(rest.join(" "), seg.ps || b !== "eval", depth + 1, out, budget); continue; }
    for (const p of segmentPackages(cw, rest)) if (out.packages.length < 256) out.packages.push(p);
  }
}

const PS_HINT = /\b(?:irm|iwr|iex|Invoke-(?:WebRequest|RestMethod|Expression))\b|\$env:/i;
// Cheap gate before the parse: an installer, runner or fetcher is named.
export const INSTALL_HINT = /\b(?:npm|cnpm|pnpm|yarn|bun|npx|bunx|pnpx|pip[0-9.]*|pipx|uv|uvx|poetry|pdm|python[0-9.]*|py|curl|wget2?|irm|iwr|invoke-(?:webrequest|restmethod))\b/i;

// → { packages: [{ecosystem, name, version}], scripts: [{ecosystem: "url", name}] }. ps: as data/agent-launch.js.
export function packageInstalls(cmd, { ps } = {}) {
  const out = { packages: [], scripts: [] };
  try {
    const s = String(cmd || "");
    if (!s || s.length > MAX_CMD || !INSTALL_HINT.test(s)) return out;
    const readings = ps === true ? [true] : ps === false ? [false] : PS_HINT.test(s) ? [false, true] : [false];
    for (const r of readings) walk(s, r, 0, out, { n: 512 });
  } catch { /* never throws: what was read so far */ }
  return out;
}
