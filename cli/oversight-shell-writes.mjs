// Weakening oversight (#84): the file writes of one shell command that the memory-file and protected-path
// checks read (cli/oversight-shell.mjs resolves and judges them). Pure: tokens in, write positions out.
//
//   * copy and install: cp, install, rsync (a local destination; `host:path` is remote), with -t /
//     --target-directory / -T read; a directory destination receives each source under its own name (cp
//     --parents: under its whole path);
//   * downloads to a file: curl -o / --output (and -O / --remote-name: the URL's own name), both under
//     --output-dir; curl -D / -c / --trace / --trace-ascii / --stderr / --libcurl / --etag-save / --hsts /
//     --alt-svc; wget -O / --output-document, its log -o / -a, --save-cookies / --rejected-log / --hsts-file,
//     and with no -O the URL's own name (%-escapes decoded, as wget does; index.html or --default-page for a
//     bare host) under -P; a URL with no scheme is read as http, as both tools do;
//   * dd of=; git checkout [<tree-ish>] [--] <path> (without --, every word may be a path: git decides at run
//     time); git restore <path> (-s / --source read); patch <file> or patch -o <file>, and its reject file -r
//     (with neither file, the diff names the files: not literal).
//   * a bare redirect, `> path` / `>> path` / `2> path` with no command word (data/shell-parse.js drops a
//     segment with no tokens, so this scans the raw text: quote-aware, heredoc bodies and comments skipped,
//     linear).
// Options are read as each tool reads them (cli/oversight-shell-options.mjs): a unique prefix of a long option is
// that option (`cp --target=d`, `wget --output-doc=f`), as GNU getopt_long, git and curl 7.x accept it.
// A write position whose target is not a literal path ($VAR, $( … ), a glob, a ~user name) is returned as
// `unknown`, and so is every write whose name is picked at run time: wget -r / -m / -i / -p / -x /
// --content-disposition / --trust-server-names / -e / --config with no -O, curl -O with -J, curl -K, curl -o
// naming a URL glob (#1), git --work-tree / --git-dir / GIT_WORK_TREE / GIT_DIR / GIT_INDEX_FILE (gitInvocation,
// which git rm / git mv share), git --pathspec-from-file, a curl or wget config chosen through the command's
// environment (CURL_HOME, XDG_CONFIG_HOME, WGETRC, SYSTEM_WGETRC, HOME); and any write tool given an option that is
// ambiguous or that the tool does not have, or a letter whose arity differs between GNU and BSD with no single
// reading. A `-` (stdout) and the null device are no write. Environment names are matched whatever their case:
// Windows reads them case-insensitively, and on POSIX the extra match only over-reports.
import { scanArgs } from "../data/shell-parse.js";
import { CP, INSTALL, RSYNC, CURL, WGET, PATCH, GIT_CHECKOUT, GIT_RESTORE, GIT_GLOBAL, GIT_BUILTINS, GIT_SAFE_CONFIG } from "./oversight-shell-options.mjs";

// Not a literal path: an expansion, a substitution, a glob or brace, or ~user (a bare ~ or ~/… is the home
// directory, which the caller expands).
export const nonLiteral = (t) => typeof t !== "string" || !t || /[$*?[\]{}`]/.test(t) || (t.startsWith("~") && !/^~(?:\/|$)/.test(t));
export const nullTarget = (t) => /^(?:\/dev\/(?:null|stdout|stderr|fd\/[0-9]+)|\$null|nul)$/i.test(String(t));
// Whether a path resolves against a base directory: true — it does not (rooted: /… everywhere; on Windows or in a
// PowerShell segment also \…, \\host\share (UNC) and a drive letter C:\…, C:/…, drive-relative C:…, which names
// another drive's directory); false — it joins the base; null — a Windows-only shape outside Windows and PowerShell,
// where C:x, \x and \\h\s are relative names (measured, git 2.39.5 and 2.54.0: `git -C a -C C:x checkout -- f`
// writes a/C:x/f), but the command may still reach a Windows tool: whether it joins is unknown.
export function rooted(p, ps = false) {
  if (p.startsWith("/")) return true;
  if (!/^(?:\\|[A-Za-z]:)/.test(p)) return false;
  return ps || process.platform === "win32" ? true : null;
}
// p under the base dir, or undefined when that is unknown (rooted null).
const joinUnder = (base, p, ps) => { if (base == null) return p; const r = rooted(p, ps); return r === null ? undefined : r ? p : `${base}/${p}`; };
const remote = (t) => /^[^/\\]*:/.test(t) && !/^[A-Za-z]:[\\/]/.test(t);
const SCHEME = /^[A-Za-z][A-Za-z0-9+.-]*:\/\//;

// The file name a URL saves under (curl -O, wget): the last path segment, no query or fragment. A URL with no
// scheme is read as http (both tools do). wget decodes %-escapes in the name, except %2F (measured: wget 1.21.3
// saves …/CLAUDE%2Emd as CLAUDE.md; curl 8.7.1 keeps it as written).
function urlName(u, { decode = false } = {}) {
  const m = /^[A-Za-z][A-Za-z0-9+.-]*:\/\/[^/?#]*(\/[^?#]*)?/.exec(SCHEME.test(String(u)) ? String(u) : `http://${u}`);
  if (!m) return null;
  const path = m[1] || "/";
  let name = path.slice(path.lastIndexOf("/") + 1);
  if (decode && name.includes("%")) { try { name = decodeURIComponent(name.replace(/%2f/gi, "%252F")); } catch { return undefined; } }
  return name || null;
}

// A `NAME=value` word set for the command (data/shell-parse.js commandOf) naming one of names, in any case.
const envSet = (env, ...names) => env.some((e) => names.some((n) => n.toUpperCase() === String(e.name).toUpperCase()));

const vals = (flags, ...names) => flags.filter((f) => names.includes(f.name)).map((f) => f.value);
const flagged = (flags, ...names) => flags.some((f) => names.includes(f.name));
const unknownOption = (flags) => flags.some((f) => f.unknown);
const CURL_FILES = ["-D", "--dump-header", "-c", "--cookie-jar", "--trace", "--trace-ascii", "--stderr", "--libcurl", "--etag-save", "--hsts", "--alt-svc"];
const WGET_FILES = ["-o", "--output-file", "-a", "--append-output", "--save-cookies", "--rejected-log", "--hsts-file"];
const WGET_RUNTIME = ["-r", "--recursive", "-m", "--mirror", "-i", "--input-file", "-p", "--page-requisites", "--content-disposition", "--trust-server-names", "-x", "--force-directories", "--protocol-directories", "-e", "--execute", "--config"];

// One write position: { dest, sources, dir, parents } — dest as written; sources: what lands in it when it is a
// directory (null: dest itself is the file); dir: true / false, or null when the caller decides (an existing
// directory); parents: each source lands under its whole path (cp --parents). → { writes: [...], unknown } for
// the command's binary and its arguments. ps: a PowerShell segment (cp / curl there are cmdlet aliases with
// their own parameters), whose options are not held to the tools' lists. env: the `NAME=value` words set for the
// command (data/shell-parse.js commandOf), read for the variables that move git's work tree or pick curl's /
// wget's config file.
export function writeTargets(bin, args, { ps = false, env = [] } = {}) {
  const writes = [];
  let unknown = false;
  const add = (dest, sources = null, dir = false, parents = false) => {
    if (dest == null || dest === "-" || nullTarget(dest)) return;
    if (nonLiteral(dest)) { unknown = true; return; }
    writes.push({ dest, sources, dir, ...(parents ? { parents: true } : {}) });
  };
  const scan = (list, spec) => {
    const r = scanArgs(list, ps ? { shortValued: spec.shortValued, longValued: spec.longValued, longAll: spec.longAll, negatable: spec.negatable } : spec);
    if (!ps && unknownOption(r.flags)) unknown = true;
    return r;
  };
  if (bin === "cp" || bin === "install" || bin === "rsync") {
    const { flags, positional } = scan(args, bin === "cp" ? CP : bin === "install" ? INSTALL : RSYNC);
    if (bin === "install" && flagged(flags, "-d", "--directory")) return { writes, unknown };
    const target = vals(flags, "-t", "--target-directory").filter((v) => v != null).pop();
    // install -T is GNU's "not a directory" but BSD's tags: the caller decides whether the destination is a directory.
    const noTarget = bin === "cp" && flagged(flags, "-T", "--no-target-directory");
    const parents = bin === "cp" && flagged(flags, "--parents");
    const sources = target != null ? positional : positional.slice(0, -1);
    const dest = target != null ? target : positional.length >= 2 ? positional[positional.length - 1] : null;
    if (dest == null || (bin === "rsync" && remote(dest))) return { writes, unknown };
    add(dest, sources, target != null || parents ? true : noTarget ? false : sources.length > 1 || /[\/\\]$/.test(dest) ? true : null, parents);
  } else if (bin === "curl") {
    const { flags, positional } = scan(args, CURL);
    // -K / --config: more options from a file. -o naming a URL glob match (#1) unless globbing is off (-g). A
    // .curlrc found through CURL_HOME / XDG_CONFIG_HOME / HOME set for this command (measured, curl 7.88.1: its
    // `output = …` is obeyed), unless -q / --disable is the first argument (curl reads no .curlrc then).
    if (flagged(flags, "-K", "--config")) unknown = true;
    if (envSet(env, "CURL_HOME", "XDG_CONFIG_HOME", "HOME") && args[0] !== "-q" && args[0] !== "--disable") unknown = true;
    const dir = vals(flags, "--output-dir").pop();
    const under = (n) => (dir != null ? `${dir}/${n}` : n);
    const globs = !flagged(flags, "-g", "--globoff");
    for (const o of vals(flags, "-o", "--output")) { if (globs && /#[0-9]/.test(o || "")) unknown = true; else add(o === "-" ? o : under(o)); }
    for (const f of vals(flags, ...CURL_FILES)) add(f);
    if (flagged(flags, "-O", "--remote-name", "--remote-name-all")) {
      // -J / --remote-header-name: the server's Content-Disposition names the file.
      if (flagged(flags, "-J", "--remote-header-name")) unknown = true;
      else for (const u of [...positional, ...vals(flags, "--url")]) {
        if (nonLiteral(u)) { unknown = true; continue; }
        const name = urlName(u);
        if (name) add(under(name));
      }
    }
  } else if (bin === "wget") {
    const { flags, positional } = scan(args, WGET);
    // A wgetrc found through WGETRC / SYSTEM_WGETRC / HOME set for this command (measured, wget 1.21.3: its
    // `output_document = …` is obeyed), unless --no-config.
    if (envSet(env, "WGETRC", "SYSTEM_WGETRC", "HOME") && !flagged(flags, "--no-config")) unknown = true;
    const docs = vals(flags, "-O", "--output-document");
    for (const o of docs) add(o);
    for (const o of vals(flags, ...WGET_FILES)) add(o);
    if (!docs.length) {
      // With no -O, a recursive / list / requisites download, a server-picked name, a URL-shaped directory tree or
      // wgetrc commands (-e, --config) name the files at run time.
      if (flagged(flags, ...WGET_RUNTIME)) unknown = true;
      else {
        const dir = vals(flags, "-P", "--directory-prefix").pop();
        const page = vals(flags, "--default-page").pop();
        for (const u of positional) {
          if (nonLiteral(u)) { unknown = true; continue; }
          const name = urlName(u, { decode: true });
          if (name === undefined) { unknown = true; continue; }
          const file = name || page || "index.html";
          add(dir != null ? `${dir}/${file}` : file);
        }
      }
    }
  } else if (bin === "dd") {
    for (const t of args) if (t.startsWith("of=")) add(t.slice(3));
  } else if (bin === "git") {
    const g = gitInvocation(args, env, { ps });
    if (g.opaque) return { writes, unknown: true };
    if (g.sub !== "checkout" && g.sub !== "restore") return { writes, unknown };
    if (g.unknown) return { writes, unknown: true };
    const { at, under } = g;
    const checkout = g.sub === "checkout";
    const rest = args.slice(at + 1);
    const dd = rest.indexOf("--");
    const { flags, positional } = scan(dd >= 0 ? rest.slice(0, dd) : rest, checkout ? GIT_CHECKOUT : GIT_RESTORE);
    if (flagged(flags, "--pathspec-from-file")) unknown = true;
    // git checkout without --: whether a word is a branch, a tree-ish or a path is decided at run time, so each one
    // (but a reflog revision, @{…}) is judged as a path; a branch name is a path that matches nothing. After --,
    // every word is a path.
    const paths = dd >= 0 ? [...(checkout ? [] : positional), ...rest.slice(dd + 1)] : positional.filter((p) => !(checkout && p.includes("@{")));
    for (const p of paths) { const u = under(p); if (u === undefined) unknown = true; else add(u); }
  } else if (bin === "patch") {
    const { flags, positional } = scan(args, PATCH);
    const dir = vals(flags, "-d", "--directory").pop();
    if (dir != null && nonLiteral(dir)) return { writes, unknown: true };
    const under = (p) => { const u = joinUnder(dir, p, ps); if (u === undefined) unknown = true; return u; };
    const out = vals(flags, "-o", "--output");
    for (const r of vals(flags, "-r", "--reject-file")) add(r === "-" ? r : under(r));
    if (out.length) out.forEach((o) => add(o === "-" ? o : under(o)));
    else if (positional.length) add(under(positional[0]));
    else unknown = true;
  }
  return { writes, unknown };
}

// One git command line, read for what git checkout / restore / rm / mv share. → { at, sub, opaque, unknown, under }:
// at, the index of the subcommand (the first word that is not a global option or its value), -1 when there is none;
// sub, the subcommand lowercased (null without one); opaque, which command runs, and so what it writes, cannot be
// told; unknown, the command writes where its arguments do not say (opaque included); under(p), a path as git
// resolves it against the -C base (undefined when that is unknown: rooted null). ps: a PowerShell segment.
//   * Global options are read as git reads them (GIT_GLOBAL, cli/oversight-shell-options.mjs): the ones that take
//     the next word skip it. Any other word starting with - (an option git does not have, an abbreviation, -Cdir),
//     --exec-path=<dir> (git then runs non-builtins from dir: measured), a word that is not literal ($OPTS may be
//     options or the command) or a word that is not a builtin (an alias, a script, an external git-<name>, a typo:
//     GIT_BUILTINS) makes it opaque; the search goes on, so `git $OPTS rm f` is still judged as a git rm, and a
//     builtin in another case (`git Rm f`) is opaque and judged as the builtin it folds to.
//   * A config key set on the command line (-c, --config-env) or in the environment (GIT_CONFIG_COUNT /
//     GIT_CONFIG_KEY_<n>) outside GIT_SAFE_CONFIG may run a command (core.fsmonitor, core.pager, alias.* …), and so
//     may a config file the environment picks (GIT_CONFIG_GLOBAL, GIT_CONFIG_SYSTEM, HOME, XDG_CONFIG_HOME: measured,
//     each one's core.fsmonitor runs on status and checkout; GIT_CONFIG is not read), GIT_CONFIG_PARAMETERS and
//     GIT_EXEC_PATH: opaque.
//   * Another work tree moves every path: --work-tree / GIT_WORK_TREE, and --git-dir / GIT_DIR, which pick a
//     repository whose own config may set core.worktree (measured, git 2.39.5, 2.47.3 and 2.54.0: checkout, restore,
//     rm and mv each write there). A core.worktree given on the command line (-c, --config-env, GIT_CONFIG_COUNT) is
//     ignored by those versions, as is one in GIT_CONFIG / GIT_CONFIG_GLOBAL / GIT_CONFIG_SYSTEM.
//   * GIT_INDEX_FILE: git writes the index it names, resolved against the top of the work tree, creating it when
//     absent (measured, the same versions: checkout <tree-ish> -- f and restore --staged).
//   * GIT_COMMON_DIR, GIT_CEILING_DIRECTORIES and GIT_DISCOVERY_ACROSS_FILESYSTEM leave the paths where they are
//     (measured, the same versions), so they change nothing here.
//   * -C is cumulative: `git -C a -C b` runs in a/b; a rooted one starts over; an empty one changes nothing. A base
//     that is not literal, or a Windows-only rooted shape after another -C outside Windows and PowerShell, is
//     unknown.
const gitGlobalKnown = (t) => GIT_GLOBAL.valueless.includes(t) || GIT_GLOBAL.eqValued.some((o) => o !== "--exec-path" && t.startsWith(`${o}=`));
const safeConfigKey = (kv) => {
  const key = String(kv ?? "").split("=")[0].toLowerCase();
  return GIT_SAFE_CONFIG.keys.includes(key) || GIT_SAFE_CONFIG.sections.some((s) => key.startsWith(`${s}.`));
};
// GIT_CONFIG_COUNT / GIT_CONFIG_KEY_<n> in the command's environment: every key git will read is set there and safe.
function envConfigSafe(env) {
  const get = (n) => env.find((e) => String(e.name).toUpperCase() === n);
  for (const e of env) if (/^GIT_CONFIG_KEY_\d+$/i.test(e.name) && !safeConfigKey(e.value)) return false;
  const count = get("GIT_CONFIG_COUNT");
  if (!count) return true;
  if (!/^\d+$/.test(count.value) || Number(count.value) > env.length) return false;
  for (let n = 0; n < Number(count.value); n++) if (!get(`GIT_CONFIG_KEY_${n}`)) return false;
  return true;
}
export function gitInvocation(args, env = [], { ps = false } = {}) {
  let at = -1, opaque = false;
  for (let i = 0; i < args.length; i++) {
    const t = args[i];
    if (GIT_GLOBAL.valued.includes(t)) { i++; continue; }
    if (t.startsWith("-")) { if (!gitGlobalKnown(t)) opaque = true; continue; }
    if (!nonLiteral(t) && GIT_BUILTINS.has(t.toLowerCase())) { if (!GIT_BUILTINS.has(t)) opaque = true; at = i; break; }
    opaque = true;
  }
  const pre = scanArgs(at < 0 ? args : args.slice(0, at), { shortValued: "Cc", longValued: GIT_GLOBAL.valued.filter((o) => o.startsWith("--")) }).flags;
  if (!vals(pre, "-c", "--config-env").every(safeConfigKey) || !envConfigSafe(env)) opaque = true;
  if (envSet(env, "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM", "GIT_CONFIG_PARAMETERS", "GIT_EXEC_PATH", "HOME", "XDG_CONFIG_HOME")) opaque = true;
  let base = null, unsure = false;
  for (const c of vals(pre, "-C")) {
    if (!c) continue;
    const r = base == null ? true : rooted(c, ps);
    if (r === null) unsure = true;
    base = r === false ? `${base}/${c}` : c;
  }
  const unknown = opaque || unsure || flagged(pre, "--work-tree", "--git-dir") || envSet(env, "GIT_WORK_TREE", "GIT_DIR", "GIT_INDEX_FILE") || (base != null && nonLiteral(base));
  return { at, sub: at < 0 ? null : args[at].toLowerCase(), opaque, unknown, under: (p) => joinUnder(base, p, ps) };
}

// The targets of redirects that have no command word (`> f`, `>> f`, `2> f`, `: ` excluded: that is a
// command). Quote-aware; a heredoc body, a quoted string and a comment are skipped. Linear in the length.
const SEP = new Set([";", "&", "|", "\n", "(", ")", "{", "}", "`"]);
const WORD_END = /[\s;&|<>()`]/;
export function bareRedirects(cmd, ps = false) {
  const s = String(cmd || "");
  const out = [];
  const esc = ps ? "`" : "\\";
  let start = true, pending = null;
  const skipQuoted = (i) => { // i at a quote → index of its closing quote (or the end)
    const q = s[i];
    for (let j = i + 1; j < s.length; j++) { if (q === '"' && s[j] === esc) { j++; continue; } if (s[j] === q) return j; }
    return s.length;
  };
  const readWord = (i) => { // → { word, next }
    let w = "", j = i;
    while (j < s.length && !WORD_END.test(s[j])) {
      if (s[j] === "'" || s[j] === '"') { const e = skipQuoted(j); w += s.slice(j + 1, e); j = e + 1; continue; }
      if (s[j] === esc && j + 1 < s.length) { w += s[j + 1]; j += 2; continue; }
      w += s[j++];
    }
    return { word: w, next: j };
  };
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === "\n" && pending) { // skip the heredoc body, up to its delimiter line
      let j = i + 1;
      for (;;) {
        const e = s.indexOf("\n", j);
        const line = s.slice(j, e < 0 ? s.length : e).replace(/^\t+/, "").trim();
        if (line === pending || e < 0) { i = e < 0 ? s.length : e; break; }
        j = e + 1;
      }
      pending = null; start = true; continue;
    }
    if (SEP.has(c)) { start = true; continue; }
    if (c === " " || c === "\t" || c === "\r") continue;
    if (c === "#" && (i === 0 || /\s/.test(s[i - 1]))) { const e = s.indexOf("\n", i); i = (e < 0 ? s.length : e) - 1; continue; }
    if (!ps && c === "<" && s[i + 1] === "<" && s[i + 2] !== "<") {
      let j = i + 2;
      if (s[j] === "-") j++;
      while (s[j] === " " || s[j] === "\t") j++;
      const m = /^(['"]?)([A-Za-z0-9_.-]+)\1/.exec(s.slice(j, j + 256));
      if (m) { pending = m[2]; i = j + m[0].length - 1; continue; }
    }
    let k = i;
    while (start && k < s.length && /[0-9]/.test(s[k])) k++;
    if (start && s[k] === ">") {
      let j = k + 1;
      if (s[j] === ">" || s[j] === "|") j++;
      if (s[j] === "&") { i = j; continue; }
      while (s[j] === " " || s[j] === "\t") j++;
      const { word, next } = readWord(j);
      if (word) out.push(word);
      i = next - 1;
      continue;
    }
    if (c === "'" || c === '"') { i = skipQuoted(i); start = false; continue; }
    if (c === esc) { i++; start = false; continue; }
    start = false;
  }
  return out;
}
