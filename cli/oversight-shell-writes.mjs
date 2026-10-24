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
// naming a URL glob (#1), git --work-tree / -c core.worktree, git --pathspec-from-file; and any write tool given
// an option that is ambiguous or that the tool does not have. A `-` (stdout) and the null device are no write.
import { scanArgs } from "../data/shell-parse.js";
import { CP, INSTALL, RSYNC, CURL, WGET, PATCH, GIT_CHECKOUT, GIT_RESTORE } from "./oversight-shell-options.mjs";

// Not a literal path: an expansion, a substitution, a glob or brace, or ~user (a bare ~ or ~/… is the home
// directory, which the caller expands).
export const nonLiteral = (t) => typeof t !== "string" || !t || /[$*?[\]{}`]/.test(t) || (t.startsWith("~") && !/^~(?:\/|$)/.test(t));
export const nullTarget = (t) => /^(?:\/dev\/(?:null|stdout|stderr|fd\/[0-9]+)|\$null|nul)$/i.test(String(t));
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
// their own parameters), whose options are not held to the tools' lists.
export function writeTargets(bin, args, { ps = false } = {}) {
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
    // -K / --config: more options from a file. -o naming a URL glob match (#1) unless globbing is off (-g).
    if (flagged(flags, "-K", "--config")) unknown = true;
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
    // The subcommand: the first word that is not a global option or its value (-C dir, -c k=v, --git-dir d).
    let at = -1;
    for (let i = 0; i < args.length; i++) {
      const t = args[i];
      if (t === "-C" || t === "-c" || t === "--git-dir" || t === "--work-tree" || t === "--namespace") { i++; continue; }
      if (t.startsWith("-")) continue;
      at = i; break;
    }
    if (at < 0 || !/^(?:checkout|restore)$/i.test(args[at])) return { writes, unknown };
    const pre = scanArgs(args.slice(0, at), { shortValued: "Cc", longValued: ["--git-dir", "--work-tree", "--namespace"] }).flags;
    // Another work tree (--work-tree, -c core.worktree=…) moves every path.
    if (flagged(pre, "--work-tree") || vals(pre, "-c").some((v) => /^core\.worktree=/i.test(v || ""))) return { writes, unknown: true };
    const base = vals(pre, "-C").pop();
    if (base != null && nonLiteral(base)) return { writes, unknown: true };
    const under = (p) => (base != null && !/^[\/\\]/.test(p) ? `${base}/${p}` : p);
    const checkout = args[at].toLowerCase() === "checkout";
    const rest = args.slice(at + 1);
    const dd = rest.indexOf("--");
    const { flags, positional } = scan(dd >= 0 ? rest.slice(0, dd) : rest, checkout ? GIT_CHECKOUT : GIT_RESTORE);
    if (flagged(flags, "--pathspec-from-file")) unknown = true;
    // git checkout without --: whether a word is a branch, a tree-ish or a path is decided at run time, so each one
    // (but a reflog revision, @{…}) is judged as a path; a branch name is a path that matches nothing. After --,
    // every word is a path.
    const paths = dd >= 0 ? [...(checkout ? [] : positional), ...rest.slice(dd + 1)] : positional.filter((p) => !(checkout && p.includes("@{")));
    for (const p of paths) add(under(p));
  } else if (bin === "patch") {
    const { flags, positional } = scan(args, PATCH);
    const dir = vals(flags, "-d", "--directory").pop();
    if (dir != null && nonLiteral(dir)) return { writes, unknown: true };
    const under = (p) => (dir != null && !/^[\/\\]/.test(p) ? `${dir}/${p}` : p);
    const out = vals(flags, "-o", "--output");
    for (const r of vals(flags, "-r", "--reject-file")) add(r === "-" ? r : under(r));
    if (out.length) out.forEach((o) => add(o === "-" ? o : under(o)));
    else if (positional.length) add(under(positional[0]));
    else unknown = true;
  }
  return { writes, unknown };
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
