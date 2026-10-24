// Weakening oversight (#84): the file writes of one shell command that the memory-file and protected-path
// checks read (cli/oversight-shell.mjs resolves and judges them). Pure: tokens in, write positions out.
//
//   * copy and install: cp, install, rsync (a local destination; `host:path` is remote), with -t /
//     --target-directory / -T read; a directory destination receives each source under its own name;
//   * downloads to a file: curl -o / --output (and -O / --remote-name: the URL's own name, under
//     --output-dir), wget -O / --output-document, its log -o / -a, and with neither -O nor -r the URL's own
//     name under -P;
//   * dd of=; git checkout [<tree-ish>] -- <path>; git restore <path> (-s / --source read); patch <file> or
//     patch -o <file> (with neither, the diff names the files: not literal);
//   * a bare redirect, `> path` / `>> path` / `2> path` with no command word (data/shell-parse.js drops a
//     segment with no tokens, so this scans the raw text: quote-aware, heredoc bodies and comments skipped,
//     linear).
// A write position whose target is not a literal path ($VAR, $( … ), a glob, a ~user name) is returned as
// `unknown`; a `-` (stdout) and the null device are no write.
import { scanArgs } from "../data/shell-parse.js";

// Not a literal path: an expansion, a substitution, a glob or brace, or ~user (a bare ~ or ~/… is the home
// directory, which the caller expands).
export const nonLiteral = (t) => typeof t !== "string" || !t || /[$*?[\]{}`]/.test(t) || (t.startsWith("~") && !/^~(?:\/|$)/.test(t));
export const nullTarget = (t) => /^(?:\/dev\/(?:null|stdout|stderr|fd\/[0-9]+)|\$null|nul)$/i.test(String(t));
const remote = (t) => /^[^/\\]*:/.test(t) && !/^[A-Za-z]:[\\/]/.test(t);

// The file name a URL saves under (curl -O, wget): the last path segment, no query or fragment.
function urlName(u) {
  const m = /^[A-Za-z][A-Za-z0-9+.-]*:\/\/[^/?#]*(\/[^?#]*)?/.exec(String(u));
  if (!m) return null;
  const path = m[1] || "/";
  const name = path.slice(path.lastIndexOf("/") + 1);
  return name || null;
}

const CP = { shortValued: "tS", longValued: ["--target-directory", "--suffix"] };
const INSTALL = { shortValued: "gmoSt", longValued: ["--group", "--mode", "--owner", "--suffix", "--target-directory", "--strip-program"] };
const RSYNC = { shortValued: "eBfTM@", longValued: ["--rsh", "--rsync-path", "--exclude", "--include", "--filter", "--files-from", "--exclude-from", "--include-from", "--password-file", "--log-file", "--backup-dir", "--suffix", "--compare-dest", "--copy-dest", "--link-dest", "--partial-dir", "--temp-dir", "--chmod", "--chown", "--usermap", "--groupmap", "--timeout", "--contimeout", "--port", "--bwlimit", "--max-size", "--min-size", "--block-size", "--out-format", "--log-file-format", "--remote-option", "--modify-window", "--info", "--debug", "--iconv", "--max-delete", "--address", "--protocol", "--write-batch", "--only-write-batch", "--read-batch"] };
const CURL = { shortValued: "AbcCdDeEFHKmoPQrtTuUwxXyYz", longValued: ["--output", "--output-dir", "--data", "--data-raw", "--data-binary", "--data-urlencode", "--json", "--header", "--user", "--request", "--user-agent", "--referer", "--cookie", "--cookie-jar", "--upload-file", "--form", "--proxy", "--range", "--max-time", "--write-out", "--config", "--cert", "--key", "--cacert", "--continue-at", "--url", "--dump-header", "--connect-timeout", "--retry", "--resolve"] };
const WGET = { shortValued: "oaiBetOTwQPUDRAIXl", longValued: ["--output-document", "--output-file", "--append-output", "--directory-prefix", "--input-file", "--tries", "--timeout", "--wait", "--user-agent", "--header", "--post-data", "--post-file", "--user", "--password", "--execute", "--level", "--accept", "--reject", "--domains", "--base", "--quota", "--limit-rate", "--referer", "--load-cookies", "--save-cookies"] };
const PATCH = { shortValued: "BDdFgioprVYz", longValued: ["--input", "--output", "--directory", "--strip", "--prefix", "--basename-prefix", "--suffix", "--reject-file", "--fuzz", "--get", "--define", "--quoting-style", "--version-control"] };
const vals = (flags, ...names) => flags.filter((f) => names.includes(f.name)).map((f) => f.value);
const flagged = (flags, ...names) => flags.some((f) => names.includes(f.name));

// One write position: { dest, sources, dir } — dest as written; sources: what lands in it when it is a
// directory (null: dest itself is the file); dir: true / false, or null when the caller decides (an existing
// directory). → { writes: [...], unknown } for the command's binary and its arguments.
export function writeTargets(bin, args) {
  const writes = [];
  let unknown = false;
  const add = (dest, sources = null, dir = false) => {
    if (dest == null || dest === "-" || nullTarget(dest)) return;
    if (nonLiteral(dest)) { unknown = true; return; }
    writes.push({ dest, sources, dir });
  };
  if (bin === "cp" || bin === "install" || bin === "rsync") {
    const spec = bin === "cp" ? CP : bin === "install" ? INSTALL : RSYNC;
    const { flags, positional } = scanArgs(args, spec);
    if (bin === "install" && flagged(flags, "-d", "--directory")) return { writes, unknown };
    const target = vals(flags, "-t", "--target-directory").filter((v) => v != null).pop();
    const noTarget = bin !== "rsync" && flagged(flags, "-T", "--no-target-directory");
    const sources = target != null ? positional : positional.slice(0, -1);
    const dest = target != null ? target : positional.length >= 2 ? positional[positional.length - 1] : null;
    if (dest == null || (bin === "rsync" && remote(dest))) return { writes, unknown };
    add(dest, sources, target != null ? true : noTarget ? false : sources.length > 1 || /[\/\\]$/.test(dest) ? true : null);
  } else if (bin === "curl") {
    const { flags, positional } = scanArgs(args, CURL);
    for (const o of vals(flags, "-o", "--output")) add(o);
    if (flagged(flags, "-O", "--remote-name", "--remote-name-all")) {
      const dir = vals(flags, "--output-dir").pop();
      for (const u of [...positional, ...vals(flags, "--url")]) {
        if (nonLiteral(u)) { unknown = true; continue; }
        const name = urlName(u);
        if (name) add(dir != null ? `${dir}/${name}` : name);
      }
    }
  } else if (bin === "wget") {
    const { flags, positional } = scanArgs(args, WGET);
    const docs = vals(flags, "-O", "--output-document");
    for (const o of docs) add(o);
    for (const o of vals(flags, "-o", "--output-file", "-a", "--append-output")) add(o);
    if (!docs.length && !flagged(flags, "-r", "--recursive", "-m", "--mirror", "-i", "--input-file")) {
      const dir = vals(flags, "-P", "--directory-prefix").pop();
      for (const u of positional) {
        if (nonLiteral(u)) { unknown = true; continue; }
        const name = urlName(u) || (/^[A-Za-z][A-Za-z0-9+.-]*:\/\//.test(u) ? "index.html" : null);
        if (name) add(dir != null ? `${dir}/${name}` : name);
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
    const base = vals(pre, "-C").pop();
    if (base != null && nonLiteral(base)) return { writes, unknown: true };
    const under = (p) => (base != null && !/^[\/\\]/.test(p) ? `${base}/${p}` : p);
    const rest = args.slice(at + 1);
    if (args[at].toLowerCase() === "checkout") {
      const dd = rest.indexOf("--");
      if (dd >= 0) for (const p of rest.slice(dd + 1)) add(under(p));
    } else {
      const { flags, positional } = scanArgs(rest, { shortValued: "s", longValued: ["--source", "--pathspec-from-file"] });
      if (flagged(flags, "--pathspec-from-file")) unknown = true;
      for (const p of positional) add(under(p));
    }
  } else if (bin === "patch") {
    const { flags, positional } = scanArgs(args, PATCH);
    const dir = vals(flags, "-d", "--directory").pop();
    if (dir != null && nonLiteral(dir)) return { writes, unknown: true };
    const under = (p) => (dir != null && !/^[\/\\]/.test(p) ? `${dir}/${p}` : p);
    const out = vals(flags, "-o", "--output");
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
