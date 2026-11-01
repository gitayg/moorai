// Exfiltration channels an agent's shell command opens, read structurally with data/shell-parse.js (the
// reader the egress rules and data/net-exec.js use), so a name counts only where the shell would run it.
//
//   textStorageHit   data posted to a paste site (pastebin, termbin, hastebin, ...), a GitHub gist or a
//                    GitLab snippet: ATT&CK T1567.003 Exfiltration to Text Storage Sites.
//   repoPushFacts    the pushes, remote changes and `gh repo create --push` of a command: the facts
//                    cli/repo-push.mjs judges against the project's own remotes (T1567.001 Exfiltration to
//                    Code Repository).
//   stagingFacts     a split into chunks (T1030 Data Transfer Size Limits) or a copy / archive of a
//                    sensitive location (T1074.001 Local Data Staging), for the session sequences in
//                    data/session-risk.js.
//
// Content-free by construction: callers keep booleans, kinds and keyed hashes; nothing here is logged.
// Bounded: the reader caps the command, the segment count and the nesting depth. Browser-safe. Never throws.
import { splitShell, commandOf, scanArgs, has, val, SHELLS, PWSH, MAX_CMD, MAX_DEPTH } from "./shell-parse.js";
import { netDestinations } from "./net-exec.js";

// The threat ids (data/threats.json): a detector or decideThreat call for an id that is not in the catalogue does nothing.
export const TEXT_STORAGE_THREAT = 95;
export const CODE_REPO_THREAT = 96;

// Every segment the shell runs, recursing into `sh -c`, `pwsh -Command`, `cmd /c` and `eval`.
function walk(cmd, ps, depth, out, budget) {
  if (depth > MAX_DEPTH || budget.n <= 0) return out;
  const segs = splitShell(String(cmd || "").slice(0, MAX_CMD), ps, 0, { segs: [], heredocs: [], nscope: 0 }).segs;
  for (let k = 0; k < segs.length && budget.n-- > 0; k++) {
    const seg = segs[k];
    const cw = commandOf(seg.tokens, seg.ps);
    const rest = cw ? seg.tokens.slice(cw.at + 1) : [];
    if (!cw) continue;
    const b = cw.binary;
    if (SHELLS.has(b)) { const ci = rest.findIndex((t) => /^-[a-z]*c[a-z]*$/.test(t)); if (ci >= 0 && rest[ci + 1] != null) { walk(rest[ci + 1], false, depth + 1, out, budget); continue; } }
    else if (PWSH.has(b)) { const ci = rest.findIndex((t) => /^-c(?:ommand)?$/i.test(t)); if (ci >= 0) { walk(rest.slice(ci + 1).join(" "), true, depth + 1, out, budget); continue; } }
    else if (b === "cmd") { const ci = rest.findIndex((t) => /^\/[ck]$/i.test(t)); if (ci >= 0) { walk(rest.slice(ci + 1).join(" "), false, depth + 1, out, budget); continue; } }
    else if (b === "eval" || b === "iex" || b === "invoke-expression") { if (rest.length) walk(rest.join(" "), seg.ps || b !== "eval", depth + 1, out, budget); continue; }
    out.push({ seg, b, rest, ps: seg.ps });
  }
  return out;
}
const segmentsOf = (cmd, ps) => walk(cmd, !!ps, 0, [], { n: 512 });

// ---- T1567.003: paste sites, gists, snippets ----

// Public paste services an anonymous client can post text to with curl, nc or Invoke-RestMethod. Matched on
// the hostname at a label boundary ("api.paste.ee" is paste.ee; "notpastebin.com" is not). ghostbin.com and
// ghostbin.co are listed although the service is often offline: a model reaches for the name it was trained on.
// Deliberately NOT here: file drops (transfer.sh, 0x0.st, file.io), which are file hosting rather than text
// storage, and general code hosts (a push is judged by cli/repo-push.mjs).
export const TEXT_STORAGE_HOSTS = Object.freeze([
  "pastebin.com", "paste.ee", "hastebin.com", "ghostbin.com", "ghostbin.co", "dpaste.com", "dpaste.org",
  "termbin.com", "rentry.co", "rentry.org", "ix.io", "sprunge.us", "paste.rs"
]);
export function textStorageHost(host) {
  const h = String(host || "").toLowerCase().replace(/\.$/, "");
  if (!h || h.length > 253) return null;
  for (const d of TEXT_STORAGE_HOSTS) if (h === d || h.endsWith(`.${d}`)) return d;
  return null;
}
export const TEXT_STORAGE_MENTION = new RegExp(`(?:${TEXT_STORAGE_HOSTS.map((d) => d.replace(/\./g, "\\.")).join("|")})(?![A-Za-z0-9-])|\\bgists?\\b|\\bsnippets?\\b`, "i");

const HTTP = new Set(["curl", "wget", "wget2", "http", "https", "xh", "xhs", "invoke-webrequest", "invoke-restmethod"]);
const GIST_API = /^https?:\/\/api\.github\.com\/gists(?:\/[0-9a-f]{1,64})?\/?(?:[?#]|$)/i;
const SNIPPET_API = /^https?:\/\/[a-z0-9.-]{1,253}(?::\d{1,5})?\/api\/v4\/(?:projects\/[^/\s]{1,200}\/)?snippets\/?(?:[?#]|$)/i;
const GH_API_GIST = /^\/?gists(?:\/[0-9a-f]{1,64})?\/?$/i;
const urlHost = (u) => String(u).replace(/^[a-z][a-z0-9+.-]*:\/\//i, "").replace(/^[^@/]*@/, "").split(/[/?#:]/)[0].toLowerCase();

// "paste" | "gist" | "snippet" | null: the command sends data to a text-storage site. A read (a GET of a raw
// paste, `gh gist view`, `gh gist list`) is not a send.
export function textStorageHit(cmd, { ps = false } = {}) {
  try {
    const s = String(cmd || "");
    if (!TEXT_STORAGE_MENTION.test(s)) return null;
    const dests = netDestinations(s, { ps });
    // An HTTP client's destination carries `upload` (a body, an upload or a non-GET method); a socket client's
    // `send` (input piped or redirected into it).
    const writes = (d) => d.upload === true || (d.upload === undefined && d.send);
    if (dests.some((d) => writes(d) && textStorageHost(d.host))) return "paste";
    const upHosts = new Set(dests.filter((d) => d.upload === true).map((d) => d.host));
    for (const { b, rest, ps: sps } of segmentsOf(s, ps)) {
      if (b === "gh") {
        const [sub, verb] = rest.filter((t) => !t.startsWith("-"));
        if (sub === "gist" && (verb === "create" || verb === "new")) return "gist";
        if (sub === "gist" && verb === "edit" && rest.some((t) => t === "-a" || t === "--add" || t.startsWith("--add="))) return "gist";
        if (sub === "api") {
          const { flags, positional } = scanArgs(rest.slice(rest.indexOf("api") + 1), { shortValued: "XfFHtqp", longValued: ["--method", "--field", "--raw-field", "--input", "--header", "--hostname", "--jq", "--template", "--preview", "--cache"] });
          const ep = positional[0] || "";
          const m = val(flags, "-X", "--method");
          const body = has(flags, "-f", "-F", "--field", "--raw-field", "--input");
          if (GH_API_GIST.test(ep) && (m ? /^(post|patch|put)$/i.test(m) : body)) return "gist";
        }
      }
      if (b === "glab" && rest[0] === "snippet" && (rest[1] === "create" || rest[1] === "new")) return "snippet";
      if (HTTP.has(b) || (sps && (b === "curl" || b === "wget"))) {
        for (const t of rest) {
          if (!/^https?:\/\//i.test(t) || !upHosts.has(urlHost(t))) continue;
          if (GIST_API.test(t)) return "gist";
          if (SNIPPET_API.test(t)) return "snippet";
        }
      }
    }
  } catch { return null; }
  return null;
}

// ---- T1567.001: pushes and remotes ----

// A repository argument as { local: true } (a path, file://, loopback) or { host, path } (lowercased, no
// port, no user, `.git` and slashes trimmed), or null when it is a remote NAME.
export function normRepoUrl(raw) {
  const s = String(raw || "").trim();
  if (!s || s.length > 2048) return null;
  if (/^file:\/\//i.test(s) || /^(?:\/|\.{1,2}(?:[/\\]|$)|~|[A-Za-z]:[\\/]|\\\\)/.test(s)) return { local: true };
  let host = "", path = "";
  const url = s.match(/^([a-z][a-z0-9+.-]{0,15}):\/\/(?:[^@/\s]{0,200}@)?(\[[0-9a-f:.]+\]|[^/:\s?#]{1,253})(?::\d{1,5})?(\/[^?#\s]*)?/i);
  if (url) { host = url[2]; path = url[3] || ""; }
  else {
    // scp-like: [user@]host:path (a colon before any slash). A bare word is a remote name.
    const scp = s.match(/^(?:[^@/\s:]{1,200}@)?([^@/\s:]{1,253}):(?!\/\/)([^\s]*)$/);
    if (!scp) return null;
    host = scp[1]; path = scp[2];
  }
  host = host.toLowerCase().replace(/\.$/, "");
  if (/^(?:localhost|127(?:\.\d{1,3}){3}|\[::1\]|::1|0\.0\.0\.0)$/.test(host)) return { local: true };
  path = path.replace(/^[/~]+/, "").replace(/\/+$/, "").replace(/\.git$/i, "").toLowerCase();
  return { host, path };
}
export const repoKey = (r) => (r && !r.local ? `${r.host}/${r.path}` : "");

const GIT_GLOBAL_VALUED = new Set(["-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path", "--config-env", "--super-prefix"]);
const PUSH_SHORT = "o";
const PUSH_LONG = ["--repo", "--push-option", "--receive-pack", "--exec"];

// { pushes: [{ dir, repo, viaRepo }], remotes: [{ dir, name, url }], ghPush: [{ owner }] }. `dir` is the directory
// the git command runs in, relative to the agent's cwd ("" = cwd): its `-C` values, after a `cd` earlier in the
// same command. `repo` is the repository argument as written (a URL, a path or a remote name), or "" for the
// default.
export function repoPushFacts(cmd, { ps = false } = {}) {
  const out = { pushes: [], remotes: [], ghPush: [] };
  try {
    const s = String(cmd || "");
    if (!/\bgit\b|\bgh\b/.test(s)) return out;
    let cd = "";
    for (const { b, rest } of segmentsOf(s, ps)) {
      if ((b === "cd" || b === "pushd" || b === "set-location" || b === "sl") && rest.length) { const p = rest.filter((t) => !t.startsWith("-")).pop(); if (p) cd = joinDir(cd, p); continue; }
      if (b === "git") {
        let i = 0, dir = cd;
        while (i < rest.length && rest[i].startsWith("-")) {
          const t = rest[i];
          if (t === "-C" && rest[i + 1] != null) { dir = joinDir(dir, rest[i + 1]); i += 2; continue; }
          if (GIT_GLOBAL_VALUED.has(t)) { i += 2; continue; }
          i++;
        }
        const sub = rest[i], args = rest.slice(i + 1);
        if (sub === "push") {
          const { flags, positional } = scanArgs(args, { shortValued: PUSH_SHORT, longValued: PUSH_LONG });
          const viaRepo = val(flags, "--repo");
          out.pushes.push({ dir, repo: positional[0] || viaRepo || "", viaRepo: !positional[0] && !!viaRepo });
        } else if (sub === "remote" && (args[0] === "add" || args[0] === "set-url")) {
          const { positional } = scanArgs(args.slice(1), { shortValued: "tm", longValued: ["--mirror"] });
          if (positional.length >= 2) out.remotes.push({ dir, name: positional[0], url: positional[1] });
        } else if (sub === "config") {
          const pos = args.filter((t) => !t.startsWith("-"));
          const m = pos[0] && pos[0].match(/^remote\.(.{1,200})\.(?:url|pushurl)$/i);
          if (m && pos[1] != null) out.remotes.push({ dir, name: m[1], url: pos[1] });
        }
        continue;
      }
      if (b === "gh" && rest[0] === "repo" && rest[1] === "create" && rest.some((t) => t === "--push" || t === "--push=true")) {
        const name = rest.slice(2).find((t) => !t.startsWith("-"));
        const owner = name && name.includes("/") ? name.split("/")[0].toLowerCase() : null;
        out.ghPush.push({ owner, name: name ? name.toLowerCase() : null });
      }
    }
  } catch { return out; }
  return out;
}
function joinDir(base, p) {
  const s = String(p);
  if (/^(?:\/|~|[A-Za-z]:[\\/]|\\\\)/.test(s)) return s;
  return base ? `${base.replace(/[\\/]+$/, "")}/${s}` : s;
}

// policy.codeRepoAllow (signed policy only): destinations a push may reach without a finding. Each entry is a
// host ("git.acme.com"), a host and owner ("github.com/acme") or a host, owner and repository
// ("github.com/acme/tools"); `*.` before a host matches any name under it. Case-blind. Malformed entries are
// ignored.
export function codeRepoAllowed(policy, r) {
  const list = policy && Array.isArray(policy.codeRepoAllow) ? policy.codeRepoAllow : [];
  if (!r || r.local) return !!(r && r.local);
  for (const raw of list.slice(0, 512)) {
    if (typeof raw !== "string" || raw.length > 512) continue;
    const e = raw.trim().toLowerCase().replace(/\/+$/, "");
    const m = e.match(/^(\*\.)?([a-z0-9.-]{1,253})((?:\/[^/\s]{1,200}){0,2})$/);
    if (!m) continue;
    const hostOk = m[1] ? r.host.endsWith(`.${m[2]}`) : r.host === m[2];
    if (!hostOk) continue;
    const want = m[3].replace(/^\//, "");
    if (!want || r.path === want || r.path.startsWith(`${want}/`)) return true;
  }
  return false;
}

// ---- T1030 / T1074.001: chunking and staging ----

// Sensitive locations a staging copy or archive collects: credential stores, private keys, keychains,
// browser profiles and their credential files, shell history, mail stores, and the home directory (or its
// Documents / Desktop) as a whole. Read on one path token, `\` read as `/`, case-blind.
const HOME = String.raw`(?:~|\$home|\$\{home\}|\$env:userprofile|%userprofile%|\/users\/[^/]+|\/home\/[^/]+|[a-z]:\/users\/[^/]+)`;
const SENSITIVE = [
  /(?:^|\/)\.(?:ssh|aws|gnupg|kube|docker|azure|password-store|thunderbird)(?:\/|$)/,
  /(?:^|\/)\.config\/(?:gcloud|gh|google-chrome|chromium|bravesoftware|microsoft-edge)(?:\/|$)/,
  /(?:^|\/)\.mozilla\/firefox(?:\/|$)/,
  /(?:^|\/)\.(?:netrc|git-credentials|npmrc|pypirc|pgpass|bash_history|zsh_history|sh_history)$/,
  /(?:^|\/)\.env(?:\.(?!example$|sample$|template$|dist$)[\w-]+)?$/,
  /(?:^|\/)id_(?:rsa|dsa|ecdsa|ed25519)(?:_sk)?$/,
  /\.(?:pem|p12|pfx|kdbx|keychain|keychain-db)$/,
  /(?:^|\/)library\/(?:keychains|cookies|mail|safari)(?:\/|$)/,
  /(?:^|\/)library\/application support\/(?:google\/chrome|bravesoftware|microsoft edge|firefox)(?:\/|$)/,
  /(?:^|\/)appdata\/(?:local|roaming)\/(?:google\/chrome|microsoft\/edge|mozilla\/firefox|bravesoftware)(?:\/|$)/,
  /(?:^|\/)(?:login data|cookies|logins\.json|key[34]\.db|consolehost_history\.txt)$/,
  /^\/etc\/shadow$/,
  new RegExp(`^${HOME}(?:\\/(?:documents|desktop))?\\/?$`)
];
export function sensitivePath(p) {
  const s = String(p || "").replace(/\\/g, "/").replace(/^["']|["']$/g, "").toLowerCase();
  if (!s || s.length > 4096 || /[\r\n]/.test(s)) return false;
  // A public key or a known-hosts file is not a secret, even inside ~/.ssh.
  if (/\.pub$|(?:^|\/)known_hosts(?:\.old)?$/.test(s)) return false;
  return SENSITIVE.some((r) => r.test(s));
}

const COPY = new Set(["cp", "gcp", "mv", "rsync", "ditto", "copy-item", "cpi", "copy", "move-item", "robocopy", "xcopy"]);
const COMPRESS = new Set(["gzip", "bzip2", "xz", "zstd", "pigz"]);
const operands = (rest) => rest.filter((t) => t && !/^-/.test(t));
// The source paths a copy names: every operand but the destination (the last, or none with -t).
function copySources(b, rest, ps) {
  if (ps || b === "copy-item" || b === "cpi" || b === "move-item") {
    const out = [];
    let pos = [];
    for (let i = 0; i < rest.length; i++) {
      const t = rest[i];
      if (/^-(?:path|literalpath|lp|pspath)$/i.test(t) && rest[i + 1] != null) { out.push(...rest[++i].split(",")); continue; }
      if (/^-(?:destination|dest)$/i.test(t)) { i++; continue; }
      if (/^-/.test(t)) continue;
      pos.push(t);
    }
    if (!out.length && pos.length) out.push(...pos[0].split(","));
    return out;
  }
  if (b === "robocopy") return operands(rest).slice(0, 1);
  const ops = operands(rest);
  if (rest.some((t) => t === "-t" || t.startsWith("--target-directory"))) return ops;
  return ops.slice(0, -1);
}

// { split, stage }: the command splits a file into chunks, and/or copies or archives a sensitive location.
export function stagingFacts(cmd, { ps = false } = {}) {
  const out = { split: false, stage: false };
  try {
    const s = String(cmd || "");
    for (const { b, rest, ps: sps } of segmentsOf(s, ps)) {
      // Chunking: split / gsplit, a split zip (-s, --split-size, zipsplit), a 7-Zip or RAR volume size (-v<size>),
      // a multi-volume tar, a dd window (skip= with count=).
      if (!sps && (b === "split" || b === "gsplit" || b === "zipsplit")) out.split = true;
      else if (b === "zip" && rest.some((t) => t === "-s" || /^--split-size(?:=|$)/.test(t))) out.split = true;
      else if ((b === "7z" || b === "7za" || b === "7zz" || b === "rar") && rest.some((t) => /^-v\d/.test(t))) out.split = true;
      else if ((b === "tar" || b === "gtar") && rest.some((t) => t === "-M" || t === "--multi-volume" || /^-[A-Za-z]*M[A-Za-z]*$/.test(t))) out.split = true;
      else if (b === "dd" && rest.some((t) => /^(?:skip|iseek)=/.test(t)) && rest.some((t) => /^count=/.test(t))) out.split = true;
      // Staging: what the segment collects.
      let sources = [];
      if (COPY.has(b)) sources = copySources(b, rest, sps);
      else if (b === "tar" || b === "gtar" || b === "bsdtar") {
        const first = rest[0] || "";
        const create = rest.some((t) => t === "-c" || t === "--create" || /^-[A-Za-z]*c[A-Za-z]*$/.test(t)) || /^[A-Za-z]*c[A-Za-z]*$/.test(first);
        if (create) sources = operands(rest);
      } else if (b === "zip" || b === "compress-archive") {
        sources = b === "zip" ? operands(rest).slice(1) : copySources("copy-item", rest, true);
      } else if (b === "7z" || b === "7za" || b === "7zz" || b === "rar") {
        if (rest[0] === "a" || rest[0] === "u") sources = operands(rest.slice(1)).slice(1);
      } else if (COMPRESS.has(b) && !rest.some((t) => t === "-d" || t === "--decompress" || /^-[A-Za-z]*d/.test(t))) sources = operands(rest);
      if (sources.some(sensitivePath)) out.stage = true;
    }
  } catch { return out; }
  return out;
}

