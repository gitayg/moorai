// Win32-style path canonicalization for the containment write guard (cli/containment-guard.mjs). Pure: strings
// in, strings out, no filesystem, so two spellings of one file give one canonical form on any host OS.
//
//   environment  %NAME% (so %HOMEDRIVE%%HOMEPATH%), $env:NAME and ${env:NAME} in any case, ${NAME}, $NAME, and
//                ~ at the start, from the env passed in; $HOME / ~ are USERPROFILE. An unknown or empty
//                variable makes the path unresolvable (""), unless folding drops it (a stream suffix, a ..).
//   separators   / and \ alike; repeated separators collapse.
//   namespaces   \\?\C:\, \\.\C:\ and \??\C:\ become C:\; \\?\UNC\server\share (and \\.\UNC\) becomes
//                \\server\share; an admin share \\host\c$\ becomes C:\ (any host: a name, an address, localhost
//                all reach the local disk); \\?\Volume{guid}\ and \\?\GLOBALROOT\Device\HarddiskVolumeN\ become
//                the wildcard root *:\, which matches every drive. Any other device path is unresolvable.
//   roots        C:\x absolute; \x rooted on cwd's drive; C:x relative to cwd when cwd is on C:, else
//                unresolvable; anything else joins cwd. An MSYS /c/... (/cygdrive/c, /mnt/c) is C:\....
//   segments     . and .. fold (.. never climbs past the root); an NTFS stream suffix (name::$DATA, name:s,
//                dir:$I30:$INDEX_ALLOCATION) is dropped from every segment; trailing dots and spaces are
//                dropped from every segment (.bashrc. / .bashrc  / .bashrc. . are .bashrc). Win32 strips a
//                trailing run only from the last segment and skips all of this under \\?\; doing it
//                everywhere can only make more spellings meet, never fewer.
//   case         compared upper-cased; case is kept in the returned string.
//   8.3 names    MOORAI~1, BASHRC~1, BASH~1.BAS: an 8.3-shaped segment whose base ends in ~digits is matched
//                against ANY segment at the same position (canonUnder), on either side, because which long name
//                it stands for is on disk, not in the string.
function envGet(env, name) {
  const k = Object.keys(env || {}).find((x) => x.toLowerCase() === name.toLowerCase());
  return k ? String(env[k] ?? "") : "";
}

const VAR = /\$\{env:([^}]+)\}|\$env:([A-Za-z0-9_]+)|\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)|%([^%\\/:*?"<>|]+)%/gi;
const DEVICE = String.raw`^(?:\\\\[?.]|\\\?\?)\\`;
const DEV_UNC = new RegExp(`${DEVICE}UNC\\\\`, "i");
const DEV_DRIVE = new RegExp(`${DEVICE}([A-Za-z]:)(?=\\\\|$)`, "i");
const DEV_VOLUME = new RegExp(`${DEVICE}(?:Volume\\{[0-9A-Fa-f-]+\\}|GLOBALROOT\\\\Device\\\\HarddiskVolume\\d+|HarddiskVolume\\d+)(?=\\\\|$)`, "i");
const DEV_ANY = new RegExp(DEVICE);

// An unknown or empty variable becomes UNKNOWN; a path still holding one after folding is unresolvable, so one
// inside a dropped stream suffix (.bashrc::$DATA) or a segment .. removes does not hide the path.
const UNKNOWN = "\u0000";
function expandVars(s, env) {
  const home = winCanon(envGet(env, "USERPROFILE"), { literal: true });
  const out = s.replace(VAR, (...m) => {
    const name = m[1] || m[2] || m[3] || m[4] || m[5];
    return (name.toUpperCase() === "HOME" ? home : envGet(env, name)) || UNKNOWN;
  });
  if (/^~(?=$|[\\/])/.test(out)) return home ? home + out.slice(1) : "";
  return out;
}

// { root, segs } of a canonical-form prefix: "C:" / "*:" / "\\server\share", then the rest split.
function rootOf(s) {
  let m = /^([A-Za-z*]):\\/.exec(s);
  if (m) return { root: `${m[1]}:`, rest: s.slice(3) };
  m = /^\\\\([^\\]+)\\([^\\]+)/.exec(s);
  if (m) {
    const share = /^([A-Za-z])\$$/.exec(m[2]);
    return share ? { root: `${share[1]}:`, rest: s.slice(m[0].length) } : { root: `\\\\${m[1]}\\${m[2]}`, rest: s.slice(m[0].length) };
  }
  return null;
}

function fold(segs, rest) {
  for (const raw of rest.split("\\")) {
    if (raw === "" || raw === ".") continue;
    if (raw === "..") { segs.pop(); continue; }
    const name = raw.replace(/:.*$/s, "").replace(/[. ]+$/, "");
    if (name) segs.push(name);
  }
  return segs;
}

const join = (root, segs) => (/:$/.test(root) ? `${root}\\${segs.join("\\")}` : [root, ...segs].join("\\"));

// The canonical absolute form of p, or "" when it cannot be made absolute without the filesystem.
// literal: no variable or ~ expansion (the string as a file API would take it).
export function winCanon(p, { env = {}, cwd = "", literal = false } = {}) {
  let s = String(p ?? "").trim().replace(/["']/g, "");
  if (!s || s.length > 4096) return "";
  if (!literal) { s = expandVars(s, env); if (!s) return ""; }
  const msys = /^\/(?:(?:cygdrive|mnt)\/)?([A-Za-z])(?=$|\/)/.exec(s);
  if (msys) s = `${msys[1]}:\\${s.slice(msys[0].length)}`;
  s = s.replace(/\//g, "\\");
  if (DEV_UNC.test(s)) s = "\\\\" + s.replace(DEV_UNC, "");
  else if (DEV_DRIVE.test(s)) s = s.replace(DEV_DRIVE, (_, d) => `${d}\\`);
  else if (DEV_VOLUME.test(s)) s = "*:\\" + s.replace(DEV_VOLUME, "");
  else if (DEV_ANY.test(s)) return "";
  let r = rootOf(s);
  if (!r) {
    const base = cwd ? rootOf(winCanon(cwd, { literal: true })) : null;
    if (!base) return "";
    const drel = /^([A-Za-z]):(?!\\)/.exec(s);
    if (drel) {
      if (base.root.toUpperCase() !== `${drel[1]}:`.toUpperCase()) return "";
      r = { root: base.root, rest: `${base.rest}\\${s.slice(2)}` };
    } else if (s.startsWith("\\")) r = { root: base.root, rest: s };
    else r = { root: base.root, rest: `${base.rest}\\${s}` };
  }
  const out = join(r.root, fold([], r.rest));
  return out.includes(UNKNOWN) ? "" : out;
}

// An 8.3 short name: base of at most 8 characters ending in ~digits, extension of at most 3.
export function isShortName(seg) {
  const m = /^([^.\\]{1,8})(?:\.([^.\\]{1,3}))?$/.exec(String(seg ?? ""));
  return !!m && /~\d+$/.test(m[1]);
}

const up = (x) => x.toUpperCase();
function partsOf(c) {
  const r = rootOf(c);
  return r ? { root: up(r.root), segs: r.rest.split("\\").filter(Boolean) } : null;
}
const rootEq = (a, b) => a === b || (/^[A-Z*]:$/.test(a) && /^[A-Z*]:$/.test(b) && (a === "*:" || b === "*:"));
const segEq = (a, b) => up(a) === up(b) || isShortName(a) || isShortName(b);

// child (canonical) equals parent (canonical) or lies beneath it.
export function canonUnder(child, parent) {
  const c = partsOf(String(child ?? "")), p = partsOf(String(parent ?? ""));
  if (!c || !p || !rootEq(c.root, p.root) || c.segs.length < p.segs.length) return false;
  return p.segs.every((s, i) => segEq(c.segs[i], s));
}

// One segment as Win32 names it: stream and trailing dots/spaces dropped ("" for none).
export function canonSegment(seg) {
  return String(seg ?? "").replace(/["']/g, "").replace(/:.*$/s, "").replace(/[. ]+$/, "");
}
