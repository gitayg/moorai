// Decoy AI API keys: fake keys in the places real ones live, so any use of one is evidence of theft.
//
// Frozen contract for v1.15.0 (the hook, the model proxy and the console build against these names):
//   Signed policy:  "decoyKeys": { "mode": "off" | "place" }            default "off" (placing files needs opt-in)
//   Alert:          reasonCode "DECOY_KEY_USED", category "Decoy AI key used", riskLevel "Critical",
//                   decoyId (opaque id, never the token), where ("hook:<stage>" | "model-proxy:<stage>")
//   Posture:        decoyKeys: { placed: <count>, source: "admin" | "agent" | "none" }
//
// The registry holds { id, kind, token } per decoy. Admin-placed decoys live in the machine dir
// (cli/machine-dir.mjs, root-owned); agent-placed ones in ~/.moorai. A token is a value that matches the
// provider's key shape but was never issued, so it authenticates nowhere.
//
// REGISTRIES (the only place a token is marked as a decoy; the token itself looks like any other key):
//   agent   ~/.moorai/decoys.json, mode 0600, written by syncDecoys():
//           { "v": 1, "decoys": [{ id, kind, token, path, sha256, createdDirs?, placedAt }] }
//   admin   <machine dir>/decoys.json (/etc/moorai/decoys.json, <ProgramData>\MoorAI\decoys.json), written by
//           the administrator and only ever READ here: { "decoys": [{ id, kind, token }] }. Admin decoys are
//           placed wherever the administrator chose; MoorAI never writes or removes them.
//
// TOKEN SHAPES: the gitleaks rules data/ai-key-shapes.js already relies on (config/gitleaks.toml rules
// openai-api-key, anthropic-api-key, gcp-api-key). The providers do not publish a key grammar; gitleaks
// is the public shape secret scanners (and key harvesters) match on, so a decoy is found by the same
// scans a real key is.
//   openai      sk-proj-<74 [A-Za-z0-9_-]>T3BlbkFJ<74 [A-Za-z0-9_-]>
//   anthropic   sk-ant-api03-<93 [A-Za-z0-9_-]>AA
//   google      AIza<35 [A-Za-z0-9_-]>
// A registry entry whose token does not have its kind's full shape is IGNORED: an empty or short "token"
// would otherwise match every string the hook sees.
//
// PLACEMENT (agent mode, signed policy decoyKeys.mode = "place"). Each decoy is a NEW file, created with
// O_EXCL so an existing file is never touched, in a place key harvesters sweep and no tool loads:
//   ~/.env.backup                    OPENAI_API_KEY=…      dotenv sweeps (every .env* under the home dir).
//                                    dotenv / python-dotenv load ".env"; dotenv-flow, Vite and Next.js load
//                                    ".env.<mode>" for their own modes, never "backup".
//   ~/.zshrc.bak (macOS)             export ANTHROPIC_API_KEY=…   shell-rc export harvesting. A shell
//   ~/.bashrc.bak (Linux, Windows)   sources .zshrc / .bashrc, never the .bak copy.
//   ~/.config/gemini/credentials.bak GEMINI_API_KEY = …    an AI-CLI-looking config dir. Gemini CLI's own
//                                    directory is ~/.gemini (it loads ~/.gemini/.env), which is NOT used.
// No file name says "decoy": an LLM-operated implant reads file names too.
// REMOVAL (mode back to "off"): each agent-placed file is deleted only while its bytes are still the ones
// MoorAI wrote (sha256 in the registry); a directory MoorAI created is removed only when empty. A file the
// user changed is left alone. Admin decoys are never removed.
import { randomBytes, createHash } from "node:crypto";
import { readFileSync, writeFileSync, mkdirSync, renameSync, unlinkSync, rmdirSync, readdirSync, existsSync } from "node:fs";
import { homedir } from "node:os";
import { join, dirname } from "node:path";
import { machineDir as defaultMachineDir } from "./machine-dir.mjs";

export const DECOY_REASON = "DECOY_KEY_USED";
export const DECOY_KINDS = Object.freeze(["openai", "anthropic", "google"]);
export const REGISTRY_FILE = "decoys.json";

const B = "[A-Za-z0-9_-]";
export const DECOY_SHAPES = Object.freeze({
  openai: new RegExp(`^sk-proj-${B}{74}T3BlbkFJ${B}{74}$`),
  anthropic: new RegExp(`^sk-ant-api03-${B}{93}AA$`),
  google: new RegExp(`^AIza${B}{35}$`)
});

const randChars = (n, rand) => rand(Math.ceil(n * 0.75) + 3).toString("base64url").slice(0, n);
// A fresh token of `kind`'s shape. `rand(n)` → n random bytes (crypto.randomBytes).
export function makeDecoyToken(kind, rand = randomBytes) {
  if (kind === "openai") return `sk-proj-${randChars(74, rand)}T3BlbkFJ${randChars(74, rand)}`;
  if (kind === "anthropic") return `sk-ant-api03-${randChars(93, rand)}AA`;
  if (kind === "google") return `AIza${randChars(35, rand)}`;
  throw new Error(`unknown decoy kind ${kind}`);
}
const validEntry = (d) => !!d && typeof d === "object" && DECOY_KINDS.includes(d.kind) && typeof d.token === "string" && DECOY_SHAPES[d.kind].test(d.token)
  && typeof d.id === "string" && /^[A-Za-z0-9_.:-]{1,64}$/.test(d.id);

function readRegistry(file) {
  try {
    const o = JSON.parse(readFileSync(file, "utf8"));
    return Array.isArray(o && o.decoys) ? o.decoys.filter(validEntry) : [];
  } catch { return []; }
}
const agentFile = (home) => join(home, ".moorai", REGISTRY_FILE);
const adminFile = (machineDir) => { try { return join(machineDir == null ? defaultMachineDir() : machineDir, REGISTRY_FILE); } catch { return null; } };

export function adminDecoys({ machineDir } = {}) { const f = adminFile(machineDir); return f ? readRegistry(f) : []; }
export function agentDecoys({ home = homedir() } = {}) { return readRegistry(agentFile(home)); }

// → [{ id, kind, token }]. Never throws.
export function decoyTokens({ home, machineDir } = {}) {
  try {
    const out = [], seen = new Set();
    for (const d of [...adminDecoys({ machineDir }), ...agentDecoys({ home: home || homedir() })]) {
      if (seen.has(d.token)) continue;
      seen.add(d.token);
      out.push({ id: d.id, kind: d.kind, token: d.token });
    }
    return out;
  } catch { return []; }
}

// → the matching decoy's id, or null. `text` may be any string; never throws.
export function matchDecoy(text, tokens) {
  try {
    if (typeof text !== "string" || !text || !Array.isArray(tokens)) return null;
    for (const t of tokens) {
      if (t && typeof t.token === "string" && DECOY_KINDS.includes(t.kind) && DECOY_SHAPES[t.kind].test(t.token) && text.includes(t.token)) return t.id;
    }
    return null;
  } catch { return null; }
}

// ---- placement ----
export function decoySites(platform = process.platform) {
  return [
    { kind: "openai", rel: [".env.backup"], render: (t) => `NODE_ENV=development\nOPENAI_API_KEY=${t}\n` },
    { kind: "anthropic", rel: [platform === "darwin" ? ".zshrc.bak" : ".bashrc.bak"], render: (t) => `export PATH="$HOME/.local/bin:$PATH"\nexport ANTHROPIC_API_KEY="${t}"\n` },
    { kind: "google", rel: [".config", "gemini", "credentials.bak"], render: (t) => `[default]\nGEMINI_API_KEY = ${t}\n` }
  ];
}
export const decoyMode = (policy) => (policy && policy.decoyKeys && typeof policy.decoyKeys === "object" && policy.decoyKeys.mode === "place" ? "place" : "off");

const sha = (s) => createHash("sha256").update(s).digest("hex");
function writeRegistry(home, decoys) {
  const f = agentFile(home);
  mkdirSync(dirname(f), { recursive: true, mode: 0o700 });
  const tmp = `${f}.${process.pid}.tmp`;
  writeFileSync(tmp, JSON.stringify({ v: 1, decoys }), { mode: 0o600 });
  renameSync(tmp, f);
}
function removeRegistry(home) { try { unlinkSync(agentFile(home)); } catch { /* absent */ } }
const readOr = (p) => { try { return readFileSync(p, "utf8"); } catch { return null; } };

// Bring the agent-placed decoys in line with the signed policy. → { mode, placed: [id], removed: [id], kept: [id], skipped: [rel] }
// `rand` and `now` are injectable for tests. Never throws; a failed write leaves that site unplaced.
export function syncDecoys({ policy = null, home = homedir(), platform = process.platform, rand = randomBytes, now = () => new Date().toISOString() } = {}) {
  const mode = decoyMode(policy);
  const res = { mode, placed: [], removed: [], kept: [], skipped: [] };
  try {
    const current = agentDecoys({ home });
    if (mode === "off") {
      if (!current.length && !existsSync(agentFile(home))) return res;
      for (const d of current) {
        if (typeof d.path !== "string" || !d.path.startsWith(home)) continue;
        const body = readOr(d.path);
        if (body != null && sha(body) === d.sha256) { try { unlinkSync(d.path); res.removed.push(d.id); } catch { /* left in place */ } }
        for (const dir of Array.isArray(d.createdDirs) ? d.createdDirs : []) {
          if (typeof dir !== "string" || !dir.startsWith(home) || dir === home) continue;
          try { if (!readdirSync(dir).length) rmdirSync(dir); } catch { /* not empty or gone */ }
        }
      }
      removeRegistry(home);
      return res;
    }
    const next = [];
    for (const site of decoySites(platform)) {
      const path = join(home, ...site.rel);
      const mine = current.find((d) => d.path === path);
      const body = readOr(path);
      if (mine && body != null && sha(body) === mine.sha256) { next.push(mine); res.kept.push(mine.id); continue; }
      if (body != null || existsSync(path)) { res.skipped.push(site.rel.join("/")); continue; } // someone else's file
      const token = makeDecoyToken(site.kind, rand);
      const text = site.render(token);
      const createdDirs = []; // deepest first, so removal empties them bottom-up
      try {
        for (let dir = dirname(path); dir.startsWith(home) && dir !== home && !existsSync(dir); dir = dirname(dir)) createdDirs.push(dir);
        if (createdDirs.length) mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
        writeFileSync(path, text, { mode: 0o600, flag: "wx" });
      } catch { res.skipped.push(site.rel.join("/")); continue; }
      const id = `dk_${rand(6).toString("hex")}`;
      next.push({ id, kind: site.kind, token, path, sha256: sha(text), ...(createdDirs.length ? { createdDirs } : {}), placedAt: now() });
      res.placed.push(id);
    }
    writeRegistry(home, next);
  } catch { /* the registry is best effort; a placed file without an entry is never removed */ }
  return res;
}

// Posture: { placed, source }. Admin decoys win the source label when both exist.
export function decoyPosture({ home = homedir(), machineDir } = {}) {
  const admin = adminDecoys({ machineDir }), agent = agentDecoys({ home });
  return { placed: admin.length + agent.length, source: admin.length ? "admin" : agent.length ? "agent" : "none" };
}
