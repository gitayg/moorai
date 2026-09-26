// AI-provider API keys AT REST — a collector for the AIBOM (cli/moorai-aibom.mjs).
//
// Looks for AI-provider keys (shapes in data/ai-key-shapes.js) in a SMALL, FIXED set of places — it
// never walks the disk:
//
//   shell-rc       ~/.zshrc ~/.zshenv ~/.bashrc ~/.bash_profile ~/.profile ~/.config/fish/config.fish
//   ai-cli-config  files (depth <= 2, <= 25 per dir) under the config dirs of known AI CLIs — see
//                  AI_CLI_DIRS below
//   dotenv         .env / .env.<name> (never .env.example|sample|template|dist) at the top level of
//                  ~ and of each immediate child dir of a few dev roots (~/code, ~/src, ~/dev,
//                  ~/projects, ~/Projects, ~/workspace, ~/repos, ~/git, ~/Developer) — <= 200 child
//                  dirs per root, <= 300 dotenv files in total
//
// Every file: skipped when > 1 MB or when its first 8 KB contain a NUL byte (binary); unreadable →
// skipped (fail-open). Symlinked DIRECTORIES are not followed; the fixed shell-rc paths are read
// through a symlink (dotfiles repos commonly symlink them).
//
// Output per finding is exactly { provider, locationClass, location, keyHash }:
//   * location is a path ONLY when it is a fixed, well-known one (~/.zshrc, ~/.env, ~/.config/aichat);
//     a key in a project's .env reports location null — the project path is not disclosed.
//   * keyHash is contentHash(key): the agent's KEYED, per-tenant HMAC (cli/content-hash.mjs), the same
//     fingerprint an alert carries when that key is seen in a prompt, so the console can match an
//     org-issued key without ever holding it here. Unenrolled → the constant NO_KEY sentinel.
// The key value, any part of it, and the file contents never leave this function.
import { readFileSync, readdirSync, statSync, openSync, readSync, closeSync, realpathSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { findAiKeys } from "../data/ai-key-shapes.js";
import { contentHash } from "./content-hash.mjs";

export const MAX_FILE_BYTES = 1024 * 1024;
const MAX_CLI_FILES_PER_DIR = 25;
const MAX_DEV_CHILDREN = 200;
const MAX_DOTENV_FILES = 300;

export const SHELL_RC = [".zshrc", ".zshenv", ".bashrc", ".bash_profile", ".profile", ".config/fish/config.fish"];
// [relative dir, tool]. Places to LOOK; a dir that does not exist costs one failed readdir.
export const AI_CLI_DIRS = [
  [".config/aichat", "aichat"],
  [".config/shell_gpt", "shell_gpt"],
  [".config/io.datasette.llm", "llm"],
  ["Library/Application Support/io.datasette.llm", "llm"],
  [".config/fabric", "fabric"],
  [".config/mods", "mods"],
  [".gemini", "gemini"]
];
export const DEV_ROOTS = ["code", "src", "dev", "projects", "Projects", "workspace", "repos", "git", "Developer"];
const DOTENV_NAME = /^\.env(?:\.[A-Za-z0-9_-]+)?$/;
const DOTENV_TEMPLATE = /example|sample|template|dist/i;

const listDir = (p) => { try { return readdirSync(p, { withFileTypes: true }); } catch { return []; } };

// Bounded, binary-safe read. null = skipped (missing, unreadable, too big, not a file, binary).
function readSmallText(p) {
  let st;
  try { st = statSync(p); } catch { return null; }
  if (!st.isFile() || st.size > MAX_FILE_BYTES) return null;
  try {
    const fd = openSync(p, "r");
    try {
      const head = Buffer.alloc(Math.min(8192, st.size));
      readSync(fd, head, 0, head.length, 0);
      if (head.includes(0)) return null;
    } finally { closeSync(fd); }
    return readFileSync(p, "utf8");
  } catch { return null; }
}

export function scanKeysAtRest({ home = homedir(), hash = contentHash } = {}) {
  const findings = [], seen = new Set();
  let filesRead = 0, filesSkipped = 0;
  const scan = (path, locationClass, location, aiContext = false) => {
    const text = readSmallText(path);
    if (text == null) { filesSkipped++; return; }
    filesRead++;
    for (const { provider, value } of findAiKeys(text, { aiContext })) {
      const keyHash = hash(value);
      const k = `${provider}|${locationClass}|${location}|${keyHash}`;
      if (seen.has(k)) continue;
      seen.add(k);
      findings.push({ provider, locationClass, location, keyHash });
    }
  };

  for (const rel of SHELL_RC) {
    const p = join(home, rel);
    try { statSync(p); } catch { continue; } // absent is not "skipped"
    scan(p, "shell-rc", `~/${rel}`);
  }

  for (const [rel, _tool] of AI_CLI_DIRS) {
    const dir = join(home, rel);
    let n = 0;
    const walk = (d, depth) => {
      for (const e of listDir(d)) {
        if (n >= MAX_CLI_FILES_PER_DIR) return;
        if (e.isFile()) { n++; scan(join(d, e.name), "ai-cli-config", `~/${rel}`, true); }
        else if (e.isDirectory() && depth < 2) walk(join(d, e.name), depth + 1);
      }
    };
    walk(dir, 1);
  }

  let dotenvs = 0;
  const scanDotenvsIn = (dir, fixedPrefix) => {
    for (const e of listDir(dir)) {
      if (dotenvs >= MAX_DOTENV_FILES) return;
      if (!e.isFile() || !DOTENV_NAME.test(e.name) || DOTENV_TEMPLATE.test(e.name)) continue;
      dotenvs++;
      scan(join(dir, e.name), "dotenv", fixedPrefix ? `${fixedPrefix}${e.name}` : null);
    }
  };
  scanDotenvsIn(home, "~/");
  const roots = new Set(); // ~/projects and ~/Projects are ONE dir on a case-insensitive volume
  for (const root of DEV_ROOTS) {
    const rootDir = join(home, root);
    let real;
    try { real = realpathSync(rootDir); } catch { continue; }
    if (roots.has(real)) continue;
    roots.add(real);
    scanDotenvsIn(rootDir, null);
    let children = 0;
    for (const e of listDir(rootDir)) {
      if (!e.isDirectory() || e.name.startsWith(".")) continue;
      if (++children > MAX_DEV_CHILDREN || dotenvs >= MAX_DOTENV_FILES) break;
      scanDotenvsIn(join(rootDir, e.name), null);
    }
  }

  return { findings, filesRead, filesSkipped };
}
