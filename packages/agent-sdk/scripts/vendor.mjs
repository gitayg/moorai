#!/usr/bin/env node
// Copy the MoorAI engine this package runs into packages/agent-sdk/moorai/, preserving the repository's
// relative layout so every `../data/…` import inside it still resolves. Run by `npm pack` (prepack); the
// in-repo package uses the live tree instead (src/core.mjs).
//
// The set is computed, not listed: start from the modules src/core.mjs loads and follow every relative
// static `import … from` / `export … from`. JSON the engine reads at runtime by path (data/threats.json)
// is added explicitly — it is the one non-import read in the closure. Every copied file is
// dependency-free; a bare-specifier import ("node:…" aside) fails the run rather than ship a broken copy.
//
//   node packages/agent-sdk/scripts/vendor.mjs [--out <dir>]
//   node packages/agent-sdk/scripts/vendor.mjs --clean        (postpack: remove packages/agent-sdk/moorai)
import { readFileSync, mkdirSync, copyFileSync, rmSync, existsSync } from "node:fs";
import { dirname, join, resolve, relative } from "node:path";
import { fileURLToPath } from "node:url";

const PKG = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const REPO = resolve(PKG, "..", "..");
const ENTRIES = ["cli/hook-core.mjs", "cli/server-mode.mjs", "cli/mcp-file-args.mjs", "cli/secret-egress.mjs", "cli/content-hash.mjs", "cli/provenance.mjs", "data/capture-tiers.js", "data/model-endpoints.js", "data/outbound-upload.js", "data/offline-default.js"];
const RUNTIME_READS = ["data/threats.json", "LICENSE"];
const IMPORT_RE = /(?:^|[\s;])(?:import|export)\s[^'"`]*?from\s*["']([^"']+)["']|(?:^|[\s;])import\s*["']([^"']+)["']/gm;

export function closure(repo = REPO) {
  const seen = new Set(), queue = [...ENTRIES];
  while (queue.length) {
    const rel = queue.shift();
    if (seen.has(rel)) continue;
    const abs = join(repo, rel);
    if (!existsSync(abs)) throw new Error(`missing ${rel}`);
    seen.add(rel);
    const src = readFileSync(abs, "utf8");
    for (const m of src.matchAll(IMPORT_RE)) {
      const spec = m[1] || m[2];
      if (spec.startsWith("node:")) continue;
      if (!spec.startsWith(".")) throw new Error(`${rel} imports a package (${spec}); the vendored engine must stay dependency-free`);
      queue.push(relative(repo, resolve(dirname(abs), spec)));
    }
  }
  return [...seen, ...RUNTIME_READS].sort();
}

function main() {
  const i = process.argv.indexOf("--out");
  const out = i > 0 ? resolve(process.argv[i + 1]) : join(PKG, "moorai");
  if (process.argv.includes("--clean")) { rmSync(join(PKG, "moorai"), { recursive: true, force: true }); return; }
  const files = closure();
  rmSync(out, { recursive: true, force: true });
  for (const rel of files) {
    mkdirSync(dirname(join(out, rel)), { recursive: true });
    copyFileSync(join(REPO, rel), join(out, rel));
  }
  process.stdout.write(`vendored ${files.length} files into ${out}\n`);
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
