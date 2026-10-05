// The moorai-server container image (docker/server/Dockerfile): the COPY set must carry every file the two
// entrypoints import, and nothing outside what `npm pack` ships. A static check, so it runs without Docker:
// both import closures are walked from cli/moorai-serve.mjs and mcp-gateway/moorai-mcp-gateway.mjs
// (including the engine modules packages/agent-sdk/src/core.mjs loads by computed path), and each file
// must sit under a COPY source that the build context's ignore-file lets through.
//
//   node --test --import ./test/hermetic-env.mjs test/server-image.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, existsSync } from "node:fs";
import { join, dirname, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const DOCKERFILE = join(ROOT, "docker", "server", "Dockerfile");
const IGNORE = join(ROOT, "docker", "server", "Dockerfile.dockerignore");
const WORKFLOW = join(ROOT, ".github", "workflows", "publish-server-image.yml");
const ENTRYPOINTS = ["cli/moorai-serve.mjs", "mcp-gateway/moorai-mcp-gateway.mjs"];
const PKG = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8"));
const rel = (p) => relative(ROOT, p).split(sep).join("/");

// Static `import … from "x"`, `export … from "x"`, side-effect `import "x"` and `import("x")` with a
// literal; plus core.mjs's `load("cli/…")`, which resolves against the engine root (the repo root).
const IMPORT_RE = /(?:import\s[^'"]*?from\s*|export\s[^'"]*?from\s*|import\s*\(\s*|^\s*import\s*)["']([^"']+)["']/gm;
const LOAD_RE = /\bload\(\s*["']([^"']+)["']\s*\)/g;
function closure(entries) {
  const files = new Set(), bare = [], missing = [];
  const walk = (abs) => {
    if (files.has(abs)) return;
    files.add(abs);
    const src = readFileSync(abs, "utf8");
    for (const m of src.matchAll(IMPORT_RE)) {
      const spec = m[1];
      if (spec.startsWith("node:")) continue;
      if (!spec.startsWith(".")) { bare.push(`${spec} <- ${rel(abs)}`); continue; }
      const target = resolve(dirname(abs), spec);
      if (!existsSync(target)) { missing.push(`${spec} <- ${rel(abs)}`); continue; }
      walk(target);
    }
    if (rel(abs) === "packages/agent-sdk/src/core.mjs") for (const m of src.matchAll(LOAD_RE)) walk(join(ROOT, m[1]));
  };
  for (const e of entries) walk(join(ROOT, e));
  return { files: [...files].map(rel).sort(), bare, missing };
}

// COPY sources, in the build context (repo root), as written. Flags (--chmod=…) skipped; --from never used.
function copySources(text) {
  const out = [];
  for (const line of text.split("\n")) {
    const m = /^\s*COPY\s+(.*)$/.exec(line);
    if (!m) continue;
    const args = m[1].trim().split(/\s+/).filter((a) => !a.startsWith("--"));
    assert.ok(!/--from/.test(m[1]), "the image is single-stage: no COPY --from");
    out.push(...args.slice(0, -1));
  }
  return out;
}
const norm = (s) => s.replace(/\/+$/, "");
const covers = (src, file) => { const s = norm(src); return file === s || file.startsWith(`${s}/`); };

const DF = readFileSync(DOCKERFILE, "utf8");
const SOURCES = copySources(DF);
const IMAGE_ONLY = ["docker/server/entrypoint.sh", "docker/server/healthcheck.mjs"];

test("IMAGE: both entrypoints' import closure is covered by a COPY line", () => {
  const { files, bare, missing } = closure(ENTRYPOINTS);
  assert.deepEqual(missing, [], "an import that does not resolve in the repo");
  assert.ok(files.length > 50, `closure walk found only ${files.length} files — the walker is broken, not the image`);
  for (const e of [...ENTRYPOINTS, "packages/agent-sdk/src/runtime.mjs", "cli/hook-core.mjs", "data/capture-tiers.js", "mcp-proxy/tool-scan.mjs"]) assert.ok(files.includes(e), `closure lacks ${e}`);
  const uncovered = files.filter((f) => !SOURCES.some((s) => covers(s, f)));
  assert.deepEqual(uncovered, [], "imported at runtime but not copied into the image");
  assert.deepEqual(bare, [], "an npm package import: the image has no node_modules (no npm install step)");
});

test("IMAGE: the COPY set is exactly package.json \"files\" + package.json + LICENSE (what npm pack ships)", () => {
  const shipped = new Set([...PKG.files.map(norm), "package.json", "LICENSE"]);
  const copied = new Set(SOURCES.filter((s) => !IMAGE_ONLY.includes(s)).map(norm));
  assert.deepEqual([...shipped].filter((f) => !copied.has(f)).sort(), [], "in package.json files but not in the image");
  assert.deepEqual([...copied].filter((f) => !shipped.has(f)).sort(), [], "copied into the image but not shipped by npm pack");
  for (const f of IMAGE_ONLY) assert.ok(SOURCES.includes(f), `${f} is not copied`);
  for (const s of SOURCES) assert.ok(existsSync(join(ROOT, s)), `COPY source ${s} does not exist`);
});

test("IMAGE: the build context ignore-file lets every COPY source through and drops secrets", () => {
  const lines = readFileSync(IGNORE, "utf8").split("\n").map((l) => l.trim()).filter((l) => l && !l.startsWith("#"));
  assert.equal(lines[0], "*", "allow-list: everything excluded first");
  const allowed = lines.filter((l) => l.startsWith("!")).map((l) => norm(l.slice(1)));
  for (const s of SOURCES) assert.ok(allowed.includes(norm(s)), `COPY ${s} would be excluded from the build context`);
  for (const p of ["**/.env", "**/*.local", "**/.session-secret"]) assert.ok(lines.includes(p), `ignore-file lacks ${p}`);
});

test("IMAGE: base image matches CI's node, runs as non-root, labelled MIT, health-checked on loopback", () => {
  const ci = readFileSync(join(ROOT, ".github", "workflows", "ci.yml"), "utf8");
  const ciNode = /node-version:\s*(\d+)/.exec(ci)[1];
  const from = /^FROM\s+(\S+)/m.exec(DF)[1];
  assert.match(from, new RegExp(`^node:${ciNode}-slim$`), `FROM ${from} vs CI node ${ciNode}`);
  const users = [...DF.matchAll(/^USER\s+(\S+)/gm)].map((m) => m[1]);
  assert.ok(users.length && !["root", "0", "0:0"].includes(users.at(-1)), `final USER is ${users.at(-1)}`);
  assert.ok(DF.indexOf("USER node") < DF.indexOf("ENTRYPOINT"), "USER must precede the entrypoint");
  assert.match(DF, new RegExp(`org\\.opencontainers\\.image\\.licenses="${PKG.license}"`));
  assert.match(readFileSync(join(ROOT, "LICENSE"), "utf8"), /^MIT License/);
  assert.match(DF, /^HEALTHCHECK .*\n?.*healthcheck\.mjs/m);
  assert.match(readFileSync(join(ROOT, "docker/server/healthcheck.mjs"), "utf8"), /http:\/\/127\.0\.0\.1:/);
  assert.match(DF, /^CMD \["moorai-serve"\]$/m);
});

test("IMAGE: the publish workflow gates on the tag, builds both arches, and checks the image for secrets", () => {
  const wf = readFileSync(WORKFLOW, "utf8");
  assert.match(wf, /tags:\s*\["v\*"\]/);
  assert.match(wf, /workflow_dispatch/);
  assert.match(wf, /\[ "v\$v" = "\$\{GITHUB_REF_NAME\}" \]/, "tag must equal package.json version");
  assert.match(wf, /platforms:\s*linux\/amd64,linux\/arm64/);
  assert.match(wf, /file:\s*docker\/server\/Dockerfile/);
  assert.match(wf, /images:\s*ghcr\.io\/gitayg\/moorai-server/);
  assert.match(wf, /org\.opencontainers\.image\.licenses=MIT/);
  assert.match(wf, /cache-from:\s*type=gha/);
  assert.match(wf, /password:\s*\$\{\{\s*secrets\.GITHUB_TOKEN\s*\}\}/);
  assert.match(wf, /secret file found in image/);
});
