#!/usr/bin/env node
// Gate for .github/workflows/guardd-install.yml: can a release moorai-guardd be installed and started on
// <platform> yet? Ready needs the install script AND no todo!()/unimplemented!() in the code compiled for
// that OS (its platform directory, plus shared code not cfg-gated to another OS), and on Windows a service
// control dispatcher in main.rs. Prints ready=<bool> and reason=<text>, appends ready=<bool> to
// $GITHUB_OUTPUT when set, and emits a ::notice:: when not ready. Exit 0 either way; 2 on bad usage.
//
//   node scripts/guardd-ci-ready.mjs <linux|macos|windows> [--root <checkout>]
import { existsSync, readFileSync, readdirSync, appendFileSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";

const PLATFORMS = { linux: "install.sh", macos: "install.sh", windows: "install.ps1" };
const STUB = /\b(?:todo|unimplemented)!\s*\(/;
const FN = /^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?(?:unsafe\s+)?fn\s/;

function rsFiles(dir) {
  if (!existsSync(dir)) return [];
  const out = [];
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, e.name);
    if (e.isDirectory()) out.push(...rsFiles(p));
    else if (e.name.endsWith(".rs")) out.push(p);
  }
  return out;
}

// Which OSes a cfg attribute admits; null = no OS restriction found.
function cfgTargets(attr) {
  const t = new Set();
  if (/\bwindows\b|target_os\s*=\s*"windows"/.test(attr)) t.add("windows");
  if (/\bunix\b/.test(attr)) { t.add("linux"); t.add("macos"); }
  if (/target_os\s*=\s*"linux"/.test(attr)) t.add("linux");
  if (/target_os\s*=\s*"macos"/.test(attr)) t.add("macos");
  if (!t.size) return null;
  return /not\s*\(/.test(attr) ? new Set(Object.keys(PLATFORMS).filter((p) => !t.has(p))) : t;
}

// The cfg on the function enclosing line i (the attribute lines directly above its `fn`), or null.
function enclosingCfg(lines, i) {
  let f = i;
  while (f >= 0 && !FN.test(lines[f])) f--;
  if (f < 0) return null;
  for (let a = f - 1; a >= 0 && /^\s*#\[/.test(lines[a]); a--) {
    if (/^\s*#\[cfg\(/.test(lines[a])) return cfgTargets(lines[a]);
  }
  return null;
}

function stubsFor(root, platform) {
  const src = join(root, "guardd", "src");
  const others = Object.keys(PLATFORMS).filter((p) => p !== platform).map((p) => join(src, "platform", p) + sep);
  const bin = join(src, "bin") + sep;
  const hits = [];
  for (const f of rsFiles(src)) {
    if (f.startsWith(bin) || others.some((o) => f.startsWith(o))) continue;
    const lines = readFileSync(f, "utf8").split("\n");
    lines.forEach((l, i) => {
      if (!STUB.test(l) || /^\s*\/\//.test(l)) return;
      const t = enclosingCfg(lines, i);
      if (t && !t.has(platform)) return;
      hits.push(`${relative(root, f).split(sep).join("/")}:${i + 1}`);
    });
  }
  // The platform layer first: it is the main thing missing before the helper can start.
  const mine = `guardd/src/platform/${platform}/`;
  return [...hits.filter((h) => h.startsWith(mine)), ...hits.filter((h) => !h.startsWith(mine))];
}

function readiness(root, platform) {
  const script = `guardd/packaging/${platform}/${PLATFORMS[platform]}`;
  if (!existsSync(join(root, script))) return { ready: false, reason: `${script} does not exist yet` };
  const hits = stubsFor(root, platform);
  if (hits.length) {
    return { ready: false, reason: `the ${platform} helper cannot start yet: ${hits.length} todo!()/unimplemented!() left in code compiled for ${platform}, first at ${hits[0]}` };
  }
  if (platform === "windows") {
    const main = join(root, "guardd", "src", "main.rs");
    const t = existsSync(main) ? readFileSync(main, "utf8") : "";
    if (!/service_dispatcher|StartServiceCtrlDispatcher/.test(t)) {
      return { ready: false, reason: "guardd/src/main.rs has no Windows service control dispatcher, so the SCM cannot start MoorAIGuard" };
    }
  }
  return { ready: true, reason: `${script} exists and the ${platform} helper has no stubs left` };
}

function main(argv) {
  const [platform, ...rest] = argv;
  if (!Object.hasOwn(PLATFORMS, platform ?? "")) {
    process.stderr.write("usage: guardd-ci-ready.mjs <linux|macos|windows> [--root <checkout>]\n");
    return 2;
  }
  let root = fileURLToPath(new URL("..", import.meta.url));
  for (let i = 0; i < rest.length; i++) {
    if (rest[i] === "--root" && rest[i + 1]) root = rest[++i];
    else { process.stderr.write(`guardd-ci-ready: unknown option ${rest[i]}\n`); return 2; }
  }
  const r = readiness(root, platform);
  process.stdout.write(`ready=${r.ready}\nreason=${r.reason}\n`);
  if (!r.ready) process.stdout.write(`::notice title=guardd-install skipped::${r.reason}; the install and agent-side test steps are skipped.\n`);
  if (process.env.GITHUB_OUTPUT) appendFileSync(process.env.GITHUB_OUTPUT, `ready=${r.ready}\n`);
  return 0;
}

process.exitCode = main(process.argv.slice(2));
