#!/usr/bin/env node
// Build the Linux packages of the MoorAI agent:
//
//   node scripts/build-linux-package.mjs [--out dist/linux] [--guardd <moorai-guardd ELF> --guardd-arch amd64|arm64]
//
// Produces, in --out:
//   moorai_<version>_all.deb          the agent (CLI, hooks, engine), systemd user units, hook installer
//   moorai-<version>-linux.tar.gz     the same tree with install.sh / uninstall.sh, for non-dpkg systems
//   moorai.spec                       an rpmbuild spec that packages the tarball (not built here)
//   moorai-guardd_<v>_<arch>.deb      only with --guardd: the privileged helper and its systemd units
//
// Pure Node (no dpkg-deb, no fakeroot): the ar and tar streams are written by scripts/linux-pkg/, every
// entry root:root, every timestamp SOURCE_DATE_EPOCH (else the last commit's time), so a rebuild of the
// same commit gives the same bytes. The version comes from package.json (guardd: guardd/Cargo.toml).
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { gzipSync } from "node:zlib";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { tarball } from "./linux-pkg/tar.mjs";
import { buildDeb, controlText, installedSizeKiB } from "./linux-pkg/deb.mjs";
import { agentEntries, agentTree, guarddTree, withDirs } from "./linux-pkg/tree.mjs";

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const MAINTAINER = "MoorAI <noreply@moorai.dev>";
const HOMEPAGE = "https://github.com/gitayg/moorai";
const GUARDD_ARCHES = new Set(["amd64", "arm64"]);

function epoch(given) {
  if (Number.isInteger(given) && given >= 0) return given;
  const env = Number(process.env.SOURCE_DATE_EPOCH);
  if (Number.isInteger(env) && env >= 0) return env;
  try { return Number(execFileSync("git", ["-C", REPO, "log", "-1", "--format=%ct"], { encoding: "utf8" }).trim()) || 0; } catch { return 0; }
}

function guarddVersion() {
  const toml = readFileSync(join(REPO, "guardd", "Cargo.toml"), "utf8");
  const m = /\[package\][^[]*?\nversion\s*=\s*"([^"]+)"/.exec(toml);
  if (!m) throw new Error("no [package] version in guardd/Cargo.toml");
  return m[1];
}

const read = (...p) => readFileSync(join(REPO, ...p));

export async function buildLinuxPackages({ outDir = join(REPO, "dist", "linux"), sourceDateEpoch, guarddBinary, guarddArch } = {}) {
  const mtime = epoch(sourceDateEpoch);
  const version = JSON.parse(read("package.json").toString("utf8")).version;
  mkdirSync(outDir, { recursive: true });
  const result = {};

  // The guardd package is checked first, so a refused binary writes nothing.
  let guarddEntries = null;
  if (guarddBinary) {
    if (!GUARDD_ARCHES.has(guarddArch)) throw new Error(`--guardd-arch must be one of ${[...GUARDD_ARCHES].join(", ")}`);
    guarddEntries = guarddTree(REPO, resolve(guarddBinary));
  }

  const data = agentTree(REPO);
  const control = controlText({
    Package: "moorai",
    Version: version,
    Architecture: "all",
    Maintainer: MAINTAINER,
    "Installed-Size": installedSizeKiB(data),
    Recommends: "nodejs (>= 18)",
    Section: "admin",
    Priority: "optional",
    Homepage: HOMEPAGE
  }, [
    "MoorAI agent: runtime guardrails for AI coding agents",
    "The moorai-* command-line tools, the hooks for AI coding agents and the",
    "detection engine, with systemd user units to register the hooks at login",
    "and to run the engine sidecar. Reports are content-free."
  ]);
  result.deb = join(outDir, `moorai_${version}_all.deb`);
  writeFileSync(result.deb, buildDeb({ control, scripts: { postinst: read("packaging/linux/deb/postinst"), prerm: read("packaging/linux/deb/prerm") }, dataEntries: data, mtime }));

  const top = `moorai-${version}`;
  const tgzEntries = withDirs([
    ...agentEntries(REPO, `${top}/root/`),
    { path: `${top}/install.sh`, type: "file", mode: 0o755, data: read("packaging/linux/tarball/install.sh") },
    { path: `${top}/uninstall.sh`, type: "file", mode: 0o755, data: read("packaging/linux/tarball/uninstall.sh") }
  ], null);
  result.tarball = join(outDir, `${top}-linux.tar.gz`);
  writeFileSync(result.tarball, gzipSync(tarball(tgzEntries, mtime), { level: 9 }));

  result.rpmSpec = join(outDir, "moorai.spec");
  writeFileSync(result.rpmSpec, read("packaging/linux/moorai.spec.in").toString("utf8").replaceAll("@VERSION@", version));

  if (guarddEntries) {
    const gv = guarddVersion();
    const gctl = controlText({
      Package: "moorai-guardd",
      Version: gv,
      Architecture: guarddArch,
      Maintainer: MAINTAINER,
      "Installed-Size": installedSizeKiB(guarddEntries),
      Section: "admin",
      Priority: "optional",
      Homepage: HOMEPAGE
    }, [
      "MoorAI privileged helper (moorai-guardd)",
      "A root systemd service that holds the device key, the policy cache, the",
      "alert queue and the alert chain outside the user's reach, and serves the",
      "MoorAI hook over /run/moorai/hook.sock."
    ]);
    result.guarddDeb = join(outDir, `moorai-guardd_${gv}_${guarddArch}.deb`);
    writeFileSync(result.guarddDeb, buildDeb({
      control: gctl,
      scripts: { postinst: read("packaging/linux/guardd-deb/postinst"), prerm: read("packaging/linux/guardd-deb/prerm"), postrm: read("packaging/linux/guardd-deb/postrm") },
      dataEntries: guarddEntries,
      mtime
    }));
  }
  return result;
}

function parseArgs(argv) {
  const o = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const v = () => { const x = argv[++i]; if (x === undefined) throw new Error(`${a} needs a value`); return x; };
    if (a === "--out") o.outDir = resolve(v());
    else if (a === "--guardd") o.guarddBinary = v();
    else if (a === "--guardd-arch") o.guarddArch = v();
    else if (a === "--help" || a === "-h") o.help = true;
    else throw new Error(`unknown option ${a}`);
  }
  return o;
}

const invoked = process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (invoked) {
  let o;
  try { o = parseArgs(process.argv.slice(2)); } catch (e) { process.stderr.write(`build-linux-package: ${e.message}\n`); process.exit(2); }
  if (o.help) {
    process.stdout.write("usage: node scripts/build-linux-package.mjs [--out dir] [--guardd <binary> --guardd-arch amd64|arm64]\n");
    process.exit(0);
  }
  buildLinuxPackages(o).then((r) => {
    for (const p of Object.values(r)) {
      const sha = createHash("sha256").update(readFileSync(p)).digest("hex");
      process.stdout.write(`${sha}  ${p}\n`);
    }
  }).catch((e) => { process.stderr.write(`build-linux-package: ${e.message}\n`); process.exit(1); });
}
