// examples/cloud/claude-code-web-setup.sh runs as root at the start of every cloud session. It must never run
// (or run git inside) a checkout an earlier session left behind: it clones the pinned tag fresh, checks the
// commit against MOORAI_COMMIT, and only then runs node. git and node are stubs on PATH here, so nothing is
// downloaded; MOORAI_INSTALL_DIR points the script at a temporary directory.
// Per-file runner:  node --test --import ./test/hermetic-env.mjs test/cloud-setup-script.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, chmodSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { rmTree } from "./fs-cleanup.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const SCRIPT = join(ROOT, "examples", "cloud", "claude-code-web-setup.sh");
const SHA = "0123456789abcdef0123456789abcdef01234567";

function sandbox() {
  const dir = mkdtempSync(join(tmpdir(), "moorai-cloudsh-"));
  const bin = join(dir, "bin");
  mkdirSync(bin);
  const log = join(dir, "log");
  writeFileSync(log, "");
  writeFileSync(join(bin, "git"), `#!/bin/sh
echo "git $*" >> "$STUB_LOG"
if [ "$1" = clone ]; then
  for a; do dest="$a"; done
  mkdir -p "$dest/.git" "$dest/cli" && echo fresh > "$dest/MARK"
  exit 0
fi
if [ "$1" = -C ] && [ "$3" = rev-parse ]; then echo "$STUB_HEAD"; exit 0; fi
exit 0
`);
  writeFileSync(join(bin, "node"), `#!/bin/sh
echo "node $* mark=$(cat "$(dirname "$(dirname "$1")")/MARK" 2>/dev/null)" >> "$STUB_LOG"
`);
  chmodSync(join(bin, "git"), 0o755);
  chmodSync(join(bin, "node"), 0o755);
  const install = join(dir, "opt", "moorai");
  return { dir, bin, log, install };
}

function run(s, env) {
  const r = spawnSync("/bin/bash", [SCRIPT], { env: { HOME: s.dir, PATH: `${s.bin}:/usr/bin:/bin`, STUB_LOG: s.log, MOORAI_INSTALL_DIR: s.install, ...env }, cwd: s.dir, encoding: "utf8" });
  return { status: r.status, err: r.stderr, log: readFileSync(s.log, "utf8") };
}

test("a checkout left by an earlier session is never run: a fresh clone at the pinned commit replaces it", () => {
  const s = sandbox();
  try {
    mkdirSync(join(s.install, ".git"), { recursive: true });
    mkdirSync(join(s.install, "cli"));
    writeFileSync(join(s.install, "MARK"), "stale");
    const r = run(s, { MOORAI_REF: "v1.28.0", MOORAI_COMMIT: SHA, STUB_HEAD: SHA });
    assert.equal(r.status, 0, r.err + r.log);
    const nodeLines = r.log.split("\n").filter((l) => l.startsWith("node "));
    assert.equal(nodeLines.length, 1, r.log);
    assert.match(nodeLines[0], /mark=fresh$/);
    assert.ok(nodeLines[0].includes(`${s.install}/cli/moorai-cloud-setup.mjs claude-code-web --install-dir ${s.install}`), nodeLines[0]);
    assert.equal(readFileSync(join(s.install, "MARK"), "utf8").trim(), "fresh");
    // git never runs inside the old checkout (its config could run code as root).
    assert.ok(!r.log.includes(`-C ${s.install} `), r.log);
    assert.match(r.log, /git clone .*--branch v1\.28\.0 /);
  } finally { rmTree(s.dir); }
});

test("a clone whose HEAD is not MOORAI_COMMIT stops before node runs", () => {
  const s = sandbox();
  try {
    const r = run(s, { MOORAI_REF: "v1.28.0", MOORAI_COMMIT: SHA, STUB_HEAD: "f".repeat(40) });
    assert.notEqual(r.status, 0);
    assert.ok(!r.log.includes("node "), r.log);
    assert.ok(!existsSync(join(s.install, "MARK")), "the unverified clone was installed");
  } finally { rmTree(s.dir); }
});

test("MOORAI_REF and a full MOORAI_COMMIT SHA are required, and nothing runs without them", () => {
  const s = sandbox();
  try {
    for (const env of [{ MOORAI_COMMIT: SHA }, { MOORAI_REF: "v1.28.0" }, { MOORAI_REF: "v1.28.0", MOORAI_COMMIT: SHA.slice(0, 12) }, { MOORAI_REF: "v1.28.0", MOORAI_COMMIT: "main" }, { MOORAI_REF: "v1.28.0", MOORAI_COMMIT: SHA.toUpperCase() }]) {
      const r = run(s, { ...env, STUB_HEAD: SHA });
      assert.notEqual(r.status, 0, JSON.stringify(env));
      assert.equal(r.log, "", JSON.stringify(env));
    }
    for (const dir of ["/", "opt/moorai", "/opt/moorai/"]) {
      const r = run(s, { MOORAI_REF: "v1.28.0", MOORAI_COMMIT: SHA, MOORAI_INSTALL_DIR: dir, STUB_HEAD: SHA });
      assert.notEqual(r.status, 0, dir);
      assert.equal(r.log, "", dir);
    }
  } finally { rmTree(s.dir); }
});
