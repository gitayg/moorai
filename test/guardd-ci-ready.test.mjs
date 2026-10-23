// The guardd-install CI gate (scripts/guardd-ci-ready.mjs, called by .github/workflows/guardd-install.yml).
// The workflow installs a real release moorai-guardd as root and waits for the service. That can only pass
// once the helper runs on that OS, so the gate says ready only when the install script exists AND the code
// compiled for that OS has no todo!()/unimplemented!() left (and, on Windows, main.rs dispatches to the SCM).
// Until then the install and agent-side steps skip with a notice and the job stays green.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const REPO = fileURLToPath(new URL("..", import.meta.url));
const SCRIPT = join(REPO, "scripts", "guardd-ci-ready.mjs");
const WORKFLOW = join(REPO, ".github", "workflows", "guardd-install.yml");

function gate(platform, { root = null, env = {} } = {}) {
  const args = [SCRIPT, platform];
  if (root) args.push("--root", root);
  const r = spawnSync(process.execPath, args, { encoding: "utf8", env: { ...process.env, GITHUB_OUTPUT: "", ...env } });
  const ready = /^ready=(true|false)$/m.exec(r.stdout)?.[1];
  const reason = /^reason=(.*)$/m.exec(r.stdout)?.[1] ?? "";
  return { status: r.status, stdout: r.stdout, stderr: r.stderr, ready, reason };
}

function tree(files) {
  const root = mkdtempSync(join(tmpdir(), "gd-ci-"));
  for (const [p, body] of Object.entries(files)) {
    mkdirSync(dirname(join(root, p)), { recursive: true });
    writeFileSync(join(root, p), body);
  }
  return root;
}

const CLEAN = "pub fn f() -> u32 { 1 }\n";
const DISPATCH = "fn main() { windows_service::service_dispatcher::start(\"MoorAIGuard\", ffi_service_main).unwrap(); }\n";

test("this checkout: macOS is ready (its platform layer is implemented); Linux and Windows are not while theirs still have todo!() stubs", () => {
  const mac = gate("macos");
  assert.equal(mac.status, 0, mac.stderr);
  assert.equal(mac.ready, "true", mac.stdout);
  assert.doesNotMatch(mac.stdout, /::notice title=guardd-install skipped::/);
  for (const [p, dir] of [["linux", "linux"], ["windows", "windows"]]) {
    const g = gate(p);
    assert.equal(g.status, 0, g.stderr);
    assert.equal(g.ready, "false", `${p}: ${g.stdout}`);
    assert.match(g.reason, new RegExp(`guardd/src/platform/${dir}/`), `${p} names the stubbed file: ${g.reason}`);
    assert.match(g.stdout, /::notice title=guardd-install skipped::/);
  }
});

test("no install script → not ready, whatever the code says", () => {
  const root = tree({ "guardd/src/platform/linux/mod.rs": CLEAN, "guardd/src/main.rs": CLEAN });
  try {
    const g = gate("linux", { root });
    assert.equal(g.ready, "false");
    assert.match(g.reason, /guardd\/packaging\/linux\/install\.sh/);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("install script and a clean platform layer → ready; another OS's stubs and cfg(windows) stubs do not count", () => {
  const root = tree({
    "guardd/packaging/linux/install.sh": "#!/bin/sh\n",
    "guardd/src/main.rs": CLEAN,
    "guardd/src/platform/mod.rs": CLEAN,
    "guardd/src/platform/linux/mod.rs": CLEAN,
    "guardd/src/platform/windows/mod.rs": "pub fn g() { todo!(\"windows\") }\n",
    "guardd/src/platform/macos/mod.rs": "pub fn g() { todo!(\"macos\") }\n",
    "guardd/src/bin/moorai-guardd-test.rs": "fn main() { todo!() }\n",
    "guardd/src/helper.rs": "#[cfg(unix)]\npub fn p() -> bool { true }\n\n#[cfg(windows)]\npub fn p() -> bool {\n    todo!(\"token\")\n}\n"
  });
  try {
    const g = gate("linux", { root });
    assert.equal(g.ready, "true", g.stdout);
    assert.ok(!/::notice/.test(g.stdout));
    const w = gate("windows", { root });
    assert.equal(w.ready, "false");
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("a todo!() or unimplemented!() in shared code, or under cfg(unix), blocks linux and macos", () => {
  for (const [file, body] of [
    ["guardd/src/helper.rs", "pub fn p() {\n    todo!(\"shared\")\n}\n"],
    ["guardd/src/state.rs", "#[cfg(unix)]\npub fn p() {\n    unimplemented!()\n}\n"],
    ["guardd/src/platform/mod.rs", "pub fn p() { unimplemented!() }\n"]
  ]) {
    const root = tree({
      "guardd/packaging/linux/install.sh": "#!/bin/sh\n",
      "guardd/packaging/macos/install.sh": "#!/bin/sh\n",
      "guardd/src/main.rs": CLEAN,
      "guardd/src/platform/linux/mod.rs": CLEAN,
      "guardd/src/platform/macos/mod.rs": CLEAN,
      [file]: body
    });
    try {
      for (const p of ["linux", "macos"]) {
        const g = gate(p, { root });
        assert.equal(g.ready, "false", `${p} ${file}`);
        assert.ok(g.reason.includes(file), g.reason);
      }
    } finally { rmSync(root, { recursive: true, force: true }); }
  }
});

test("a cfg(target_os = \"macos\") stub blocks macos only", () => {
  const root = tree({
    "guardd/packaging/linux/install.sh": "#!/bin/sh\n",
    "guardd/packaging/macos/install.sh": "#!/bin/sh\n",
    "guardd/src/main.rs": CLEAN,
    "guardd/src/platform/linux/mod.rs": CLEAN,
    "guardd/src/platform/macos/mod.rs": CLEAN,
    "guardd/src/observe.rs": "#[cfg(target_os = \"macos\")]\nfn m() {\n    todo!()\n}\n"
  });
  try {
    assert.equal(gate("linux", { root }).ready, "true");
    assert.equal(gate("macos", { root }).ready, "false");
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("windows: a clean platform layer is not enough without an SCM dispatcher in main.rs", () => {
  const files = {
    "guardd/packaging/windows/install.ps1": "param()\n",
    "guardd/src/platform/windows/mod.rs": CLEAN,
    "guardd/src/main.rs": CLEAN
  };
  let root = tree(files);
  try {
    const g = gate("windows", { root });
    assert.equal(g.ready, "false");
    assert.match(g.reason, /service control dispatcher/);
  } finally { rmSync(root, { recursive: true, force: true }); }
  root = tree({ ...files, "guardd/src/main.rs": DISPATCH });
  try { assert.equal(gate("windows", { root }).ready, "true"); } finally { rmSync(root, { recursive: true, force: true }); }
});

test("writes ready=<bool> to $GITHUB_OUTPUT, and refuses an unknown platform", () => {
  const dir = mkdtempSync(join(tmpdir(), "gd-ci-out-"));
  try {
    const out = join(dir, "out");
    writeFileSync(out, "");
    const g = gate("linux", { env: { GITHUB_OUTPUT: out } });
    assert.equal(g.status, 0);
    assert.equal(readFileSync(out, "utf8"), "ready=false\n");
    const bad = gate("solaris");
    assert.equal(bad.status, 2);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("the workflow gates every install and agent-side step on this script", () => {
  const y = readFileSync(WORKFLOW, "utf8");
  const gates = [...y.matchAll(/- name: Check whether the helper can be installed[\s\S]*?id: gate\s*\n\s*run: (.+)/g)].map((m) => m[1].trim());
  assert.deepEqual(gates, ["node scripts/guardd-ci-ready.mjs ${{ matrix.platform }}", "node scripts/guardd-ci-ready.mjs windows"]);
  assert.ok(!/if \[ -f "\$script" \]/.test(y), "the old existence-only gate is gone");
  const steps = [...y.matchAll(/- name: (Install [^\n]+|Agent-side tests[^\n]*)\n\s*if: ([^\n]+)/g)];
  assert.equal(steps.length, 4, steps.map((s) => s[1]).join(" | "));
  for (const s of steps) assert.equal(s[2].trim(), "steps.gate.outputs.ready == 'true'", s[1]);
});
