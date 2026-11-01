// What threatcl is given (#85): the hook runs `threatcl validate` outside the agent's sandbox and egress controls
// on a model the agent wrote, so a model that could make threatcl fetch a URL or read another file (imports,
// including, a URL, an escape or template that could build one, an HCL file function) is never handed to it
// ("untrusted-input"); a clean model is validated as a copy in a fresh empty directory, with a minimal
// environment (HOME is that empty directory, proxies point at a closed port) and, on macOS, under sandbox-exec
// with network denied.
//
//   node --test --import ./test/hermetic-env.mjs test/boundary-threatcl-input.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, chmodSync, existsSync, statSync, readFileSync, realpathSync } from "node:fs";
import { join, dirname, basename } from "node:path";
import { tmpdir } from "node:os";
import { spawn, spawnSync } from "node:child_process";
import { boundaryAtStop, boundaryWriteFields } from "../cli/boundary-stop.mjs";
import { validateThreatModels } from "../cli/boundary-model.mjs";

const win = process.platform === "win32";
const rootOwned = (p) => { try { const st = statSync(p); return st.uid === 0 && !(st.mode & 0o022); } catch { return false; } };
const TRUE = "/usr/bin/true";
const tmp = (tag) => mkdtempSync(join(tmpdir(), `moorai-tci-${tag}-`));
function put(dir, rel, text) { const p = join(dir, rel); mkdirSync(dirname(p), { recursive: true }); writeFileSync(p, text); return p; }
const model = (body = "") => `spec_version = "0.1.15"\n\nthreatmodel "Payments" {\n  author = "@sec"\n  description = "card flow"\n${body}}\n`;

// A repository whose turn edited the given model; the Stop result with threatclPath = bin.
function stopOn(text, bin) {
  const policy = { threatModel: { v: 1, threatclPath: bin } };
  const proj = tmp("proj");
  put(proj, ".git/HEAD", "ref: refs/heads/main\n");
  const f = put(proj, "security/payments.hcl", text);
  const fields = boundaryWriteFields("Edit", { file_path: f, old_string: "card flow", new_string: "card flow v2" }, f, proj, policy);
  assert.equal(fields.tm, 1, "the edit is a threat-model write");
  const rows = [{ ev: "prompt" }, { ev: "pre", tool: "Edit", decision: "allow", u: "t1", ...fields }];
  return boundaryAtStop({ rows, scope: rows, cwd: proj, policy }).validation;
}
// A fake threatcl (called directly, bypassing the owner checks) that records that it ran, and what it saw.
function recorder() {
  const d = tmp("rec");
  const out = join(d, "seen");
  const p = join(d, "threatcl");
  writeFileSync(p, `#!/bin/sh\n{ echo "PWD=$(pwd -P)"; echo "ARG1=$1"; echo "ARG2=$2"; echo "---ENV"; /usr/bin/env; echo "---MODEL"; cat "$2"; } > "${out}"\nexit 0\n`);
  chmodSync(p, 0o755);
  return { bin: p, ran: () => existsSync(out), seen: () => readFileSync(out, "utf8") };
}

const REFUSED = {
  "imports of a URL": model(`  imports = ["https://example.invalid/x.hcl"]\n`),
  "imports of a local file (no URL)": model(`  imports = ["controls/base.hcl"]\n`),
  "including (no URL)": `spec_version = "0.1.15"\n\nthreatmodel "Payments" {\n  including = "shared/base.hcl"\n  author = "@sec"\n  description = "card flow"\n}\n`,
  "a URL in a heredoc (no imports)": model(`  attributes {\n    note = <<EOT\nsee https://example.invalid/x\nEOT\n  }\n`),
  "a URL in a quoted string (no imports)": model(`  link = "http://169.254.169.254/latest/meta-data/"\n`),
  "mixed case IMPORTS": model(`  IMPORTS = ["x.hcl"]\n`),
  "Including with whitespace and a tab": model(`  Including\t   =    "x.hcl"\n`),
  "imports on a single-line block": `spec_version = "0.1.15"\nthreatmodel "Payments" { imports = ["x.hcl"] }\n# card flow\n`,
  "imports after a block comment": model(`  /* c */ imports = ["x.hcl"]\n`),
  "a unicode escape (could spell a URL or a key)": model(`  link = "https:\\u002F\\u002Fexample.invalid"\n`),
  "a template interpolation (could build a URL)": model(`  link = "https:\${"/"}/example.invalid"\n`),
  "an HCL file function": model(`  note = file ("/etc/passwd")\n`),
};

for (const [name, text] of Object.entries(REFUSED)) {
  test(`untrusted-input: ${name}: threatcl is not spawned`, { skip: win }, () => {
    const d = tmp("ref");
    const f = put(d, "tm.hcl", text);
    const r = recorder();
    assert.equal(validateThreatModels([f], { bin: r.bin, timeoutMs: 3000 }), "untrusted-input");
    assert.equal(r.ran(), false, "threatcl was spawned on an untrusted model");
  });
}

test("untrusted-input at Stop with a root-owned threatclPath: tmv untrusted-input, not pass", { skip: win || !rootOwned(TRUE) }, () => {
  assert.deepEqual(stopOn(REFUSED["imports of a URL"], TRUE), { result: "untrusted-input", files: 0 });
  assert.deepEqual(stopOn(REFUSED["including (no URL)"], TRUE), { result: "untrusted-input", files: 0 });
  assert.deepEqual(stopOn(model(), TRUE), { result: "pass", files: 1 }, "a clean model still runs");
});

test("a clean model runs, as a copy in a fresh empty directory, with a minimal environment (HOME = that directory, closed proxies)", { skip: win }, () => {
  const proj = tmp("clean");
  const text = model(`  attributes {\n    note = "Stores card numbers; calls the FX service"\n  }\n`);
  const f = put(proj, "security/payments.hcl", text);
  const r = recorder();
  process.env.MOORAI_TEST_SECRET = "s3cr3t";
  try { assert.equal(validateThreatModels([f], { bin: r.bin, timeoutMs: 5000 }), "pass"); } finally { delete process.env.MOORAI_TEST_SECRET; }
  assert.ok(r.ran(), "threatcl did not run on a clean model");
  const seen = r.seen();
  const [head, rest] = seen.split("---ENV\n");
  const [envText, modelText] = rest.split("---MODEL\n");
  const kv = Object.fromEntries(head.trim().split("\n").map((l) => [l.slice(0, l.indexOf("=")), l.slice(l.indexOf("=") + 1)]));
  assert.equal(kv.ARG1, "validate");
  // The directory is removed after the run, so it is compared by name: the copy sits in threatcl's working
  // directory, a fresh moorai-threatcl-* directory, never the project.
  assert.ok(kv.ARG2.startsWith("/") && basename(dirname(kv.ARG2)) === basename(kv.PWD), "the model passed is not a copy in the working directory");
  assert.match(basename(kv.PWD), /^moorai-threatcl-/);
  assert.notEqual(kv.ARG2, f, "the agent's file itself was passed");
  assert.ok(!kv.PWD.startsWith(realpathSync(proj)) && !kv.ARG2.startsWith(proj), "threatcl ran in the project");
  assert.equal(existsSync(dirname(kv.ARG2)), false, "the temporary directory was not removed");
  assert.equal(modelText, text, "the copy differs from the checked model");
  const env = Object.fromEntries(envText.trim().split("\n").map((l) => [l.slice(0, l.indexOf("=")), l.slice(l.indexOf("=") + 1)]));
  assert.equal(env.HOME, join(tmpdir(), basename(kv.PWD)), "HOME is not the fresh empty working directory");
  assert.notEqual(env.HOME, process.env.MOORAI_TEST_REAL_HOME, "the real home was passed");
  assert.equal(env.MOORAI_TEST_SECRET, undefined, "the hook's environment was inherited");
  assert.equal(env.PATH, "/usr/bin:/bin");
  for (const k of ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"]) assert.equal(env[k], "http://127.0.0.1:9", k);
  assert.equal(env.NO_PROXY, "");
  assert.equal(env.no_proxy, "");
  const extra = Object.keys(env).filter((k) => !["PATH", "HOME", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "all_proxy", "no_proxy", "PWD", "OLDPWD", "SHLVL", "_", "__CF_USER_TEXT_ENCODING"].includes(k));
  assert.deepEqual(extra, [], "unexpected variables reached threatcl");
});

test("macOS: threatcl runs under sandbox-exec with network denied (direct connect to a live local server fails)", { skip: process.platform !== "darwin" || !rootOwned("/usr/bin/sandbox-exec") || !rootOwned("/usr/bin/curl") }, async () => {
  const srv = spawn(process.execPath, ["-e", "require('http').createServer((q,s)=>s.end('ok')).listen(0,'127.0.0.1',function(){process.stdout.write(String(this.address().port))})"], { stdio: ["ignore", "pipe", "ignore"] });
  try {
    const port = await new Promise((res) => srv.stdout.once("data", (b) => res(String(b).trim())));
    const url = `http://127.0.0.1:${port}/`;
    const control = spawnSync("/usr/bin/curl", ["-s", "-m", "3", "--noproxy", "*", "-o", "/dev/null", url]);
    assert.equal(control.status, 0, "control: the local server is not reachable outside the sandbox");
    const d = tmp("net");
    const out = join(d, "rc");
    const p = join(d, "threatcl");
    writeFileSync(p, `#!/bin/sh\n/usr/bin/curl -s -m 3 --noproxy '*' -o /dev/null ${url}\necho $? > "${out}"\nexit 0\n`);
    chmodSync(p, 0o755);
    const f = put(d, "tm.hcl", model());
    assert.equal(validateThreatModels([f], { bin: p, timeoutMs: 8000 }), "pass");
    const rc = Number(readFileSync(out, "utf8").trim());
    assert.notEqual(rc, 0, "threatcl reached the network");
    assert.notEqual(rc, 28, "the connection was made and timed out (not denied)");
  } finally { srv.kill(); }
});
