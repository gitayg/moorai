// Per-file runner:  node --test test/hook-gaps-env-path.test.mjs
//
// GAP 2 — reading a .env by ABSOLUTE path. Measured before the fix (enrolled sandbox, no policy and a
// policy that configures nothing): `cat .env`, `cat ./.env` and `cat ~/proj/.env` -> ask (#55), but
// `cat <73-char abs path>/.env` -> allow, and a Read of the same file -> allow. Two causes:
//   * #55 `cred-file-access` allowed at most 50 characters between the read verb and `.env`, so the
//     verdict depended on how deep the project lived on disk;
//   * the Read branch never evaluated the PATH against #55 at all, only the file's content.
// The fix makes an absolute path behave exactly like the relative one — `ask` under the built-in
// default, never stricter — and keeps env TEMPLATES (.env.example / .sample / .template) unflagged.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const HOOK = join(ROOT, "cli", "moorai-hook.mjs");

// Public AWS documentation example pair — grants nothing.
const ENV_BODY = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n";
const SECRET_ONLY = "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n";
const LIVE = [".env", ".env.local", ".env.production"];
const TEMPLATES = [".env.example", ".env.sample", ".env.template"];

// A deliberately DEEP project dir so the absolute path is well past the old 50-char window.
function sandbox(policy, body = ENV_BODY) {
  const home = mkdtempSync(join(tmpdir(), "moorai-gap2-"));
  mkdirSync(join(home, ".moorai"), { recursive: true });
  writeFileSync(join(home, ".moorai", "config.json"), JSON.stringify({ serverUrl: "http://127.0.0.1:1", tenant: "gap2", installToken: "tok-gap2" }));
  if (policy) writeFileSync(join(home, ".moorai", "hook-policy.json"), JSON.stringify(policy));
  const proj = join(home, "work", "clients", "acme-corporation", "services", "billing-api");
  mkdirSync(proj, { recursive: true });
  for (const f of [...LIVE, ...TEMPLATES]) writeFileSync(join(proj, f), body);
  return { home, proj };
}

function runHook(home, cwd, payload) {
  const res = spawnSync("node", [HOOK], {
    input: JSON.stringify({ session_id: "g2", ...payload }),
    cwd,
    encoding: "utf8",
    timeout: 30000,
    env: { PATH: process.env.PATH || "/usr/bin:/bin", HOME: home, USERPROFILE: home, XDG_CONFIG_HOME: join(home, ".config"), XDG_STATE_HOME: join(home, ".local", "state"), MoorAI_SERVER: "http://127.0.0.1:1", MoorAI_TENANT: "gap2" }
  });
  assert.equal(res.status, 0, res.stderr);
  const out = (res.stdout || "").trim();
  if (!out) return "allow";
  return JSON.parse(out).hookSpecificOutput?.permissionDecision || "allow";
}

const bash = (command) => ({ tool_name: "Bash", tool_input: { command } });
const read = (file_path) => ({ tool_name: "Read", tool_input: { file_path } });

for (const [label, policy] of [["no policy", null], ["default policy", { captureTier: "content-free" }]]) {
  test(`GAP 2 (${label}): an absolute / ~ path to a live .env gets the same verdict as ./.env`, () => {
    const { home, proj } = sandbox(policy);
    try {
      assert.ok(proj.length > 60, `sandbox path must exceed the old window; got ${proj.length}`);
      const rel = runHook(home, proj, bash("cat ./.env"));
      assert.equal(rel, "ask", "baseline: the relative read is #55 ask");
      const tilde = proj.replace(home, "~");
      for (const f of LIVE) {
        assert.equal(runHook(home, proj, bash(`cat ${f}`)), rel, `cat ${f}`);
        assert.equal(runHook(home, proj, bash(`cat ${join(proj, f)}`)), rel, `cat <abs>/${f}`);
        assert.equal(runHook(home, proj, bash(`cat ${tilde}/${f}`)), rel, `cat ~/…/${f}`);
        assert.equal(runHook(home, proj, read(join(proj, f))), rel, `Read <abs>/${f}`);
      }
    } finally { rmSync(home, { recursive: true, force: true }); }
  });

  test(`GAP 2 (${label}): env TEMPLATES stay unflagged in every path form`, () => {
    // Content without an AKIA id, so the only thing that could flag these is the #55 path rule (and
    // #39 is report-only here anyway).
    const { home, proj } = sandbox(policy, SECRET_ONLY);
    try {
      for (const f of TEMPLATES) {
        assert.equal(runHook(home, proj, bash(`cat ${f}`)), "allow", `cat ${f}`);
        assert.equal(runHook(home, proj, bash(`cat ./${f}`)), "allow", `cat ./${f}`);
        assert.equal(runHook(home, proj, bash(`cat ${join(proj, f)}`)), "allow", `cat <abs>/${f}`);
        assert.equal(runHook(home, proj, read(join(proj, f))), "allow", `Read <abs>/${f}`);
      }
    } finally { rmSync(home, { recursive: true, force: true }); }
  });
}

test("GAP 2: no stricter than relative — a live .env is ask, never deny, under the built-in default", () => {
  const { home, proj } = sandbox(null);
  try {
    assert.equal(runHook(home, proj, read(join(proj, ".env"))), "ask");
    assert.equal(runHook(home, proj, bash(`cat ${join(proj, ".env")}`)), "ask");
    // A non-credential file at the same depth is untouched.
    writeFileSync(join(proj, "README.md"), "# billing api\n");
    assert.equal(runHook(home, proj, read(join(proj, "README.md"))), "allow");
    assert.equal(runHook(home, proj, bash(`cat ${join(proj, "README.md")}`)), "allow");
  } finally { rmSync(home, { recursive: true, force: true }); }
});
