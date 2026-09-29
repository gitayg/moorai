// moorai-doctor: every check is driven through the real CLI in a sandbox HOME, and the ones that claim
// to mirror the hook are pinned against the hook's own installer, loader and decision.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync, spawn } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, chmodSync, readdirSync, lstatSync, utimesSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash, generateKeyPairSync, sign as cryptoSign } from "node:crypto";
import http from "node:http";
import { policyCanonical, policyDigest } from "../cli/hook-core.mjs";
import { checkManaged, readManagedSettings, diffSurface } from "../cli/doctor-hosts.mjs";
import { noPolicyBaseline, breakGlassAnchorPath } from "../cli/doctor-policy.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const DOCTOR = join(ROOT, "cli", "moorai-doctor.mjs");
const HOOK = join(ROOT, "cli", "moorai-hook.mjs");
const TOKEN = "tok-doctor-SECRET-7f3a9c1e5b";
const TENANT = "doctor-test";

function sandbox({ config } = {}) {
  const home = mkdtempSync(join(tmpdir(), "moorai-doctor-test-"));
  mkdirSync(join(home, ".moorai"), { recursive: true });
  if (config) writeFileSync(join(home, ".moorai", "config.json"), JSON.stringify(config), { mode: 0o600 });
  return home;
}
function env(home) {
  return { PATH: process.env.PATH || "/usr/bin:/bin", HOME: home, USERPROFILE: home, XDG_CONFIG_HOME: join(home, ".config"), XDG_STATE_HOME: join(home, ".local", "state") };
}
function doctorSync(home, args = ["--offline"]) {
  const r = spawnSync(process.execPath, [DOCTOR, ...args], { env: env(home), encoding: "utf8", timeout: 60000 });
  return { ...r, json: args.includes("--json") ? JSON.parse(r.stdout) : null };
}
function doctorAsync(home, args) {
  return new Promise((res) => {
    const c = spawn(process.execPath, [DOCTOR, ...args], { env: env(home) });
    let out = "", err = "";
    c.stdout.on("data", (d) => (out += d)); c.stderr.on("data", (d) => (err += d));
    c.on("close", (status) => res({ status, stdout: out, stderr: err }));
  });
}
const check = (r, id) => r.json.checks.find((c) => c.id === id);
function installClaude(home) {
  const r = spawnSync(process.execPath, [HOOK, "install"], { env: env(home), encoding: "utf8", timeout: 20000 });
  assert.equal(r.status, 0, r.stderr);
}
// Every file under home: path -> size + mtime + sha256. Directories by path.
function snapshot(home) {
  const out = {};
  const walk = (d) => {
    for (const n of readdirSync(d)) {
      const p = join(d, n);
      const st = lstatSync(p);
      if (st.isDirectory()) { out[p] = "dir"; walk(p); }
      else out[p] = `${st.size}:${st.mtimeMs}:${createHash("sha256").update(readFileSync(p)).digest("hex")}:${(st.mode & 0o777).toString(8)}`;
    }
  };
  walk(home);
  return out;
}
const KEYS = generateKeyPairSync("ed25519");
const SPKI = KEYS.publicKey.export({ type: "spki", format: "der" }).toString("base64");
function signed(policy, tenant = TENANT, iat = "2026-09-01T00:00:00.000Z") {
  const msg = policyCanonical({ v: 1, tenant, iat, digest: policyDigest(policy) });
  return { ...policy, policySig: { v: 1, alg: "ed25519", tenant, iat, sig: cryptoSign(null, Buffer.from(msg), KEYS.privateKey).toString("base64") } };
}
function pin(home) {
  const body = JSON.stringify({ v: 1, tenant: TENANT, keys: [SPKI], iat: "", updated: "2026-09-01T00:00:00.000Z" });
  writeFileSync(join(home, ".moorai", "policy-pin.json"), body);
  mkdirSync(join(home, ".config", "moorai"), { recursive: true });
  writeFileSync(join(home, ".config", "moorai", "policy-pin.json"), body);
}

test("doctor: unenrolled device with no host registration fails, coaches, and the self-test proves the hook decides", () => {
  const home = sandbox();
  try {
    const r = doctorSync(home, ["--offline", "--json"]);
    assert.equal(r.status, 1, r.stderr);
    assert.equal(r.json.exitCode, 1);
    assert.equal(check(r, "hosts:any").status, "fail");
    assert.equal(check(r, "enrollment").status, "warn");
    assert.match(check(r, "enrollment").summary, /coach mode/);
    const st = check(r, "selftest");
    assert.equal(st.status, "ok", st.summary);
    assert.equal(st.details.benign.decision, "allow");
    assert.equal(st.details.knownBad.decision, "allow");
    assert.equal(st.details.knownBad.coach, true);
    assert.match(st.details.knownBad.reason, /MoorAI coach: .*#54/);
    const human = doctorSync(home, ["--offline"]);
    assert.match(human.stdout, /FAIL {2}Any host: MoorAI is not registered in any agent host/);
    assert.match(human.stdout, /fix: node .*moorai-hook\.mjs" install/);
  } finally { rmSync(home, { recursive: true, force: true }); }
});

test("doctor: Claude Code registration is compared with what the real installer writes — current is ok, a stale surface fails", () => {
  const home = sandbox();
  try {
    installClaude(home);
    let r = doctorSync(home, ["--offline", "--no-selftest", "--json"]);
    const c = check(r, "host:claude-code");
    assert.equal(c.status, "ok", c.summary);
    assert.equal(r.status, 0, JSON.stringify(r.json.checks.filter((x) => x.status === "fail")));
    assert.deepEqual(Object.keys(c.details.expected).sort(), ["PostToolUse", "PreToolUse", "UserPromptSubmit"]);

    // A pre-upgrade device: PreToolUse on the old four-matcher list, no PostToolUse / UserPromptSubmit.
    const p = join(home, ".claude", "settings.json");
    const s = JSON.parse(readFileSync(p, "utf8"));
    s.hooks.PreToolUse = s.hooks.PreToolUse.filter((e) => ["Read", "Bash", "mcp__.*", "Task"].includes(e.matcher));
    delete s.hooks.PostToolUse; delete s.hooks.UserPromptSubmit;
    writeFileSync(p, JSON.stringify(s));
    r = doctorSync(home, ["--offline", "--no-selftest", "--json"]);
    const stale = check(r, "host:claude-code");
    assert.equal(stale.status, "fail");
    assert.match(stale.summary, /missing event\(s\) PostToolUse, UserPromptSubmit/);
    assert.match(stale.summary, /PreToolUse matchers are \[Bash Read Task mcp__\.\*\], current is/);
    assert.equal(r.status, 1);

    // Entries pointing at a hook file that no longer exists.
    installClaude(home);
    const t = readFileSync(p, "utf8").split(HOOK).join(join(home, "gone", "moorai-hook.mjs"));
    writeFileSync(p, t);
    r = doctorSync(home, ["--offline", "--no-selftest", "--json"]);
    assert.match(check(r, "host:claude-code").summary, /hook file missing: .*gone\/moorai-hook\.mjs/);
  } finally { rmSync(home, { recursive: true, force: true }); }
});

test("doctor: adapter hosts are checked against their own installers (codex, cursor)", () => {
  const home = sandbox();
  try {
    for (const id of ["codex", "cursor"]) {
      const r = spawnSync(process.execPath, [join(ROOT, "cli", "moorai-agent-hook.mjs"), id, "install"], { env: env(home), encoding: "utf8", timeout: 20000 });
      assert.equal(r.status, 0, r.stderr);
    }
    let r = doctorSync(home, ["--offline", "--no-selftest", "--json"]);
    assert.equal(check(r, "host:cursor").status, "ok", check(r, "host:cursor").summary);
    // Codex runs user hooks only after trust review; no [hooks.state] → warn, not ok.
    assert.equal(check(r, "host:codex").status, "warn");
    assert.match(check(r, "host:codex").summary, /trust/);
    const f = join(home, ".cursor", "hooks.json");
    const cfg = JSON.parse(readFileSync(f, "utf8"));
    delete cfg.hooks.postToolUse;
    writeFileSync(f, JSON.stringify(cfg));
    r = doctorSync(home, ["--offline", "--no-selftest", "--json"]);
    assert.equal(check(r, "host:cursor").status, "fail");
    assert.match(check(r, "host:cursor").summary, /missing event\(s\) postToolUse/);
  } finally { rmSync(home, { recursive: true, force: true }); }
});

test("doctor: enrolled device against a local console — GET only, token never printed, self-test enforces", async () => {
  const seen = [];
  const srv = http.createServer((req, res) => {
    seen.push(`${req.method} ${req.url.split("?")[0]}`);
    if (req.url.startsWith("/api/policy/pubkey")) { res.writeHead(404); return res.end(); }
    if (req.url.startsWith("/api/policy")) { res.writeHead(200, { "content-type": "application/json" }); return res.end(JSON.stringify({ captureTier: "content-free" })); }
    res.writeHead(404); res.end();
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  const serverUrl = `http://127.0.0.1:${srv.address().port}`;
  const home = sandbox({ config: { serverUrl, tenant: TENANT, installToken: TOKEN } });
  try {
    installClaude(home);
    const r = await doctorAsync(home, ["--json"]);
    const human = await doctorAsync(home, []);
    for (const out of [r.stdout, r.stderr, human.stdout, human.stderr]) assert.ok(!out.includes(TOKEN), "install token printed");
    const j = JSON.parse(r.stdout);
    const get = (id) => j.checks.find((c) => c.id === id);
    const fp = createHash("sha256").update(TOKEN).digest("hex").slice(0, 8);
    assert.equal(get("enrollment").status, "ok");
    assert.match(get("enrollment").summary, new RegExp(`token present \\(sha256:${fp}\\) · enforce mode`));
    assert.equal(get("console").status, "ok", get("console").summary);
    // Served unsigned to a device with no anchor and no pin: accepted, but unverified.
    assert.equal(get("policy").status, "warn", get("policy").summary);
    assert.match(get("policy").summary, /UNVERIFIED/);
    const st = get("selftest");
    assert.equal(st.status, "ok", st.summary);
    assert.equal(st.details.knownBad.decision, "deny");
    assert.ok(seen.length > 0, "console was never contacted");
    assert.deepEqual(seen.filter((s) => !s.startsWith("GET ")), [], `non-GET requests reached the console: ${seen}`);
    assert.ok(!seen.some((s) => s.includes("/api/alerts")), "doctor posted an alert");
  } finally { srv.close(); rmSync(home, { recursive: true, force: true }); }
});

test("doctor: pinned device — a planted unsigned cache fails, a signed one verifies, a signed policy that softens #54 is caught by the self-test", () => {
  const home = sandbox({ config: { serverUrl: "http://127.0.0.1:1", tenant: TENANT, installToken: TOKEN } });
  const cache = join(home, ".moorai", "hook-policy.json");
  try {
    pin(home);
    writeFileSync(cache, "{}");
    let r = doctorSync(home, ["--offline", "--json"]);
    assert.equal(check(r, "policy").status, "fail");
    assert.match(check(r, "policy").summary, /cache:unsigned/);

    writeFileSync(cache, JSON.stringify(signed({ captureTier: "content-free" })));
    r = doctorSync(home, ["--offline", "--json"]);
    assert.equal(check(r, "policy").status, "ok", check(r, "policy").summary);
    assert.match(check(r, "policy").summary, /signature verifies \(pinned \(1 key/);
    assert.equal(check(r, "selftest").details.knownBad.decision, "deny");

    writeFileSync(cache, JSON.stringify(signed({ captureTier: "content-free", threatPolicy: { 54: "notify" } })));
    r = doctorSync(home, ["--offline", "--json"]);
    const st = check(r, "selftest");
    assert.equal(st.status, "warn", st.summary);
    assert.match(st.summary, /policy sets #54 to "notify": a reverse shell is allowed/);
    assert.equal(st.details.knownBad.decision, "allow");
  } finally { rmSync(home, { recursive: true, force: true }); }
});

test("doctor: key files looser than 0600 fail, an unsigned break-glass marker fails, a malformed cache warns", { skip: process.platform === "win32" }, () => {
  const home = sandbox();
  try {
    writeFileSync(join(home, ".moorai", "intent.key"), "a".repeat(64), { mode: 0o644 });
    chmodSync(join(home, ".moorai", "intent.key"), 0o644);
    writeFileSync(join(home, ".moorai", "break-glass"), JSON.stringify({ v: 2, expires: "2099-01-01T00:00:00Z" }));
    let r = doctorSync(home, ["--offline", "--no-selftest", "--json"]);
    assert.equal(check(r, "state").status, "fail");
    assert.match(check(r, "state").summary, /intent\.key is mode 644, expected 600/);
    assert.equal(check(r, "break-glass").status, "fail");
    assert.match(check(r, "break-glass").summary, /rejected \(unsigned\)/);
    chmodSync(join(home, ".moorai", "intent.key"), 0o600);
    rmSync(join(home, ".moorai", "break-glass"));
    writeFileSync(join(home, ".moorai", "instruction-fp.json"), "{not json", { mode: 0o600 });
    r = doctorSync(home, ["--offline", "--no-selftest", "--json"]);
    assert.equal(check(r, "state").status, "warn", check(r, "state").summary);
    assert.equal(check(r, "break-glass").status, "ok");
  } finally { rmSync(home, { recursive: true, force: true }); }
});

test("doctor is read-only: every file under HOME is byte-, mtime- and mode-identical after a full run", async () => {
  const hits = [];
  const srv = http.createServer((req, res) => { hits.push(req.url); res.writeHead(200, { "content-type": "application/json" }); res.end(JSON.stringify(signed({ captureTier: "content-free" }, TENANT, "2026-09-02T00:00:00.000Z"))); });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  const home = sandbox({ config: { serverUrl: `http://127.0.0.1:${srv.address().port}`, tenant: TENANT, installToken: TOKEN } });
  try {
    installClaude(home);
    pin(home);
    writeFileSync(join(home, ".moorai", "hook-policy.json"), JSON.stringify(signed({ captureTier: "content-free" })));
    // Outside the hook's 60s cache window, so the loader really fetches — and would re-cache, re-pin and
    // write last-known-good if it were pointed at this HOME instead of a sandbox copy.
    const old = new Date(Date.now() - 2 * 3600e3);
    utimesSync(join(home, ".moorai", "hook-policy.json"), old, old);
    writeFileSync(join(home, ".moorai", "posture"), "fail-open");
    writeFileSync(join(home, ".moorai", "action-audit.jsonl"), '{"x":1}\n');
    const before = snapshot(home);
    for (const args of [[], ["--offline"], ["--json"]]) {
      const r = await doctorAsync(home, args);
      assert.ok(r.status === 0 || r.status === 1, r.stderr);
    }
    assert.ok(hits.some((u) => u.startsWith("/api/policy?")), "the loader never fetched; the test proves nothing");
    assert.deepEqual(snapshot(home), before);
  } finally { srv.close(); rmSync(home, { recursive: true, force: true }); }
});

test("doctor managed settings: allowManagedHooksOnly without MoorAI fails, with MoorAI passes, disableAllHooks fails (read from a managed dir)", () => {
  const dir = mkdtempSync(join(tmpdir(), "moorai-managed-"));
  try {
    writeFileSync(join(dir, "managed-settings.json"), JSON.stringify({ allowManagedHooksOnly: true }));
    let c = checkManaged(readManagedSettings(dir));
    assert.equal(c.status, "fail");
    assert.match(c.summary, /allowManagedHooksOnly is true .* Claude Code will not run MoorAI's user-level hooks/);
    mkdirSync(join(dir, "managed-settings.d"));
    writeFileSync(join(dir, "managed-settings.d", "10-moorai.json"), JSON.stringify({ hooks: { PreToolUse: [{ matcher: "Bash", hooks: [{ type: "command", command: 'node "/opt/moorai/cli/moorai-hook.mjs"' }] }] } }));
    c = checkManaged(readManagedSettings(dir));
    assert.equal(c.status, "ok", c.summary);
    assert.ok(c.managedHooks);
    writeFileSync(join(dir, "managed-settings.json"), JSON.stringify({ disableAllHooks: true }));
    c = checkManaged(readManagedSettings(dir));
    assert.equal(c.status, "fail");
    assert.match(c.summary, /disableAllHooks is true/);
    assert.equal(checkManaged([]).status, "ok");
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("doctor mirrors the hook's private constants by reading them, so they cannot drift silently", () => {
  const src = readFileSync(HOOK, "utf8");
  assert.deepEqual(noPolicyBaseline(src), { captureTier: "content-free", builtinDefault: true });
  assert.ok(src.includes(JSON.stringify(breakGlassAnchorPath())) || process.platform === "win32", "break-glass anchor path drifted from moorai-hook.mjs BG_ANCHOR");
  assert.deepEqual(diffSurface({ A: ["x"] }, { A: ["x"] }).ok, true);
});
