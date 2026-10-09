// Sandbox egress policies from egressRules (cli/sandbox-policy.mjs; MXC and Seatbelt mirrored in
// src-tauri/src/mxc_egress.rs).
//
// Four layers, each able to fail on its own:
//   1. golden cases in test/fixtures/mxc/sandbox-cases.json, per target — `cargo test` replays the mxc and
//      seatbelt halves against the Rust mirror;
//   2. every MXC network section validates against microsoft/mxc's stable schema 1.0.0;
//   3. the safety properties checked by small evaluators written here, independent of the generator:
//      default deny stays deny, a block is never let through by an over-broad expression, and every rule a
//      target cannot carry is reported;
//   4. on macOS, the generated Seatbelt section run under the real sandbox-exec.
//
//   node --test test/sandbox-policy.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from "node:fs";
import { spawnSync, spawn } from "node:child_process";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { sandboxPolicy, mxcEgress, mxcNetwork, seatbeltEgress, openshellEgress, SANDBOX_TARGETS } from "../cli/sandbox-policy.mjs";
import { validateEgressRule } from "../cli/egress-rules.mjs";

const Ajv = await import("ajv").then((m) => m.default, () => null);
const read = (rel) => readFileSync(new URL(`../${rel}`, import.meta.url), "utf8");
const CASES = JSON.parse(read("test/fixtures/mxc/sandbox-cases.json"));
const SCHEMA = JSON.parse(read("test/fixtures/mxc/mxc-config.schema.1.0.0.json"));
const CLI = fileURLToPath(new URL("../cli/sandbox-policy.mjs", import.meta.url));

// Rule sets built to tempt each mapping into widening: a block followed by a broader allow, in every
// combination of host shape, port and request field.
const ADVERSARIAL = [
  { egressRules: [{ host: "evil.example.com", action: "block" }, { host: "*.example.com", port: 443, action: "allow" }], egressDefault: "block" },
  { egressRules: [{ host: "*.corp.example", action: "block" }, { host: "api.corp.example", port: 443, action: "allow" }] },
  { egressRules: [{ host: "203.0.113.5", action: "block" }, { host: "203.0.113.5", port: 443, action: "allow" }, { host: "203.0.113.6", action: "allow" }] },
  { egressRules: [{ host: "203.0.113.5", port: 443, method: "GET", action: "allow" }, { host: "203.0.113.5", port: 443, action: "block" }, { host: "203.0.113.5", action: "allow" }], egressDefault: "block" },
  { egressRules: [{ host: "203.0.113.7", port: [22, 23], action: "block" }, { host: "203.0.113.7", binary: "curl", action: "allow" }, { host: "203.0.113.7", port: 8080, action: "allow" }] },
  { egressRules: [{ host: "010.0.0.1", port: 443, action: "block" }, { host: "8.0.0.1", action: "allow" }], egressDefault: "block" },
  { egressRules: [{ host: "localhost", port: 5432, action: "block" }, { host: "localhost", action: "allow" }, { host: "127.0.0.1", port: 6379, method: "POST", action: "block" }], egressDefault: "block" },
  { egressRules: [{ host: "api.example.org", port: 443, method: "DELETE", action: "block" }, { host: "api.example.org", port: 443, action: "allow" }, { host: "*.example.org", port: 443, method: ["GET"], path: "/v1/*", action: "allow" }] },
  { egressRules: [{ host: "x.example.net", binary: "curl", action: "block" }, { host: "x.example.net", port: 443, action: "allow" }, { host: "[2001:db8::9]", action: "block" }, { host: "[2001:db8::9]", port: 443, action: "allow" }] },
  { egressRules: [{ host: "a.example.io", port: 443, path: "/admin/*", action: "block" }, { host: "a.example.io", port: 443, binary: ["git", "WebFetch"], action: "allow" }] }
];
const ALL = [...CASES.map((c) => c.input), ...ADVERSARIAL];
const validRules = (input) => (Array.isArray(input.egressRules) ? input.egressRules.slice(0, 512) : [])
  .map((r, index) => ({ r, index, v: validateEgressRule(r) })).filter((x) => !x.v.error);
const conditional = (r) => r.binary !== undefined || r.method !== undefined || r.path !== undefined;

// ---- independent evaluators of each target's output ----

const v4n = (a) => a.split(".").reduce((n, o) => n * 256 + Number(o), 0);
function inCidr(cidr, addr) {
  const [net, bits] = cidr.split("/");
  if (!/^\d+\.\d+\.\d+\.\d+$/.test(net) || !/^\d+\.\d+\.\d+\.\d+$/.test(addr)) return net === addr && (bits === "128" || bits === "32");
  const span = 2 ** (32 - Number(bits));
  return Math.floor(v4n(addr) / span) === Math.floor(v4n(net) / span);
}
function inPorts(ports, port) {
  if (!ports) return true;
  return ports.some((p) => p.port === undefined || (p.endPort === undefined ? p.port === port : port >= p.port && port <= p.endPort));
}
// MXC: an explicit deny wins, then any allow, else the default.
function mxcAllows(network, addr, port) {
  const hit = (rule) => (!rule.to || rule.to.some((t) => inCidr(t.cidr, addr))) && inPorts(rule.ports, port);
  if ((network.egress.deny || []).some(hit)) return false;
  if ((network.egress.allow || []).some(hit)) return true;
  return network.egress.default === "allow";
}
// Seatbelt as measured: among filtered rules the last match wins; else the unfiltered rule; else allow.
function seatbeltAllows(text, host, port) {
  const lines = text.split("\n").map((l) => l.trim()).filter((l) => l.startsWith("("));
  let dflt = "allow", last = null;
  for (const l of lines) {
    const m = l.match(/^\((allow|deny) network-outbound(?: \(remote ip "([^"]+)"\))?\)$/);
    if (!m) continue;
    if (!m[2]) { dflt = m[1]; continue; }
    const [h, p] = m[2].split(":");
    if ((h === "*" || (h === "localhost" && host === "localhost")) && (p === "*" || Number(p) === port)) last = m[1];
  }
  return (last || dflt) === "allow";
}
// OpenShell connection stage: some endpoint's host and port match (binaries are ignored, so this
// over-approximates what can connect).
function osHostMatch(pattern, host) {
  if (pattern.startsWith("**.")) return host.endsWith(pattern.slice(2)) && host.length > pattern.length - 2;
  return pattern === host;
}
function osEndpoints(policy, host, port) {
  return Object.values(policy.network_policies).flatMap((r) => r.endpoints)
    .filter((ep) => osHostMatch(ep.host, host) && (ep.ports || [ep.port]).includes(port));
}

// Sample tuples for a rule's host and ports.
function samples(e) {
  const h = e.v.rule.host;
  const hosts = h.suffix ? [`a${h.suffix}`, `b.c${h.suffix}`] : [h.exact];
  const ports = e.v.rule.port ? [...e.v.rule.port] : [1, 22, 443, 8443, 65535];
  return hosts.flatMap((host) => ports.map((port) => ({ host, port })));
}
const hostMatches = (v, host) => (v.rule.host.suffix ? host.endsWith(v.rule.host.suffix) : v.rule.host.exact === host);
const portMatches = (v, port) => !v.rule.port || v.rule.port.includes(port);

// ---- 1. golden ----

test("golden cases: every target reproduces its expected output (cargo replays mxc and seatbelt)", () => {
  assert.ok(CASES.length >= 10);
  for (const c of CASES) {
    const m = mxcEgress(c.input);
    assert.deepStrictEqual({ allow: m.allow, deny: m.deny, unexpressed: m.unexpressed }, c.mxc, `mxc: ${c.name}`);
    const s = seatbeltEgress(c.input);
    assert.deepStrictEqual({ text: s.text, unexpressed: s.unexpressed }, c.seatbelt, `seatbelt: ${c.name}`);
    assert.deepStrictEqual(openshellEgress(c.input), c.openshell, `openshell: ${c.name}`);
  }
});

test("the entry point returns the policy plus what could not be expressed, and refuses gVisor", () => {
  assert.deepEqual(SANDBOX_TARGETS, ["mxc", "seatbelt", "openshell"]);
  const input = { egressRules: [{ host: "203.0.113.1", port: 443, method: "GET", action: "allow" }], egressDefault: "block" };
  const mxc = sandboxPolicy(input, "mxc");
  assert.equal(mxc.ok, true);
  assert.deepEqual(mxc.policy.egress.allow, [{ to: [{ cidr: "203.0.113.1/32" }], ports: [{ protocol: "tcp", port: 443 }] }]);
  assert.deepEqual(mxc.unexpressed.map((u) => [u.index, u.fields, u.effect]), [[0, ["method"], "coarsened"]]);
  assert.equal(typeof sandboxPolicy(input, "seatbelt").policy, "string");
  const os = sandboxPolicy(input, "openshell");
  assert.match(os.yaml, /^version: 1\nnetwork_policies:\n {2}moorai_0:\n/);
  const g = sandboxPolicy(input, "gvisor");
  assert.equal(g.ok, false);
  assert.equal(g.reasonCode, "unsupported-target");
  assert.match(g.reason, /network policy/);
});

// ---- 2. schema ----

test("every MXC network section validates against microsoft/mxc stable schema 1.0.0", { skip: Ajv ? false : "ajv is not installed (run npm install)" }, () => {
  const ajv = new Ajv({ strict: false, allErrors: true });
  ajv.addSchema(SCHEMA);
  const validate = ajv.getSchema(`${SCHEMA.$id}#/definitions/Network`);
  for (const input of ALL) {
    const n = mxcNetwork(["140.82.112.0/20"], mxcEgress(input));
    assert.ok(validate(n), `${JSON.stringify(input).slice(0, 80)}: ${ajv.errorsText(validate.errors)}`);
  }
  assert.equal(validate({ egress: { default: "deny", deny: [{ to: [{ cidr: "1.2.3.4/32" }], ports: [{ port: 1, endPort: 70000 }] }] } }), false, "the validator is live");
});

// ---- 3. properties ----

test("default deny stays deny: MXC never opens its default, Seatbelt and OpenShell never name a wildcard host", () => {
  for (const input of ALL) {
    const n = mxcNetwork([], mxcEgress(input));
    assert.equal(n.egress.default, "deny");
    assert.deepEqual(n.ingress, { default: "deny", hostLoopback: "allow" });
    for (const r of n.egress.allow || []) for (const t of r.to) assert.match(t.cidr, /\/(32|128)$/, "allows name single addresses only");
    const sb = seatbeltEgress(input).text;
    assert.doesNotMatch(sb, /\(allow network-outbound \(remote (ip|tcp|udp)\d? "\*:/, "never allows a wildcard host");
    if (input.egressDefault === "block") {
      assert.match(sb, /^\(deny network-outbound\)$/m);
      assert.ok(!seatbeltAllows(sb, "203.0.113.200", 443), "a non-loopback host stays denied");
    }
    for (const r of Object.values(openshellEgress(input).policy.network_policies)) {
      for (const ep of r.endpoints) {
        assert.ok(ep.host && ep.host !== "*" && ep.host !== "**", "no catch-all host");
        if (ep.host.startsWith("**.")) assert.ok(ep.host.split(".").length >= 3, "wildcards keep three labels");
        assert.equal(ep.allowed_ips, undefined);
        assert.ok(ep.port || ep.ports, "every endpoint names its ports");
      }
    }
  }
});

test("a block rule is never let through by an over-broad expression", () => {
  let checked = 0;
  for (const input of ALL) {
    const rules = validRules(input);
    const net = mxcNetwork([], mxcEgress(input));
    const sb = seatbeltEgress(input).text;
    const os = openshellEgress(input).policy;
    for (const b of rules.filter((x) => x.r.action === "block" && !conditional(x.r))) {
      for (const t of samples(b)) {
        // First-match: an earlier unconditional allow/alert for the same tuple legitimately wins.
        const earlier = rules.filter((x) => x.index < b.index && hostMatches(x.v, t.host) && portMatches(x.v, t.port));
        if (earlier.some((x) => x.r.action !== "block" && !conditional(x.r))) continue;
        const v4 = /^\d+\.\d+\.\d+\.\d+$/.test(t.host), v6 = t.host.startsWith("[");
        const loopback = t.host === "localhost" || t.host === "[::1]" || t.host.startsWith("127.");
        if ((v4 || v6) && !loopback) {
          assert.equal(mxcAllows(net, v6 ? t.host.slice(1, -1) : t.host, t.port), false, `mxc lets ${t.host}:${t.port} through`);
          checked++;
        }
        if (t.host === "localhost") { assert.equal(seatbeltAllows(sb, "localhost", t.port), false, `seatbelt lets localhost:${t.port} through`); checked++; }
        if (!earlier.some((x) => x.r.action !== "block")) {
          assert.deepEqual(osEndpoints(os, t.host, t.port), [], `openshell lets ${t.host}:${t.port} through`);
          checked++;
        }
      }
    }
  }
  assert.ok(checked >= 40, `checked ${checked} tuples`);
});

test("conditional blocks become OpenShell deny_rules that cover the blocked method on every path they could name", () => {
  const os = openshellEgress(ADVERSARIAL[7]).policy.network_policies;
  assert.deepEqual(os.moorai_1.endpoints[0].deny_rules, [{ method: "DELETE", path: "**" }]);
  assert.equal(os.moorai_1.endpoints[0].access, "full");
  assert.deepEqual(os.moorai_2.endpoints[0].deny_rules, [{ method: "DELETE", path: "**" }], "the wildcard allow inherits the deny too");
  const admin = openshellEgress(ADVERSARIAL[9]).policy.network_policies.moorai_1.endpoints[0];
  assert.deepEqual(admin.deny_rules, [{ method: "*", path: "**" }], "a prefix-path block is widened to every path, never narrowed");
});

test("every field a target cannot carry is reported, never silently widened", () => {
  for (const input of ALL) {
    const rules = validRules(input);
    const mxc = mxcEgress(input).unexpressed, sb = seatbeltEgress(input).unexpressed, os = openshellEgress(input).unexpressed;
    const at = (list, i) => list.filter((u) => u.index === i);
    for (const { r, index, v } of rules) {
      const h = v.rule.host;
      const ip = !h.suffix && (/^\d+\.\d+\.\d+\.\d+$/.test(h.exact) || h.exact.startsWith("[")) && !h.exact.startsWith("127.") && h.exact !== "[::1]";
      const cond = ["binary", "method", "path"].filter((k) => r[k] !== undefined);
      // MXC carries numeric hosts and ports only.
      if (!ip) assert.ok(at(mxc, index).some((u) => u.fields.includes("host") && u.effect === "omitted"), `mxc #${index} host`);
      else if (cond.length) assert.ok(at(mxc, index).some((u) => cond.every((f) => u.fields.includes(f)) && ["coarsened", "omitted"].includes(u.effect)), `mxc #${index} ${cond}`);
      // Seatbelt carries "localhost" and ports only.
      if (h.suffix || !["localhost", "127.0.0.1", "[::1]"].includes(h.exact)) assert.ok(at(sb, index).some((u) => u.reason === "seatbelt-host"), `seatbelt #${index}`);
      else {
        if (h.exact !== "localhost") assert.ok(at(sb, index).some((u) => u.reason === "seatbelt-localhost-alias"), `seatbelt alias #${index}`);
        if (cond.length) assert.ok(at(sb, index).some((u) => cond.every((f) => u.fields.includes(f))), `seatbelt #${index} ${cond}`);
      }
      // OpenShell: binaries are matched differently, ports are mandatory, and an emitted rule is listed.
      if (r.action !== "block") {
        const emitted = Object.keys(openshellEgress(input).policy.network_policies).includes(`moorai_${index}`);
        if (!emitted) assert.ok(at(os, index).some((u) => ["omitted", "narrowed"].includes(u.effect)), `openshell #${index} missing without a report`);
        if (emitted && r.binary !== undefined) assert.ok(at(os, index).some((u) => u.fields.includes("binary")), `openshell #${index} binary`);
        if (r.port === undefined) assert.ok(!emitted, `openshell #${index} emitted without a port`);
      }
    }
    // MoorAI's default is allow; a target that keeps deny says so.
    if (input.egressDefault !== "block") {
      assert.ok(mxc.some((u) => u.index === -1 && u.reason === "mxc-default-deny"));
      assert.ok(os.some((u) => u.index === -1 && u.reason === "openshell-default-deny"));
    }
  }
});

test("reports carry no host, path or binary values", () => {
  const input = { egressRules: [{ id: "keep-id", host: "secret-host.example", binary: "curl", method: "POST", path: "/token/*", action: "allow" }, { host: "s3cret.example", port: 1, action: "nope" }] };
  for (const t of SANDBOX_TARGETS) {
    const text = JSON.stringify(sandboxPolicy(input, t).unexpressed);
    for (const leak of ["secret-host", "s3cret", "/token", "curl\""]) assert.ok(!text.includes(leak), `${t} report leaks ${leak}`);
    assert.ok(text.includes("keep-id"));
  }
});

test("MXC launch policy: egressRules add numeric rules next to egressAllow, a block carves the CIDR, nothing else moves", async () => {
  const { buildMxcPolicy } = await import("../cli/mxc-policy.mjs");
  const ENV = { USERPROFILE: "C:\\Users\\dev", ProgramData: "C:\\ProgramData", ProgramFiles: "C:\\Program Files", SystemRoot: "C:\\Windows" };
  const base = { agent: "claude", workspace: "C:\\src\\proj", env: ENV, commandLine: "claude.exe", egressAllow: ["140.82.112.0/20"] };
  const plain = buildMxcPolicy(base);
  const ruled = buildMxcPolicy({ ...base, egressRules: [{ host: "140.82.112.9", action: "block" }, { host: "*.github.com", action: "allow" }], egressDefault: "allow" });
  assert.equal(plain.egressUnexpressed, undefined);
  assert.deepEqual({ ...ruled.policy, network: plain.policy.network }, plain.policy, "only the network section changes");
  assert.equal(mxcAllows(plain.policy.network, "140.82.112.9", 443), true);
  assert.equal(mxcAllows(ruled.policy.network, "140.82.112.9", 443), false);
  assert.equal(mxcAllows(ruled.policy.network, "140.82.112.10", 443), true);
  assert.equal(ruled.policy.network.egress.default, "deny");
  assert.deepEqual(ruled.egressUnexpressed.map((u) => u.reason), ["mxc-host-name", "mxc-default-deny"]);
});

test("CLI: prints the policy on stdout and the unexpressed list on stderr", () => {
  const dir = mkdtempSync(join(tmpdir(), "moorai-sbp-"));
  try {
    const f = join(dir, "rules.json");
    writeFileSync(f, JSON.stringify({ egressRules: [{ host: "api.example.com", port: 443, action: "allow" }, { host: "localhost", action: "block" }], egressDefault: "block" }));
    const os = spawnSync(process.execPath, [CLI, "--target", "openshell", "--rules", f], { encoding: "utf8" });
    assert.equal(os.status, 0, os.stderr);
    assert.match(os.stdout, /host: "api\.example\.com"\n\s+port: 443\n/);
    assert.match(os.stderr, /openshell-loopback/);
    const sb = spawnSync(process.execPath, [CLI, "--target", "seatbelt", "--rules", f], { encoding: "utf8" });
    assert.match(sb.stdout, /^\(deny network-outbound\)$/m);
    assert.doesNotMatch(sb.stdout, /localhost/, "a blocked loopback under a deny default needs no loopback allow");
    const bad = spawnSync(process.execPath, [CLI, "--target", "gvisor", "--rules", f], { encoding: "utf8" });
    assert.equal(bad.status, 1);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// ---- 4. measured on macOS ----

const SB_SKIP = process.platform !== "darwin" ? "macOS only" : spawnSync("sandbox-exec", ["-p", "(version 1)(allow default)", "/usr/bin/true"]).status !== 0 ? "sandbox-exec unavailable" : false;

test("Seatbelt: the generated section, run under sandbox-exec, denies exactly what it says", { skip: SB_SKIP }, async () => {
  const servers = await Promise.all([0, 0].map(() => new Promise((res) => { const s = createServer((c) => c.end()).listen(0, "127.0.0.1", () => res(s)); })));
  const [open, blocked] = servers.map((s) => s.address().port);
  try {
    const { text, unexpressed } = seatbeltEgress({ egressRules: [{ host: "localhost", port: blocked, action: "block" }, { host: "api.example.com", action: "allow" }], egressDefault: "block" });
    assert.ok(unexpressed.some((u) => u.index === 1 && u.reason === "seatbelt-host"), "the hostname allow is reported, not opened");
    const profile = `(version 1)\n(allow default)\n${text}`;
    const probe = `const net=require("node:net");const t=(h,p)=>new Promise(r=>{const s=net.connect({host:h,port:p});s.setTimeout(1500,()=>{s.destroy();r("timeout")});s.on("connect",()=>{s.destroy();r("connected")});s.on("error",e=>r(e.code))});(async()=>{console.log(JSON.stringify({open:await t("127.0.0.1",${open}),blocked:await t("127.0.0.1",${blocked}),remote:await t("192.0.2.1",443)}))})()`;
    const out = await new Promise((res, rej) => {
      const c = spawn("sandbox-exec", ["-p", profile, process.execPath, "-e", probe], { stdio: ["ignore", "pipe", "pipe"] });
      let o = "", e = "";
      c.stdout.on("data", (d) => (o += d));
      c.stderr.on("data", (d) => (e += d));
      c.on("close", (code) => (code === 0 ? res(o) : rej(new Error(`sandbox-exec ${code}: ${e}`))));
    });
    assert.deepEqual(JSON.parse(out), { open: "connected", blocked: "EPERM", remote: "EPERM" });
  } finally { for (const s of servers) s.close(); }
});
