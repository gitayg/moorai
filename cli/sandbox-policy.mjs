#!/usr/bin/env node
// egressRules / egressDefault (cli/egress-rules.mjs, the rule set MoorAI's own check judges) -> the network
// part of a kernel sandbox policy, so one rule set drives both layers. Pure: no filesystem, no clock.
//
//   sandboxPolicy({ egressRules, egressDefault }, "mxc" | "seatbelt" | "openshell")
//     -> { ok:true, target, policy, unexpressed:[...] } | { ok:false, reasonCode, reason }
//
// A sandbox sees connections, not calls. What it cannot express is listed in `unexpressed`, one entry per
// rule (or for egressDefault, index -1), never silently widened:
//   { index, id?, action, fields:[...], effect, reason }
//   effect "omitted"     the rule is not in the sandbox policy; MoorAI's check is the only layer for it.
//          "coarsened"   an allow is in the sandbox without these fields: the sandbox lets more through than
//                        the rule, and MoorAI's check still enforces the fields.
//          "narrowed"    the sandbox is stricter than the rule here (some traffic the rule allows is denied).
//          "approximated" the sandbox matches these fields by a different notion (OpenShell binaries).
//          "may-be-inert" emitted, but the backend may need more than MoorAI grants for it to take effect.
//          "invalid"     MoorAI drops the rule (or the default) too.
//
// Semantics carried over: rules are read in order and the first match decides; `alert` lets a call through,
// so it counts as allow; no egressDefault means allow; loopback (localhost, 127.0.0.1, [::1]) with no
// matching rule is allowed whatever the default. A rule's binary, method or path cannot be seen by a
// connection-level sandbox, so for one (host, port) a conditional allow makes the sandbox allow it (MoorAI
// judges the rest), a conditional block leaves it to the default, and an unconditional block always wins
// over a coarsened allow — a block never ends up allowed through an over-broad expression.
//
// Targets: mxc (Windows, cli/mxc-policy.mjs; mirrored in src-tauri/src/mxc_egress.rs), seatbelt (macOS
// sandbox-exec; mirrored in the same Rust file, used by src-tauri/src/platform.rs), openshell (NVIDIA
// OpenShell network_policies, JS only). gVisor is not a target: runsc does no per-host egress policy, its
// egress comes from the deployment's network policy. Design notes: docs/CAPABILITY_SPEC.md "Sandbox egress
// policies from egressRules".
//
//   node cli/sandbox-policy.mjs --target mxc|seatbelt|openshell --rules <file.json>

import { readFileSync, realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { validateEgressRule, normBinary, validEgressDefault } from "./egress-rules.mjs";

export const SANDBOX_TARGETS = Object.freeze(["mxc", "seatbelt", "openshell"]);
const MAX_RULES = 512; // cli/egress-rules.mjs validateEgressRules reads at most this many
const ID_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const V4 = /^\d+\.\d+\.\d+\.\d+$/; // WHATWG serialises every IPv4 host as four decimal parts

// ---- rules -> normalised entries (shared by every target) ----

// The validated host -> { kind, host }. kind: "ip4" | "ip6" | "name" | "suffix". `host` is the WHATWG form
// MoorAI's own check compares against (cli/egress-rules.mjs ruleHost), so two spellings of one address are
// one address here too.
function hostOf(v) {
  if (v.host.suffix) return { kind: "suffix", host: v.host.suffix };
  const h = v.host.exact;
  if (h.startsWith("[")) return { kind: "ip6", host: h };
  if (V4.test(h)) return { kind: "ip4", host: h };
  return { kind: "name", host: h };
}
const isLoopbackName = (h) => h === "localhost" || h === "127.0.0.1" || h === "[::1]";
const isLoopbackRange = (k, h) => (k === "ip4" && h.startsWith("127.")) || (k === "ip6" && h === "[::1]") || (k === "name" && h === "localhost");

// { entries, slots, list } — entries: the valid rules in order; slots[index]: report lines for that rule;
// list: report lines about the list itself.
function readRules(raw) {
  const out = { entries: [], slots: new Map(), list: [] };
  if (raw === undefined || raw === null) return out;
  if (!Array.isArray(raw)) { out.list.push({ index: -1, fields: ["egressRules"], effect: "invalid", reason: "not-a-list" }); return out; }
  raw.slice(0, MAX_RULES).forEach((r, index) => {
    const v = validateEgressRule(r);
    if (v.error) {
      const id = r && typeof r.id === "string" && ID_RE.test(r.id) ? r.id : undefined;
      out.slots.set(index, [{ index, ...(id ? { id } : {}), fields: ["rule"], effect: "invalid", reason: "invalid-rule" }]);
      return;
    }
    const cond = ["binary", "method", "path"].filter((k) => r[k] !== undefined);
    out.entries.push({
      index, raw: r, v, ...(v.rule.id ? { id: v.rule.id } : {}), action: r.action, allow: r.action !== "block",
      ...hostOf(v.rule), ports: v.rule.port ? [...new Set(v.rule.port)].sort((a, b) => a - b) : null, cond
    });
  });
  if (raw.length > MAX_RULES) out.list.push({ index: MAX_RULES, fields: ["egressRules"], effect: "invalid", reason: "too-many-rules" });
  return out;
}

function note(st, e, fields, effect, reason) {
  const line = { index: e.index, ...(e.id ? { id: e.id } : {}), action: e.action, fields, effect, reason };
  const slot = st.slots.get(e.index) || [];
  if (!slot.some((x) => x.reason === reason)) slot.push(line);
  st.slots.set(e.index, slot);
}

function report(st, tail) {
  const idx = [...st.slots.keys()].sort((a, b) => a - b);
  return [...idx.flatMap((i) => st.slots.get(i)), ...st.list, ...tail];
}

function readDefault(raw, tail) {
  if (raw === undefined || raw === null) return "allow";
  if (validEgressDefault(raw)) return raw === "block" ? "block" : "allow";
  tail.push({ index: -1, fields: ["egressDefault"], effect: "invalid", reason: "invalid-default" });
  return "allow";
}

// The first-match decision for one (address, port) atom. `port` null is "any port no rule names".
// -> { v: "allow"|"deny", by: "rule"|"coarse"|"default", shadowed: [entries] }
function decide(list, port, fallthrough, st, tag) {
  const maybe = [];
  for (const e of list) {
    if (!(e.ports === null || (port !== null && e.ports.includes(port)))) continue;
    if (e.cond.length) { if (e.allow) maybe.push(e); continue; }
    if (e.allow) return { v: "allow", by: "rule" };
    for (const m of maybe) note(st, m, m.cond, "narrowed", `${tag}-block-wins`);
    return { v: "deny", by: "rule" };
  }
  if (maybe.length) return { v: "allow", by: "coarse" };
  return { v: fallthrough, by: "default" };
}

function atoms(list, fallthrough, st, tag) {
  const ports = [...new Set(list.flatMap((e) => e.ports || []))].sort((a, b) => a - b);
  return { other: decide(list, null, fallthrough, st, tag), ports: ports.map((p) => ({ port: p, ...decide(list, p, fallthrough, st, tag) })) };
}

// ---- MXC (microsoft/mxc stable schema 1.0.0) ----
//
// Fields used (test/fixtures/mxc/mxc-config.schema.1.0.0.json):
//   NetworkEgress.deny   "Optional explicit deny rules. Deny takes precedence over allow."
//   NetworkRule.to       "Optional destination CIDRs."      NetworkPeer.cidr "The IPv4 or IPv6 CIDR ..."
//   NetworkPort.port / endPort ("Optional inclusive end of a destination-port range") / protocol
// Numeric destinations only (networking.md 1.1: "The egress schema selects numeric destinations, protocols,
// and ports, not durable DNS names or application payloads"), and host loopback is the single
// bidirectional `ingress.hostLoopback` switch the model proxy needs, so loopback rules cannot be expressed.
// The launch keeps `egress.default: "deny"`; egressDefault never opens it.

function isPrivate(kind, host) {
  if (kind === "ip4") {
    const [a, b] = host.split(".").map(Number);
    return a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254);
  }
  const first = parseInt(host.slice(1).split(":")[0] || "0", 16);
  return (first & 0xfe00) === 0xfc00 || (first & 0xffc0) === 0xfe80;
}

function complement(ports) {
  const out = [];
  let lo = 1;
  for (const p of ports) {
    if (p > lo) out.push(p - 1 === lo ? { port: lo } : { port: lo, endPort: p - 1 });
    lo = p + 1;
  }
  if (lo <= 65535) out.push(lo === 65535 ? { port: lo } : { port: lo, endPort: 65535 });
  return out;
}

// -> { allow:[NetworkRule], deny:[NetworkRule], unexpressed }
export function mxcEgress({ egressRules, egressDefault } = {}) {
  const st = readRules(egressRules), tail = [];
  const d = readDefault(egressDefault, tail);
  if (d !== "block") tail.push({ index: -1, fields: ["egressDefault"], effect: "narrowed", reason: "mxc-default-deny" });
  const byAddr = new Map();
  for (const e of st.entries) {
    if (isLoopbackRange(e.kind, e.host)) { note(st, e, ["host"], "omitted", "mxc-loopback"); continue; }
    if (e.kind === "name" || e.kind === "suffix") { note(st, e, ["host"], "omitted", "mxc-host-name"); continue; }
    if (e.cond.length) note(st, e, e.cond, e.allow ? "coarsened" : "omitted", "mxc-l7-fields");
    if (e.allow && isPrivate(e.kind, e.host)) note(st, e, ["host"], "may-be-inert", "mxc-private-network");
    if (!byAddr.has(e.host)) byAddr.set(e.host, []);
    byAddr.get(e.host).push(e);
  }
  const allow = [], deny = [];
  for (const [host, list] of byAddr) {
    const to = [{ cidr: host.startsWith("[") ? `${host.slice(1, -1)}/128` : `${host}/32` }];
    const a = atoms(list, "deny", st, "mxc");
    const allowed = a.ports.filter((x) => x.v === "allow").map((x) => x.port);
    const ruleDenied = a.ports.filter((x) => x.v === "deny" && x.by === "rule").map((x) => x.port);
    if (a.other.v === "allow") {
      allow.push({ to, ports: [{ protocol: "tcp" }] });
      const denied = a.ports.filter((x) => x.v === "deny").map((x) => x.port);
      if (denied.length) deny.push({ to, ports: denied.map((port) => ({ port })) });
      continue;
    }
    if (allowed.length) allow.push({ to, ports: allowed.map((port) => ({ protocol: "tcp", port })) });
    if (a.other.by === "rule") deny.push(allowed.length ? { to, ports: complement(allowed) } : { to });
    else if (ruleDenied.length) deny.push({ to, ports: ruleDenied.map((port) => ({ port })) });
  }
  return { allow, deny, unexpressed: report(st, tail) };
}

// The `network` section of an MXC launch request. `cidrAllow` is the host-only numeric egressAllow list
// cli/mxc-policy.mjs already carried (tcp/443).
export function mxcNetwork(cidrAllow, egress) {
  const network = { egress: { default: "deny" }, ingress: { default: "deny", hostLoopback: "allow" } };
  const allow = [];
  if (cidrAllow.length) allow.push({ to: cidrAllow.map((cidr) => ({ cidr })), ports: [{ protocol: "tcp", port: 443 }] });
  if (egress) allow.push(...egress.allow);
  if (allow.length) network.egress.allow = allow;
  if (egress && egress.deny.length) network.egress.deny = egress.deny;
  return network;
}

// ---- Seatbelt (macOS sandbox-exec SBPL) ----
//
// Measured on macOS 27.0 (26A428), sandbox-exec -p:
//   (remote ip "1.2.3.4:443")      -> "host must be * or localhost in network address"
//   (remote ip "example.com:443")  -> same error;  (remote ip "*:1-100") -> "invalid port in network address"
//   (remote ip "localhost:*") allows 127.0.0.1 and ::1 (and 0.0.0.0), not 127.0.0.2
//   between filtered rules the last match wins; an unfiltered (deny network-outbound) is the default
//   whatever its position; a bare deny also refuses AF_UNIX connects unless (remote unix-socket) is allowed.
// So only loopback can be named. Every other host keeps the default: egressDefault "block" denies all
// outbound but loopback (route allowed hosts through a loopback proxy); anything else keeps today's allow.

export function seatbeltEgress({ egressRules, egressDefault } = {}) {
  const st = readRules(egressRules), tail = [];
  const d = readDefault(egressDefault, tail) === "block" ? "deny" : "allow";
  const lo = [];
  for (const e of st.entries) {
    if (e.kind === "suffix" || !isLoopbackName(e.host)) { note(st, e, ["host"], "omitted", "seatbelt-host"); continue; }
    if (e.host !== "localhost") note(st, e, ["host"], e.allow ? "coarsened" : "narrowed", "seatbelt-localhost-alias");
    if (e.cond.length) note(st, e, e.cond, e.allow ? "coarsened" : "omitted", "seatbelt-l7-fields");
    lo.push(e);
  }
  const a = atoms(lo, "allow", st, "seatbelt");
  const lines = [";; egress: generated by MoorAI from egressRules/egressDefault (cli/sandbox-policy.mjs)"];
  if (d === "deny") lines.push("(deny network-outbound)", "(allow network-outbound (remote unix-socket))");
  if (a.other.v !== d) lines.push(`(${a.other.v} network-outbound (remote ip "localhost:*"))`);
  for (const x of a.ports) if (x.v !== a.other.v) lines.push(`(${x.v} network-outbound (remote ip "localhost:${x.port}"))`);
  return { text: lines.join("\n") + "\n", unexpressed: report(st, tail) };
}

// ---- OpenShell (NVIDIA/OpenShell @ b959bb6, docs/how-it-works/policies/schema.mdx + network-rules.mdx) ----
//
//   "OpenShell checks every outbound connection from a sandbox against the `network_policies` section of its
//    policy, and denies any connection that no rule allows."  -> default deny, nothing else expressible.
//   "Network rules are not an ordered firewall list ... A matching deny rule takes precedence over any allow"
//   endpoint: host ("Hostname, IP address, or wildcard pattern"), port | ports ("Set `port` or `ports`"),
//   protocol rest, enforcement enforce, rules [{allow:{method,path}}], access full, deny_rules [{method,path}]
//   "A wildcard host must have at least three DNS labels"; "`**` is allowed only as the whole first label"
//   binaries [{path}] "Executable path or glob"; "A binary matches the executable that opens the connection
//   or any of its parent processes"; "A rule with an empty `binaries` list matches no binary".
//   "Network policy never authorizes an outbound endpoint whose destination is loopback, link-local, or
//    unspecified" ... "also blocks the Kubernetes and etcd control-plane ports 2379, 2380, 6443, 10250, 10255"
// There is no connection-level deny, so an earlier MoorAI block that an OpenShell allow would cover either
// becomes request deny_rules (method/path blocks) or removes that allow (fail-safe).

const CONTROL_PLANE = [2379, 2380, 6443, 10250, 10255];
const GLOB_CHARS = /[*?[\]]/;
const NOT_EXECUTABLE = (b) => b === "webfetch" || b === "websearch" || b.includes("__") || b === "invoke-webrequest" || b === "invoke-restmethod";

function osHost(e) {
  if (e.kind === "suffix") {
    const labels = e.host.slice(1).split(".");
    return labels.length >= 2 ? { host: `**${e.host}` } : { reason: "openshell-wildcard-labels" };
  }
  if (isLoopbackRange(e.kind, e.host)) return { reason: "openshell-loopback" };
  if (e.kind === "ip6") return { reason: "openshell-ipv6-unconfirmed" };
  if (e.kind === "ip4" && (e.host.startsWith("169.254.") || e.host === "0.0.0.0")) return { reason: "openshell-blocked-range" };
  return { host: e.host };
}
const binNames = (e) => (e.raw.binary === undefined ? null : [].concat(e.raw.binary).map((b) => normBinary(String(b).trim())));
const literal = (names) => names && names.every((n) => !n.includes("*"));
function binOverlap(a, b) {
  const x = binNames(a), y = binNames(b);
  if (!x || !y || !literal(x) || !literal(y)) return true;
  return x.some((n) => y.includes(n));
}
function binCovers(b, a) {
  const x = binNames(a), y = binNames(b);
  if (!y) return true;
  return !!x && literal(x) && literal(y) && x.every((n) => y.includes(n));
}
function hostOverlap(a, b) {
  if (a.kind !== "suffix" && b.kind !== "suffix") return a.host === b.host;
  if (a.kind === "suffix" && b.kind === "suffix") return a.host.endsWith(b.host) || b.host.endsWith(a.host);
  const [s, x] = a.kind === "suffix" ? [a, b] : [b, a];
  return x.host.endsWith(s.host);
}
function hostCovers(b, a) {
  if (b.kind !== "suffix") return a.kind !== "suffix" && a.host === b.host;
  return a.host.endsWith(b.host);
}
const portOverlap = (a, b) => !a.ports || !b.ports || a.ports.some((p) => b.ports.includes(p));
const portCovers = (b, a) => !b.ports || (!!a.ports && a.ports.every((p) => b.ports.includes(p)));

// MoorAI path (validated, normalised) -> OpenShell rule path globs, or null when it cannot be written.
function allowPaths(p) {
  if (!p) return ["**"];
  if (p.exact !== undefined) return GLOB_CHARS.test(p.exact) ? null : [p.exact];
  const q = p.prefix;
  if (GLOB_CHARS.test(q)) return null;
  if (q === "/") return ["**"];
  return q.endsWith("/") ? [`${q}**`] : [`${q}*`, `${q}*/**`];
}

export function openshellEgress({ egressRules, egressDefault } = {}) {
  const st = readRules(egressRules), tail = [];
  if (readDefault(egressDefault, tail) !== "block") tail.push({ index: -1, fields: ["egressDefault"], effect: "narrowed", reason: "openshell-default-deny" });
  const blocks = [], emitted = [];
  const network_policies = {};
  for (const e of st.entries) {
    if (!e.allow) {
      if (isLoopbackRange(e.kind, e.host)) note(st, e, ["host"], "omitted", "openshell-loopback");
      blocks.push(e);
      continue;
    }
    const h = osHost(e);
    if (!h.host) { note(st, e, ["host"], "omitted", h.reason); continue; }
    if (!e.ports) { note(st, e, ["port"], "omitted", "openshell-port-required"); continue; }
    let binaries = [{ path: "/**" }];
    const names = binNames(e);
    if (names) {
      if (names.includes("*")) binaries = [{ path: "/**" }];
      else {
        const exe = names.filter((n) => !NOT_EXECUTABLE(n));
        if (!exe.length) { note(st, e, ["binary"], "omitted", "openshell-binary-not-executable"); continue; }
        if (exe.length < names.length) note(st, e, ["binary"], "narrowed", "openshell-binary-not-executable");
        binaries = [...new Set(exe)].map((n) => ({ path: `/**/${n}` }));
      }
      note(st, e, ["binary"], "approximated", "openshell-binary-identity");
    }
    const paths = allowPaths(e.v.rule.path);
    if (!paths) { note(st, e, ["path"], "omitted", "openshell-path-glob-chars"); continue; }
    if (e.v.rule.path && e.v.rule.path.prefix !== undefined && e.v.rule.path.prefix !== "/") note(st, e, ["path"], "narrowed", "openshell-path-prefix");
    const denyRules = [];
    let dropped = false;
    for (const b of blocks) {
      if (!hostOverlap(e, b) || !portOverlap(e, b) || !binOverlap(e, b)) continue;
      const exact = hostCovers(b, e) && portCovers(b, e) && binCovers(b, e);
      if (!b.cond.includes("method") && !b.cond.includes("path")) {
        note(st, e, ["host"], exact ? "omitted" : "narrowed", exact ? "openshell-shadowed-by-block" : "openshell-no-connection-deny");
        dropped = true;
        break;
      }
      const bp = b.v.rule.path;
      const dpaths = !bp ? ["**"] : bp.exact !== undefined && !GLOB_CHARS.test(bp.exact) ? [bp.exact] : ["**"];
      for (const m of b.v.rule.method || ["*"]) for (const path of dpaths) {
        if (!denyRules.some((r) => r.method === m && r.path === path)) denyRules.push({ method: m, path });
      }
      if (!exact || b.cond.includes("binary") || (bp && bp.exact === undefined)) note(st, e, ["method", "path"], "narrowed", "openshell-deny-broadened");
    }
    if (dropped) continue;
    const ep = { host: h.host, ...(e.ports.length === 1 ? { port: e.ports[0] } : { ports: e.ports }) };
    const inspected = !!(e.v.rule.method || e.v.rule.path) || denyRules.length > 0;
    if (inspected) {
      ep.protocol = "rest";
      ep.enforcement = "enforce";
      if (e.v.rule.method || e.v.rule.path) ep.rules = (e.v.rule.method || ["*"]).flatMap((method) => paths.map((path) => ({ allow: { method, path } })));
      else { ep.access = "full"; note(st, e, ["port"], "narrowed", "openshell-inspected"); }
      if (denyRules.length) ep.deny_rules = denyRules;
    }
    if (e.kind !== "suffix" && e.ports.some((p) => CONTROL_PLANE.includes(p))) note(st, e, ["port"], "narrowed", "openshell-control-plane-port");
    network_policies[`moorai_${e.index}`] = { ...(e.id ? { name: e.id } : {}), endpoints: [ep], binaries };
    emitted.push({ e, inspected });
  }
  for (const x of emitted) {
    if (x.inspected) continue;
    if (emitted.some((y) => y.inspected && hostOverlap(x.e, y.e) && portOverlap(x.e, y.e))) note(st, x.e, ["method", "path"], "narrowed", "openshell-mixed-inspection");
  }
  const policy = { version: 1, network_policies };
  return { policy, yaml: toYaml(policy), unexpressed: report(st, tail) };
}

// Minimal YAML: block maps and lists, every string double-quoted (a JSON string is a valid YAML scalar).
export function toYaml(v, ind = "") {
  const scalar = (x) => (typeof x === "string" ? JSON.stringify(x) : String(x));
  const isObj = (x) => x && typeof x === "object";
  if (Array.isArray(v)) {
    return v.map((x) => {
      if (!isObj(x)) return `${ind}- ${scalar(x)}\n`;
      const body = toYaml(x, ind + "  ");
      return `${ind}- ${body.slice(ind.length + 2)}`;
    }).join("");
  }
  return Object.entries(v).map(([k, x]) => {
    if (!isObj(x)) return `${ind}${k}: ${scalar(x)}\n`;
    if (Array.isArray(x) ? !x.length : !Object.keys(x).length) return `${ind}${k}: ${Array.isArray(x) ? "[]" : "{}"}\n`;
    return `${ind}${k}:\n${toYaml(x, ind + "  ")}`;
  }).join("");
}

// ---- the one entry point ----
export function sandboxPolicy(rules, target) {
  const r = rules && typeof rules === "object" ? rules : {};
  const input = { egressRules: r.egressRules, egressDefault: r.egressDefault };
  if (target === "mxc") {
    const eg = mxcEgress(input);
    return { ok: true, target, policy: mxcNetwork([], eg), unexpressed: eg.unexpressed };
  }
  if (target === "seatbelt") {
    const sb = seatbeltEgress(input);
    return { ok: true, target, policy: sb.text, unexpressed: sb.unexpressed };
  }
  if (target === "openshell") {
    const os = openshellEgress(input);
    return { ok: true, target, policy: os.policy, yaml: os.yaml, unexpressed: os.unexpressed };
  }
  return { ok: false, reasonCode: "unsupported-target", reason: `target must be one of ${SANDBOX_TARGETS.join(", ")} (gVisor: egress comes from the deployment's network policy)` };
}

// ---- CLI ----
const HELP = `sandbox-policy — the network part of a sandbox policy from MoorAI egressRules/egressDefault

  node cli/sandbox-policy.mjs --target mxc|seatbelt|openshell --rules <file.json>

<file.json> is an object with egressRules and/or egressDefault (a policy or machine-wide config works).
Prints the policy (openshell: YAML) on stdout and every rule the target cannot express on stderr.
`;

function main(argv) {
  if (!argv.length || argv.includes("--help") || argv.includes("-h")) { process.stdout.write(HELP); return 0; }
  let target = "", file = "";
  for (let k = 0; k < argv.length; k++) {
    if (argv[k] === "--target") target = argv[++k];
    else if (argv[k] === "--rules") file = argv[++k];
    else { process.stderr.write(`unknown argument ${argv[k]}\n`); return 2; }
  }
  let doc;
  try { doc = JSON.parse(readFileSync(file, "utf8")); } catch (e) { process.stderr.write(`sandbox-policy: cannot read ${file || "(no --rules)"}: ${e.message}\n`); return 2; }
  const r = sandboxPolicy(doc, target);
  if (!r.ok) { process.stderr.write(`sandbox-policy: ${r.reasonCode}: ${r.reason}\n`); return 1; }
  process.stdout.write(target === "openshell" ? r.yaml : typeof r.policy === "string" ? r.policy : JSON.stringify(r.policy, null, 2) + "\n");
  for (const u of r.unexpressed) process.stderr.write(`not expressed: ${JSON.stringify(u)}\n`);
  return 0;
}

const isMain = (() => { try { return realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url)); } catch { return false; } })();
if (isMain) process.exit(main(process.argv.slice(2)));
