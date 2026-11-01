// mcpServerSandbox: start the real MCP server under a kernel network sandbox built from MoorAI's egress
// rules, so what the server's own code does with the network is bounded too, not only what its JSON-RPC
// says. The stdio guard (./moorai-mcp-guard.mjs) plans the spawn here and changes nothing else: same
// command, same arguments, same environment, same stdio pipes.
//
//   mcpServerSandbox "off" (default) | "network"
//
// WHO DECIDES. The root-owned admin binding (top-level key), then the verified signed policy, then "off":
// the precedence of failMode (cli/fail-mode.mjs) and containmentClaudeCode (cli/containment-enforce.mjs).
// Exact lowercase values only; anything else is warned about by source and key, never the value, and the
// next source decides. The guard reads both before the spawn, from local copies only (no fetch).
//
// WHAT "network" DOES. macOS: `sandbox-exec -p <profile> <cmd> <args...>`, where the profile is
// `(allow default)` plus the Seatbelt network section cli/sandbox-policy.mjs builds from egressRules /
// egressDefault (the policy's rules, then the admin binding's; the policy's default, else the admin
// binding's — the order MoorAI's own egress check reads them in, cli/egress-rules.mjs egressFrom).
// Seatbelt can name loopback only, so:
//   egressDefault "block"   every outbound connection but loopback (and AF_UNIX) is refused by the kernel
//                           (EPERM). An allow rule for an internet host is NOT in the profile ("omitted",
//                           reported): allowed hosts fail too, and so does a server that fetches its own
//                           code at start (`npx -y pkg`). DNS (mDNSResponder), AppleEvents and exec of
//                           /usr/bin/open and /usr/bin/osascript are denied too (CONTAIN_LINES).
//   anything else           no non-loopback host and no DNS is restricted; only loopback port rules apply.
// Not full containment either way: file and process access are not restricted.
// Every rule sandboxPolicy cannot express is listed (stderr + one content-free alert), never widened.
//
// WHEN IT CANNOT RUN (Linux, Windows, no /usr/bin/sandbox-exec, a profile that could not be built), the
// mcpGateway fail mode decides (cli/mcp-fail.mjs): closed → the server is not started (one Blocked alert,
// reasonCode CONTAINMENT_UNAVAILABLE); open (the default) → it starts unsandboxed with a High alert and a
// stderr line. Coach mode (unenrolled, unmanaged) never refuses, as for every other guard block.
//
// Content-free: alerts carry the mode, a fixed reason token, the server label and, for unexpressed rules,
// each rule's index, id, action, fields, effect and reason. Never a host, a command or an argument.
import { existsSync } from "node:fs";
import { EventEmitter } from "node:events";
import { PassThrough, Writable } from "node:stream";
import { sandboxPolicy } from "../cli/sandbox-policy.mjs";
import { REASON, ENFORCEMENT } from "../cli/provenance.mjs";

export const SERVER_SANDBOX_MODES = Object.freeze(["off", "network"]);
export const SANDBOX_EXEC = "/usr/bin/sandbox-exec";
export const SERVER_SANDBOX_CATEGORY = "Containment: MCP server sandbox unavailable";
export const SERVER_SANDBOX_UNEXPRESSED_CATEGORY = "Containment: MCP server sandbox rules not expressed";
const KEY = "mcpServerSandbox";
const MAX_REPORTED = 64;
const PROFILE_HEAD = "(version 1)\n(allow default)\n";
// Appended when the profile denies non-loopback egress (egressDefault "block"). Measured on macOS 27.0 with
// sandbox-exec: without them `(allow network-outbound (remote unix-socket))` and `(allow default)` leave
// name resolution open (node dns.lookup and python getaddrinfo of a public name resolve through
// mDNSResponder, a DNS exfiltration channel), and osascript / open reach other apps. With them a public
// lookup is ENOTFOUND, localhost still resolves (::1), loopback still connects, node / python / npx and their
// child processes start, osascript can send no AppleEvent, and exec of /usr/bin/open and /usr/bin/osascript
// is EPERM. NOT closed: the launchservicesd / lsd lookups alone do not stop `open` (measured: it still
// exits 0), so the exec deny is what refuses it, and only for those two paths; other routes to
// LaunchServices (a program that calls it directly) were not measured. File and process access stay open.
const CONTAIN_LINES = [
  '(deny mach-lookup (global-name "com.apple.mDNSResponder") (global-name "com.apple.mDNSResponderHelper") (global-name "com.apple.nsurlsessiond") (global-name "com.apple.coreservices.launchservicesd") (global-name "com.apple.lsd.mapdb") (global-name "com.apple.lsd.open"))',
  "(deny appleevent-send)",
  '(deny network-outbound (literal "/private/var/run/mDNSResponder"))',
  '(deny process-exec (literal "/usr/bin/open") (literal "/usr/bin/osascript"))'
];
const WHY_TEXT = {
  platform: "this platform has no supported sandbox (macOS sandbox-exec only)",
  "no-sandbox-exec": `${SANDBOX_EXEC} is missing`,
  "profile-error": "the sandbox profile could not be built"
};

const own = (o, k) => o !== null && typeof o === "object" && Object.prototype.hasOwnProperty.call(o, k);
const isObj = (o) => o !== null && typeof o === "object" && !Array.isArray(o);
function defaultWarn(m) { try { process.stderr.write(`moorai: ${m}\n`); } catch { /* a warning, never a decision */ } }

// policy: the verified signed policy (or null). admin: the parsed admin binding (cli/server-mode.mjs
// systemConfig()). → { mode, source: "admin" | "policy" | "default" }. Never throws.
export function resolveServerSandbox(policy, { admin = null, warn = defaultWarn } = {}) {
  const w = typeof warn === "function" ? (m) => { try { warn(m); } catch { /* never throws */ } } : () => {};
  for (const [src, label, source] of [[admin, "admin binding", "admin"], [policy, "signed policy", "policy"]]) {
    if (!own(src, KEY)) continue;
    if (SERVER_SANDBOX_MODES.includes(src[KEY])) return { mode: src[KEY], source };
    w(`${KEY} in the ${label} is not one of ${SERVER_SANDBOX_MODES.join(", ")}; ignored`);
  }
  return { mode: "off", source: "default" };
}

// The backend this machine can run, or null.
export function sandboxBackend({ platform = process.platform, exists = existsSync } = {}) {
  if (platform !== "darwin") return null;
  try { return exists(SANDBOX_EXEC) ? "seatbelt" : null; } catch { return null; }
}

// The rules sandboxPolicy reads: the policy's then the admin binding's (first match decides), and the
// policy's default, else the admin binding's. origin[i] names where merged rule i came from.
export function sandboxEgress(policy, admin) {
  const egressRules = [], origin = [];
  let egressDefault;
  for (const [doc, source] of [[policy, "policy"], [admin, "admin"]]) {
    if (!isObj(doc)) continue;
    if (Array.isArray(doc.egressRules)) doc.egressRules.forEach((r, index) => { egressRules.push(r); origin.push({ source, index }); });
    else if (doc.egressRules !== undefined && doc.egressRules !== null) { egressRules.push(doc.egressRules); origin.push({ source, index: -1 }); }
    if (egressDefault === undefined && doc.egressDefault !== undefined && doc.egressDefault !== null) egressDefault = doc.egressDefault;
  }
  return { egressRules, egressDefault, origin };
}

function defaultSource(policy, admin) {
  if (isObj(policy) && policy.egressDefault != null) return "policy";
  if (isObj(admin) && admin.egressDefault != null) return "admin";
  return "default";
}

// sandboxPolicy's report lines, with each merged index mapped back to its own document.
function located(unexpressed, origin, policy, admin) {
  return unexpressed.map((u) => {
    if (u.index === -1) return { ...u, source: defaultSource(policy, admin) };
    const o = origin[u.index];
    return o ? { ...u, source: o.source, index: o.index } : { ...u, source: "merged" };
  });
}

// → { mode, source, state, cmd, args, why?, blocksNonLoopback?, unexpressed }
//   state "off"          cmd/args are the real command, unchanged.
//         "sandboxed"    cmd is sandbox-exec, args ["-p", profile, realCmd, ...realArgs].
//         "unavailable"  requested, no backend, fail mode open (or coach): the real command, unchanged.
//         "refused"      requested, no backend, fail mode closed: cmd/args null, nothing is started.
export function planServerSpawn({ cmd, args = [], policy = null, admin = null, platform = process.platform, exists = existsSync, failMode = "open", coach = false, warn = defaultWarn } = {}) {
  const { mode, source } = resolveServerSandbox(policy, { admin, warn });
  const base = { mode, source, cmd, args, unexpressed: [] };
  if (mode !== "network") return { ...base, state: "off" };
  const fallback = (why) => (failMode === "closed" && !coach ? { ...base, state: "refused", why, cmd: null, args: null } : { ...base, state: "unavailable", why });
  if (platform !== "darwin") return fallback("platform");
  if (!sandboxBackend({ platform, exists })) return fallback("no-sandbox-exec");
  let r;
  const eg = sandboxEgress(policy, admin);
  try { r = sandboxPolicy({ egressRules: eg.egressRules, egressDefault: eg.egressDefault }, "seatbelt"); } catch { r = null; }
  if (!r || !r.ok || typeof r.policy !== "string") return fallback("profile-error");
  const blocksNonLoopback = /^\(deny network-outbound\)$/m.test(r.policy);
  const profile = PROFILE_HEAD + r.policy + (blocksNonLoopback ? CONTAIN_LINES.join("\n") + "\n" : "");
  return {
    ...base, state: "sandboxed", cmd: SANDBOX_EXEC, args: ["-p", profile, cmd, ...args],
    blocksNonLoopback,
    unexpressed: located(r.unexpressed, eg.origin, policy, admin)
  };
}

const slim = (u) => ({ index: u.index, source: u.source, ...(u.id ? { id: u.id } : {}), ...(u.action ? { action: u.action } : {}), fields: u.fields, effect: u.effect, reason: u.reason });

// The stderr lines (the MCP client keeps them in its server log). Off: none.
export function serverSandboxNotes(plan, server) {
  const pre = `moorai-mcp-guard: MCP server "${server}"`;
  if (!plan || plan.mode !== "network") return [];
  const out = [];
  if (plan.state === "sandboxed") {
    out.push(`${pre} runs under the macOS network sandbox (mcpServerSandbox "network", from the ${plan.source === "admin" ? "admin binding" : "signed policy"})`);
    if (!plan.blocksNonLoopback) out.push(`${pre}: the sandbox restricts no non-loopback host and no DNS: egressDefault is not "block", and Seatbelt can name loopback only`);
    else out.push(`${pre}: the server process's own network connections and DNS are limited to loopback; hosts your egress rules allow are refused too (Seatbelt can name loopback only). EXPERIMENTAL. This is not full containment: file and process access are not restricted, so the server can still write a LaunchAgent or cron job, edit MCP-client or MoorAI config, or run launchctl, and such work runs later outside the sandbox; only /usr/bin/open and /usr/bin/osascript are refused as routes to other apps`);
    for (const u of plan.unexpressed) out.push(`${pre}: egress rule not expressed in the sandbox: ${JSON.stringify(slim(u))}`);
  } else if (plan.state === "unavailable") {
    out.push(`${pre} runs UNSANDBOXED: mcpServerSandbox is "network" but ${WHY_TEXT[plan.why] || plan.why}; the mcpGateway fail mode is open`);
  } else if (plan.state === "refused") {
    out.push(`${pre} was not started: mcpServerSandbox is "network" but ${WHY_TEXT[plan.why] || plan.why}, and your organization's mcpGateway fail mode is closed`);
  }
  return out;
}

// The content-free alerts for one launch. The guard posts each once (one launch = one process).
export function serverSandboxAlerts(plan, { server = "", failModeSource = "default" } = {}) {
  if (!plan || plan.mode !== "network") return [];
  const common = { threatId: 0, stage: "mcp", tool: "desktop:mcp-sandbox", sandboxMode: plan.mode, sandboxSource: plan.source, ...(server ? { mcpServer: server } : {}) };
  if (plan.state === "unavailable" || plan.state === "refused") {
    const refused = plan.state === "refused";
    return [{
      ...common, category: SERVER_SANDBOX_CATEGORY, riskLevel: refused ? "Blocked" : "High", decision: refused ? "deny" : "notify",
      reasonCode: REASON.CONTAINMENT_UNAVAILABLE, ...(refused ? { enforcement: ENFORCEMENT.STRENGTHENED } : {}),
      failMode: refused ? "closed" : "open", failModeSource, sandboxWhy: plan.why,
      contentHash: `mcp-sandbox:${plan.state}:${plan.why}`
    }];
  }
  if (plan.state === "sandboxed" && plan.unexpressed.length) {
    const reasons = [...new Set(plan.unexpressed.map((u) => `${u.effect}/${u.reason}`))].sort().join(",");
    return [{
      ...common, category: SERVER_SANDBOX_UNEXPRESSED_CATEGORY, riskLevel: "Medium", decision: "notify",
      blocksNonLoopback: plan.blocksNonLoopback, unexpressedCount: plan.unexpressed.length,
      unexpressed: plan.unexpressed.slice(0, MAX_REPORTED).map(slim),
      contentHash: `mcp-sandbox:unexpressed:${reasons}`
    }];
  }
  return [];
}

// The heartbeat field (cli/moorai-hook.mjs posture beat), from static prerequisites only.
export function serverSandboxPosture(policy, { admin = null, platform = process.platform, exists = existsSync } = {}) {
  const { mode } = resolveServerSandbox(policy, { admin, warn: () => {} });
  if (mode !== "network") return { mode, state: "off" };
  return { mode, state: sandboxBackend({ platform, exists }) ? "on" : "unavailable" };
}

// What the guard holds in place of a child when the server is refused: ends with code 1 (the spawn-failure
// exit), takes the client's writes and drops them, so the guard's lifecycle runs unchanged.
export function refusedChild() {
  const c = new EventEmitter();
  c.stdin = new Writable({ write(_chunk, _enc, cb) { cb(); } });
  c.stdout = new PassThrough();
  c.stderr = new PassThrough();
  c.pid = undefined;
  c.kill = () => false;
  setImmediate(() => {
    c.stdout.end();
    c.stderr.end();
    c.emit("exit", 1, null);
    setImmediate(() => c.emit("close", 1, null));
  });
  return c;
}
