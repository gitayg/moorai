// Is moorai-guardd, the MoorAI privileged helper, installed on this device, and is it healthy?
//
// Installed means the files the installers in guardd/packaging/ lay out are there (the binary and the
// service definition). Healthy means the endpoint passes the hook-side ownership walk of contract §3.6
// (every directory from the trust root down owned by root and not writable by group or others, the
// socket owned by root), device.pub passes the same check and is an ed25519 key, and the helper answers
// a `hello` whose proof verifies against that key and names that key's id. A user process cannot pass
// the walk (it cannot create an entry in a root-owned 0755 directory) or sign the proof.
//
// The result is content-free: enums plus the helper's own semver. No path, tenant, device id or key id
// leaves this module. Nothing here reads the environment for a path (contract §3.1, §10.2); the `root`
// and `trustUid` options exist for tests, the way guardd's own tests use Paths::under (§11.2), and no
// CLI flag reaches them.
import { readFileSync, existsSync } from "node:fs";
import { createConnection } from "node:net";
import { randomBytes } from "node:crypto";
import { execFileSync } from "node:child_process";
import { join, posix } from "node:path";
import { createRequire } from "node:module";
import { checkOwnedPath, endpointFor, runDirFor, encodeFrame, FrameDecoder, buildRequest, helloProofInput, keyIdOfSpki, verifyHelloProof, PROTO_VERSION } from "./guardd-client.mjs";

const VERSION = (() => { try { return createRequire(import.meta.url)("../package.json").version; } catch { return "0.0.0"; } })();

export const HELPER_STATES = Object.freeze([
  "not-installed", "partial", "installed-not-running", "running-unprobed", "healthy", "not-ready",
  "unreachable", "untrusted", "unverified"
]);
export const HELLO_RESULTS = Object.freeze(["skipped", "ok", "not-ready", "bad-proof", "key-mismatch", "timeout", "error"]);
export const POSTURE_KEYS = Object.freeze(["state", "binary", "service", "endpoint", "devicePub", "hello", "helperVersion"]);
export const DEFAULT_TIMEOUT_MS = 250;

const LINUX_UNITS = ["moorai-guardd.service", "moorai-guardd.socket"];
const WIN_BINARY = "C:\\Program Files\\MoorAI\\moorai-guardd.exe";

// Where each installer puts the helper (guardd/packaging/<os>/install.*) and the contract §3.1 endpoint.
export function guarddLayout(platform = process.platform) {
  if (platform === "darwin") {
    return { binary: "/Library/PrivilegedHelperTools/moorai-guardd", units: ["/Library/LaunchDaemons/run.glick.moorai.guardd.plist"], altUnits: [], endpoint: endpointFor("darwin"), runDir: runDirFor("darwin") };
  }
  if (platform === "win32") {
    return { binary: WIN_BINARY, service: "MoorAIGuard", units: [], altUnits: [], endpoint: endpointFor("win32") };
  }
  return {
    binary: "/usr/sbin/moorai-guardd",
    units: LINUX_UNITS.map((u) => `/usr/lib/systemd/system/${u}`),
    // Distributions without a merged /usr, and packages built for them, use /lib/systemd/system.
    altUnits: LINUX_UNITS.map((u) => `/lib/systemd/system/${u}`),
    endpoint: endpointFor("linux"),
    runDir: runDirFor("linux")
  };
}

const under = (root, p) => (root === "/" ? p : join(root, p));
// The §3.6 step 1 walk lives in cli/guardd-client.mjs (one implementation for the hook and this status).
export { checkOwnedPath };

function readDevicePubAt(path, opts) {
  const v = checkOwnedPath(path, { ...opts, kind: "file" });
  if (v !== "ok") return { devicePub: v, spki: null };
  try {
    const spki = readFileSync(join(opts.root === "/" ? "/" : opts.root, posix.relative("/", path)), "utf8").trim();
    keyIdOfSpki(spki);
    return { devicePub: "ok", spki };
  } catch { return { devicePub: "invalid", spki: null }; }
}

const SEMVER = /^\d{1,5}\.\d{1,5}\.\d{1,5}(?:[-+][0-9A-Za-z.-]{1,20})?$/;

// One `hello` on a fresh connection; resolves to { hello, helperVersion? }. Never throws.
export function probeHello(endpoint, spki, timeoutMs = DEFAULT_TIMEOUT_MS) {
  return new Promise((resolve) => {
    const nonce = randomBytes(16).toString("hex");
    let settled = false;
    let sock;
    const done = (r) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try { sock.destroy(); } catch { /* already gone */ }
      resolve(r);
    };
    const timer = setTimeout(() => done({ hello: "timeout" }), timeoutMs);
    const dec = new FrameDecoder();
    try { sock = createConnection(endpoint); } catch { done({ hello: "error" }); return; }
    sock.on("connect", () => {
      try {
        sock.write(encodeFrame(buildRequest("hello", 1, { proto: [PROTO_VERSION], client: "moorai-hook", clientVersion: VERSION, nonce })));
      } catch { done({ hello: "error" }); }
    });
    sock.on("data", (chunk) => {
      let m;
      try { dec.push(chunk); m = dec.next(); } catch { done({ hello: "error" }); return; }
      if (!m) return;
      if (m.op === "error") { done({ hello: m.code === "not_ready" ? "not-ready" : "error" }); return; }
      if (m.op !== "hello" || m.id !== 1 || typeof m.keyId !== "string" || typeof m.helperVersion !== "string" || typeof m.proof !== "string") {
        done({ hello: "error" });
        return;
      }
      if (m.keyId !== keyIdOfSpki(spki)) { done({ hello: "key-mismatch" }); return; }
      if (!verifyHelloProof(spki, helloProofInput(nonce, m.keyId, m.helperVersion), m.proof)) { done({ hello: "bad-proof" }); return; }
      done(SEMVER.test(m.helperVersion) ? { hello: "ok", helperVersion: m.helperVersion } : { hello: "ok" });
    });
    sock.on("error", () => done({ hello: "error" }));
    sock.on("close", () => done({ hello: "error" }));
  });
}

// `sc.exe query MoorAIGuard` by absolute path: "running", "stopped" or "absent".
export function windowsServiceState(run = (exe, args) => execFileSync(exe, args, { encoding: "utf8", timeout: 3000, windowsHide: true, stdio: ["ignore", "pipe", "ignore"] })) {
  try {
    const out = run("C:\\Windows\\System32\\sc.exe", ["query", "MoorAIGuard"]);
    const m = /STATE\s*:\s*\d+\s+(\w+)/.exec(out || "");
    if (!m) return "absent";
    return m[1] === "RUNNING" ? "running" : "stopped";
  } catch { return "absent"; }
}

function stateOf(s) {
  if (s.endpoint === "untrusted" || s.devicePub === "untrusted" || s.devicePub === "invalid") return "untrusted";
  if (s.endpoint === "absent") {
    if (s.binary && s.service) return "installed-not-running";
    return s.binary || s.service ? "partial" : "not-installed";
  }
  switch (s.hello) {
    case "ok": return "healthy";
    case "not-ready": return "not-ready";
    case "bad-proof": case "key-mismatch": return "untrusted";
    case "timeout": case "error": return "unreachable";
    default: return s.devicePub === "absent" ? "unverified" : "running-unprobed";
  }
}

// The content-free install and health status. `probe: false` never connects. `serviceQuery` (Windows)
// returns "running" | "stopped" | "absent"; the default asks the SCM.
export async function helperInstallStatus({ platform = process.platform, root = "/", trustUid = 0, probe = true, timeoutMs = DEFAULT_TIMEOUT_MS, serviceQuery = null } = {}) {
  const L = guarddLayout(platform);
  const s = { state: "not-installed", binary: false, service: false, endpoint: "absent", devicePub: "absent", hello: "skipped" };
  let spki = null;
  if (platform === "win32") {
    const svc = (serviceQuery || windowsServiceState)();
    s.binary = existsSync(root === "/" ? L.binary : join(root, "Program Files", "MoorAI", "moorai-guardd.exe"));
    s.service = svc === "running" || svc === "stopped";
    s.endpoint = svc === "running" ? "ok" : "absent";
    if (s.endpoint === "ok") {
      try {
        const { devicePubPathFor } = await import("./guardd-client.mjs");
        const p = root === "/" ? devicePubPathFor("win32") : join(root, "ProgramData", "MoorAI", "run", "device.pub");
        let text = "";
        if (root === "/") { const { readRootOwned } = await import("./hook-core.mjs"); text = readRootOwned(p); } else if (existsSync(p)) text = readFileSync(p, "utf8");
        if (text) { spki = text.trim(); keyIdOfSpki(spki); s.devicePub = "ok"; }
      } catch { s.devicePub = "invalid"; spki = null; }
    }
  } else {
    s.binary = existsSync(under(root, L.binary));
    const has = (list) => list.length > 0 && list.every((u) => existsSync(under(root, u)));
    s.service = has(L.units) || has(L.altUnits);
    s.endpoint = checkOwnedPath(L.endpoint, { root, trustUid, platform, kind: "socket" });
    if (s.endpoint === "ok") {
      const d = readDevicePubAt(`${L.runDir}/device.pub`, { root, trustUid, platform });
      s.devicePub = d.devicePub;
      spki = d.spki;
    }
  }
  if (probe && s.endpoint === "ok" && s.devicePub === "ok" && spki) {
    const r = await probeHello(platform === "win32" || root === "/" ? L.endpoint : under(root, L.endpoint), spki, timeoutMs);
    s.hello = r.hello;
    if (r.helperVersion) s.helperVersion = r.helperVersion;
  }
  s.state = stateOf(s);
  return s;
}
