// Learned per-agent drift: after a learning period, the first time an actor uses a new tool, MCP server,
// network host, git repository or cloud credential profile raises one content-free "first seen" alert.
//
//   node --test --import ./test/hermetic-env.mjs test/learned-drift.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, readdirSync, existsSync, rmSync } from "node:fs";
import { join, dirname } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import http from "node:http";
import { observeDrift, driftConfig, normalizeRemote, cloudProfiles } from "../data/learned-drift.js";
import { repoIdentity, remoteFromConfig } from "../cli/drift-state.mjs";

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const HOOK = join(ROOT, "cli", "moorai-hook.mjs");
const H = 3600000;

// ---- pure baseline ----

const cfg = (o = {}) => ({ ...driftConfig(null), ...o });
const host = (k) => ({ type: "host", key: k });

test("pure: learning period is silent, the first new value after it alerts once", () => {
  let st = null, t = 1_000_000;
  for (let i = 0; i < 3; i++) {
    const r = observeDrift(st, "A", [host(`h${i}`)], t += 1000, cfg({ learnEvents: 3 }));
    assert.equal(r.alerts.length, 0, `learning event ${i} must be silent`);
    assert.equal(r.learning, true);
    st = r.state;
  }
  const r4 = observeDrift(st, "A", [host("new")], t += 1000, cfg({ learnEvents: 3 }));
  assert.equal(r4.learning, false);
  assert.deepEqual(r4.alerts, [{ type: "host", key: "new" }]);
  const r5 = observeDrift(r4.state, "A", [host("new")], t += 1000, cfg({ learnEvents: 3 }));
  assert.equal(r5.alerts.length, 0, "a value already seen is silent");
});

test("pure: rate limit is one alert per type per actor per window; other types are independent", () => {
  let st = null, t = 5_000_000;
  const c = cfg({ learnEvents: 1 });
  st = observeDrift(st, "A", [host("known")], t, c).state;
  const r1 = observeDrift(st, "A", [host("n1")], t += 1000, c);
  assert.equal(r1.alerts.length, 1);
  const r2 = observeDrift(r1.state, "A", [host("n2"), { type: "tool", key: "t1" }], t += 1000, c);
  assert.deepEqual(r2.alerts, [{ type: "tool", key: "t1" }], "second new host inside the window is rate-limited; a new tool is not");
  const r3 = observeDrift(r2.state, "A", [host("n3")], t += 23 * H, c);
  assert.equal(r3.alerts.length, 0, "still inside 24h");
  const r4 = observeDrift(r3.state, "A", [host("n4")], t += 2 * H, c);
  assert.deepEqual(r4.alerts, [{ type: "host", key: "n4" }], "after 24h the type can alert again");
  // rate-limited values are still learned, so they stay silent afterwards
  assert.equal(observeDrift(r4.state, "A", [host("n2"), host("n3")], t += 30 * H, c).alerts.length, 0);
});

test("pure: actors are separate baselines", () => {
  const c = cfg({ learnEvents: 1 });
  let st = observeDrift(null, "A", [host("x")], 1, c).state;
  st = observeDrift(st, "A", [host("y")], 2, c).state; // A alerts on y
  const b = observeDrift(st, "B", [host("y")], 3, c);
  assert.equal(b.learning, true, "B starts its own learning period");
  assert.equal(b.alerts.length, 0);
});

test("pure: learning ends after learnDays even below learnEvents", () => {
  const c = cfg({ learnEvents: 1000, learnDays: 2 });
  const st = observeDrift(null, "A", [host("x")], 0, c).state;
  assert.equal(observeDrift(st, "A", [host("y")], 1 * 24 * H, c).alerts.length, 0);
  assert.equal(observeDrift(st, "A", [host("y")], 3 * 24 * H, c).alerts.length, 1);
});

test("pure: bounded — seen values per actor and actors are LRU-capped", () => {
  const c = cfg({ learnEvents: 0, maxPerActor: 5, maxActors: 3, rateLimitHours: 0 });
  let st = null;
  for (let i = 0; i < 20; i++) st = observeDrift(st, "A", [host(`v${i}`)], i * 2 * H, c).state;
  assert.equal(Object.keys(st.actors.A.seen).length, 5);
  assert.ok(st.actors.A.seen["host|v19"] && !st.actors.A.seen["host|v0"], "oldest evicted, newest kept");
  for (let i = 0; i < 6; i++) st = observeDrift(st, `X${i}`, [], 100 * H + i * 2 * H, c).state;
  assert.equal(Object.keys(st.actors).length, 3);
  assert.ok(st.actors.X5, "the current actor is never the one evicted");
});

test("pure: a malformed state reads as an empty baseline (quieter, never louder)", () => {
  for (const bad of [null, 5, "x", [], { actors: 7 }, { actors: { A: { seen: "no" } } }, { actors: { A: { first: 0, n: "9", last: 0 } } }]) {
    const r = observeDrift(bad, "A", [host("h")], 10, cfg({ learnEvents: 3 }));
    assert.equal(r.alerts.length, 0);
    assert.equal(r.learning, true);
  }
});

test("pure: mode off learns nothing loud", () => {
  const c = cfg({ learnEvents: 0, mode: "off" });
  assert.equal(observeDrift(null, "A", [host("h")], 1, c).alerts.length, 0);
});

test("config: defaults and overrides", () => {
  assert.deepEqual(driftConfig(null), { mode: "alert", learnEvents: 50, learnDays: 7, maxPerActor: 128, maxActors: 32, rateLimitHours: 24 });
  assert.equal(driftConfig({ learnedDrift: { learnEvents: 3, mode: "off" } }).learnEvents, 3);
  assert.equal(driftConfig({ learnedDrift: { mode: "off" } }).mode, "off");
  assert.equal(driftConfig({ learnedDrift: { learnEvents: -1, mode: "bogus" } }).learnEvents, 50);
});

// ---- value extraction ----

test("normalizeRemote: https / ssh / scp spellings of one repo compare equal, credentials dropped", () => {
  const want = "github.com/acme/app";
  for (const u of ["https://github.com/Acme/App.git", "https://user:tok-9f8e@github.com:443/acme/app", "git@github.com:acme/app.git", "ssh://git@github.com/acme/app/", "git@GitHub.com:Acme/App"]) {
    assert.equal(normalizeRemote(u), want, u);
  }
  assert.equal(normalizeRemote("/srv/repos/app.git"), "/srv/repos/app");
  assert.equal(normalizeRemote(""), "");
});

test("cloudProfiles: aws / gcloud / kube / az forms", () => {
  const cases = [
    ["aws s3 ls --profile prod-admin", ["aws:prod-admin"]],
    ["aws --region us-east-1 sts get-caller-identity --profile=ops", ["aws:ops"]],
    ["AWS_PROFILE=billing aws s3 ls", ["aws:billing"]],
    ["export AWS_PROFILE='sec-audit'", ["aws:sec-audit"]],
    ["$env:AWS_PROFILE = \"win-prof\"", ["aws:win-prof"]],
    ["gcloud compute instances list --configuration corp-prod", ["gcloud:corp-prod"]],
    ["gcloud config configurations activate staging", ["gcloud:staging"]],
    ["CLOUDSDK_ACTIVE_CONFIG_NAME=dev gcloud info", ["gcloud:dev"]],
    ["kubectl --context arn:aws:eks:us-east-1:1:cluster/prod get pods", ["kube:arn:aws:eks:us-east-1:1:cluster/prod"]],
    ["kubectl config use-context kind-kind", ["kube:kind-kind"]],
    ["helm upgrade x ./chart --kube-context prod-eu", ["kube:prod-eu"]],
    ["kubectx gke_proj_zone_c1", ["kube:gke_proj_zone_c1"]],
    ["az account set --subscription 0000-sub", ["az:0000-sub"]]
  ];
  for (const [c, want] of cases) assert.deepEqual(cloudProfiles(c), want, c);
  for (const c of ["cargo build --profile release", "npm test", "kubectl get pods", "kubectx -", "echo $AWS_PROFILE", "aws s3 ls --profile $P"]) {
    assert.deepEqual(cloudProfiles(c), [], c);
  }
});

test("repoIdentity: origin remote, first-remote fallback, no remote, worktree .git file", () => {
  const base = mkdtempSync(join(tmpdir(), "moorai-repoid-"));
  try {
    const a = join(base, "a"); mkdirSync(join(a, ".git"), { recursive: true }); mkdirSync(join(a, "src", "deep"), { recursive: true });
    writeFileSync(join(a, ".git", "config"), '[core]\n\tbare = false\n[remote "upstream"]\n\turl = https://github.com/up/x.git\n[remote "origin"]\n\turl = git@github.com:acme/app.git\n');
    assert.deepEqual(repoIdentity(join(a, "src", "deep")), { root: a, remote: "git@github.com:acme/app.git" });
    const b = join(base, "b"); mkdirSync(join(b, ".git"), { recursive: true });
    writeFileSync(join(b, ".git", "config"), '[remote "fork"]\n\turl = https://gitlab.example/f/y\n');
    assert.equal(repoIdentity(b).remote, "https://gitlab.example/f/y");
    const c = join(base, "c"); mkdirSync(join(c, ".git"), { recursive: true });
    assert.deepEqual(repoIdentity(c), { root: c, remote: "" });
    const wt = join(base, "wt"); mkdirSync(wt); mkdirSync(join(a, ".git", "worktrees", "wt"), { recursive: true });
    writeFileSync(join(a, ".git", "worktrees", "wt", "commondir"), "../..\n");
    writeFileSync(join(wt, ".git"), `gitdir: ${join(a, ".git", "worktrees", "wt")}\n`);
    assert.equal(repoIdentity(wt).remote, "git@github.com:acme/app.git");
    assert.equal(repoIdentity("relative/path"), null);
    assert.equal(remoteFromConfig(""), "");
  } finally { rmSync(base, { recursive: true, force: true }); }
});

// ---- end to end through the real hook ----

async function withServer(policy, fn) {
  const alerts = [];
  const server = http.createServer((req, res) => {
    if (req.url.startsWith("/api/policy")) { res.writeHead(200, { "Content-Type": "application/json" }); res.end(JSON.stringify(policy)); return; }
    if (req.url === "/api/alerts" && req.method === "POST") {
      let b = ""; req.on("data", (c) => { b += c; }); req.on("end", () => { try { alerts.push(JSON.parse(b)); } catch { /* ignore */ } res.writeHead(200); res.end("{}"); });
      return;
    }
    res.writeHead(404); res.end();
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  try { return await fn(server.address().port, alerts); } finally { server.close(); }
}

function makeHome(port, token = "tok-drift") {
  const home = mkdtempSync(join(tmpdir(), "moorai-drift-"));
  mkdirSync(join(home, ".moorai"), { recursive: true });
  const cfgObj = { serverUrl: `http://127.0.0.1:${port}`, tenant: "acme" };
  if (token) cfgObj.installToken = token;
  writeFileSync(join(home, ".moorai", "config.json"), JSON.stringify(cfgObj));
  return home;
}

async function runHook(home, payload) {
  const child = spawn(process.execPath, [HOOK], { cwd: home, stdio: ["pipe", "pipe", "pipe"], env: { ...process.env, HOME: home, USERPROFILE: home, MOORAI_OFFLINE_MODE: "" } });
  let out = "";
  child.stdout.on("data", (c) => { out += c; });
  child.stderr.on("data", () => {});
  child.stdin.end(JSON.stringify({ session_id: "sess-drift", cwd: home, ...payload }));
  await new Promise((r) => child.on("exit", r));
  const t = out.trim();
  return t ? (JSON.parse(t).hookSpecificOutput?.permissionDecision || "allow") : "allow";
}
const bash = (command, extra = {}) => ({ tool_name: "Bash", tool_input: { command }, ...extra });

const CATEGORY = "Agent drift: first seen";
const driftAlerts = (alerts) => alerts.filter((a) => a.category === CATEGORY);
function stateText(home) {
  const dir = join(home, ".moorai");
  return readdirSync(dir).filter((f) => f.endsWith(".json") && f !== "config.json").map((f) => readFileSync(join(dir, f), "utf8")).join("\n");
}

test("hook e2e: silent during learning, one alert for a new host, silent on repeat, rate-limited per type", async () => {
  await withServer({ captureTier: "content-free", learnedDrift: { learnEvents: 3 } }, async (port, alerts) => {
    const home = makeHome(port);
    try {
      await runHook(home, bash("curl -s https://docs.learn-one.example/a"));
      await runHook(home, bash("curl -s https://docs.learn-two.example/b"));
      await runHook(home, bash("ls -la"));
      assert.equal(driftAlerts(alerts).length, 0, "the learning period is silent");
      assert.equal(await runHook(home, bash("curl -s https://exfil-drop-7731.example.net/x")), "allow", "report-only");
      const hits = driftAlerts(alerts);
      assert.equal(hits.length, 1, `expected one drift alert, got ${JSON.stringify(hits)}`);
      const a = hits[0];
      assert.equal(a.threatId, 64);
      assert.equal(a.stage, "behavior");
      assert.equal(a.tool, "hook:learned-drift", "the tool name is itself a drift value, so it is not in the alert");
      assert.equal(a.drift.type, "host");
      assert.match(a.contentHash, /^h2:[0-9a-f]{16}$/, "a keyed hash, not nokey and not the value");
      await runHook(home, bash("curl -s https://exfil-drop-7731.example.net/y"));
      assert.equal(driftAlerts(alerts).length, 1, "the same host again is silent");
      await runHook(home, bash("curl -s https://second-new-host-5520.example.org/z"));
      assert.equal(driftAlerts(alerts).length, 1, "a second new host inside the rate-limit window is silent");
      // a different TYPE is not rate-limited by the host alert
      await runHook(home, bash("aws s3 ls --profile prod-admin-9931"));
      const prof = driftAlerts(alerts).filter((x) => x.drift.type === "cloud-profile");
      assert.equal(prof.length, 1, "a new cloud profile alerts on its own");
      // content-free: no raw value in any state file or any drift alert
      const blob = stateText(home) + JSON.stringify(driftAlerts(alerts));
      for (const raw of ["exfil-drop-7731", "second-new-host-5520", "prod-admin-9931", "learn-one", "aws:prod"]) {
        assert.ok(!blob.includes(raw), `raw value ${raw} leaked into state or alert`);
      }
      assert.ok(existsSync(join(home, ".moorai", "learned-drift.json")));
    } finally { rmSync(home, { recursive: true, force: true }); }
  });
});

test("hook e2e: a new git repository and a new MCP server after learning alert with keyed hashes", async () => {
  await withServer({ captureTier: "content-free", learnedDrift: { learnEvents: 2 } }, async (port, alerts) => {
    const home = makeHome(port);
    const repo = join(home, "work", "secret-merger-repo");
    mkdirSync(join(repo, ".git"), { recursive: true });
    writeFileSync(join(repo, ".git", "config"), '[remote "origin"]\n\turl = https://bot:ghp_rawtoken123@github.com/acme/secret-merger-repo.git\n');
    try {
      await runHook(home, bash("ls"));
      await runHook(home, bash("pwd"));
      assert.equal(driftAlerts(alerts).length, 0);
      await runHook(home, bash("git status", { cwd: repo }));
      await runHook(home, { tool_name: "mcp__zz_payroll_srv__list", tool_input: {} });
      const types = driftAlerts(alerts).map((a) => a.drift.type).sort();
      assert.deepEqual(types, ["mcp", "repo", "tool"], `got ${JSON.stringify(types)}`);
      const blob = stateText(home) + JSON.stringify(driftAlerts(alerts));
      for (const raw of ["secret-merger-repo", "ghp_rawtoken123", "zz_payroll_srv", "mcp__zz"]) assert.ok(!blob.includes(raw), `raw ${raw} leaked`);
    } finally { rmSync(home, { recursive: true, force: true }); }
  });
});

test("hook e2e: a corrupted state file never breaks the call and never alerts", async () => {
  await withServer({ captureTier: "content-free", learnedDrift: { learnEvents: 1 } }, async (port, alerts) => {
    const home = makeHome(port);
    try {
      writeFileSync(join(home, ".moorai", "learned-drift.json"), "{not json");
      writeFileSync(join(home, ".moorai", "deletion-volume.json"), "[1,2");
      assert.equal(await runHook(home, bash("curl -s https://after-corrupt.example.com")), "allow");
      assert.equal(driftAlerts(alerts).length, 0, "a reset baseline starts in learning");
      JSON.parse(readFileSync(join(home, ".moorai", "learned-drift.json"), "utf8"));
    } finally { rmSync(home, { recursive: true, force: true }); }
  });
});

test("hook e2e: mode off records and posts nothing", async () => {
  await withServer({ captureTier: "content-free", learnedDrift: { mode: "off", learnEvents: 0 } }, async (port, alerts) => {
    const home = makeHome(port);
    try {
      await runHook(home, bash("curl -s https://off-mode.example.com"));
      assert.equal(driftAlerts(alerts).length, 0);
      assert.ok(!existsSync(join(home, ".moorai", "learned-drift.json")));
    } finally { rmSync(home, { recursive: true, force: true }); }
  });
});
