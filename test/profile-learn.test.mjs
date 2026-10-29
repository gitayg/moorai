// "Watch, then enforce" (cli/profile-learn.mjs, cli/moorai-profile.mjs): a draft workload profile learned
// from the session ledger and the destination map, checked by the workload-profile checker it is meant for.
//
//   node --test --import ./test/hermetic-env.mjs test/profile-learn.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn, spawnSync } from "node:child_process";
import http from "node:http";
import { learnProfile } from "../cli/profile-learn.mjs";
import { validateProfile, evaluateProfile, PROFILE_DRIFT } from "../cli/workload-profile.mjs";
import { rmTree } from "./fs-cleanup.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const CLI = join(ROOT, "cli", "moorai-profile.mjs");
const UNTIL = "2026-10-28T00:00:00.000Z";
const day = (d, h = 10) => new Date(Date.UTC(2026, 9, d, h)).toISOString();

// Six sessions on six days (Oct 20-25): Bash, Read, Edit and one GitHub MCP tool every day, npm registry
// reached every day by the ci-build workload. Plus: a denied WebFetch and a denied host (never learned), a
// host reached by ANOTHER workload, and rows outside the window on both sides.
function fixture() {
  const sessionRows = [], destinations = [];
  for (let d = 20; d <= 25; d++) {
    for (const tool of ["Bash", "Read", "Edit", "mcp__github__create_issue"]) sessionRows.push({ ts: day(d), s: `s${d}`, a: "", ev: "pre", tool, decision: "allow", reasonCode: "NO_MATCH" });
    sessionRows.push({ ts: day(d), s: `s${d}`, a: "", ev: "post", tool: "Bash", decision: "allow" });
    destinations.push({ ts: day(d), tool: "Bash", kind: "host", name: "registry.npmjs.org", decision: "allow", device: "svc:ci-build" });
  }
  sessionRows.push({ ts: day(22, 11), s: "s22", ev: "pre", tool: "WebFetch", decision: "deny", reasonCode: "DETECTOR_MATCH" });
  sessionRows.push({ ts: day(23, 11), s: "s23", ev: "pre", tool: "Write", decision: "allow", reasonCode: "COACH_UNENROLLED", basisCode: "DETECTOR_MATCH" });
  destinations.push({ ts: day(22, 11), tool: "Bash", kind: "host", name: "paste.example", decision: "deny", device: "svc:ci-build" });
  destinations.push({ ts: day(23, 11), tool: "Bash", kind: "host", name: "other-team.example", decision: "allow", device: "svc:other" });
  destinations.push({ ts: day(23, 12), tool: "mcp__github__create_issue", kind: "mcp", name: "github", decision: "allow", device: "svc:ci-build" });
  destinations.push({ ts: day(24, 12), tool: "Bash", kind: "host", name: "127.0.0.1", decision: "allow", device: "svc:ci-build" });
  // Outside the window: 15 days before UNTIL, and after it.
  sessionRows.push({ ts: day(13), s: "old", ev: "pre", tool: "NotebookEdit", decision: "allow" });
  destinations.push({ ts: day(13), tool: "Bash", kind: "host", name: "old.example", decision: "allow", device: "svc:ci-build" });
  sessionRows.push({ ts: day(28, 5), s: "late", ev: "pre", tool: "Glob", decision: "allow" });
  return { sessionRows, destinations };
}
const learn = (o = {}) => learnProfile({ ...fixture(), serviceId: "ci-build", until: UNTIL, ...o });

test("learning from a fixture ledger produces the expected draft, in report mode", () => {
  const r = learn();
  assert.equal(r.ok, true, r.error);
  assert.equal(r.thin, false);
  assert.deepEqual(r.profile, {
    id: "learned-ci-build",
    description: "Learned by moorai-profile from 6 session(s) on 6 day(s), 2026-10-14 to 2026-10-28",
    match: { serviceId: "ci-build" },
    action: "report",
    tools: ["Bash", "Edit", "Read", "mcp__github__create_issue"],
    mcpServers: ["github"],
    hosts: ["registry.npmjs.org"]
  });
  assert.deepEqual(r.items.tools.find((s) => s.name === "Bash"), { name: "Bash", count: 6, denied: 0, firstSeen: day(20), lastSeen: day(25) });
  assert.deepEqual(r.observation.sessions, 6);
  assert.deepEqual(r.observation.days, 6);
});

test("denied and coached calls are not learned; an item seen only that way is listed as excluded", () => {
  const r = learn();
  assert.ok(!r.profile.tools.includes("WebFetch") && !r.profile.tools.includes("Write"));
  assert.ok(!r.profile.hosts.includes("paste.example"));
  assert.deepEqual(r.excluded.map((e) => `${e.kind}:${e.name}`), ["tool:WebFetch", "tool:Write", "host:paste.example"]);
  // A tool allowed once and denied once is learned, with the denial counted.
  const f = fixture();
  f.sessionRows.push({ ts: day(24, 13), s: "s24", ev: "pre", tool: "Bash", decision: "deny" });
  const m = learnProfile({ ...f, serviceId: "ci-build", until: UNTIL });
  assert.equal(m.items.tools.find((s) => s.name === "Bash").denied, 1);
  assert.ok(m.profile.tools.includes("Bash"));
});

test("the draft round-trips through the workload-profile checker: a tool not learned is PROFILE_DRIFT in report mode", () => {
  const { profile } = learn();
  assert.equal(validateProfile(profile).error, undefined);
  const policy = { workloadProfiles: [profile] };
  const ev = (tool, toolInput = {}) => evaluateProfile({ policy, serviceId: "ci-build", tool, toolInput });
  for (const t of ["Bash", "Read", "Edit"]) assert.deepEqual([ev(t).decision, ev(t).alerts.length], ["allow", 0], t);
  assert.equal(ev("Bash", { command: "npm view lodash --registry https://registry.npmjs.org/" }).alerts.length, 0);

  const w = ev("Write", { file_path: "/tmp/x" });
  assert.equal(w.decision, "allow");
  assert.equal(w.alerts.length, 1);
  assert.equal(w.alerts[0].reasonCode, PROFILE_DRIFT);
  assert.deepEqual([w.alerts[0].driftKind, w.alerts[0].driftItem, w.alerts[0].profileId, w.alerts[0].profileAction], ["tool", "Write", "learned-ci-build", "report"]);
  const h = ev("Bash", { command: "curl https://paste.example/up" });
  assert.deepEqual(h.alerts.map((a) => [a.driftKind, a.driftItem]), [["host", "paste.example"]]);
  const s = ev("mcp__slack__post_message", {});
  assert.deepEqual(s.alerts.map((a) => a.driftKind), ["tool", "mcpServer"]);

  // The switch: the same profile with one field flipped denies what report mode only reported.
  const blocked = evaluateProfile({ policy: { workloadProfiles: [{ ...profile, action: "block" }] }, serviceId: "ci-build", tool: "Write", toolInput: {} });
  assert.equal(blocked.decision, "deny");
  assert.equal(blocked.reasonCode, PROFILE_DRIFT);
});

test("window filtering: --days and --until bound what is learned", () => {
  const r = learn();
  assert.ok(!r.profile.tools.includes("NotebookEdit"), "15 days before the window end");
  assert.ok(!r.profile.tools.includes("Glob"), "after the window end");
  assert.ok(!r.profile.hosts.includes("old.example"));
  const wide = learn({ days: 16, until: day(28, 6) });
  assert.ok(wide.profile.tools.includes("NotebookEdit") && wide.profile.tools.includes("Glob"));
  assert.ok(wide.profile.hosts.includes("old.example"));
  const narrow = learn({ days: 2, minDays: 1, minSessions: 1 });
  assert.equal(narrow.observation.sessions, 0);
  assert.equal(narrow.thin, true);
});

test("hosts follow the serviceId; loopback is never listed; a kind with nothing observed is omitted, never []", () => {
  const r = learn();
  assert.ok(!r.profile.hosts.includes("other-team.example"), "another workload's host");
  assert.ok(!r.profile.hosts.includes("127.0.0.1"));
  assert.ok(r.warnings.some((w) => w.code === "tools-unscoped"));
  const lap = learn({ serviceId: undefined, repo: "git@github.com:Acme/App.git" });
  assert.deepEqual(lap.profile.match, { repo: "github:acme/app" });
  assert.equal(lap.profile.id, "learned-github-acme-app");
  assert.ok(lap.profile.hosts.includes("other-team.example"), "a repo match cannot scope hosts");
  assert.ok(lap.warnings.some((w) => w.code === "hosts-unscoped"));
  const f = fixture();
  const nohosts = learnProfile({ sessionRows: f.sessionRows, destinations: [], serviceId: "ci-build", until: UNTIL });
  assert.equal("hosts" in nohosts.profile, false);
  assert.ok(nohosts.warnings.some((w) => w.code === "no-hosts"));
  assert.equal(learnProfile({ ...f }).ok, false, "no match key");
});

test("the diff against the profile in force: added, removed and kept, globs judged as the checker judges them", () => {
  const declared = { policy: { workloadProfiles: [{ id: "ci", match: { serviceId: "ci-build" }, tools: ["Bash", "Read", "Write", "mcp__jira__*"], hosts: ["*.npmjs.org"] }] } };
  const d = learn({ declared }).diff;
  assert.deepEqual(d.against, { id: "ci", source: "policy", action: "report" });
  assert.deepEqual(d.tools.added.map((s) => s.name), ["Edit", "mcp__github__create_issue"]);
  assert.deepEqual(d.tools.removed, ["Write", "mcp__jira__*"]);
  assert.deepEqual(d.tools.kept.map((s) => s.name), ["Bash", "Read"]);
  assert.equal(d.mcpServers.declared, "unconstrained");
  assert.deepEqual([d.hosts.added, d.hosts.removed, d.hosts.kept.map((s) => s.name)], [[], [], ["registry.npmjs.org"]]);
  assert.equal(d.readyToBlock, false);
  // Adopt the draft, keep watching: the next run over the same records finds nothing outside it.
  const { profile } = learn();
  const again = learn({ declared: { policy: { workloadProfiles: [profile] } } });
  assert.equal(again.diff.readyToBlock, true);
  assert.ok(again.warnings.some((w) => w.code === "same-id"));
  assert.equal(learn().diff.against, null);
});

test("deterministic: shuffled records give byte-identical output", () => {
  const a = JSON.stringify(learn());
  const f = fixture();
  const shuffled = learnProfile({ sessionRows: [...f.sessionRows].reverse(), destinations: [...f.destinations].reverse(), serviceId: "ci-build", until: UNTIL });
  assert.equal(JSON.stringify(shuffled), a);
});

test("thin-data guard: too few sessions or days is flagged, and the CLI refuses without --force", () => {
  const f = fixture();
  const two = { sessionRows: f.sessionRows.filter((r) => r.s === "s20" || r.s === "s21"), destinations: [] };
  const r = learnProfile({ ...two, serviceId: "ci-build", until: UNTIL });
  assert.equal(r.thin, true);
  assert.ok(r.warnings.some((w) => w.code === "thin-data"));
  assert.equal(learnProfile({ ...two, serviceId: "ci-build", until: UNTIL, minSessions: 2, minDays: 2 }).thin, false);

  const home = mkdtempSync(join(tmpdir(), "moorai-learn-"));
  try {
    mkdirSync(join(home, ".moorai"));
    writeFileSync(join(home, ".moorai", "session-ledger.jsonl"), two.sessionRows.map((x) => JSON.stringify(x)).join("\n") + "\n");
    const run = (...args) => spawnSync(process.execPath, [CLI, "learn", "--service-id", "ci-build", "--until", UNTIL, "--policy", join(home, "none.json"), ...args], { env: { ...process.env, HOME: home, USERPROFILE: home }, encoding: "utf8" });
    writeFileSync(join(home, "none.json"), "[]");
    const refused = run();
    assert.equal(refused.status, 3, refused.stderr);
    assert.match(refused.stderr, /too little observed/);
    const forced = run("--force", "--json");
    assert.equal(forced.status, 0, forced.stderr);
    const out = JSON.parse(forced.stdout);
    assert.ok(out.warnings.some((w) => w.code === "thin-data"));
    assert.equal(out.profile.action, "report");
  } finally { rmTree(home); }
});

test("CLI reads the device's own records and writes a draft that validates", () => {
  const home = mkdtempSync(join(tmpdir(), "moorai-learn-"));
  try {
    const f = fixture();
    mkdirSync(join(home, ".moorai"));
    writeFileSync(join(home, ".moorai", "session-ledger.jsonl"), f.sessionRows.map((x) => JSON.stringify(x)).join("\n") + "\n");
    writeFileSync(join(home, ".moorai", "destinations.jsonl"), f.destinations.map((x) => JSON.stringify(x)).join("\n") + "\n");
    writeFileSync(join(home, "pol.json"), JSON.stringify({ workloadProfiles: [{ id: "ci", match: { serviceId: "ci-build" }, tools: ["Bash"] }] }));
    const outFile = join(home, "draft.json");
    const r = spawnSync(process.execPath, [CLI, "learn", "--service-id", "ci-build", "--until", UNTIL, "--policy", join(home, "pol.json"), "--out", outFile], { env: { ...process.env, HOME: home, USERPROFILE: home }, encoding: "utf8" });
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /\+ Edit {2}6 call\(s\)/);
    assert.match(r.stdout, /Compared with the profile in force: "ci"/);
    const draft = JSON.parse(readFileSync(outFile, "utf8"));
    assert.deepEqual(draft, learn().profile);
    assert.equal(validateProfile(draft).error, undefined);
    const bad = spawnSync(process.execPath, [CLI, "learn"], { env: { ...process.env, HOME: home }, encoding: "utf8" });
    assert.equal(bad.status, 2);
  } finally { rmTree(home); }
});

// ---- per-workload rows: svc / repo on the session ledger ----

// The fixture's tool rows stamped as the ci-build workload in repo acme/app, plus another workload's rows.
function stamped() {
  const f = fixture();
  for (const r of f.sessionRows) Object.assign(r, { svc: "ci-build", repo: "github:acme/app" });
  for (let d = 20; d <= 25; d++) f.sessionRows.push({ ts: day(d, 14), s: `o${d}`, ev: "pre", tool: "mcp__slack__post_message", decision: "allow", svc: "other", repo: "github:acme/other" });
  return f;
}

test("tools and MCP servers narrow to rows whose svc / repo match; another workload's rows are dropped", () => {
  const f = stamped();
  const r = learnProfile({ ...f, serviceId: "ci-build", until: UNTIL });
  assert.deepEqual(r.profile.tools, ["Bash", "Edit", "Read", "mcp__github__create_issue"]);
  assert.deepEqual(r.profile.mcpServers, ["github"]);
  assert.deepEqual(r.observation.scope.sessionRows, { matched: 26, deviceWide: 0 });
  assert.ok(!r.warnings.some((w) => w.code === "tools-unscoped"), "no fallback rows, no warning");
  const byRepo = learnProfile({ ...f, repo: "https://github.com/acme/other.git", until: UNTIL, minSessions: 1 });
  assert.deepEqual(byRepo.profile.tools, ["mcp__slack__post_message"]);
  assert.deepEqual(byRepo.observation.scope.sessionRows, { matched: 6, deviceWide: 0 });
  // Both keys: a row must match both; a row of the right service in another repo is dropped.
  f.sessionRows.push({ ts: day(24, 15), s: "x", ev: "pre", tool: "Glob", decision: "allow", svc: "ci-build", repo: "github:acme/other" });
  assert.ok(!learnProfile({ ...f, serviceId: "ci-build", repo: "github:acme/app", until: UNTIL }).profile.tools.includes("Glob"));
});

test("old rows without svc / repo are a counted device-wide fallback, and only then is tools-unscoped raised", () => {
  const f = stamped();
  f.sessionRows.push({ ts: day(24, 16), s: "s24", ev: "pre", tool: "Grep", decision: "allow" });
  const r = learnProfile({ ...f, serviceId: "ci-build", until: UNTIL });
  assert.ok(r.profile.tools.includes("Grep"));
  assert.deepEqual(r.observation.scope.sessionRows, { matched: 26, deviceWide: 1 });
  const w = r.warnings.find((x) => x.code === "tools-unscoped");
  assert.match(w.text, /^1 of 27 tool call\(s\)/);
  assert.deepEqual(r.observation.scope.hostRows, { matched: 7, deviceWide: 0 }); // 6 npm + the denied paste.example
  // Repo-only: destination rows name no repo, so hosts are device-wide and say so.
  const repoOnly = learnProfile({ ...f, repo: "github:acme/app", until: UNTIL });
  assert.ok(repoOnly.warnings.some((x) => x.code === "hosts-unscoped"));
  assert.equal(repoOnly.observation.scope.hostRows.matched, 0);
});

test("window truncated: warned when the oldest retained row of a record is newer than the window start", () => {
  assert.ok(!learn().warnings.some((w) => w.code === "window-truncated"), "the fixture reaches back before the window");
  const f = fixture();
  const recent = { sessionRows: f.sessionRows.filter((r) => r.ts >= day(20)), destinations: f.destinations };
  const r = learnProfile({ ...recent, serviceId: "ci-build", until: UNTIL });
  const t = r.warnings.filter((w) => w.code === "window-truncated");
  assert.equal(t.length, 1);
  assert.match(t[0].text, /^the session ledger's oldest retained row is from 2026-10-20T10:00:00.000Z, after the window start 2026-10-14T00:00:00.000Z/);
  assert.equal(learnProfile({ sessionRows: [], destinations: [], serviceId: "ci-build", until: UNTIL }).warnings.some((w) => w.code === "window-truncated"), false, "no records: thin, not truncated");
});

// The real hook in server mode, policy from a local console: the ledger row names the workload.
const HOOK = join(ROOT, "cli", "moorai-hook.mjs");
function hookSandbox() {
  const home = mkdtempSync(join(tmpdir(), "moorai-learn-hook-"));
  const proj = join(home, "proj");
  mkdirSync(join(proj, ".git"), { recursive: true });
  mkdirSync(join(home, ".moorai"), { recursive: true });
  writeFileSync(join(proj, ".git", "config"), '[remote "origin"]\n\turl = git@github.com:Acme/App.git\n');
  return { home, proj };
}
function policyServer(policy) {
  const srv = http.createServer((req, res) => {
    req.resume();
    req.on("end", () => {
      if (req.method === "POST") { res.writeHead(201); return res.end("{}"); }
      if (req.url.startsWith("/api/policy/pubkey")) { res.writeHead(404); return res.end(); }
      if (req.url.startsWith("/api/policy")) { res.writeHead(200, { "content-type": "application/json" }); return res.end(JSON.stringify(policy)); }
      res.writeHead(404); res.end();
    });
  });
  return new Promise((r) => srv.listen(0, "127.0.0.1", () => r({ url: `http://127.0.0.1:${srv.address().port}`, close: () => srv.close() })));
}
function runHook(sb, env, tool_name, tool_input) {
  return new Promise((res, rej) => {
    const c = spawn(process.execPath, [HOOK], { cwd: sb.proj, env });
    let err = "";
    c.stdout.resume(); c.stderr.on("data", (d) => (err += d));
    c.on("error", rej);
    c.on("close", (status) => (status === 0 ? res() : rej(new Error(`hook exit ${status}: ${err}`))));
    c.stdin.end(JSON.stringify({ hook_event_name: "PreToolUse", tool_name, tool_input, tool_use_id: "tu-1", session_id: "learn", transcript_path: "", cwd: sb.proj, permission_mode: "default" }));
  });
}
const ledgerRows = (sb) => readFileSync(join(sb.home, ".moorai", "session-ledger.jsonl"), "utf8").trim().split("\n").map((l) => JSON.parse(l));
const baseEnv = (sb) => ({ PATH: process.env.PATH || "/usr/bin:/bin", HOME: sb.home, USERPROFILE: sb.home, XDG_CONFIG_HOME: join(sb.home, ".config"), XDG_STATE_HOME: join(sb.home, ".local", "state"), CLAUDE_PROJECT_DIR: sb.proj });

test("hook: a server-mode run writes svc on the ledger row, and repo only when a repo profile resolved it", async () => {
  const cases = [
    [{ id: "app", match: { repo: "github:acme/app" }, tools: ["Read"], action: "report" }, { svc: "learn-bot", repo: "github:acme/app" }],
    [{ id: "svc", match: { serviceId: "learn-bot" }, tools: ["Read"], action: "report" }, { svc: "learn-bot", repo: undefined }]
  ];
  for (const [profile, want] of cases) {
    const sb = hookSandbox();
    const c = await policyServer({ captureTier: "content-free", workloadProfiles: [profile] });
    try {
      await runHook(sb, { ...baseEnv(sb), MOORAI_MODE: "server", MOORAI_SERVER_URL: c.url, MOORAI_TENANT: "lp", MOORAI_INSTALL_TOKEN: "tok-lp-1", MOORAI_SERVICE_ID: "learn-bot" }, "Bash", { command: "ls" });
      const pre = ledgerRows(sb).filter((r) => r.ev === "pre");
      assert.equal(pre.length, 1);
      assert.deepEqual([pre[0].svc, pre[0].repo], [want.svc, want.repo], profile.id);
    } finally { c.close(); rmTree(sb.home); }
  }
  // Outside server mode: no svc.
  const sb = hookSandbox();
  try {
    await runHook(sb, baseEnv(sb), "Bash", { command: "ls" });
    const pre = ledgerRows(sb).filter((r) => r.ev === "pre");
    assert.equal(pre.length, 1);
    assert.equal("svc" in pre[0], false);
    assert.equal("repo" in pre[0], false);
  } finally { rmTree(sb.home); }
});
