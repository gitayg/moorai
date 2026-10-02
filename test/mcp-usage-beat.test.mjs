// The MCP usage tally (cli/mcp-usage-beat.mjs): the sender side of the console's proxy-vs-hook
// cross-check. Each surface that sees an MCP tools/call (the Claude Code hook's mcp__ branch, the
// stdio proxy) counts it locally per UTC day / path / host / server label, and a COMPLETED day is
// posted to POST /api/mcp-usage once, content-free. A failed post is retried after ten minutes, not
// on every call. Run in-process against a throwaway state dir and a local stand-in console.
//
//   node --test test/mcp-usage-beat.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, readFileSync, statSync, existsSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import {
  recordMcpCall, flushMcpUsage, dueDays, usageHost, sanitizeLabel, readTally,
  USAGE_HOSTS, MAX_SERVERS, MAX_DAYS, RETRY_MS, TALLY_FILE
} from "../cli/mcp-usage-beat.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const DAY = 24 * 3600 * 1000;
const T0 = Date.parse("2026-10-01T12:00:00Z");
const ID = { user: "alice", device: "box-1", platform: "darwin", actor: "h2:actor" };
const CFG = (url) => ({ serverUrl: url, tenant: "acme", installToken: "tok-usage" });

function dir(t) { const d = mkdtempSync(join(tmpdir(), "moorai-usage-")); t.after(() => rmSync(d, { recursive: true, force: true })); return d; }
async function consoleStub(t, statuses = [201]) {
  const posts = [];
  let i = 0;
  const srv = createServer((req, res) => {
    let b = "";
    req.on("data", (c) => (b += c));
    req.on("end", () => {
      if (req.url === "/api/mcp-usage" && req.method === "POST") {
        posts.push({ token: req.headers["x-install-token"], type: req.headers["content-type"], body: JSON.parse(b) });
        res.writeHead(statuses[Math.min(i++, statuses.length - 1)]); return res.end("{}");
      }
      res.writeHead(404); res.end("{}");
    });
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  t.after(() => srv.close());
  return { url: `http://127.0.0.1:${srv.address().port}`, posts };
}

test("TALLY: counts per UTC day / path / host / label, 0600, and ignores anything that is not a label", (t) => {
  const d = dir(t);
  assert.equal(recordMcpCall({ path: "proxy", host: "claude-desktop", label: "github" }, { dir: d, now: T0 }), true);
  recordMcpCall({ path: "proxy", host: "claude-desktop", label: "github" }, { dir: d, now: T0 + 1000 });
  recordMcpCall({ path: "hook", host: "claude-code", label: "github" }, { dir: d, now: T0 });
  recordMcpCall({ path: "proxy", host: "claude-desktop", label: "github" }, { dir: d, now: T0 + DAY });
  assert.equal(recordMcpCall({ path: "elsewhere", host: "claude-code", label: "x" }, { dir: d, now: T0 }), false, "unknown path");
  assert.equal(recordMcpCall({ path: "hook", host: "claude-code", label: "  \u0000\n " }, { dir: d, now: T0 }), false, "empty label");
  const tally = readTally(d);
  assert.deepEqual(JSON.parse(JSON.stringify(tally.days)), {
    "2026-10-01": { "proxy|claude-desktop": { github: 2 }, "hook|claude-code": { github: 1 } },
    "2026-10-02": { "proxy|claude-desktop": { github: 1 } }
  });
  if (process.platform !== "win32") assert.equal(statSync(join(d, TALLY_FILE)).mode & 0o777, 0o600);
});

test("TALLY: host outside the frozen vocabulary is 'unknown'; labels are stripped of control chars and capped at 64", (t) => {
  const d = dir(t);
  assert.equal(usageHost("claude-desktop"), "claude-desktop");
  assert.equal(usageHost("mcp-json"), "unknown");
  assert.equal(usageHost(undefined), "unknown");
  assert.deepEqual(USAGE_HOSTS, ["claude-code", "codex", "cursor", "gemini", "copilot", "claude-desktop", "vscode", "unknown"]);
  assert.equal(sanitizeLabel("git\u0007hub\n"), "github");
  assert.equal(sanitizeLabel("a".repeat(200)).length, 64);
  recordMcpCall({ path: "proxy", host: "made-up", label: "x".repeat(100) }, { dir: d, now: T0 });
  const keys = Object.keys(readTally(d).days["2026-10-01"]);
  assert.deepEqual(keys, ["proxy|unknown"]);
  assert.deepEqual(Object.keys(readTally(d).days["2026-10-01"]["proxy|unknown"]), ["x".repeat(64)]);
});

test("BOUNDED: at most 64 labels per day/path/host and the 14 most recent days; a corrupt file starts over", (t) => {
  const d = dir(t);
  for (let i = 0; i < MAX_SERVERS + 10; i++) recordMcpCall({ path: "hook", host: "codex", label: `srv${i}` }, { dir: d, now: T0 });
  assert.equal(Object.keys(readTally(d).days["2026-10-01"]["hook|codex"]).length, MAX_SERVERS);
  for (let i = 1; i <= MAX_DAYS + 5; i++) recordMcpCall({ path: "hook", host: "codex", label: "s" }, { dir: d, now: T0 + i * DAY });
  const days = Object.keys(readTally(d).days).sort();
  assert.equal(days.length, MAX_DAYS);
  assert.equal(days[days.length - 1], new Date(T0 + (MAX_DAYS + 5) * DAY).toISOString().slice(0, 10));
  writeFileSync(join(d, TALLY_FILE), "{not json");
  assert.equal(recordMcpCall({ path: "hook", host: "codex", label: "s" }, { dir: d, now: T0 }), true);
  assert.deepEqual(Object.keys(readTally(d).days), ["2026-10-01"]);
  // __proto__ as a label is data, not a prototype write.
  assert.equal(recordMcpCall({ path: "hook", host: "codex", label: "__proto__" }, { dir: d, now: T0 }), true);
  assert.equal(readTally(d).days["2026-10-01"]["hook|codex"]["__proto__"], 1);
  assert.equal({}.polluted, undefined);
});

test("CONTRACT: a completed day posts exactly the frozen shape — no tool names, no arguments, the install token header", async (t) => {
  const d = dir(t);
  const c = await consoleStub(t);
  recordMcpCall({ path: "proxy", host: "vscode", label: "github", tool: "create_issue", arguments: { body: "SECRET-ARG" } }, { dir: d, now: T0 });
  recordMcpCall({ path: "proxy", host: "vscode", label: "github" }, { dir: d, now: T0 });
  recordMcpCall({ path: "proxy", host: "vscode", label: "filesystem" }, { dir: d, now: T0 });
  const r = await flushMcpUsage({ config: CFG(c.url), identity: ID, path: "proxy", host: "vscode", dir: d, now: T0 + DAY });
  assert.deepEqual(r.posted, ["2026-10-01"]);
  assert.equal(c.posts.length, 1);
  const { token, type, body } = c.posts[0];
  assert.equal(token, "tok-usage");
  assert.match(type, /application\/json/);
  assert.deepEqual(body, {
    user: "alice", device: "box-1", platform: "darwin", actor: "h2:actor",
    day: "2026-10-01", path: "proxy", host: "vscode",
    servers: [{ label: "github", calls: 2 }, { label: "filesystem", calls: 1 }]
  });
  const raw = JSON.stringify(body);
  assert.ok(!raw.includes("create_issue") && !raw.includes("SECRET-ARG") && !raw.includes("acme"), raw);
  assert.ok(!readFileSync(join(d, TALLY_FILE), "utf8").includes("create_issue"), "the tally itself holds no tool names");
});

test("ONCE A DAY: today is never posted; a completed day is posted once; the next flush that day posts nothing", async (t) => {
  const d = dir(t);
  const c = await consoleStub(t);
  recordMcpCall({ path: "hook", host: "claude-code", label: "github" }, { dir: d, now: T0 });
  const today = await flushMcpUsage({ config: CFG(c.url), identity: ID, path: "hook", host: "claude-code", dir: d, now: T0 });
  assert.equal(c.posts.length, 0, "today's partial tally is not posted");
  assert.deepEqual(today.posted, []);
  await flushMcpUsage({ config: CFG(c.url), identity: ID, path: "hook", host: "claude-code", dir: d, now: T0 + DAY });
  assert.equal(c.posts.length, 1);
  // A late write for the day already sent, and more flushes the same day: nothing more leaves.
  recordMcpCall({ path: "hook", host: "claude-code", label: "github" }, { dir: d, now: T0 });
  recordMcpCall({ path: "hook", host: "claude-code", label: "github" }, { dir: d, now: T0 + DAY });
  for (let i = 0; i < 3; i++) await flushMcpUsage({ config: CFG(c.url), identity: ID, path: "hook", host: "claude-code", dir: d, now: T0 + DAY + i * RETRY_MS * 2 });
  assert.equal(c.posts.length, 1, "no second post the same day");
  assert.deepEqual(dueDays({ path: "hook", host: "claude-code" }, { dir: d, now: T0 + DAY }), []);
  // The next day the second day posts — once.
  await flushMcpUsage({ config: CFG(c.url), identity: ID, path: "hook", host: "claude-code", dir: d, now: T0 + 2 * DAY });
  assert.equal(c.posts.length, 2);
  assert.equal(c.posts[1].body.day, "2026-10-02");
});

test("PER KEY: a flush posts only its own path/host; several unsent days post one body each, oldest first", async (t) => {
  const d = dir(t);
  const c = await consoleStub(t);
  recordMcpCall({ path: "proxy", host: "claude-desktop", label: "a" }, { dir: d, now: T0 });
  recordMcpCall({ path: "proxy", host: "claude-desktop", label: "a" }, { dir: d, now: T0 + DAY });
  recordMcpCall({ path: "hook", host: "claude-code", label: "a" }, { dir: d, now: T0 });
  await flushMcpUsage({ config: CFG(c.url), identity: ID, path: "proxy", host: "claude-desktop", dir: d, now: T0 + 2 * DAY });
  assert.deepEqual(c.posts.map((p) => [p.body.path, p.body.host, p.body.day]), [["proxy", "claude-desktop", "2026-10-01"], ["proxy", "claude-desktop", "2026-10-02"]]);
});

test("RETRY: a failed post is retried after ten minutes, not on the next call; success then stamps the day", async (t) => {
  const d = dir(t);
  const c = await consoleStub(t, [500, 201]);
  recordMcpCall({ path: "proxy", host: "cursor", label: "github" }, { dir: d, now: T0 });
  const f = (now) => flushMcpUsage({ config: CFG(c.url), identity: ID, path: "proxy", host: "cursor", dir: d, now });
  const r1 = await f(T0 + DAY);
  assert.equal(r1.failed, true);
  assert.equal(c.posts.length, 1);
  await f(T0 + DAY + 1000);
  await f(T0 + DAY + RETRY_MS - 1000);
  assert.equal(c.posts.length, 1, "no retry inside the ten-minute window");
  const r2 = await f(T0 + DAY + RETRY_MS + 1000);
  assert.deepEqual(r2.posted, ["2026-10-01"]);
  assert.equal(c.posts.length, 2);
  await f(T0 + DAY + 3 * RETRY_MS);
  assert.equal(c.posts.length, 2, "stamped after success");
});

test("RETRY: an unreachable console counts as a failure and holds the ten-minute pause", async (t) => {
  const d = dir(t);
  recordMcpCall({ path: "proxy", host: "cursor", label: "github" }, { dir: d, now: T0 });
  let calls = 0;
  const fetchImpl = async () => { calls++; throw new Error("ECONNREFUSED"); };
  const r = await flushMcpUsage({ config: CFG("http://127.0.0.1:9"), identity: ID, path: "proxy", host: "cursor", dir: d, now: T0 + DAY, fetchImpl });
  assert.equal(r.failed, true);
  await flushMcpUsage({ config: CFG("http://127.0.0.1:9"), identity: ID, path: "proxy", host: "cursor", dir: d, now: T0 + DAY + 1000, fetchImpl });
  assert.equal(calls, 1);
});

test("UNENROLLED: no install token, nothing is posted (the tally still counts locally)", async (t) => {
  const d = dir(t);
  const c = await consoleStub(t);
  recordMcpCall({ path: "hook", host: "claude-code", label: "github" }, { dir: d, now: T0 });
  const r = await flushMcpUsage({ config: { serverUrl: c.url, tenant: "x" }, identity: ID, path: "hook", host: "claude-code", dir: d, now: T0 + DAY });
  assert.equal(r.skipped, "unenrolled");
  assert.equal(c.posts.length, 0);
});

test("CAP: more than 64 servers in a day post the 64 busiest", async (t) => {
  const d = dir(t);
  const c = await consoleStub(t);
  // Fill to the label cap with one-call servers, then make one of them busy.
  for (let i = 0; i < MAX_SERVERS; i++) recordMcpCall({ path: "hook", host: "gemini", label: `s${i}` }, { dir: d, now: T0 });
  for (let i = 0; i < 5; i++) recordMcpCall({ path: "hook", host: "gemini", label: "s63" }, { dir: d, now: T0 });
  await flushMcpUsage({ config: CFG(c.url), identity: ID, path: "hook", host: "gemini", dir: d, now: T0 + DAY });
  const s = c.posts[0].body.servers;
  assert.equal(s.length, MAX_SERVERS);
  assert.deepEqual(s[0], { label: "s63", calls: 6 });
  assert.ok(s.every((x) => Object.keys(x).join() === "label,calls" && Number.isInteger(x.calls)));
});

test("SERVER MODE: the usage identity is the workload (serviceWho), as the hook sends it", (t) => {
  const home = dir(t);
  const code = `import { usageIdentity } from ${JSON.stringify(join(ROOT, "cli", "mcp-usage-beat.mjs"))}; process.stdout.write(JSON.stringify(usageIdentity()));`;
  const env = { ...process.env, HOME: home, USERPROFILE: home, MOORAI_MODE: "server", MOORAI_SERVICE_ID: "ci-runner-7", MOORAI_INSTALL_TOKEN: "tok-sm" };
  const r = spawnSync(process.execPath, ["--input-type=module", "-e", code], { env, encoding: "utf8", cwd: home });
  assert.equal(r.status, 0, r.stderr);
  const id = JSON.parse(r.stdout);
  assert.equal(id.user, "service");
  assert.equal(id.device, "svc:ci-runner-7");
  assert.equal(id.platform, process.platform);
  assert.match(id.actor, /^h2:/);
  const off = spawnSync(process.execPath, ["--input-type=module", "-e", code], { env: { ...process.env, HOME: home, USERPROFILE: home, MOORAI_MODE: "" }, encoding: "utf8", cwd: home });
  const id2 = JSON.parse(off.stdout);
  assert.notEqual(id2.device, "svc:ci-runner-7");
  assert.ok(!existsSync(join(home, ".moorai", TALLY_FILE)), "computing an identity writes nothing");
});
