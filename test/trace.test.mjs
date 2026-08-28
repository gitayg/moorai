// Content-free session/trace replay tests. Sibling of posture.test.mjs, same throwaway-HOME harness:
// the CLI resolves STATE_DIR (~/.moorai) from os.homedir(), so an isolated HOME lets us seed a real
// action-audit.jsonl and drive the actual CLI process end-to-end.
//
// The load-bearing assertion is the sacred rule: a row is seeded that ALSO carries content-bearing
// fields (matchText, argText, filePath, cmdShape) exactly as a mis-tiered or attacker-crafted row
// might — and NONE of those values may ever appear in the rendered trace, human or JSON.
//
//   node --test test/trace.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const CLI = join(ROOT, "cli", "moorai-trace.mjs");

// A content string that MUST NOT survive into any output. Seeded into the content-bearing fields.
const SECRET = "sk-live-DEADBEEF-super-secret-value";
const SECRET_PATH = "/Users/victim/.aws/credentials";

function withHome(rows, run) {
  const home = mkdtempSync(join(tmpdir(), "moorai-trace-"));
  try {
    mkdirSync(join(home, ".moorai"), { recursive: true });
    if (rows != null) writeFileSync(join(home, ".moorai", "action-audit.jsonl"), rows.map((r) => JSON.stringify(r)).join("\n") + "\n");
    const env = { ...process.env, HOME: home, USERPROFILE: home };
    delete env.XDG_CONFIG_HOME; delete env.XDG_STATE_HOME; // resolve state dirs under the throwaway HOME
    return run((args = []) => spawnSync(process.execPath, [CLI, ...args], { env, encoding: "utf8" }));
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
}

// Three content-free rows out of time order + one row that ALSO smuggles content fields.
const SEED = [
  { ts: "2026-08-28T10:00:02.000Z", tool: "hook:mcp__github__create_issue", stage: "mcp", riskLevel: "Info", decision: "allow", mcpServer: "github", contentHash: "h2:aaaa1111", actor: "1837465", user: "alice", device: "mac-01" },
  { ts: "2026-08-28T10:00:00.000Z", tool: "hook:Read", stage: "scan", riskLevel: "High", contentHash: "h2:bbbb2222", actor: "1837465", user: "alice", device: "mac-01",
    // content-bearing fields a higher tier / crafted row might carry — must be dropped:
    matchText: SECRET, argText: SECRET, filePath: SECRET_PATH, cmdShape: "cat [1 args]" },
  { ts: "2026-08-28T10:00:01.000Z", tool: "hook:Bash", stage: "egress", riskLevel: "Blocked", contentHash: "h2:cccc3333", actor: "9999999", user: "bob", device: "mac-02" }
];

test("renders the chain in timestamp order (not file order)", () => {
  withHome(SEED, (cli) => {
    const out = cli().stdout;
    const iRead = out.indexOf("Read"), iBash = out.indexOf("Bash"), iGithub = out.indexOf("github");
    assert.ok(iRead >= 0 && iBash >= 0 && iGithub >= 0, `all tools should render:\n${out}`);
    assert.ok(iRead < iBash && iBash < iGithub, `order must be 10:00:00 Read → 10:00:01 Bash → 10:00:02 github:\n${out}`);
  });
});

test("SACRED RULE: no seeded content string ever appears in human output", () => {
  withHome(SEED, (cli) => {
    const out = cli().stdout;
    assert.equal(out.includes(SECRET), false, "matchText/argText value leaked into the trace");
    assert.equal(out.includes(SECRET_PATH), false, "filePath value leaked into the trace");
    assert.equal(out.includes("cat [1 args]"), false, "cmdShape value leaked into the trace");
  });
});

test("SACRED RULE: no seeded content string appears in --json output either", () => {
  withHome(SEED, (cli) => {
    const out = cli(["--json"]).stdout;
    assert.equal(out.includes(SECRET), false);
    assert.equal(out.includes(SECRET_PATH), false);
    assert.equal(out.includes("cat [1 args]"), false);
    const steps = JSON.parse(out);
    assert.equal(steps.length, 3);
    assert.deepEqual(steps.map((s) => s.tool), ["Read", "Bash", "mcp__github__create_issue"]);
    // the one-way hash and decision survive; nothing content-bearing does
    assert.equal(steps[0].hash, "h2:bbbb2222");
    assert.equal(steps[2].decision, "allow");
    for (const s of steps) for (const k of Object.keys(s)) assert.ok(!["matchText", "argText", "filePath", "cmdShape"].includes(k), `content field ${k} present in JSON step`);
  });
});

test("--agent filters to a single actor", () => {
  withHome(SEED, (cli) => {
    const steps = JSON.parse(cli(["--json", "--agent", "9999999"]).stdout);
    assert.equal(steps.length, 1);
    assert.equal(steps[0].tool, "Bash");
  });
});

test("--limit caps to the most recent N steps", () => {
  withHome(SEED, (cli) => {
    const steps = JSON.parse(cli(["--json", "--limit", "2"]).stdout);
    assert.equal(steps.length, 2);
    assert.deepEqual(steps.map((s) => s.tool), ["Bash", "mcp__github__create_issue"]); // the two latest
  });
});

test("a Blocked row with no explicit decision renders as deny", () => {
  withHome(SEED, (cli) => {
    const bash = JSON.parse(cli(["--json"]).stdout).find((s) => s.tool === "Bash");
    assert.equal(bash.decision, "deny");
  });
});

test("empty logs → clean no-activity message, never a crash", () => {
  withHome([], (cli) => {
    const r = cli();
    assert.equal(r.status, 0);
    assert.match(r.stdout, /No on-device activity recorded/);
  });
});

test("missing logs entirely → clean no-activity message, never a crash", () => {
  withHome(null, (cli) => {
    const r = cli();
    assert.equal(r.status, 0);
    assert.match(r.stdout, /No on-device activity recorded/);
  });
});
