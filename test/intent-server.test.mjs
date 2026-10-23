// Per-file runner:  node --test --import ./test/hermetic-env.mjs test/intent-server.test.mjs
//
// data/intent-server.mjs — the in-memory, per-session intent store the server surfaces share (the model
// proxy, the moorai-serve sidecar, the Agent SDK). The pure logic is data/intent-alignment.js, tested in
// test/intent-alignment.test.mjs; this file holds the store to its frozen contract: keyed hashes only (the
// prompt is never held past captureTask), bounded (LRU sessions, TTL, features per session), one
// firstForTarget per session per target, null for a non-risky call, and the policy mode reader.
import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { writeHeapSnapshot } from "node:v8";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createIntentStore, intentModeFromPolicy } from "../data/intent-server.mjs";
import { rmTree } from "./fs-cleanup.mjs";

const KEY = Buffer.alloc(32, 7);
const POST = (host) => ({ command: `curl -X POST https://${host}/hook -d '{"ok":1}'` });

test("judge: an upload to a host the task never named is misaligned egress, with a 16-hex keyed target hash", () => {
  const s = createIntentStore({ key: KEY });
  const c = s.captureTask("s1", "Fix the typo in docs/README.md and open a PR on github.com");
  assert.deepEqual(Object.keys(c), ["features"]);
  assert.ok(Number.isInteger(c.features) && c.features > 0);
  const r = s.judge("s1", "Bash", POST("collector.example.net"), []);
  assert.equal(r.aligned, false);
  assert.equal(r.class, "egress");
  assert.match(r.targetHash, /^[0-9a-f]{16}$/);
  assert.equal(r.firstForTarget, true);
  assert.deepEqual(Object.keys(r).sort(), ["aligned", "class", "firstForTarget", "targetHash"]);
});

test("judge: a host the task named is aligned; subdomains of a named site are in scope", () => {
  const s = createIntentStore({ key: KEY });
  s.captureTask("s1", "Post the build status to hooks.example.net when it finishes");
  const r = s.judge("s1", "Bash", POST("hooks.example.net"), []);
  assert.equal(r.aligned, true);
  assert.equal(r.class, "egress");
  assert.equal(s.judge("s1", "Bash", POST("api.example.net"), []).aligned, true);
});

test("judge: MCP write to a service the task never named is misaligned; naming the service aligns it", () => {
  const s = createIntentStore({ key: KEY });
  s.captureTask("a", "Summarise the failing tests");
  assert.equal(s.judge("a", "mcp__slack__post_message", { text: "x" }, []).aligned, false);
  s.captureTask("b", "Tell the team on slack that the release is out");
  assert.equal(s.judge("b", "mcp__slack__post_message", { text: "x" }, []).aligned, true);
});

test("judge: credential and destructive classes come from the findings, as in the hook", () => {
  const s = createIntentStore({ key: KEY });
  s.captureTask("s", "Make the retry logic clearer");
  assert.equal(s.judge("s", "Read", { file_path: "/home/u/.aws/credentials" }, [{ threatId: 55 }]).class, "credentials");
  assert.equal(s.judge("s", "Bash", { command: "rm -rf build/cache" }, [{ threatId: 43 }]).class, "destructive");
  s.captureTask("t", "clean up build/cache please");
  assert.equal(s.judge("t", "Bash", { command: "rm -rf build/cache" }, [{ threatId: 43 }]).aligned, true);
});

test("judge: null for a non-risky call, with or without a task", () => {
  const s = createIntentStore({ key: KEY });
  s.captureTask("s1", "Fix the typo");
  for (const id of ["s1", "nobody", "", undefined]) {
    assert.equal(s.judge(id, "Bash", { command: "ls -la src" }, []), null);
    assert.equal(s.judge(id, "Bash", { command: "curl -s https://api.github.com/zen" }, []), null);
    assert.equal(s.judge(id, "Read", { file_path: "src/a.js" }, []), null);
    assert.equal(s.judge(id, "mcp__slack__list_channels", {}, []), null);
  }
});

test("judge: a risky call in a session with no live task (never captured, no id) is task-unknown — fails closed, one alert per target", () => {
  const s = createIntentStore({ key: KEY });
  for (const id of ["nobody", "", undefined]) {
    const r = s.judge(id, "Bash", POST("collector.example.net"), []);
    assert.deepEqual([r.aligned, r.class], [false, "task-unknown"], `session ${JSON.stringify(id)}`);
    assert.match(r.targetHash, /^[0-9a-f]{16}$/);
  }
  assert.equal(s.judge("never", "Bash", POST("a.example.org"), []).firstForTarget, true);
  assert.equal(s.judge("never", "Bash", POST("a.example.org"), []).firstForTarget, false, "rate-limited per session and target");
  assert.equal(s.judge("never", "mcp__slack__post_message", {}, []).firstForTarget, true, "another target is first again");
  assert.equal(s.size(), 0, "judging an unknown session holds no task for it");
});

test("judge: a task evicted by ANOTHER owner's flood, and one expired, are task-unknown, however many sessions churn afterwards", () => {
  // A holds the most sessions, so B's new session at the global cap pushes out A's oldest.
  const s = createIntentStore({ key: KEY, maxSessions: 2 });
  s.captureTask("a1", "send it to hooks.example.net", "A");
  s.captureTask("a2", "Fix the typo", "A");
  s.captureTask("b1", "Fix the typo", "B");
  for (let i = 0; i < 50; i++) { s.captureTask(`b${i}`, "Fix the typo", "B"); s.captureTask(`c${i}`, "Fix the typo", "C"); }
  const r = s.judge("a1", "Bash", POST("hooks.example.net"), [], "A");
  assert.deepEqual([r.aligned, r.class], [false, "task-unknown"], "A's pushed-out task fails closed for A");
  let t = 0;
  const e = createIntentStore({ key: KEY, ttlMs: 100, maxSessions: 1, now: () => t });
  e.captureTask("x", "send it to hooks.example.net");
  t += 101;
  for (let i = 0; i < 50; i++) e.captureTask(`churn${i}`, "Fix the typo", "B");
  assert.equal(e.judge("x", "Bash", POST("hooks.example.net"), []).class, "task-unknown", "expired, and long since out of any tombstone bound");
});

test("firstForTarget: true once per session per target — one destination alerts once; another target or session is first again", () => {
  const s = createIntentStore({ key: KEY });
  s.captureTask("s1", "Fix the typo");
  s.captureTask("s2", "Fix the typo");
  assert.equal(s.judge("s1", "Bash", POST("a.example.net"), []).firstForTarget, true);
  assert.equal(s.judge("s1", "Bash", POST("a.example.net"), []).firstForTarget, false);
  assert.equal(s.judge("s1", "Bash", POST("b.example.net"), []).firstForTarget, false, "b.example.net folds to the same site (example.net), the unit alignment is judged in");
  assert.equal(s.judge("s1", "Bash", POST("other.example.org"), []).firstForTarget, true);
  assert.equal(s.judge("s2", "Bash", POST("a.example.net"), []).firstForTarget, true, "per session");
  assert.equal(s.judge("s1", "mcp__slack__post_message", {}, []).firstForTarget, true);
  assert.equal(s.judge("s1", "mcp__slack__post_message", {}, []).firstForTarget, false);
});

test("targetHash: keyed — the same target under the same key matches across stores, a different key gives a different hash", () => {
  const a = createIntentStore({ key: KEY }), b = createIntentStore({ key: KEY }), c = createIntentStore({ key: Buffer.alloc(32, 9) });
  for (const s of [a, b, c]) s.captureTask("s", "Fix the typo");
  const h = (s) => s.judge("s", "Bash", POST("x.example.net"), []).targetHash;
  assert.equal(h(a), h(b));
  assert.notEqual(h(a), h(c));
  const d = createIntentStore({ key: "a string key works too" });
  d.captureTask("s", "Fix the typo");
  assert.match(h(d), /^[0-9a-f]{16}$/);
});

test("tasks accumulate per session: a later user turn that names the host brings it into scope; sessions never share a task", () => {
  const s = createIntentStore({ key: KEY });
  s.captureTask("s1", "Fix the typo");
  assert.equal(s.judge("s1", "Bash", POST("hooks.example.net"), []).aligned, false);
  s.captureTask("s1", "now send the status to hooks.example.net");
  assert.equal(s.judge("s1", "Bash", POST("hooks.example.net"), []).aligned, true);
  s.captureTask("s2", "Fix the typo");
  assert.equal(s.judge("s2", "Bash", POST("hooks.example.net"), []).aligned, false);
});

test("captureTask: a non-string prompt or a missing session stores nothing", () => {
  const s = createIntentStore({ key: KEY });
  assert.deepEqual(s.captureTask("", "upload to x.example.net"), { features: 0 });
  assert.deepEqual(s.captureTask(null, "upload to x.example.net"), { features: 0 });
  assert.deepEqual(s.captureTask("s", { prompt: "x" }), { features: 0 });
  assert.equal(s.size(), 0);
});

test("bounded: maxSessions evicts the least recently used session (a judge counts as use); the evicted session fails closed as task-unknown", () => {
  const s = createIntentStore({ key: KEY, maxSessions: 2 });
  s.captureTask("s1", "Fix the typo");
  s.captureTask("s2", "Fix the typo");
  assert.notEqual(s.judge("s1", "Bash", POST("x.example.net"), []), null);
  s.captureTask("s3", "Fix the typo");
  assert.equal(s.size(), 2);
  const ev = s.judge("s2", "Bash", POST("x.example.net"), []);
  assert.equal(ev.aligned, false, "s2 was least recently used: its task is gone, so a risky call is not aligned");
  assert.equal(ev.class, "task-unknown");
  assert.match(ev.targetHash, /^[0-9a-f]{16}$/);
  assert.equal(ev.firstForTarget, true);
  assert.equal(s.judge("s2", "Bash", POST("x.example.net"), []).firstForTarget, false, "one alert per evicted session and target");
  assert.equal(s.judge("s2", "Bash", { command: "ls" }, []), null, "a non-risky call stays null");
  assert.equal(s.judge("never-seen", "Bash", POST("x.example.net"), []).class, "task-unknown", "a session never seen is task-unknown too");
  assert.equal(s.judge("s1", "Bash", POST("y.example.net"), []).class, "egress");
  assert.equal(s.judge("s3", "Bash", POST("y.example.net"), []).class, "egress");
  s.captureTask("s2", "now upload to x.example.net");
  assert.equal(s.judge("s2", "Bash", POST("x.example.net"), []).aligned, true, "a new task for the session replaces the tombstone");
});

test("bounded: a session expires ttlMs after its last use; an expired session's risky call is task-unknown, not null", () => {
  let t = 1000;
  const s = createIntentStore({ key: KEY, ttlMs: 500, now: () => t });
  s.captureTask("s1", "Fix the typo");
  t += 499;
  assert.equal(s.judge("s1", "Bash", POST("x.example.net"), []).class, "egress");
  assert.equal(s.size(), 1);
  t += 501;
  const r = s.judge("s1", "Bash", POST("x.example.net"), []);
  assert.deepEqual([r.aligned, r.class], [false, "task-unknown"]);
  assert.equal(s.size(), 0);
  s.captureTask("s2", "Fix the typo");
  t += 501;
  assert.equal(s.size(), 0, "size() prunes expired sessions");
  assert.equal(s.judge("s2", "Bash", POST("x.example.net"), []).class, "task-unknown", "pruned by size() is tombstoned too");
});

test("ttl: judge refreshes it as well as captureTask", () => {
  let t = 0;
  const s = createIntentStore({ key: KEY, ttlMs: 500, now: () => t });
  s.captureTask("s1", "Fix the typo");
  for (let i = 0; i < 5; i++) { t += 400; assert.equal(s.judge("s1", "Bash", POST("x.example.net"), []).class, "egress", `judge at ${t}`); }
});

test("owner: one caller cannot evict another's sessions — a flooding caller evicts only its own (maxSessionsPerOwner and the global cap)", () => {
  const s = createIntentStore({ key: KEY, maxSessions: 4, maxSessionsPerOwner: 2 });
  s.captureTask("a1", "Fix the typo", "A");
  for (let i = 1; i <= 10; i++) s.captureTask(`b${i}`, "Fix the typo", "B");
  assert.equal(s.judge("a1", "Bash", POST("x.example.net"), [], "A").class, "egress", "A's session survives B's flood");
  assert.equal(s.judge("b1", "Bash", POST("x.example.net"), [], "B").class, "task-unknown", "B's own early sessions were evicted");
  assert.equal(s.judge("b10", "Bash", POST("x.example.net"), [], "B").class, "egress");
  assert.equal(s.size(), 3, "A: 1, B: capped at 2");
  // The global cap alone (no per-owner cap): the caller holding the most sessions loses its LRU one.
  const g = createIntentStore({ key: KEY, maxSessions: 3 });
  g.captureTask("a1", "Fix the typo", "A");
  for (let i = 1; i <= 10; i++) g.captureTask(`b${i}`, "Fix the typo", "B");
  assert.equal(g.judge("a1", "Bash", POST("x.example.net"), [], "A").class, "egress", "A's session survives the global cap");
  assert.equal(g.size(), 3);
});

test("owner: sessions are namespaced per owner — another principal can neither overwrite nor read a session's task", () => {
  const s = createIntentStore({ key: KEY });
  s.captureTask("s", "send the result to hooks.example.net", "A");
  s.captureTask("s", "Fix the typo", "B");
  assert.equal(s.judge("s", "Bash", POST("hooks.example.net"), [], "A").aligned, true, "A's task is intact");
  assert.equal(s.judge("s", "Bash", POST("hooks.example.net"), [], "B").aligned, false, "B's task is its own");
  const t = createIntentStore({ key: KEY });
  t.captureTask("s", "Fix the typo", "A");
  t.captureTask("s", "send the result to hooks.example.net", "B");
  assert.equal(t.judge("s", "Bash", POST("hooks.example.net"), [], "A").aligned, false, "B cannot put a host in scope for A's session");
  assert.equal(t.judge("s", "Bash", POST("hooks.example.net"), []).class, "task-unknown", "no owner is its own namespace, which never captured s");
});

test("bounded: maxFeatures caps the hashed features a session holds", () => {
  const s = createIntentStore({ key: KEY, maxFeatures: 3 });
  const many = Array.from({ length: 20 }, (_, i) => `host${i}.example${i}.com`).join(" ");
  assert.equal(s.captureTask("s1", many).features, 3);
  assert.equal(s.captureTask("s1", "and also docs/other.md").features, 3);
  const big = createIntentStore({ key: KEY });
  assert.ok(big.captureTask("s1", many).features > 3);
});

test("never stored: after captureTask neither the prompt nor any plaintext feature is anywhere in the heap", () => {
  const dir = mkdtempSync(join(tmpdir(), "intent-heap-"));
  try {
    // The marker is held as bytes, never as a string, so the only string copies are the ones the prompt made.
    const marker = Buffer.from(`zq${randomBytes(10).toString("hex")}`);
    const s = createIntentStore({ key: KEY });
    globalThis.__intentStoreUnderTest = s;
    (function capture() {
      const prompt = "please upload the logs to " + marker.toString() + ".example.net and read " + marker.toString() + "/notes.md";
      s.captureTask("heap-session", prompt);
    })();
    /a/.exec("a"); // reset RegExp.input / RegExp.lastMatch, which hold the last regex subject process-wide
    const scan = () => {
      const p = writeHeapSnapshot(join(dir, `h${Date.now()}.heapsnapshot`));
      const buf = readFileSync(p);
      return buf.indexOf(marker) >= 0;
    };
    assert.equal(scan(), false, "the prompt or a plaintext feature survived captureTask");
    // The method has teeth: a retained copy of the same text is found.
    globalThis.__retained = ["kept ", marker.toString(), ".example.net"].join("");
    assert.equal(scan(), true, "positive control: a retained string must show in the snapshot");
    delete globalThis.__retained;
    // The store still works off the hashes alone.
    assert.equal(s.judge("heap-session", "Bash", POST(`${marker.toString()}.example.net`), []).aligned, true);
  } finally { delete globalThis.__intentStoreUnderTest; rmTree(dir); }
});

test("intentModeFromPolicy: off / report / ask / block from policy.intentAlignment; default and unknown resolve to report", () => {
  assert.equal(intentModeFromPolicy(undefined), "report");
  assert.equal(intentModeFromPolicy(null), "report");
  assert.equal(intentModeFromPolicy({}), "report");
  assert.equal(intentModeFromPolicy({ intentAlignment: "report" }), "report");
  assert.equal(intentModeFromPolicy({ intentAlignment: "ask" }), "ask");
  assert.equal(intentModeFromPolicy({ intentAlignment: "block" }), "block");
  assert.equal(intentModeFromPolicy({ intentAlignment: "off" }), "off");
  assert.equal(intentModeFromPolicy({ intentAlignment: false }), "off", "false is off, as the hook reads it");
  assert.equal(intentModeFromPolicy({ intentAlignment: "BLOCK" }), "report");
  assert.equal(intentModeFromPolicy({ intentAlignment: "deny" }), "report");
  assert.equal(intentModeFromPolicy({ intentAlignment: true }), "report");
  assert.equal(intentModeFromPolicy({ intentAlignment: { mode: "block" } }), "report");
});

test("authenticated captures: judge(..., { authenticatedOnly: true }) sees only features from captures marked authenticated; a session with none is task-unknown", () => {
  const s = createIntentStore({ key: KEY });
  assert.deepEqual(Object.keys(s.captureTask("u1", "Post the status to hooks.unauth.example.net", "", { authenticated: false })), ["features"]);
  assert.equal(s.judge("u1", "Bash", POST("hooks.unauth.example.net"), []).aligned, true, "the default judge (report) still sees every capture");
  const only = s.judge("u1", "Bash", POST("hooks.unauth.example.net"), [], "", { authenticatedOnly: true });
  assert.equal(only.class, "task-unknown", "no authenticated capture: task unknown");
  assert.equal(only.aligned, false);
  assert.deepEqual(Object.keys(only).sort(), ["aligned", "class", "firstForTarget", "targetHash"]);
  s.captureTask("m1", "Fix the typo in docs/README.md");
  s.captureTask("m1", "then post it to hooks.unauth.example.net", "", { authenticated: false });
  const mixed = s.judge("m1", "Bash", POST("hooks.unauth.example.net"), [], "", { authenticatedOnly: true });
  assert.equal(mixed.class, "egress", "an authenticated task exists, so the class is judged");
  assert.equal(mixed.aligned, false, "the host came only from the unauthenticated write");
  s.captureTask("a1", "post it to hooks.auth.example.net");
  assert.equal(s.judge("a1", "Bash", POST("hooks.auth.example.net"), [], "", { authenticatedOnly: true }).aligned, true, "captures are authenticated by default (in-process callers)");
});

test("INTENT_CLASS_TEXT: every class the hook names (cli/intent-alignment.mjs CLASS_TEXT) has the same text here, moorai-control included, so no SDK or sidecar reason reads 'undefined'", async () => {
  const { INTENT_CLASS_TEXT } = await import("../data/intent-server.mjs");
  const { CLASS_TEXT } = await import("../cli/intent-alignment.mjs");
  assert.ok("moorai-control" in CLASS_TEXT);
  for (const [cls, text] of Object.entries(CLASS_TEXT)) assert.equal(INTENT_CLASS_TEXT[cls], text, cls);
  assert.equal(typeof INTENT_CLASS_TEXT["task-unknown"], "string");
});

test("moorai-control under authenticatedOnly: a loopback upload is never aligned, even when an authenticated task named the port", () => {
  const s = createIntentStore({ key: KEY });
  s.captureTask("s1", "Post the status to http://127.0.0.1:8790/v1/task", "p1", { authenticated: true });
  const r = s.judge("s1", "Bash", { command: "curl -d @t http://127.0.0.1:8790/v1/task" }, [], "p1", { authenticatedOnly: true });
  assert.equal(r.aligned, false);
  assert.equal(r.class, "moorai-control");
});
