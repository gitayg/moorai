// context.tree's cached frontier, upload state and mode (cli/context-tree.mjs), the parts the hook relies on:
// O(log n) appends across processes through <session>.frontier, self-healing when it is missing or stale,
// the per-session lock taken through cli/alert-seq.mjs withFileLock, the console upload worker, and the
// contextTree policy mode.
//
//   node --test --import ./test/hermetic-env.mjs test/context-tree-hook-frontier.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, readFileSync, unlinkSync, appendFileSync, existsSync, statSync, utimesSync } from "node:fs";
import { createRequire, syncBuiltinESMExports } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawn } from "node:child_process";
import { leafOf, appendLeaf, loadSession, sessionFile, frontierFile, readFrontier, sessionHead, sweepRetention, contextTreeMode, flushContextTree, readUpload, uploadFile, claimUpload, ContextTree, UPLOAD_AT_LEAVES, canonicalJson } from "../cli/context-tree.mjs";
import { withFileLock, stampAlertSeq } from "../cli/alert-seq.mjs";
import { rmTree } from "./fs-cleanup.mjs";

const KEY = Buffer.alloc(32, 7);
const SID = "h2:0123456789abcdef";
const newHome = () => mkdtempSync(join(tmpdir(), "moorai-ctx-frontier-"));
const leaf = (i) => leafOf({ stage: "tool-output", sourceKind: "name", source: "Bash", bytes: `output ${i}`, tenantKey: KEY, ts: "2026-10-13T00:00:00.000Z" });
const posix = process.platform !== "win32";

test("the frontier holds the compact range: size, the file's bytes, and one subtree hash per set bit; its root is the tree's", (t) => {
  const home = newHome(); t.after(() => rmTree(home));
  const mem = new ContextTree();
  for (let i = 0; i < 37; i++) {
    const r = appendLeaf(SID, leaf(i), { home });
    mem.append(leaf(i));
    assert.deepEqual([r.index, r.size, r.root], [i, i + 1, mem.root()], `append ${i}`);
    const f = readFrontier(SID, { home });
    assert.equal(f.size, i + 1);
    assert.equal(f.hashes.length, (i + 1).toString(2).replace(/0/g, "").length, "one hash per set bit of the size");
    assert.equal(f.bytes, statSync(sessionFile(SID, { home })).size);
  }
  assert.deepEqual(sessionHead(SID, { home }), { size: 37, root: mem.root() });
  if (posix) assert.equal(statSync(frontierFile(SID, { home })).mode & 0o777, 0o600);
});

test("an append with a valid frontier never reads the session file (O(log n), not a reload)", (t) => {
  const home = newHome(); t.after(() => rmTree(home));
  for (let i = 0; i < 64; i++) appendLeaf(SID, leaf(i), { home });
  const fs = createRequire(import.meta.url)("node:fs");
  const file = sessionFile(SID, { home });
  const orig = fs.readFileSync;
  let reads = 0;
  fs.readFileSync = function (p, ...rest) { if (String(p) === file) reads++; return orig.call(this, p, ...rest); };
  syncBuiltinESMExports();
  let r, h;
  try { r = appendLeaf(SID, leaf(64), { home }); h = sessionHead(SID, { home }); } finally { fs.readFileSync = orig; syncBuiltinESMExports(); }
  assert.equal(reads, 0, "the session file was read on the append path");
  assert.deepEqual([r.index, r.healed], [64, false]);
  assert.equal(h.root, loadSession(SID, { home }).root);
  assert.equal(r.root, h.root);
});

test("self-healing: a missing, corrupt or stale frontier is rebuilt from the session file once, and the root stays right", (t) => {
  const home = newHome(); t.after(() => rmTree(home));
  for (let i = 0; i < 10; i++) appendLeaf(SID, leaf(i), { home });
  const ff = frontierFile(SID, { home });
  unlinkSync(ff);
  let r = appendLeaf(SID, leaf(10), { home });
  assert.deepEqual([r.index, r.healed, r.root], [10, true, loadSession(SID, { home }).root], "missing");
  r = appendLeaf(SID, leaf(11), { home });
  assert.equal(r.healed, false, "healed once, then the cache serves");
  writeFileSync(ff, "{not json");
  r = appendLeaf(SID, leaf(12), { home });
  assert.deepEqual([r.index, r.healed, r.root], [12, true, loadSession(SID, { home }).root], "corrupt");
  // A frontier whose hashes are wrong for its byte count would give a wrong root: it is rejected by shape
  // (hash count != set bits) and rebuilt.
  const f = JSON.parse(readFileSync(ff, "utf8"));
  writeFileSync(ff, JSON.stringify({ ...f, hashes: f.hashes.slice(1) }));
  r = appendLeaf(SID, leaf(13), { home });
  assert.deepEqual([r.index, r.healed, r.root], [13, true, loadSession(SID, { home }).root], "wrong shape");
  // A leaf written past the frontier (an append that could not get the lock) leaves its byte count behind.
  const lock = sessionFile(SID, { home }) + ".lock";
  writeFileSync(lock, String(process.pid));
  assert.equal(appendLeaf(SID, leaf(14), { home, lockWaitMs: 5 }).unlocked, true);
  unlinkSync(lock);
  assert.deepEqual(sessionHead(SID, { home }), { size: 15, root: loadSession(SID, { home }).root }, "head heals too");
  r = appendLeaf(SID, leaf(15), { home });
  assert.deepEqual([r.index, r.healed, r.root], [15, false, loadSession(SID, { home }).root], "head already rewrote it");
  // A hand-appended torn line: stale bytes, rebuilt, the fragment closed off.
  appendFileSync(sessionFile(SID, { home }), '{"stage":"pro');
  r = appendLeaf(SID, leaf(16), { home });
  const s = loadSession(SID, { home });
  assert.deepEqual([r.index, r.healed, r.tornTail, r.root, s.size, s.skipped.length], [16, true, true, s.root, 17, 1]);
});

test("parallel processes, mixed locked and unlocked appends: the frontier's root equals the full recompute", async (t) => {
  const home = newHome(); t.after(() => rmTree(home));
  const mod = new URL("../cli/context-tree.mjs", import.meta.url).href;
  // Every third append gives up on the lock almost at once, so some leaves land past the frontier and the
  // next locked append has to heal it.
  const code = `import { leafOf, appendLeaf } from ${JSON.stringify(mod)};
    const out = [];
    for (let i = 0; i < 30; i++) {
      const l = leafOf({ stage: "prompt", bytes: "p" + process.argv[1] + "-" + i, tenantKey: Buffer.alloc(32, 1), ts: "t" });
      const r = appendLeaf(${JSON.stringify(SID)}, l, { home: ${JSON.stringify(home)}, lockWaitMs: i % 3 === 2 ? 0 : 5000 });
      out.push({ index: r.index, root: r.root, size: r.size });
    }
    process.stdout.write(JSON.stringify(out));`;
  const run = (n) => new Promise((res, rej) => {
    const c = spawn(process.execPath, ["--input-type=module", "-e", code, String(n)], { stdio: ["ignore", "pipe", "inherit"] });
    let o = ""; c.stdout.on("data", (d) => { o += d; });
    c.on("exit", (code) => (code === 0 ? res(JSON.parse(o)) : rej(new Error(`child ${n} exit ${code}`))));
  });
  const all = (await Promise.all(Array.from({ length: 8 }, (_, n) => run(n)))).flat();
  const s = loadSession(SID, { home });
  assert.deepEqual([s.size, s.skipped.length, s.tornTail], [240, 0, false], "every leaf kept, none torn");
  const indexed = all.filter((x) => Number.isInteger(x.index));
  assert.equal(new Set(indexed.map((x) => x.index)).size, indexed.length, "no index handed out twice");
  // Each locked append's root is the root of the tree at its size, as recomputed from the file.
  for (const x of indexed) assert.equal(x.root, s.tree.rootAt(x.size), `index ${x.index}`);
  assert.deepEqual(sessionHead(SID, { home }), { size: 240, root: s.root });
  const last = appendLeaf(SID, leaf(999), { home });
  assert.equal(last.root, loadSession(SID, { home }).root);
});

test("a lock-less line landing between a locked append's stat and its write: the index and root come from the file", (t) => {
  const home = newHome(); t.after(() => rmTree(home));
  for (let i = 0; i < 5; i++) appendLeaf(SID, leaf(i), { home });
  const fs = createRequire(import.meta.url)("node:fs");
  const file = sessionFile(SID, { home });
  const orig = fs.openSync;
  let once = true;
  // The lock-less writer's line goes in just before this append opens the session file to write its own.
  fs.openSync = function (p, flags, ...rest) {
    if (once && String(p) === file && flags === "a") { once = false; fs.openSync = orig; syncBuiltinESMExports(); fs.appendFileSync(file, canonicalJson(leaf(100)) + "\n"); }
    return orig.call(this, p, flags, ...rest);
  };
  syncBuiltinESMExports();
  let r;
  try { r = appendLeaf(SID, leaf(5), { home }); } finally { fs.openSync = orig; syncBuiltinESMExports(); }
  assert.equal(once, false, "the interleaving happened");
  const s = loadSession(SID, { home });
  assert.equal(s.size, 7);
  assert.deepEqual(s.tree.leaves[6], leaf(5), "this append's leaf is the 7th line");
  assert.deepEqual([r.index, r.size, r.root], [6, 7, s.root], "not the index the frontier would have handed out (5)");
  const next = appendLeaf(SID, leaf(6), { home });
  assert.deepEqual([next.index, next.healed, next.root], [7, true, loadSession(SID, { home }).root], "the stale frontier is rebuilt");
});

test("the append lock is alert-seq's withFileLock (no private copy), with its behaviour", (t) => {
  const src = readFileSync(new URL("../cli/context-tree.mjs", import.meta.url), "utf8");
  assert.match(src, /import \{ withFileLock \} from "\.\/alert-seq\.mjs"/);
  assert.doesNotMatch(src, /openSync\([^)]*"wx"/, "no lock acquisition of its own");
  const dir = newHome(); t.after(() => rmTree(dir));
  const lock = join(dir, "x.lock");
  assert.deepEqual(withFileLock(lock, () => 42, { mode: 0o600 }), { held: true, value: 42 });
  assert.equal(existsSync(lock), false, "released");
  writeFileSync(lock, String(process.pid));
  const t0 = Date.now();
  assert.deepEqual(withFileLock(lock, () => 1, { waitMs: 20 }), { held: false }, "a live holder's lock is never broken");
  assert.ok(Date.now() - t0 < 1000);
  // An abandoned lock (old, holder gone) is broken.
  writeFileSync(lock, "999999999");
  const old = (Date.now() - 10000) / 1000;
  utimesSync(lock, old, old);
  assert.deepEqual(withFileLock(lock, () => "ok"), { held: true, value: "ok" });
  // stampAlertSeq still numbers alerts through it.
  const a = stampAlertSeq({ category: "x" }, { tenant: "t", dir }), b = stampAlertSeq({ category: "y" }, { tenant: "t", dir });
  assert.deepEqual([a.seq, b.seq], [1, 2]);
});

test("retention sweeps old frontier and upload files with their session", (t) => {
  const home = newHome(); t.after(() => rmTree(home));
  appendLeaf(SID, leaf(0), { home, upload: true });
  const files = [sessionFile(SID, { home }), frontierFile(SID, { home }), uploadFile(SID, { home })];
  for (const f of files) assert.ok(existsSync(f), f);
  const old = (Date.now() - 40 * 86400000) / 1000;
  for (const f of files) utimesSync(f, old, old);
  assert.equal(sweepRetention({ home }).deleted, 3);
  for (const f of files) assert.equal(existsSync(f), false, f);
});

test("contextTree mode: from the verified policy; absent or unknown is local; console needs a signature envelope", () => {
  const sig = { policySig: { v: 1, sig: "abc" } };
  assert.equal(contextTreeMode(null), "local");
  assert.equal(contextTreeMode({}), "local");
  assert.equal(contextTreeMode({ contextTree: "bogus" }), "local");
  assert.equal(contextTreeMode({ contextTree: "off" }), "off");
  assert.equal(contextTreeMode({ contextTree: "off", ...sig }), "off");
  assert.equal(contextTreeMode({ contextTree: "local", ...sig }), "local");
  assert.equal(contextTreeMode({ contextTree: "console", ...sig }), "console");
  assert.equal(contextTreeMode({ contextTree: "console" }), "local", "unsigned console reads local");
});

test("upload: the lease is taken at UPLOAD_AT_LEAVES; the worker posts unsent leaves in order, advances only on 2xx, and backs off", async (t) => {
  const home = newHome(); t.after(() => rmTree(home));
  const now = 1_000_000;
  let due = 0;
  for (let i = 0; i < UPLOAD_AT_LEAVES; i++) if (appendLeaf(SID, leaf(i), { home, upload: true, now }).uploadDue) due++;
  assert.equal(due, 1, "one call takes the lease");
  assert.equal(readUpload(SID, { home }).lease, now);
  const posts = [];
  let status = 500;
  const fetchImpl = async (url, init) => { posts.push({ url, body: JSON.parse(init.body), headers: init.headers }); return { status }; };
  const config = { serverUrl: "http://console.invalid", installToken: "tok" };
  let r = await flushContextTree({ config, home, fetchImpl, now: () => now, backoff: () => ({ active: false }) });
  assert.deepEqual([r.status, r.posted], ["rejected", 0]);
  let u = readUpload(SID, { home });
  assert.deepEqual([u.sent, u.rejects, u.retryAt > now, u.lease], [0, 1, true, 0]);
  assert.equal(appendLeaf(SID, leaf(50), { home, upload: true, now: now + 1 }).uploadDue, false, "no lease inside the back-off");
  status = 200;
  r = await flushContextTree({ config, home, fetchImpl, now: () => now + 2, backoff: () => ({ active: false }) });
  assert.deepEqual([r.status, r.posted], ["posted", 51]);
  const ok = posts[1];
  assert.equal(ok.url, "http://console.invalid/api/context-tree");
  assert.equal(ok.headers["X-Install-Token"], "tok");
  assert.deepEqual([ok.body.v, ok.body.sessionHash, ok.body.leaves.length, ok.body.leaves[0].index, ok.body.leaves[50].index], [1, SID, 51, 0, 50]);
  assert.deepEqual(ok.body.leaves[7], { index: 7, ...loadSession(SID, { home }).tree.leaves[7] });
  assert.equal(readUpload(SID, { home }).sent, 51);
  r = await flushContextTree({ config, home, fetchImpl, now: () => now + 3, backoff: () => ({ active: false }) });
  assert.equal(posts.length, 2, "nothing unsent: nothing posted");
  appendLeaf(SID, leaf(51), { home, upload: true, now: now + 4 });
  assert.equal(claimUpload(SID, { home, now: now + 5 }), true, "session end takes the lease for one pending leaf");
  r = await flushContextTree({ config, home, fetchImpl, now: () => now + 6, backoff: () => ({ active: false }) });
  assert.deepEqual(posts[2].body.leaves.map((l) => l.index), [51]);
  // The console back-off: nothing sent, a retry scheduled.
  appendLeaf(SID, leaf(52), { home, upload: true, now: now + 7 });
  r = await flushContextTree({ config, home, fetchImpl, now: () => now + 8, backoff: () => ({ active: true }) });
  assert.deepEqual([r.status, posts.length, readUpload(SID, { home }).retryAt > now + 8], ["console-backoff", 3, true]);
  // A session never marked for upload is never sent.
  appendLeaf("h2:fedcba9876543210", leaf(0), { home });
  r = await flushContextTree({ config, home, fetchImpl, now: () => now + 400000, backoff: () => ({ active: false }) });
  assert.ok(posts.every((p) => p.body.sessionHash === SID));
  assert.equal(claimUpload("h2:fedcba9876543210", { home }), false);
});
