// context.tree persistence (cli/context-tree.mjs): append-only JSONL per session, 0600 in a 0700 directory,
// one write per leaf, a torn last line reported and never rewritten, a hard cap that stops appending without
// dropping anything, a retention sweep, and indices that stay unique when hook processes append in parallel.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync, appendFileSync, statSync, existsSync, utimesSync, mkdirSync, openSync, closeSync } from "node:fs";
import { createRequire, syncBuiltinESMExports } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawn } from "node:child_process";
import { leafOf, appendLeaf, loadSession, sessionFile, sweepRetention, treeDir, listSessions, ContextTree } from "../cli/context-tree.mjs";
import { deriveKey } from "../cli/content-hash.mjs";
import { rmTree } from "./fs-cleanup.mjs";

const KEY = deriveKey("tenant-token-A");
const SID = "h2:0123456789abcdef";
const newHome = () => mkdtempSync(join(tmpdir(), "ctxtree-"));
const leaf = (i, stage = "file") => leafOf({ stage, source: stage === "file" ? `/w/f${i}.txt` : undefined, bytes: `content ${i} `.repeat(i % 2 ? 40 : 1), tenantKey: KEY, ts: new Date(1760000000000 + i).toISOString(), platform: "linux" });
const posix = process.platform !== "win32";

test("append-only JSONL: indices count up, the returned root is the tree root, a reload recomputes it", (t) => {
  const home = newHome(); t.after(() => rmTree(home));
  const mem = new ContextTree();
  for (let i = 0; i < 20; i++) {
    const r = appendLeaf(SID, leaf(i), { home });
    const m = mem.append(leaf(i));
    assert.deepEqual([r.index, r.root, r.capped], [i, m.root, false]);
  }
  const s = loadSession(SID, { home });
  assert.deepEqual([s.size, s.root, s.skipped, s.tornTail], [20, mem.root(), [], false]);
  const lines = readFileSync(sessionFile(SID, { home }), "utf8").split("\n");
  assert.equal(lines.length, 21);
  assert.equal(lines[20], "");
  assert.deepEqual(JSON.parse(lines[3]), leaf(3), "each line is one leaf, nothing else");
  assert.ok(sessionFile(SID, { home }).endsWith(join(".moorai", "context-tree", "h2-0123456789abcdef.jsonl")));
  assert.deepEqual(listSessions({ home }), [SID]);
});

test("permissions: directory 0700, session file 0600", { skip: !posix && "POSIX modes" }, (t) => {
  const home = newHome(); t.after(() => rmTree(home));
  mkdirSync(treeDir(home), { recursive: true, mode: 0o755 });
  appendLeaf(SID, leaf(0), { home });
  assert.equal(statSync(treeDir(home)).mode & 0o777, 0o700);
  assert.equal(statSync(sessionFile(SID, { home })).mode & 0o777, 0o600);
});

test("one append is one write() of one whole line to the session file", (t) => {
  const home = newHome(); t.after(() => rmTree(home));
  appendLeaf(SID, leaf(0), { home });
  const fs = createRequire(import.meta.url)("node:fs");
  const file = sessionFile(SID, { home });
  const origOpen = fs.openSync, origWrite = fs.writeSync;
  const fds = new Map(), writes = [];
  fs.openSync = function (p, ...rest) { const fd = origOpen.call(this, p, ...rest); fds.set(fd, String(p)); return fd; };
  fs.writeSync = function (fd, buf, ...rest) { if (fds.get(fd) === file) writes.push(Buffer.from(buf).toString("utf8")); return origWrite.call(this, fd, buf, ...rest); };
  syncBuiltinESMExports();
  try { appendLeaf(SID, leaf(1), { home }); } finally { fs.openSync = origOpen; fs.writeSync = origWrite; syncBuiltinESMExports(); }
  assert.equal(writes.length, 1);
  assert.equal(writes[0], JSON.stringify(JSON.parse(writes[0])) + "\n");
  assert.ok(!writes[0].slice(0, -1).includes("\n"));
});

test("a torn last line is ignored and reported, never rewritten; the next append closes it off", (t) => {
  const home = newHome(); t.after(() => rmTree(home));
  for (let i = 0; i < 3; i++) appendLeaf(SID, leaf(i), { home });
  const file = sessionFile(SID, { home });
  const torn = JSON.stringify(leaf(3)).slice(0, 40);
  appendFileSync(file, torn);
  const before = readFileSync(file);
  const s = loadSession(SID, { home });
  assert.deepEqual([s.size, s.tornTail, s.skipped.length, s.skipped[0].line, s.skipped[0].bytes], [3, true, 1, 4, 40]);
  assert.ok(readFileSync(file).equals(before), "load does not touch the file");
  const r = appendLeaf(SID, leaf(4), { home });
  assert.deepEqual([r.index, r.tornTail, r.skipped.length], [3, true, 1], "the append reports the torn tail it found");
  const after = readFileSync(file);
  assert.ok(after.subarray(0, before.length).equals(before), "the torn bytes are kept as they were");
  const s2 = loadSession(SID, { home });
  assert.deepEqual([s2.size, s2.tornTail, s2.skipped.length], [4, false, 1]);
  assert.deepEqual(s2.tree.leaves[3], leaf(4));
});

test("a line that is not a content-free leaf is skipped and reported", (t) => {
  const home = newHome(); t.after(() => rmTree(home));
  appendLeaf(SID, leaf(0), { home });
  appendFileSync(sessionFile(SID, { home }), JSON.stringify({ ...leaf(1), sourceHash: "/etc/passwd" }) + "\n");
  appendLeaf(SID, leaf(2), { home });
  const s = loadSession(SID, { home });
  assert.deepEqual([s.size, s.skipped.map((x) => x.line)], [2, [2]]);
  assert.throws(() => appendLeaf(SID, { ...leaf(3), blobHash: "raw text" }, { home }), /content-free/);
});

test("cap: at maxLeaves appends stop and say so; no old leaf is dropped", (t) => {
  const home = newHome(); t.after(() => rmTree(home));
  for (let i = 0; i < 3; i++) assert.equal(appendLeaf(SID, leaf(i), { home, maxLeaves: 3 }).index, i);
  const before = readFileSync(sessionFile(SID, { home }));
  const r = appendLeaf(SID, leaf(3), { home, maxLeaves: 3 });
  assert.deepEqual([r.capped, r.index, r.size, r.root], [true, null, 3, loadSession(SID, { home }).root]);
  assert.ok(readFileSync(sessionFile(SID, { home })).equals(before));
  assert.equal(loadSession(SID, { home, maxLeaves: 3 }).capped, true);
});

test("retention: files older than N days are deleted, newer ones kept; a new session runs the sweep", (t) => {
  const home = newHome(); t.after(() => rmTree(home));
  const now = Date.now();
  appendLeaf("h2:aaaaaaaaaaaaaaaa", leaf(0), { home });
  appendLeaf("h2:bbbbbbbbbbbbbbbb", leaf(0), { home });
  const old = sessionFile("h2:aaaaaaaaaaaaaaaa", { home });
  const t31 = (now - 31 * 86400000) / 1000;
  utimesSync(old, t31, t31);
  writeFileSync(join(treeDir(home), "unrelated.txt"), "x");
  utimesSync(join(treeDir(home), "unrelated.txt"), t31, t31);
  assert.deepEqual(sweepRetention({ home, days: 30, now }), { deleted: 1 });
  assert.ok(!existsSync(old));
  assert.ok(existsSync(sessionFile("h2:bbbbbbbbbbbbbbbb", { home })));
  assert.ok(existsSync(join(treeDir(home), "unrelated.txt")), "only session files are swept");
  appendLeaf("h2:cccccccccccccccc", leaf(0), { home });
  utimesSync(sessionFile("h2:bbbbbbbbbbbbbbbb", { home }), t31, t31);
  appendLeaf("h2:dddddddddddddddd", leaf(0), { home, retentionDays: 30 });
  assert.ok(!existsSync(sessionFile("h2:bbbbbbbbbbbbbbbb", { home })), "first leaf of a new session swept the old file");
  appendLeaf("h2:cccccccccccccccc", leaf(1), { home });
  assert.ok(existsSync(sessionFile("h2:cccccccccccccccc", { home })));
});

test("session ids: keyed ids only; the NO_KEY sentinel and path tricks are refused", () => {
  for (const bad of ["h2:nokey", "../x", "a/b", "h2-abc", "", "x".repeat(129)]) assert.throws(() => sessionFile(bad, { home: "/h" }), /session id/, bad);
  assert.equal(sessionFile("h2:00ff", { home: "/h" }), join("/h", ".moorai", "context-tree", "h2-00ff.jsonl"));
});

test("lock held elsewhere: the leaf is still written (index null), never dropped", (t) => {
  const home = newHome(); t.after(() => rmTree(home));
  appendLeaf(SID, leaf(0), { home });
  const lock = sessionFile(SID, { home }) + ".lock";
  writeFileSync(lock, String(process.pid));
  const r = appendLeaf(SID, leaf(1), { home, lockWaitMs: 10 });
  assert.deepEqual([r.unlocked, r.index, r.root], [true, null, null]);
  assert.equal(loadSession(SID, { home }).size, 2);
  assert.ok(existsSync(lock), "someone else's live lock is left alone");
});

test("parallel hook processes: every leaf gets a distinct index and every leaf is kept", async (t) => {
  const home = newHome(); t.after(() => rmTree(home));
  const mod = new URL("../cli/context-tree.mjs", import.meta.url).href;
  const code = `import { leafOf, appendLeaf } from ${JSON.stringify(mod)};
    const out = [];
    for (let i = 0; i < 25; i++) {
      const l = leafOf({ stage: "prompt", bytes: "p" + process.argv[1] + "-" + i, tenantKey: Buffer.alloc(32, 1), ts: "t" });
      out.push(appendLeaf(${JSON.stringify(SID)}, l, { home: ${JSON.stringify(home)}, lockWaitMs: 5000 }).index);
    }
    process.stdout.write(JSON.stringify(out));`;
  const run = (n) => new Promise((res, rej) => {
    const c = spawn(process.execPath, ["--input-type=module", "-e", code, String(n)], { stdio: ["ignore", "pipe", "inherit"] });
    let o = ""; c.stdout.on("data", (d) => { o += d; });
    c.on("exit", (code) => (code === 0 ? res(JSON.parse(o)) : rej(new Error(`child ${n} exit ${code}`))));
  });
  const all = (await Promise.all(Array.from({ length: 8 }, (_, n) => run(n)))).flat();
  assert.equal(all.length, 200);
  assert.ok(all.every((i) => Number.isInteger(i)), "every append got the lock");
  assert.deepEqual([...all].sort((a, b) => a - b), Array.from({ length: 200 }, (_, i) => i));
  const s = loadSession(SID, { home });
  assert.deepEqual([s.size, s.skipped.length], [200, 0]);
});
