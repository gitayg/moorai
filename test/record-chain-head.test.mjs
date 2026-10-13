// The chain head (cli/record-chain.mjs) is the only memory of the last number handed out. A head that
// was not persisted, or that cannot be read back, must never make the chain hand out a number again or
// restart at 1: on the alert chain that is a duplicate seq, which the console records as a counter reset.
// Faults come from a test-only preload (test/fixtures/record-chain-fault.mjs), never a production switch.
//
//   node --test --import ./test/hermetic-env.mjs test/record-chain-head.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync, readFileSync, readdirSync, chmodSync, statSync, existsSync, utimesSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { stampAlertSeq } from "../cli/alert-seq.mjs";
import { nextLink, genesis } from "../cli/record-chain.mjs";
import { rmTree } from "./fs-cleanup.mjs";

const SEQ_URL = new URL("../cli/alert-seq.mjs", import.meta.url).href;
const CHAIN_URL = new URL("../cli/record-chain.mjs", import.meta.url).href;
const FAULT = new URL("./fixtures/record-chain-fault.mjs", import.meta.url).href;
const HEAD = ".chain-alerts.head.json";
const POSIX_USER = process.platform !== "win32" && !(process.getuid && process.getuid() === 0);
const tmp = (tag) => mkdtempSync(join(tmpdir(), `moorai-chain-${tag}-`));
const stamp = (dir, n = 1) => Array.from({ length: n }, (_, i) => stampAlertSeq({ i }, { tenant: "t", dir }).seq ?? null);

// Runs `body` in a child with the fault preload. `body` sees `dir`, `stamp(n)`, `link()` and `fault`
// (globalThis.__chainFault) and assigns its result to `out`, which comes back parsed.
function faulted(dir, body) {
  const script = `const { stampAlertSeq } = await import(${JSON.stringify(SEQ_URL)});
    const { nextLink } = await import(${JSON.stringify(CHAIN_URL)});
    const dir = ${JSON.stringify(dir)}; const fault = globalThis.__chainFault;
    const stamp = (n = 1) => Array.from({ length: n }, (_, i) => stampAlertSeq({ i }, { tenant: "t", dir }).seq ?? null);
    const link = () => nextLink("alerts", "r", { tenant: "t", dir });
    let out; ${body}
    console.log(JSON.stringify(out));`;
  const r = spawnSync(process.execPath, ["--import", FAULT, "--input-type=module", "-e", script], { encoding: "utf8", timeout: 30000 });
  return { ...r, out: r.status === 0 ? JSON.parse(r.stdout) : undefined };
}
const leftovers = (dir) => readdirSync(dir).filter((f) => f.includes(".tmp"));

test("a head write that fails (ENOSPC) hands out no number, and the stamp after it clears takes the next one", () => {
  const dir = tmp("enospc");
  try {
    const r = faulted(dir, `const before = stamp(2);
      fault.fail = { op: "writeFileSync", code: "ENOSPC" };
      const during = stamp(2); const l = link();
      fault.fail = null;
      out = { before, during, l, after: stamp(1) };`);
    assert.equal(r.status, 0, r.stderr);
    const { before, during, l, after } = r.out;
    assert.deepEqual(before, [1, 2]);
    assert.deepEqual(during, [null, null], `a head that was not persisted still handed out ${during}`);
    assert.equal(l.seq, 0, "nextLink reports no number");
    assert.equal(l.unnumbered, "head-unsaved");
    assert.equal(typeof l.prev, "string"); assert.equal(typeof l.chash, "string");
    assert.deepEqual(after, [3]);
    assert.deepEqual(leftovers(dir), []);
  } finally { rmTree(dir); }
});

test("every step of the head write that fails (fsync, rename) hands out no number and leaves no temp file", () => {
  for (const op of ["fsyncSync", "renameSync"]) {
    const dir = tmp(op);
    try {
      const r = faulted(dir, `const before = stamp(1);
        fault.fail = { op: ${JSON.stringify(op)}, code: "EIO" };
        const during = stamp(2);
        const left = (await import("node:fs")).readdirSync(dir).filter((f) => f.includes(".tmp"));
        fault.fail = null;
        out = { before, during, left, after: stamp(1) };`);
      assert.equal(r.status, 0, r.stderr);
      assert.deepEqual(r.out, { before: [1], during: [null, null], left: [], after: [2] }, op);
      assert.deepEqual(leftovers(dir), [], op);
    } finally { rmTree(dir); }
  }
});

test("a read-only head file never gives one number twice; a read-only directory gives none until it is writable", { skip: !POSIX_USER && "needs POSIX permissions and a non-root user" }, () => {
  const dir = tmp("ro");
  try {
    assert.deepEqual(stamp(dir, 3), [1, 2, 3]);
    chmodSync(join(dir, HEAD), 0o444);
    const ro = stamp(dir, 2).filter((s) => s !== null);
    assert.equal(new Set(ro).size, ro.length, `duplicates with a read-only head: ${ro}`);
    assert.ok(ro.every((s) => s > 3), `${ro}`);
    const last = ro.length ? ro[ro.length - 1] : 3;
    chmodSync(dir, 0o555);
    try { assert.deepEqual(stamp(dir, 2), [null, null]); } finally { chmodSync(dir, 0o755); }
    assert.deepEqual(stamp(dir, 1), [last + 1]);
  } finally { try { chmodSync(dir, 0o755); } catch { /* removed */ } rmTree(dir); }
});

test("a crash in the middle of a head write never restarts the counter", () => {
  const dir = tmp("crash");
  try {
    const r = faulted(dir, `fault.crashOn = 6; out = stamp(10);`);
    assert.equal(r.signal, "SIGKILL", `the child was meant to die in the 6th head write: ${r.status} ${r.stderr}`);
    // The dead child still holds the alert lock; aged past the stale age, the next stamper breaks it.
    const old = (Date.now() - 30000) / 1000;
    utimesSync(join(dir, ".chain-alerts.lock"), old, old);
    const next = stamp(dir, 1)[0];
    assert.equal(next, 6, `after a crash the counter went to ${next}`);
    assert.doesNotThrow(() => JSON.parse(readFileSync(join(dir, HEAD), "utf8")), "the head on disk is whole");
  } finally { rmTree(dir); }
});

test("a torn head with no good copy takes no number rather than restarting at 1, and stays that way", () => {
  const dir = tmp("torn");
  try {
    writeFileSync(join(dir, HEAD), '{"seq":41,"chash":"9f2c');
    assert.deepEqual(stamp(dir, 2), [null, null]);
    const l = nextLink("alerts", "r", { tenant: "t", dir });
    assert.equal(l.seq, 0);
    assert.equal(l.unnumbered, "head-unreadable");
    assert.equal(l.prev, genesis("alerts", "t"));
    assert.equal(readFileSync(join(dir, HEAD), "utf8"), '{"seq":41,"chash":"9f2c', "the torn head is left for inspection");
  } finally { rmTree(dir); }
});

test("a head that exists but cannot be read takes no number rather than restarting at 1", { skip: !POSIX_USER && "needs POSIX permissions and a non-root user" }, () => {
  const dir = tmp("unreadable");
  try {
    assert.deepEqual(stamp(dir, 2), [1, 2]);
    chmodSync(join(dir, HEAD), 0o000);
    if (existsSync(join(dir, HEAD + ".prev"))) chmodSync(join(dir, HEAD + ".prev"), 0o000);
    assert.deepEqual(stamp(dir, 1), [null]);
    chmodSync(join(dir, HEAD), 0o644);
    assert.deepEqual(stamp(dir, 1), [3]);
  } finally { rmTree(dir); }
});

test("a torn head with a good copy resumes after the copy's number and stays linked", () => {
  const dir = tmp("copy");
  try {
    const links = Array.from({ length: 4 }, () => nextLink("otel", "r", { tenant: "t", dir }));
    assert.deepEqual(links.map((l) => l.seq), [1, 2, 3, 4]);
    writeFileSync(join(dir, ".chain-otel.head.json"), "{\"seq\":4,");
    const l5 = nextLink("otel", "r", { tenant: "t", dir });
    assert.equal(l5.seq, 5);
    assert.equal(l5.prev, links[3].chash, "the resumed link commits to the last good head");
    assert.equal(JSON.parse(readFileSync(join(dir, ".chain-otel.head.json"), "utf8")).seq, 5, "the head is rewritten whole");
  } finally { rmTree(dir); }
});

test("the head is written to a temp file, fsynced, then renamed over the head, after its copy, keeping the head's mode", () => {
  const dir = tmp("atomic");
  try {
    assert.deepEqual(stamp(dir, 1), [1]);
    if (process.platform !== "win32") chmodSync(join(dir, HEAD), 0o600);
    const r = faulted(dir, `fault.trace.length = 0; stamp(1); out = fault.trace;`);
    assert.equal(r.status, 0, r.stderr);
    const head = join(dir, HEAD);
    const ops = r.out;
    const ren = ops.findIndex((o) => o[0] === "renameSync" && o[2] === head);
    assert.ok(ren > 0, `no rename onto the head: ${JSON.stringify(ops)}`);
    const tmpPath = ops[ren][1];
    assert.notEqual(tmpPath, head);
    const wrote = ops.findIndex((o) => o[0] === "writeFileSync" && o[1] === tmpPath);
    const synced = ops.findIndex((o) => o[0] === "fsyncSync" && o[1] === tmpPath);
    assert.ok(wrote >= 0 && synced > wrote && ren > synced, `write, fsync, rename out of order: ${JSON.stringify(ops)}`);
    assert.ok(!ops.some((o) => o[0] === "writeFileSync" && o[1] === head), "the head itself is never written in place");
    const copy = ops.findIndex((o) => o[0] === "renameSync" && o[2] === head + ".prev");
    assert.ok(copy >= 0 && copy < ren, `the copy is not replaced before the head: ${JSON.stringify(ops)}`);
    assert.equal(JSON.parse(readFileSync(head + ".prev", "utf8")).seq, 2, "the copy holds the head just written");
    if (process.platform !== "win32") {
      assert.equal(statSync(head).mode & 0o777, 0o600, "the head keeps its mode");
      assert.ok(!ops.some((o) => o[0] === "fsyncSync" && o[1] === dir), `the directory is fsynced, doubling the alert lock hold: ${JSON.stringify(ops)}`);
    }
    assert.deepEqual(leftovers(dir), []);
  } finally { rmTree(dir); }
});

test("a fresh directory still starts at 1 and the stamp needs no head or copy to exist", () => {
  const dir = tmp("fresh");
  try {
    assert.ok(!existsSync(join(dir, HEAD)));
    assert.deepEqual(stamp(dir, 2), [1, 2]);
  } finally { rmTree(dir); }
});

test("a local log chain's head is replaced atomically but never fsynced (it is written on every hook event)", () => {
  const dir = tmp("logchain");
  try {
    const r = faulted(dir, `const { stampRecord } = await import(${JSON.stringify(CHAIN_URL)});
      const seqs = [1, 2, 3].map((i) => stampRecord("signals.jsonl", { i }, { tenant: "t", dir }).chain.seq);
      out = { seqs, ops: fault.trace };`);
    assert.equal(r.status, 0, r.stderr);
    assert.deepEqual(r.out.seqs, [1, 2, 3]);
    const head = join(dir, ".chain-signals.jsonl.head.json");
    assert.ok(r.out.ops.some((o) => o[0] === "renameSync" && o[2] === head), "the head is renamed into place");
    assert.ok(!r.out.ops.some((o) => o[0] === "writeFileSync" && o[1] === head), "the head is never written in place");
    assert.deepEqual(r.out.ops.filter((o) => o[0] === "fsyncSync"), [], "no fsync on the log chain");
  } finally { rmTree(dir); }
});
