// Test-only preload (`node --import`) for test/record-chain-head.test.mjs: fault injection and an
// operation trace for the chain head files (any path containing ".chain-"). Production code never loads
// it and has no switch for it. The test's child script drives it through globalThis.__chainFault:
//   fail       { op, code }: that fs call on a chain path throws an error with that code
//              (op: "writeFileSync" | "fsyncSync" | "renameSync")
//   crashOn    n: the n-th write of a file whose name ends in ".head.json" writes only the first half
//              of its data, then the process kills itself (a crash in the middle of the write)
//   trace      every chain-path fs call, in order: [op, path], and every fsync, with its fd's path
import fs from "node:fs";
import { syncBuiltinESMExports } from "node:module";

const ctl = (globalThis.__chainFault = { fail: null, crashOn: 0, trace: [] });
const chain = (p) => typeof p === "string" && p.includes(".chain-");
const fdPath = new Map();
let headWrites = 0;

function maybeFail(op, p) {
  if (ctl.fail && ctl.fail.op === op && chain(p)) {
    const e = new Error(`${ctl.fail.code}: injected (${op} ${p})`);
    e.code = ctl.fail.code;
    throw e;
  }
}

const orig = { writeFileSync: fs.writeFileSync, openSync: fs.openSync, closeSync: fs.closeSync, fsyncSync: fs.fsyncSync, renameSync: fs.renameSync };

fs.writeFileSync = function (p, data, ...rest) {
  if (chain(p)) {
    ctl.trace.push(["writeFileSync", p]);
    maybeFail("writeFileSync", p);
    if (ctl.crashOn && String(p).endsWith(".head.json") && ++headWrites === ctl.crashOn) {
      const s = String(data);
      orig.writeFileSync.call(this, p, s.slice(0, Math.floor(s.length / 2)));
      process.kill(process.pid, "SIGKILL");
    }
  }
  return orig.writeFileSync.call(this, p, data, ...rest);
};
fs.openSync = function (p, ...rest) {
  const fd = orig.openSync.call(this, p, ...rest);
  fdPath.set(fd, String(p));
  return fd;
};
fs.closeSync = function (fd) { fdPath.delete(fd); return orig.closeSync.call(this, fd); };
fs.fsyncSync = function (fd) {
  const p = fdPath.get(fd);
  ctl.trace.push(["fsyncSync", p]);
  maybeFail("fsyncSync", p);
  return orig.fsyncSync.call(this, fd);
};
fs.renameSync = function (a, b) {
  if (chain(a) || chain(b)) { ctl.trace.push(["renameSync", a, b]); maybeFail("renameSync", b); }
  return orig.renameSync.call(this, a, b);
};
syncBuiltinESMExports();
