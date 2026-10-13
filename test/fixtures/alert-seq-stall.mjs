// Test-only preload (`node --import`) for test/alert-evidence.test.mjs: holds this process inside the
// alert sequence critical section. The first write of the alert chain head (the lock is held at that
// point) first writes MOORAI_TEST_STALL_MARK, then blocks for MOORAI_TEST_STALL_MS, then writes. Only the
// test child that is spawned with this preload reads these variables; production code never does.
import fs from "node:fs";
import { syncBuiltinESMExports } from "node:module";

const ms = Number(process.env.MOORAI_TEST_STALL_MS) || 0;
const mark = process.env.MOORAI_TEST_STALL_MARK;
const write = fs.writeFileSync;
let stalled = false;
fs.writeFileSync = function (path, ...rest) {
  if (!stalled && String(path).endsWith(".chain-alerts.head.json")) {
    stalled = true;
    if (mark) write(mark, String(process.pid));
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
  }
  return write.call(this, path, ...rest);
};
syncBuiltinESMExports();
