// Teardown helpers for tests that run the hook, the gateway or a proxy against a throwaway HOME.
//
// WHY. The hook hands work to DETACHED, unref'd workers (posture beat, index scan, agent scan,
// escalation, MCP-usage flush — cli/moorai-hook.mjs, cli/mcp-usage-beat.mjs). They outlive the hook
// process the test awaited, and they `mkdirSync(~/.moorai, { recursive: true })` + write a stamp when
// they finish. MEASURED: a posture-beat worker recreated `<home>/.moorai/posture-beat-claude-code.json`
// after the test's rmSync had already removed the whole home; when the write lands mid-walk instead,
// rmSync fails with ENOTEMPTY and the test fails in teardown (CI; 3 of 20 local runs of five files under load).
// The test cannot wait for those workers (it never sees their pids), so removal retries, and a dir
// left behind by a late writer is accepted — a failed test is not.
import { rmSync } from "node:fs";

const RACE_CODES = new Set(["ENOTEMPTY", "EBUSY", "EPERM"]);
const sleepSync = (ms) => Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);

export function rmTree(dir) {
  try {
    rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 50 });
  } catch (e) {
    if (!RACE_CODES.has(e && e.code)) throw e;
    sleepSync(200);
    try { rmSync(dir, { recursive: true, force: true }); } catch (e2) { if (!RACE_CODES.has(e2 && e2.code)) throw e2; }
  }
}

// Stops a child the test spawned and resolves once it has exited, so nothing it is still writing
// races the teardown's rmTree. SIGTERM first (the gateway drains on it), SIGKILL if it overstays.
export function stopChild(child, graceMs = 5000) {
  if (!child || child.exitCode !== null || child.signalCode !== null) return Promise.resolve();
  return new Promise((resolve) => {
    const t = setTimeout(() => { try { child.kill("SIGKILL"); } catch { /* gone */ } }, graceMs);
    child.once("exit", () => { clearTimeout(t); resolve(); });
    try { child.kill(); } catch { clearTimeout(t); resolve(); }
  });
}
