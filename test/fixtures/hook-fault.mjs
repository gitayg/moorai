// TEST-ONLY fault injection for the hook's internal-error path (test/fail-mode-hook.test.mjs). Loaded as
// a Node preload, never by the hook itself:
//
//   node --import <file URL of this module> cli/moorai-hook.mjs
//
// The hook has no knob that makes it throw, and must not have one: under an open fail mode a switch that
// forces an internal error is a switch that lets a call through unread. So the fault comes from outside
// the hook's code: String.prototype.startsWith throws when the string it is called on contains SENTINEL.
// Every other string behaves exactly as before. The hook calls startsWith on the call's own strings in
// code that no try/catch wraps (agentPath() on a Read's file_path before the file is read; postDispatched()
// on a PostToolUse's tool name), so the throw reaches main().catch, which is the path a real bug takes.
// If a refactor ever wraps or removes those calls, the fault stops firing and the tests that rely on it
// fail loudly (no deny, no FAULT_MARK on stderr); they never pass vacuously.
export const SENTINEL = "moorai-fault-sentinel";
export const FAULT_MARK = "hook-fault: injected";

const orig = String.prototype.startsWith;
let fired = false;
Object.defineProperty(String.prototype, "startsWith", {
  configurable: true,
  writable: true,
  value: function startsWith(...args) {
    const s = String(this);
    if (s.includes(SENTINEL)) {
      if (!fired) { fired = true; try { process.stderr.write(`${FAULT_MARK}\n`); } catch { /* the throw is the point */ } }
      throw new Error("injected test fault");
    }
    return orig.apply(s, args);
  }
});
