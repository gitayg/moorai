// Process setup for the command hook, imported first by cli/moorai-hook.mjs so it runs before any other module
// is evaluated.
//
// The hook is one short process per tool call, and most of its scan time on a short input is V8 compiling the
// detectors' regular expressions on their first execution (about 300 prompt-stage patterns, measured 29 ms of a
// 10-character scan). V8 runs a peephole optimizer over each pattern's interpreter bytecode at that compile; off,
// the same scan measured 14 ms. The optimizer rewrites bytecode sequences only: what a pattern matches does not
// change, and a pattern that runs often is still compiled to native code by V8's tier-up. Turning it off is a
// per-process V8 setting; a Node that refuses it keeps the default and only loses the time.
import v8 from "node:v8";

try { v8.setFlagsFromString("--no-regexp-peephole-optimization"); } catch { /* the default compiler stays */ }
