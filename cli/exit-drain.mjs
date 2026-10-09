// Leave a short-lived process by letting its event loop drain instead of calling process.exit().
//
// MEASURED (Windows 11, Node 24.15.0): two or more fetch() calls followed immediately by process.exit(0)
// abort the process with 0xC0000409 and
//     Assertion failed: !(handle->flags & UV_HANDLE_CLOSING), file src\win\async.c, line 76
// 5/5 runs, with or without an AbortSignal. The same child does not crash when it waits 50 ms before
// exiting, when V8 runs a single WebAssembly tier (--liftoff-only or --no-liftoff), or when it lets the
// loop end on its own. Node's fetch parses HTTP with llhttp compiled to WebAssembly, and V8 compiles
// the optimised tier of that module on a background thread. process.exit() closes the platform's
// async handle while that job can still post its result to it, and libuv on Windows asserts on a send
// to a closing handle (deps/uv/src/win/async.c:76, uv_async_send); the Unix uv_async_send has no such
// assert. A natural exit is safe: after uv_run, Node calls NodePlatform::DrainTasks, which blocks on
// user-blocking worker tasks ("e.g. wasm async compilation tasks", src/node_platform.cc).
//
// So: set the exit code and return a promise that never settles. A caller that `return`s or awaits it
// runs nothing further (the guarantee process.exit gave), and the process ends as soon as the loop is
// empty. Call it only once the work that matters has settled (the hook has awaited every post).
//
// What can still hold the loop: a fetch aborted by its AbortSignal while the TCP connect is pending
// (a console that never answers the SYN). MEASURED (Node 22 macOS, Node 24 Windows): the fetch rejects
// at the timeout, but the socket stays connecting and holds the loop; a drained exit took 10.6 s (the
// fetch implementation's own connect timeout). process.exit used to cut that short. Every request has settled by
// now, so any TCP socket left is dead weight and is destroyed. The hard exit remains a backstop
// for anything else (a ref'd timer, a child's pipe); it is unref'd, so it never holds the process open.
import net from "node:net";

export const EXIT_GRACE_MS = 1000;

export function exitWhenDrained(code = 0, graceMs = EXIT_GRACE_MS) {
  process.exitCode = code;
  try {
    // TCP only: stdio is a pipe or a TTY, never TCP (and reading process.stdin here would create it).
    for (const h of typeof process._getActiveHandles === "function" ? process._getActiveHandles() : []) {
      if (h instanceof net.Socket && h._handle && h._handle.constructor.name === "TCP") h.destroy();
    }
  } catch { /* the backstop below still bounds the exit */ }
  setTimeout(() => process.exit(code), graceMs).unref();
  return new Promise(() => {});
}
