// Opt-in: block-mode MCP tool drift end to end between REAL agent pieces (the stdio guard and the HTTP
// gateway) and the REAL console started from its own repo — see scripts/mcp-tool-drift-console-e2e.mjs
// for the seven steps it walks over real HTTP (block mode set by the admin, fingerprints reported,
// approval pinned into the signed policy, drift quarantined + toolDrift + alert, re-approval, release).
//
//   MOORAI_LIVE_CONSOLE=1 [MOORAI_CONSOLE_DIR=../RAISEME-server] node --test --import ./test/hermetic-env.mjs test/mcp-tool-drift-console-e2e.test.mjs
//
// Skipped without MOORAI_LIVE_CONSOLE=1 (the console is another repo, not a dependency of this one).
// Falsification: MOORAI_E2E_BREAK=no-block serves the walk without the admin's block step and must go red.
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { runConsoleE2E } from "../scripts/mcp-tool-drift-console-e2e.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const CONSOLE_DIR = process.env.MOORAI_CONSOLE_DIR || resolve(ROOT, "..", "RAISEME-server");
const skip = process.env.MOORAI_LIVE_CONSOLE !== "1" ? "opt-in: set MOORAI_LIVE_CONSOLE=1"
  : !existsSync(join(CONSOLE_DIR, "server", "server.js")) ? `no console at ${CONSOLE_DIR} (set MOORAI_CONSOLE_DIR)` : false;

test("real agent + real console: block → report → approve → drift quarantined + toolDrift + alert → re-approve → released", { skip, timeout: 240000 }, async (t) => {
  const lines = [];
  let r;
  try { r = await runConsoleE2E({ consoleDir: CONSOLE_DIR, log: (s) => lines.push(s) }); }
  finally { for (const l of lines) t.diagnostic(l); }
  assert.ok(r.ok);
  const need = ["1. mcpToolDrift set to block", "2. fingerprints arrived", "3. admin approves", "5. drifted tool left out", "5. call to the drifted tool refused", "5. unchanged tool still works", "5. console registry shows toolDrift", "5. quarantine alert arrived", "6. admin re-approves", "7. after the policy refresh the tool is released"];
  for (const piece of ["stdio guard", "HTTP gateway"]) {
    for (const n of need.slice(1)) assert.ok(r.steps.some((s) => s.piece === piece && s.ok && s.step.startsWith(n)), `${piece}: missing step "${n}"`);
  }
  assert.ok(r.steps.some((s) => s.piece === "console" && s.ok && s.step.startsWith(need[0])));
});
