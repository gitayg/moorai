// Preloaded into every unit-test process by `npm run test:unit` (`node --test --import ...`).
//
// WHY THIS EXISTS, measured rather than assumed. 27 test files build a throwaway HOME and spawn the
// hook with `{ ...process.env, HOME: sandbox }`. That is NOT enough to isolate the device's state:
// cli/state-dirs.mjs resolves two of its three user-scope write legs from base-directory variables
// that are INDEPENDENT of HOME —
//
//     LATCH_DIR      = $XDG_CONFIG_HOME/moorai   (Windows: %APPDATA%\MoorAI)
//     BREADCRUMB_DIR = $XDG_STATE_HOME/moorai    (Windows: %LOCALAPPDATA%\MoorAI)
//
// — so on any machine that sets them (every XDG-configured Linux desktop, and every GitHub Actions
// Ubuntu runner) the policy-key pin, the last-known-good policy and the posture latch escape the
// sandbox into ONE directory shared by every test process in the run. MEASURED on this repo, node 22
// in a Linux container, `--test-concurrency=4`: with XDG_CONFIG_HOME exported the suite went from
// 872/873 to 863/873, and the shared latch ended up holding a policy pin listing the signing keys of
// two different tenants written by two different test files.
//
// Deleting the variables here — in each test file's process, before the file's imports load (node 22
// runs an `--import` preload in every test child, not in the runner) — is inherited by every
// `{ ...process.env }` spawn, so all 27 files become hermetic at one point instead of 27.
// The variables are only unset for tests; a test that wants to exercise a specific base directory sets
// it explicitly on the child it spawns (test/posture.test.mjs does exactly that).
for (const v of ["XDG_CONFIG_HOME", "XDG_STATE_HOME", "APPDATA", "LOCALAPPDATA"]) delete process.env[v];
// The agent's own version on an alert (`agentVersion`, cli/agent-names.mjs) is read from these. A suite run
// from inside Claude Code or Cursor inherits them; a test that wants one sets it on the child it spawns.
for (const v of ["AI_AGENT", "CURSOR_VERSION"]) delete process.env[v];

// HOME itself, for the same reason. Every module that resolves a state path at IMPORT time
// (cli/state-dirs.mjs: `STATE_DIR = join(os.homedir(), ".moorai")`) and is imported by a test IN-PROCESS
// wrote to the developer's real home. MEASURED with a throwaway HOME on the full suite: three files —
// escalation-async and semantic (data/model-escalation.mjs appends ~/.moorai/escalation-outcomes.jsonl
// on every local-model attempt) and otel (cli/record-chain.mjs advances ~/.moorai/.chain-otel.head.json
// on every emitted span) — and no others. Each test file now gets its own empty home, so in-process
// imports and `{ ...process.env }` spawns alike resolve there; a test that wants a specific home still
// passes HOME to the child it spawns. home-guard.mjs fails the file if anything still reaches the real one.
import { installHomeGuard } from "./home-guard.mjs";
installHomeGuard();

// The HOST'S OWN SOCKETS, for the same reason. The hook's daily posture worker (cli/moorai-hook.mjs
// posturebeat) samples the TCP table (cli/local-ai-inventory.mjs tcpTable: `lsof` on macOS) and posts a
// device-level LOCAL_MODEL_EXPOSED / AI_API_CALLER_UNKNOWN alert for what it finds. MEASURED on a dev Mac
// running Ollama on 127.0.0.1:11434: every hook test whose console counts alerts received that alert from
// the developer's own machine (session-correlation: "has session undefined"; alert-evidence: one more alert
// in the deferred window), and with an empty `lsof` first on PATH the whole suite passed. Hook children are
// spawned with this process's PATH (`{ ...process.env }` or `PATH: process.env.PATH`), so an `lsof` that
// prints nothing, first on PATH, hides the host's sockets from every one of them. Tests that exercise the
// detectors inject their own table (test/posture-inventory-beat.test.mjs, test/local-model-exposure.test.mjs).
// macOS only: Linux reads /proc/net/tcp with no spawn and Windows runs netstat.exe, so a Linux or Windows
// box with an exposed local model server or an unknown AI-API caller can still leak an alert into a test.
if (process.platform === "darwin") {
  const { mkdtempSync: mk, writeFileSync: wf, chmodSync: ch, rmSync: rm } = await import("node:fs");
  const { tmpdir: td } = await import("node:os");
  const { join: jn, delimiter } = await import("node:path");
  const dir = mk(jn(td(), "moorai-no-host-sockets-"));
  wf(jn(dir, "lsof"), "#!/bin/sh\nexit 0\n");
  ch(jn(dir, "lsof"), 0o755);
  process.env.PATH = `${dir}${delimiter}${process.env.PATH || "/usr/bin:/bin"}`;
  process.on("exit", () => { try { rm(dir, { recursive: true, force: true }); } catch { /* tmp */ } });
}
