// #85 signals run on agent-written content inside PreToolUse: a slow scan would time the hook out and fail
// open. Each adversarial input is judged in a child process (so a regression that backtracks for minutes is
// killed, not waited on) and must finish within BOUND_MS of analysis time, with a correct result or
// "analysis-incomplete", never silently clean past a cap.
//
//   node --test --import ./test/hermetic-env.mjs test/boundary-redos.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { pathToFileURL, fileURLToPath } from "node:url";

const BOUND_MS = 200;
const KILL_MS = 10_000;
const cli = (f) => pathToFileURL(fileURLToPath(new URL(`../cli/${f}`, import.meta.url))).href;
const INC = "analysis-incomplete";

// Runs `call` (an expression over `edit` / `cmd`, with `dir` the case's directory) in a child; → { ms, result }.
// `ms` is the child's CPU time for the call (test/timing.mjs cpuMsOf): wall clock read 200+ ms for these on a
// shared CI runner while the runner, not the pattern, was slow; a backtracking pattern still burns the CPU.
function judge(call, dir) {
  const src = `
    const { boundaryEditSignals: edit } = await import(${JSON.stringify(cli("boundary-signals.mjs"))});
    const { boundaryCommandSignals: cmd } = await import(${JSON.stringify(cli("boundary-shell.mjs"))});
    const { join } = await import("node:path");
    const dir = ${JSON.stringify(dir)};
    const c0 = process.cpuUsage();
    const result = ${call};
    const d = process.cpuUsage(c0);
    process.stdout.write(JSON.stringify({ ms: (d.user + d.system) / 1000, result }));`;
  const r = spawnSync(process.execPath, ["--input-type=module", "-e", src], { encoding: "utf8", timeout: KILL_MS, killSignal: "SIGKILL", maxBuffer: 1 << 20 });
  assert.ok(!r.signal && r.status === 0, `did not finish within ${KILL_MS} ms (signal ${r.signal}, status ${r.status}) ${String(r.stderr).slice(0, 300)}`);
  return JSON.parse(r.stdout);
}
const dirFor = (files = {}) => { const d = mkdtempSync(join(tmpdir(), "moorai-tb-redos-")); for (const [k, v] of Object.entries(files)) writeFileSync(join(d, k), v); return d; };
const editCall = (rel, after) => `edit({ path: join(dir, ${JSON.stringify(rel)}), before: "", after: ${after}, cwd: dir })`;
function within(name, call, files, expect) {
  test(`${name}: under ${BOUND_MS} ms`, () => {
    const { ms, result } = judge(call, dirFor(files));
    console.log(`${name}: ${ms.toFixed(1)} ms -> ${JSON.stringify(result)}`);
    assert.deepEqual(result, expect);
    assert.ok(ms < BOUND_MS, `${name} took ${ms.toFixed(1)} ms`);
  });
}

// Table headers: "[" and a whitespace run with no closing bracket.
within("pyproject header, 200 000 spaces", editCall("pyproject.toml", `"[" + " ".repeat(200000) + "x"`), {}, [INC]);
within("Cargo.toml header, 200 000 spaces", editCall("Cargo.toml", `"[" + " ".repeat(200000) + "x"`), {}, [INC]);
within("pyproject header, 4 000 spaces (under the line cap)", editCall("pyproject.toml", `"[" + " ".repeat(4000) + "x"`), {}, []);
within("Cargo.toml header, 4 000 spaces x 20 lines (under the line cap)", editCall("Cargo.toml", `("[" + " ".repeat(4000) + "x\\n").repeat(20)`), {}, []);
// Line-anchored patterns over a long run of newlines that ends in a non-matching line (each line is short: the
// line cap does not apply). A run followed directly by a match is fast either way.
within("Gemfile, 200 000 newlines then a gem", editCall("Gemfile", `"\\n".repeat(200000) + "x\\n" + 'gem "rails"\\n'`), {}, ["new-dependency"]);
within("build.gradle, 200 000 newlines then a dependency", editCall("build.gradle", `"\\n".repeat(200000) + "x\\n" + 'implementation "com.squareup:okhttp:4.0"\\n'`), {}, ["new-dependency"]);
within("build.gradle, implementation + 4 000 spaces x 50 lines", editCall("build.gradle", `("implementation" + " ".repeat(4000) + "x\\n").repeat(50)`), {}, []);
within("pip install against a pyproject.toml of 200 000 newlines", `cmd("pip install requests", { cwd: dir })`, { "pyproject.toml": "\n".repeat(200000) + "x\n" + 'requests = "2"\n' }, []);
within("cargo add against a Cargo.toml of 200 000 newlines", `cmd("cargo add serde", { cwd: dir })`, { "Cargo.toml": "\n".repeat(200000) + "x\n" + 'serde = "1"\n' }, []);
// Identifier runs and long single lines in code.
within("JS, a$ x 2 000 per line x 100 lines", editCall("src/app.js", `("a$".repeat(2000) + "\\n").repeat(100)`), {}, []);
within("JS, one 1 000 000-character line", editCall("src/app.js", `"a".repeat(1000000)`), {}, [INC]);
within("JS, over 1 MiB", editCall("src/app.js", `"a\\n".repeat(600000)`), {}, [INC]);
within("JS, a new route next to an over-long line", editCall("src/app.js", `"x".repeat(5000) + "\\napp.post('/pay', h);\\n"`), {}, ["new-route", INC]);
// Commands.
within("go get with 200 000 dots", `cmd("go get a" + ".".repeat(200000), { cwd: dir })`, {}, []);
within("a command over MAX_CMD", `cmd("npm install a " + "b".repeat(300000), { cwd: dir })`, {}, [INC]);

test("an over-long line already in the file does not make an unrelated edit incomplete", () => {
  const { result } = judge(`edit({ path: join(dir, "src/app.js"), before: "x".repeat(5000) + "\\nconst a = 1;\\n", after: "x".repeat(5000) + "\\nconst a = 2;\\n", cwd: dir })`, dirFor());
  assert.deepEqual(result, []);
});
