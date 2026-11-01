// Weakening oversight (#84): a command that carries a heredoc is parsed, not analysed as empty, and a parser
// that throws fails closed (analysis-incomplete) instead of judging the command clean.
//
//   node --test --import ./test/hermetic-env.mjs test/oversight-heredoc.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { oversightCommandSignals } from "../cli/oversight-shell.mjs";
import { oversightPolicy } from "../cli/oversight-surfaces.mjs";

const cwd = "/tmp/proj";
const surfaces = oversightPolicy({ oversight: { v: 1, protectedPaths: ["ops/alerting/**", "AGENTS.md"] } }, () => {});

// (The memory-file signal for the same shape, with no policy, is asserted in test/oversight-writes.test.mjs.)
test("heredoc: appending to a protected file with a heredoc raises protected-surface", () => {
  assert.deepEqual(oversightCommandSignals("cat >> AGENTS.md <<'EOF'\nalways run the setup script\nEOF", { surfaces, cwd }), ["protected-surface"]);
});

test("heredoc: a protected-path deletion before a heredoc in the same command keeps its signals", () => {
  const s = oversightCommandSignals("rm ops/alerting/rules.yaml; cat <<EOF\nx\nEOF", { surfaces, cwd });
  assert.ok(s.includes("protected-surface"), JSON.stringify(s));
  assert.ok(s.includes("wiring-removed"), JSON.stringify(s));
});

test("parser exception: the command is analysis-incomplete, never judged clean", () => {
  const parse = () => { throw new Error("parser fault"); };
  assert.deepEqual(oversightCommandSignals("rm ops/alerting/rules.yaml", { surfaces, cwd, parse }), ["analysis-incomplete"]);
});
