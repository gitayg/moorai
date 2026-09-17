// Per-file runner:  node --test test/hook-gaps-named-secret.test.mjs
//
// GAP 3 — a named cloud secret on its own line produced no finding:
//   buildEngine({}).scan("AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", …) -> []
// It was only caught when an AKIA… id sat beside it. Root cause: the two entropy-gated detectors
// (secret-aws-secret, secret-generic-assignment) carry a refine(), so src/engine.js _matchDetector
// recompiles their patterns through safeRegex — which has refused both since v0.63.2
// ("multiple-unbounded-quantifiers": `\s*[:=]\s*` + `{20,}`). They were silently dead.
//
// Every value below is fabricated for this test; none is a real credential.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { buildEngine } from "../cli/hook-core.mjs";
import { SECRET_DETECTORS } from "../data/secrets-patterns.js";
import { redosReason } from "../src/safe-regex.js";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const HOOK = join(ROOT, "cli", "moorai-hook.mjs");
const engine = buildEngine({});
const has39 = (text, stage = "prompt", ctx) => engine.scan(text, stage, ctx).some((f) => f.threat.id === 39);

const FAKE = "Q7vR2mXk9LpT4sWb8NcY1hZe6JdF3gUa";

test("GAP 3: every refine-gated secret pattern survives the engine's ReDoS gate", () => {
  for (const d of SECRET_DETECTORS) {
    if (!d.refine) continue;
    for (const p of d.patterns) assert.equal(redosReason(p.source), "", `${d.detectorId} ${p.source}`);
  }
});

test("GAP 3: a named cloud secret assignment is detected on its own", () => {
  const positives = [
    "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    `export OPENAI_API_KEY=${FAKE}`,
    `DATADOG_API_KEY="${FAKE}"`,
    `STRIPE_SECRET_KEY: ${FAKE}`,
    `SLACK_BOT_TOKEN=${FAKE}`,
    `POSTGRES_PASSWORD='${FAKE}'`,
    `{"SENTRY_AUTH_TOKEN": "${FAKE}"}`
  ];
  for (const t of positives) {
    for (const stage of ["prompt", "file", "output"]) assert.ok(has39(t, stage), `${stage}: ${t}`);
  }
});

test("GAP 3: placeholders and references do NOT fire", () => {
  const negatives = [
    "OPENAI_API_KEY=your-key-here",
    "OPENAI_API_KEY=your-openai-api-key-goes-here",
    "AWS_SECRET_ACCESS_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "AWS_SECRET_ACCESS_KEY=<secret>",
    "GITHUB_TOKEN=${GITHUB_TOKEN}",
    "GITHUB_TOKEN=$GITHUB_TOKEN_FROM_THE_ENVIRONMENT",
    "DB_PASSWORD=changeme",
    "DB_PASSWORD=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "SECRET_KEY=replace-me-with-a-long-random-string",
    "API_TOKEN=0123456789abcdefghijklmnopqrstuv",
    "STRIPE_SECRET_KEY=EXAMPLE_STRIPE_SECRET_KEY_VALUE",
    "SESSION_TOKEN=REDACTED_REDACTED_REDACTED",
    "the NEXT_PUBLIC_API_KEY variable is read at build time",
    `MAX_TOKEN=${"9".repeat(24)}`,
    "COMMIT_TOKEN=3f786850e387550fdab836ed7e6dc881de23001b"
  ];
  for (const t of negatives) assert.equal(has39(t, "prompt"), false, t);
});

test("GAP 3: an EXAMPLE value in an env TEMPLATE does not fire; the same line in a live file does", () => {
  const line = "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
  assert.equal(has39(line, "file", { template: true }), false);
  assert.equal(has39(line, "file", { template: false }), true);
  // A real-looking value (no placeholder marker) in a template is still a leak.
  assert.equal(has39(`OPENAI_API_KEY=${FAKE}`, "file", { template: true }), true);
});

test("GAP 3 (hook): with #39 enforced, a live .env with only the secret line is denied; .env.example is not", () => {
  const home = mkdtempSync(join(tmpdir(), "moorai-gap3-"));
  try {
    mkdirSync(join(home, ".moorai"), { recursive: true });
    writeFileSync(join(home, ".moorai", "config.json"), JSON.stringify({ serverUrl: "http://127.0.0.1:1", tenant: "gap3", installToken: "tok-gap3" }));
    writeFileSync(join(home, ".moorai", "hook-policy.json"), JSON.stringify({ captureTier: "content-free", threatPolicy: { 39: "block" } }));
    const proj = join(home, "proj");
    mkdirSync(proj, { recursive: true });
    const body = "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n";
    writeFileSync(join(proj, "settings.env"), body);
    writeFileSync(join(proj, ".env.example"), body);
    const run = (payload) => {
      const res = spawnSync("node", [HOOK], {
        input: JSON.stringify({ session_id: "g3", ...payload }), cwd: proj, encoding: "utf8", timeout: 30000,
        env: { PATH: process.env.PATH || "/usr/bin:/bin", HOME: home, USERPROFILE: home, XDG_CONFIG_HOME: join(home, ".config"), XDG_STATE_HOME: join(home, ".local", "state"), MoorAI_SERVER: "http://127.0.0.1:1", MoorAI_TENANT: "gap3" }
      });
      assert.equal(res.status, 0, res.stderr);
      const out = (res.stdout || "").trim();
      return out ? JSON.parse(out).hookSpecificOutput?.permissionDecision : "allow";
    };
    assert.equal(run({ tool_name: "Read", tool_input: { file_path: join(proj, "settings.env") } }), "deny");
    assert.equal(run({ tool_name: "Read", tool_input: { file_path: join(proj, ".env.example") } }), "allow");
    assert.equal(run({ tool_name: "Bash", tool_input: { command: `cat ${join(proj, ".env.example")}` } }), "allow");
  } finally { rmSync(home, { recursive: true, force: true }); }
});
