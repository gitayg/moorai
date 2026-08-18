// Standalone cross-platform smoke test for the on-device AI Agent Gateway (Feature 1) and the
// shadow-AI catalog (Feature 2). Runs anywhere Node runs — no external deps. `node cli/verify-gateway.mjs`.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { buildEngine, mcpGateway } from "./hook-core.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
let pass = 0, fail = 0;
const check = (name, got, want) => { const ok = got === want; console.log(`${ok ? "PASS" : "FAIL"}  ${name}  (got ${got}, want ${want})`); ok ? pass++ : fail++; };

console.log(`platform=${process.platform} arch=${process.arch} node=${process.version}`);

// --- Gateway decisions (Feature 1) ---
{
  const policy = {};
  const g = mcpGateway(buildEngine(policy), policy, { tool: "mcp__github__search", server: "github", args: JSON.stringify({ q: "hello" }) });
  check("no-policy clean call -> allow", g.decision, "allow");
  check("no-policy clean call -> gate null", g.gate, null);
}
{
  const policy = { mcpAllow: ["github"] };
  const g = mcpGateway(buildEngine(policy), policy, { tool: "mcp__evil__run", server: "evil", args: "{}" });
  check("unapproved server -> deny", g.decision, "deny");
  check("unapproved server -> gate 'server'", g.gate, "server");
}
{
  const policy = { mcpToolRules: { "mcp__github__create_issue": { deny: ["rm -rf"] } } };
  const g = mcpGateway(buildEngine(policy), policy, { tool: "mcp__github__create_issue", server: "github", args: JSON.stringify({ body: "run rm -rf /" }) });
  check("denied arg pattern -> deny", g.decision, "deny");
  check("denied arg pattern -> gate 'args'", g.gate, "args");
}

// --- Shadow-AI catalog (Feature 2) ---
{
  const cat = JSON.parse(readFileSync(join(ROOT, "data/ai-catalog.json"), "utf8"));
  check("catalog has apps", cat.apps.length > 0, true);
  check("catalog has extensions", cat.extensions.length > 0, true);
  console.log(`catalog: ${cat.apps.length} apps, ${cat.extensions.length} extensions`);
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
