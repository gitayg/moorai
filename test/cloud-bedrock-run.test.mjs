// Bedrock inventory, live path (`moorai-cloud-inventory bedrock --run`): the tool shells out to the
// customer's own AWS CLI. No test here calls AWS. MOORAI_AWS_CLI points the tool at a fake `aws` written
// below, which logs its argv and environment and answers from the same unprojected fixtures the export
// path uses — so it ignores `--query`, which makes it the worst case: a CLI that handed back every name,
// instruction and ARN. The records must still be content-free, and identical to the export path's.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, chmodSync, existsSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync, spawn } from "node:child_process";
import http from "node:http";
import { deriveKey } from "../cli/content-hash.mjs";
import { readExport } from "../cloud/bedrock/read-export.mjs";
import { buildInventory } from "../cloud/inventory.mjs";
import { COMMANDS } from "../cloud/bedrock/commands.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const FIX = join(ROOT, "test", "fixtures", "cloud-bedrock");
const CLI = join(ROOT, "cloud", "moorai-cloud-inventory.mjs");
const TOKEN = "cloudtesttoken0123456789abcdef01";

// Fake AWS CLI. Maps `<service> <op> --region R [--agent-id A] [--action-group-id G]` to a fixture file;
// a missing file is answered the way the real CLI answers an AccessDenied (exit 254, the caller's ARN
// in stderr) so the test can check that stderr is classified, not relayed.
const FAKE = `#!/usr/bin/env node
const fs = require("fs"), path = require("path");
const argv = process.argv.slice(2);
const opt = (n) => { const i = argv.indexOf(n); return i >= 0 ? argv[i + 1] : undefined; };
fs.appendFileSync(process.env.FAKE_AWS_LOG, JSON.stringify({ argv, AWS_PROFILE: process.env.AWS_PROFILE || null }) + "\\n");
const [service, op] = argv;
const region = opt("--region"), agent = opt("--agent-id"), ag = opt("--action-group-id");
let file;
if (service === "sts") file = "account.json";
else if (op === "get-agent-action-group") file = path.join(region, op, agent + "." + ag + ".json");
else if (agent) file = path.join(region, op, agent + ".json");
else file = path.join(region, op + ".json");
const full = path.join(process.env.FAKE_AWS_FIX, file);
if (!fs.existsSync(full)) {
  process.stderr.write("\\nAn error occurred (AccessDeniedException) when calling the X operation: User: arn:aws:iam::210987654321:user/CANARY_IAM_USER is not authorized to perform: bedrock-agentcore:ListAgentRuntimes AKIACANARYSECRETKEY\\n");
  process.exit(254);
}
let out = JSON.parse(fs.readFileSync(full, "utf8"));
const pg = process.env.FAKE_AWS_PAGINATE;
if (pg && op === pg && region === "us-east-1") {
  const key = Object.keys(out).find((k) => Array.isArray(out[k]));
  const tok = opt("--starting-token");
  out = tok === "page2" ? { [key]: out[key].slice(1) } : { [key]: out[key].slice(0, 1), NextToken: "page2" };
}
process.stdout.write(JSON.stringify(out, null, 4));
`;

function setup({ enrolled = true } = {}) {
  const home = mkdtempSync(join(tmpdir(), "moorai-cloud-run-"));
  if (enrolled) {
    mkdirSync(join(home, ".moorai"), { recursive: true });
    writeFileSync(join(home, ".moorai", "config.json"), JSON.stringify({ serverUrl: "http://127.0.0.1:9", tenant: "acme", installToken: TOKEN }));
  }
  const aws = join(home, "fake-aws.cjs");
  writeFileSync(aws, FAKE);
  chmodSync(aws, 0o755);
  const log = join(home, "aws.log");
  writeFileSync(log, "");
  return { home, aws, log };
}
const envFor = (s, extra = {}) => {
  const env = { ...process.env, HOME: s.home, USERPROFILE: s.home, MOORAI_MODE: "", MOORAI_AWS_CLI: s.aws, FAKE_AWS_LOG: s.log, FAKE_AWS_FIX: FIX, ...extra };
  for (const k of ["AWS_PROFILE", "AWS_REGION", "AWS_DEFAULT_REGION"]) if (!(k in extra)) delete env[k];
  return env;
};
const run = (s, args, extra) => spawnSync(process.execPath, [CLI, ...args], { encoding: "utf8", timeout: 90000, env: envFor(s, extra) });
const calls = (s) => readFileSync(s.log, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l));
const exportInv = (regions) => {
  const b = readExport(FIX);
  if (regions) for (const r of Object.keys(b.regions)) if (!regions.includes(r)) delete b.regions[r];
  return buildInventory(b, { key: deriveKey(TOKEN) });
};

test("--run: same records as the export path, from the worst-case (unprojected) CLI output", () => {
  const s = setup();
  try {
    const r = run(s, ["bedrock", "--run", "--regions", "us-east-1,eu-west-1"]);
    assert.equal(r.status, 0, r.stderr);
    const inv = JSON.parse(r.stdout);
    assert.deepEqual(inv.records, exportInv().inventory.records);
    assert.ok(!/CANARY|arn:|AKIA/.test(r.stdout + r.stderr), "content, an ARN or a key reached our output");
  } finally { rmSync(s.home, { recursive: true, force: true }); }
});

test("--run: every call is a table-driven read-only List/Get with --region, JSON output, no pager and a projection", () => {
  const s = setup();
  try {
    assert.equal(run(s, ["bedrock", "--run", "--regions", "us-east-1,eu-west-1"]).status, 0);
    const cs = calls(s);
    const ops = new Set(COMMANDS.map((c) => `${c.service} ${c.op}`).concat("sts get-caller-identity"));
    assert.ok(cs.length > 20);
    for (const { argv } of cs) {
      assert.ok(ops.has(`${argv[0]} ${argv[1]}`), `unexpected call ${argv[0]} ${argv[1]}`);
      assert.match(argv[1], /^(list|get)-/);
      for (const f of ["--region", "--output", "--no-cli-pager", "--query"]) assert.ok(argv.includes(f), `${argv[1]} lacks ${f}`);
      assert.equal(argv[argv.indexOf("--output") + 1], "json");
      assert.ok(!argv.includes("--debug") && !argv.includes("--profile"));
    }
    // The action-group detail is fetched per action group, the inference profiles are APPLICATION only.
    assert.equal(cs.filter((c) => c.argv[1] === "get-agent-action-group").length, 5);
    const ip = cs.find((c) => c.argv[1] === "list-inference-profiles");
    assert.equal(ip.argv[ip.argv.indexOf("--type-equals") + 1], "APPLICATION");
    assert.deepEqual([...new Set(cs.filter((c) => c.argv[0] !== "sts").map((c) => c.argv[c.argv.indexOf("--region") + 1]))].sort(), ["eu-west-1", "us-east-1"]);
  } finally { rmSync(s.home, { recursive: true, force: true }); }
});

test("--run honours AWS_PROFILE and AWS_REGION from the environment, and --profile when given", () => {
  const s = setup();
  try {
    const r = run(s, ["bedrock", "--run"], { AWS_PROFILE: "inventory-ro", AWS_REGION: "eu-west-1" });
    assert.equal(r.status, 0, r.stderr);
    assert.deepEqual(JSON.parse(r.stdout).regions, ["eu-west-1"]);
    const cs = calls(s);
    assert.ok(cs.every((c) => c.AWS_PROFILE === "inventory-ro"), "AWS_PROFILE not passed through to the CLI");
    assert.ok(cs.every((c) => !c.argv.includes("--profile")));
    writeFileSync(s.log, "");
    assert.equal(run(s, ["bedrock", "--run", "--regions", "eu-west-1", "--profile", "audit"]).status, 0);
    assert.ok(calls(s).every((c) => c.argv[c.argv.indexOf("--profile") + 1] === "audit"));
  } finally { rmSync(s.home, { recursive: true, force: true }); }
});

test("--run with no region from flag or environment is a usage error and calls nothing", () => {
  const s = setup();
  try {
    const r = run(s, ["bedrock", "--run"]);
    assert.equal(r.status, 2);
    assert.match(r.stderr, /region/i);
    assert.deepEqual(calls(s), []);
  } finally { rmSync(s.home, { recursive: true, force: true }); }
});

test("--run: a failed call is classified, and its stderr (caller ARN, a key-shaped string) is never relayed", () => {
  const s = setup();
  try {
    const r = run(s, ["bedrock", "--run", "--regions", "eu-west-1"]);
    assert.equal(r.status, 0, r.stderr);
    assert.ok(!/CANARY|AKIA|arn:|210987654321/.test(r.stderr + r.stdout));
    assert.match(r.stderr, /eu-west-1 list-agent-runtimes: access-denied/);
  } finally { rmSync(s.home, { recursive: true, force: true }); }
});

test("--run follows a NextToken page by page and merges the pages", () => {
  const s = setup();
  try {
    const r = run(s, ["bedrock", "--run", "--regions", "us-east-1"], { FAKE_AWS_PAGINATE: "list-guardrails" });
    assert.equal(r.status, 0, r.stderr);
    assert.equal(JSON.parse(r.stdout).records.filter((x) => x.kind === "guardrail").length, 2);
    const g = calls(s).filter((c) => c.argv[1] === "list-guardrails");
    assert.equal(g.length, 2);
    assert.equal(g[1].argv[g[1].argv.indexOf("--starting-token") + 1], "page2");
  } finally { rmSync(s.home, { recursive: true, force: true }); }
});

test("--run --export writes the export layout; --from on it gives the same records", () => {
  const s = setup();
  const dir = join(s.home, "export");
  try {
    const a = run(s, ["bedrock", "--run", "--regions", "us-east-1,eu-west-1", "--export", dir]);
    assert.equal(a.status, 0, a.stderr);
    assert.ok(existsSync(join(dir, "account.json")) && existsSync(join(dir, "us-east-1", "get-agent", "AGENTAAAAA.json")));
    assert.ok(readdirSync(join(dir, "us-east-1", "get-agent-action-group")).includes("AGENTAAAAA.ACTGRPAAA2.json"));
    const b = run(s, ["bedrock", "--from", dir]);
    assert.equal(b.status, 0, b.stderr);
    assert.deepEqual(JSON.parse(b.stdout).records, JSON.parse(a.stdout).records);
  } finally { rmSync(s.home, { recursive: true, force: true }); }
});

test("--run refuses before calling AWS when the device is not enrolled", () => {
  const s = setup({ enrolled: false });
  try {
    const r = run(s, ["bedrock", "--run", "--regions", "us-east-1"]);
    assert.equal(r.status, 2);
    assert.deepEqual(calls(s), []);
  } finally { rmSync(s.home, { recursive: true, force: true }); }
});

test("--post sends exactly {platform, account, regions, records} with the install token header", async () => {
  const s = setup();
  let got;
  const srv = http.createServer((req, res) => {
    let b = "";
    req.on("data", (c) => (b += c));
    req.on("end", () => { got = { url: req.url, method: req.method, token: req.headers["x-install-token"], ct: req.headers["content-type"], body: JSON.parse(b) }; res.writeHead(201, { "content-type": "application/json" }); res.end('{"ok":true}'); });
  });
  await new Promise((ok) => srv.listen(0, "127.0.0.1", ok));
  try {
    writeFileSync(join(s.home, ".moorai", "config.json"), JSON.stringify({ serverUrl: `http://127.0.0.1:${srv.address().port}`, tenant: "acme", installToken: TOKEN }));
    const child = spawn(process.execPath, [CLI, "bedrock", "--from", FIX, "--post"], { env: envFor(s) });
    let err = "";
    child.stderr.on("data", (d) => (err += d));
    const code = await new Promise((ok) => child.on("close", ok));
    assert.equal(code, 0, err);
    assert.equal(got.method, "POST");
    assert.equal(got.url, "/api/cloud-inventory");
    assert.equal(got.token, TOKEN);
    assert.match(got.ct, /application\/json/);
    assert.deepEqual(Object.keys(got.body).sort(), ["account", "platform", "records", "regions"]);
    assert.deepEqual(got.body.records, exportInv().inventory.records);
    assert.match(err, /posted 22 records/);
  } finally { srv.close(); rmSync(s.home, { recursive: true, force: true }); }
});
