// Bedrock inventory, export path (`moorai-cloud-inventory bedrock --from DIR`): JSON the customer exported
// with the AWS CLI in, content-free records out.
//
// The fixtures in test/fixtures/cloud-bedrock are synthetic AWS CLI v2 output, field-for-field on the
// Response Syntax blocks of the Bedrock API Reference, and NOT projected — every name, description,
// instruction, prompt template, OpenAPI payload and ARN a real export would carry is present, and every
// free-text one contains the marker CANARY. The load-bearing test is "nothing the customer wrote, and no
// raw identifier, reaches a record": it serialises the whole inventory and looks for each of them.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, cpSync, existsSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { deriveKey, hashWithKey } from "../cli/content-hash.mjs";
import { readExport } from "../cloud/bedrock/read-export.mjs";
import { buildInventory } from "../cloud/inventory.mjs";
import { modelFamily } from "../cloud/bedrock/model-family.mjs";
import { FLAGS, flagsFor } from "../cloud/bedrock/risk.mjs";
import { recordProblems, assertContentFree } from "../cloud/record-schema.mjs";
import { iamPolicy, COMMANDS } from "../cloud/bedrock/commands.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const FIX = join(ROOT, "test", "fixtures", "cloud-bedrock");
const CLI = join(ROOT, "cloud", "moorai-cloud-inventory.mjs");
const TOKEN = "cloudtesttoken0123456789abcdef01";
const KEY = deriveKey(TOKEN);
const H = (s) => hashWithKey(KEY, s);
const ACCT = "210987654321";
const arn = (region, rest) => `arn:aws:bedrock:${region}:${ACCT}:${rest}`;

const fixtureText = (dir = FIX) => readdirSync(dir, { recursive: true }).filter((f) => f.endsWith(".json")).map((f) => readFileSync(join(dir, f), "utf8")).join("\n");
const build = (dir = FIX, key = KEY) => buildInventory(readExport(dir), { key });
const recs = (inv, kind, region) => inv.inventory.records.filter((r) => r.kind === kind && (!region || r.region === region));
const byId = (inv, id) => inv.inventory.records.find((r) => r.id === id);

// Every raw identifier in the fixtures. None may appear in a record.
const RAW_IDS = ["AGENTAAAAA", "AGENTBBBBB", "AGENTCCCCC", "ACTGRPAAA1", "ACTGRPAAA2", "ACTGRPAAA3", "ACTGRPBBB1", "ACTGRPBBB2",
  "ALIASAAAA1", "ALIASBBBB1", "TSTALIASID", "KBAAAAAAAA", "KBBBBBBBBB", "KBCCCCCCCC", "gr0abc12def3", "gr0zzz99yy88", "gr0eu0000001",
  "abcdefghij12", "zyxwvutsrq98", "pt0canary01", "ip0canary001", "abcde12345", ACCT, "999988887777", "AIDACANARYUSERID01"];

test("export path: every resource the fixtures define becomes exactly one record", () => {
  const inv = build();
  const count = (k, r) => recs(inv, k, r).length;
  assert.equal(count("agent", "us-east-1"), 2);
  assert.equal(count("alias", "us-east-1"), 3);
  assert.equal(count("action-group", "us-east-1"), 5);
  assert.equal(count("knowledge-base", "us-east-1"), 3);
  assert.equal(count("guardrail", "us-east-1"), 2);
  assert.equal(count("custom-model", "us-east-1"), 2);
  assert.equal(count("provisioned-throughput", "us-east-1"), 1);
  assert.equal(count("inference-profile", "us-east-1"), 1);
  assert.equal(count("agentcore-runtime", "us-east-1"), 1);
  assert.equal(count("agent", "eu-west-1"), 1);
  assert.equal(count("guardrail", "eu-west-1"), 1);
  assert.equal(inv.inventory.records.length, 22);
  assert.equal(inv.inventory.platform, "bedrock");
  assert.deepEqual(inv.inventory.regions, ["eu-west-1", "us-east-1"]);
});

test("content-free: no name, description, instruction, prompt, schema, ARN, raw id or account id reaches the inventory", () => {
  const out = JSON.stringify(build().inventory);
  assert.ok(!/CANARY/i.test(out), "customer text leaked: " + (out.match(/.{0,40}CANARY.{0,40}/i) || [""])[0]);
  assert.ok(!out.includes("arn:"), "an ARN leaked");
  for (const id of RAW_IDS) assert.ok(!out.includes(id), `raw identifier leaked: ${id}`);
  // Positive control: the fixture really does carry all of it, so the absence above means something.
  const raw = fixtureText();
  assert.ok(raw.includes("CANARY_INSTRUCTION") && raw.includes("CANARY_OPENAPI") && raw.includes("arn:aws:lambda"));
  for (const id of RAW_IDS) assert.ok(raw.includes(id), `control: fixture lacks ${id}`);
});

test("every record passes the strict allow-list schema", () => {
  for (const r of build().inventory.records) assert.deepEqual(recordProblems(r), [], `${r.kind}: ${recordProblems(r).join(", ")}`);
});

test("the schema refuses a name, an unknown attribute, free text, a raw ARN and an unknown kind", () => {
  const good = build().inventory.records.find((r) => r.kind === "agent");
  assert.deepEqual(recordProblems(good), []);
  assert.ok(recordProblems({ ...good, name: "payroll" }).includes("name"));
  assert.ok(recordProblems({ ...good, attrs: { ...good.attrs, instruction: "x" } }).includes("attrs.instruction"));
  assert.ok(recordProblems({ ...good, attrs: { ...good.attrs, modelFamily: "anthropic claude for payroll" } }).includes("attrs.modelFamily"));
  assert.ok(recordProblems({ ...good, id: arn("us-east-1", "agent/AGENTAAAAA") }).includes("id"));
  assert.ok(recordProblems({ ...good, kind: "lambda" }).includes("kind"));
  assert.ok(recordProblems({ ...good, status: "PREPARED for payroll" }).includes("status"));
  assert.throws(() => assertContentFree([{ ...good, description: "CANARY" }]), (e) => /description/.test(e.message) && !/CANARY/.test(e.message));
});

test("ids are the tenant-keyed hash of the resource ARN, stable per tenant and different across tenants", () => {
  const inv = build();
  for (const r of inv.inventory.records) assert.match(r.id, /^h2:[0-9a-f]{16}$/);
  assert.ok(byId(inv, H(arn("us-east-1", "agent/AGENTAAAAA"))), "agent A");
  assert.ok(byId(inv, H(arn("eu-west-1", "agent/AGENTCCCCC"))), "agent C");
  assert.ok(byId(inv, H(arn("us-east-1", "agent-alias/AGENTAAAAA/ALIASAAAA1"))), "alias");
  assert.ok(byId(inv, H(arn("us-east-1", "knowledge-base/KBAAAAAAAA"))), "kb");
  assert.ok(byId(inv, H(arn("us-east-1", "guardrail/gr0abc12def3"))), "guardrail");
  assert.ok(byId(inv, H(arn("us-east-1", "custom-model/amazon.titan-text-express-v1:0:8k/abcdefghij12"))), "custom model");
  assert.ok(byId(inv, H(arn("us-east-1", "provisioned-model/pt0canary01"))), "provisioned throughput");
  assert.equal(inv.inventory.account, H(ACCT));
  const ag = byId(inv, H(arn("us-east-1", "agent-alias/AGENTAAAAA/ALIASAAAA1")));
  assert.equal(ag.parent, H(arn("us-east-1", "agent/AGENTAAAAA")));
  const other = build(FIX, deriveKey("a-different-tenant-token-000000000"));
  const mine = new Set(inv.inventory.records.map((r) => r.id));
  assert.ok(other.inventory.records.every((r) => !mine.has(r.id)), "two tenants share an id");
  assert.deepEqual(build().inventory.records.map((r) => r.id), inv.inventory.records.map((r) => r.id), "not stable");
});

test("no enrollment key: the inventory refuses to build rather than emit h2:nokey for every resource", () => {
  assert.throws(() => buildInventory(readExport(FIX), { key: null }), /enrol/i);
});

test("risk flags: agent A has no guardrail, a code interpreter and a knowledge base", () => {
  const a = byId(build(), H(arn("us-east-1", "agent/AGENTAAAAA")));
  assert.deepEqual(a.flags, ["agent-code-interpreter", "agent-kb-no-guardrail", "agent-no-guardrail"]);
  assert.equal(a.attrs.guardrailAttached, false);
  assert.equal(a.attrs.codeInterpreter, true);
  assert.equal(a.attrs.userInput, true);
  assert.equal(a.attrs.computerUse, false);
  assert.equal(a.attrs.actionGroupCount, 3);
  assert.equal(a.attrs.knowledgeBaseCount, 1);
  assert.equal(a.attrs.aliasCount, 2);
  assert.equal(a.attrs.memoryEnabled, true);
  assert.equal(a.attrs.customerKey, false);
  assert.equal(a.attrs.modelFamily, "anthropic.claude");
  assert.equal(a.status, "PREPARED");
  assert.equal(a.updatedDay, "2026-09-14");
});

test("risk flags: agent B has a DRAFT guardrail, computer use and a custom model; a DISABLED action group does not count", () => {
  const b = byId(build(), H(arn("us-east-1", "agent/AGENTBBBBB")));
  assert.deepEqual(b.flags, ["agent-computer-use", "agent-custom-model", "agent-guardrail-draft"]);
  assert.equal(b.attrs.guardrailAttached, true);
  assert.equal(b.attrs.guardrailVersion, "DRAFT");
  assert.equal(b.attrs.actionGroupCount, 1);
  assert.equal(b.attrs.knowledgeBaseCount, 1);
  assert.equal(b.attrs.codeInterpreter, false);
  assert.equal(b.attrs.customerKey, true);
  assert.equal(b.attrs.modelFamily, "custom-model");
});

test("risk flags: a guarded agent with a numbered guardrail version raises nothing", () => {
  const c = byId(build(), H(arn("eu-west-1", "agent/AGENTCCCCC")));
  assert.deepEqual(c.flags, []);
  assert.equal(c.attrs.modelFamily, "amazon.nova");
  assert.equal(c.attrs.guardrailVersion, "numbered");
  assert.equal(c.status, "NOT_PREPARED");
});

test("knowledge bases: reachable through an unguarded agent is flagged, through a guarded one is not", () => {
  const inv = build();
  const kbA = byId(inv, H(arn("us-east-1", "knowledge-base/KBAAAAAAAA")));
  const kbB = byId(inv, H(arn("us-east-1", "knowledge-base/KBBBBBBBBB")));
  const kbC = byId(inv, H(arn("us-east-1", "knowledge-base/KBCCCCCCCC")));
  assert.deepEqual(kbA.flags, ["kb-reachable-without-guardrail"]);
  assert.deepEqual(kbA.attrs, { agentCount: 1, unguardedAgentCount: 1 });
  assert.deepEqual(kbB.flags, []);
  assert.deepEqual(kbB.attrs, { agentCount: 1, unguardedAgentCount: 0 });
  assert.deepEqual(kbC.attrs, { agentCount: 0, unguardedAgentCount: 0 }, "a DISABLED association is not a path");
  assert.equal(kbC.status, "UPDATE_UNSUCCESSFUL");
});

test("guardrails: attachment is linked whether the agent names the guardrail by id or by ARN", () => {
  const inv = build();
  assert.equal(byId(inv, H(arn("us-east-1", "guardrail/gr0abc12def3"))).attrs.agentCount, 1);
  assert.equal(byId(inv, H(arn("us-east-1", "guardrail/gr0zzz99yy88"))).attrs.agentCount, 0);
  assert.equal(byId(inv, H(arn("us-east-1", "guardrail/gr0zzz99yy88"))).attrs.crossRegion, true);
  assert.equal(byId(inv, H(arn("eu-west-1", "guardrail/gr0eu0000001"))).attrs.agentCount, 1);
});

test("custom models, provisioned throughput, inference profiles, AgentCore runtimes, aliases, action groups", () => {
  const inv = build();
  const tuned = byId(inv, H(arn("us-east-1", "custom-model/amazon.titan-text-express-v1:0:8k/abcdefghij12")));
  assert.deepEqual(tuned.flags, ["custom-model-active"]);
  assert.deepEqual(tuned.attrs, { customizationType: "FINE_TUNING", baseModelFamily: "amazon.titan", shared: false, provisioned: true });
  const shared = byId(inv, H("arn:aws:bedrock:us-east-1:999988887777:custom-model/imported/zyxwvutsrq98"));
  assert.deepEqual(shared.flags, ["custom-model-active", "custom-model-imported", "custom-model-shared"]);
  assert.equal(shared.attrs.baseModelFamily, "meta.llama3");
  const pt = recs(inv, "provisioned-throughput")[0];
  assert.deepEqual(pt.attrs, { modelUnits: 1, commitment: true, modelKind: "custom", modelFamily: "amazon.titan" });
  assert.equal(pt.status, "InService");
  const ip = recs(inv, "inference-profile")[0];
  assert.deepEqual(ip.attrs, { type: "APPLICATION", modelCount: 2, modelFamily: "anthropic.claude", multiRegion: true });
  const rt = recs(inv, "agentcore-runtime")[0];
  assert.deepEqual(rt.attrs, { version: 3 });
  assert.equal(rt.status, "READY");
  assert.equal(rt.updatedDay, "2026-09-25");
  const test = recs(inv, "alias").find((r) => r.attrs.testAlias);
  assert.deepEqual(test.attrs, { invocationState: null, routesTo: "draft", provisionedThroughput: false, testAlias: true });
  const opsAlias = byId(inv, H(arn("us-east-1", "agent-alias/AGENTBBBBB/ALIASBBBB1")));
  assert.deepEqual(opsAlias.attrs, { invocationState: "REJECT_INVOCATIONS", routesTo: "version", provisionedThroughput: true, testAlias: false });
  const sig = (id) => byId(inv, H(`${arn("us-east-1", `agent/${id.slice(0, 10)}`)}/action-group/${id.slice(11)}`));
  assert.deepEqual(sig("AGENTAAAAA/ACTGRPAAA1").attrs, { signature: "custom", executor: "lambda" });
  assert.deepEqual(sig("AGENTAAAAA/ACTGRPAAA2").attrs, { signature: "AMAZON.CodeInterpreter", executor: "none" });
  assert.deepEqual(sig("AGENTBBBBB/ACTGRPBBB2").attrs, { signature: "custom", executor: "return-control" });
  assert.equal(sig("AGENTBBBBB/ACTGRPBBB2").status, "DISABLED");
});

test("model family: the coarse provider.family id, never the customer's own text", () => {
  const cases = {
    "anthropic.claude-3-5-sonnet-20240620-v1:0": "anthropic.claude",
    "us.anthropic.claude-3-7-sonnet-20250219-v1:0": "anthropic.claude",
    "global.anthropic.claude-sonnet-4-5-20250929-v1:0": "anthropic.claude",
    "eu.amazon.nova-pro-v1:0": "amazon.nova",
    "amazon.titan-text-express-v1": "amazon.titan",
    "meta.llama3-1-70b-instruct-v1:0": "meta.llama3",
    "arn:aws:bedrock:us-east-1::foundation-model/mistral.mistral-large-2402-v1:0": "mistral.mistral",
    "arn:aws:bedrock:us-east-1:210987654321:inference-profile/us.anthropic.claude-3-haiku-20240307-v1:0": "anthropic.claude",
    "arn:aws:bedrock:us-east-1:210987654321:custom-model/amazon.titan-text-express-v1:0:8k/abcdefghij12": "custom-model",
    "arn:aws:bedrock:us-east-1:210987654321:application-inference-profile/ip0canary001": "application-inference-profile",
    "arn:aws:bedrock:us-east-1:210987654321:provisioned-model/pt0canary01": "provisioned-model",
    "arn:aws:bedrock:us-east-1:210987654321:imported-model/abc": "other",
    "CANARY my secret model": "other",
    "": null,
    [undefined]: null
  };
  for (const [input, want] of Object.entries(cases)) assert.equal(modelFamily(input === "undefined" ? undefined : input), want, input);
});

test("every flag is documented with its severity and the AWS field it comes from", () => {
  assert.deepEqual(Object.keys(FLAGS).sort(), ["agent-code-interpreter", "agent-computer-use", "agent-custom-model", "agent-guardrail-draft",
    "agent-kb-no-guardrail", "agent-no-guardrail", "custom-model-active", "custom-model-imported", "custom-model-shared", "kb-reachable-without-guardrail"]);
  for (const [id, f] of Object.entries(FLAGS)) {
    assert.match(f.severity, /^(high|medium|low|info)$/, id);
    assert.ok(f.kind && f.source && f.why, id);
  }
  // An attribute that is unknown (null) never raises a flag in either direction.
  assert.deepEqual(flagsFor("agent", { guardrailAttached: null, codeInterpreter: null, computerUse: null, knowledgeBaseCount: null, modelFamily: null, guardrailVersion: null }), []);
});

test("an unknown status from AWS is OTHER, never the raw string", () => {
  const dir = mkdtempSync(join(tmpdir(), "moorai-cloud-"));
  try {
    cpSync(FIX, dir, { recursive: true });
    const p = join(dir, "us-east-1", "list-agents.json");
    const j = JSON.parse(readFileSync(p, "utf8"));
    j.agentSummaries[0].agentStatus = "CANARY_NEW_STATUS";
    writeFileSync(p, JSON.stringify(j));
    rmSync(join(dir, "us-east-1", "get-agent", "AGENTAAAAA.json"));
    const inv = build(dir);
    const a = byId(inv, H(arn("us-east-1", "agent/AGENTAAAAA")));
    assert.equal(a.status, "OTHER");
    assert.ok(!JSON.stringify(inv.inventory).includes("CANARY"));
    // Without GetAgent the id is still the hash of the same ARN, built from region + account + agentId,
    // and the guardrail fact still comes from the ListAgents summary.
    assert.equal(a.attrs.guardrailAttached, false);
    assert.equal(a.attrs.modelFamily, null);
    assert.ok(inv.errors.some((e) => e.region === "us-east-1" && e.command === "get-agent" && e.class === "missing"));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("a command missing from the export is reported per region, not guessed", () => {
  const inv = build();
  assert.deepEqual(inv.errors, [{ region: "eu-west-1", command: "list-agent-runtimes", class: "missing" }]);
});

test("the minimum IAM policy is exactly the read-only actions the collector calls", () => {
  const p = iamPolicy();
  const actions = p.Statement[0].Action;
  assert.deepEqual(actions.slice().sort(), ["bedrock-agentcore:ListAgentRuntimes", "bedrock:GetAgent", "bedrock:GetAgentActionGroup", "bedrock:ListAgentActionGroups",
    "bedrock:ListAgentAliases", "bedrock:ListAgentKnowledgeBases", "bedrock:ListAgents", "bedrock:ListCustomModels", "bedrock:ListGuardrails",
    "bedrock:ListInferenceProfiles", "bedrock:ListKnowledgeBases", "bedrock:ListProvisionedModelThroughputs"]);
  for (const a of actions) assert.match(a, /^bedrock(-agentcore)?:(List|Get)[A-Za-z]+$/);
  for (const c of COMMANDS) assert.match(c.op, /^(list|get)-/);
  assert.equal(p.Statement[0].Effect, "Allow");
});

// ---- the CLI, export path ----
function sandbox(enrolled = true) {
  const home = mkdtempSync(join(tmpdir(), "moorai-cloud-home-"));
  if (enrolled) {
    mkdirSync(join(home, ".moorai"), { recursive: true });
    writeFileSync(join(home, ".moorai", "config.json"), JSON.stringify({ serverUrl: "http://127.0.0.1:9", tenant: "acme", installToken: TOKEN }));
  }
  return home;
}
const run = (args, home, extraEnv = {}) => spawnSync(process.execPath, [CLI, ...args], {
  encoding: "utf8", timeout: 60000, env: { ...process.env, HOME: home, USERPROFILE: home, MOORAI_MODE: "", ...extraEnv }
});

test("CLI --from: prints the inventory as JSON; stderr carries counts only", () => {
  const home = sandbox();
  try {
    const r = run(["bedrock", "--from", FIX], home);
    assert.equal(r.status, 0, r.stderr);
    const inv = JSON.parse(r.stdout);
    assert.deepEqual(Object.keys(inv).sort(), ["account", "platform", "records", "regions", "schema"]);
    assert.equal(inv.records.length, 22);
    assert.equal(inv.account, H(ACCT));
    assert.ok(!/CANARY|arn:/.test(r.stdout + r.stderr));
    assert.match(r.stderr, /22 records/);
  } finally { rmSync(home, { recursive: true, force: true }); }
});

test("CLI --from --regions keeps only the named regions", () => {
  const home = sandbox();
  try {
    const r = run(["bedrock", "--from", FIX, "--regions", "eu-west-1"], home);
    assert.equal(r.status, 0, r.stderr);
    const inv = JSON.parse(r.stdout);
    assert.deepEqual(inv.regions, ["eu-west-1"]);
    assert.ok(inv.records.every((x) => x.region === "eu-west-1"));
  } finally { rmSync(home, { recursive: true, force: true }); }
});

test("CLI: not enrolled exits 2 and prints no inventory", () => {
  const home = sandbox(false);
  try {
    const r = run(["bedrock", "--from", FIX], home);
    assert.equal(r.status, 2);
    assert.equal(r.stdout, "");
    assert.match(r.stderr, /enrol/i);
  } finally { rmSync(home, { recursive: true, force: true }); }
});

test("CLI --policy prints the minimum IAM policy and touches nothing else", () => {
  const home = sandbox(false);
  try {
    const r = run(["bedrock", "--policy"], home);
    assert.equal(r.status, 0, r.stderr);
    assert.deepEqual(JSON.parse(r.stdout), iamPolicy());
  } finally { rmSync(home, { recursive: true, force: true }); }
});

test("CLI: no mode is a usage error; --run is never implied", () => {
  const home = sandbox();
  try {
    const r = run(["bedrock"], home, { MOORAI_AWS_CLI: join(home, "no-such-aws") });
    assert.equal(r.status, 2);
    assert.match(r.stderr, /--from|--run/);
    assert.ok(!existsSync(join(home, "no-such-aws")));
  } finally { rmSync(home, { recursive: true, force: true }); }
});
