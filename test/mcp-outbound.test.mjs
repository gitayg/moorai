// What an agent sends to an MCP tool (cli/mcp-outbound.mjs, merged into mcpGateway): the argument values
// with their line breaks, content an argument carries base64-encoded, and the over-sharing signal
// (policy mcpOversharing). Pure: mcpGateway over the built engine, no process.
//
//   node --test --import ./test/hermetic-env.mjs test/mcp-outbound.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { buildEngine, mcpGateway, decideText } from "../cli/hook-core.mjs";
import { OVERSHARE_CATEGORY, OVERSHARE_THREAT, oversharingPolicy, oversharingAlertFields } from "../cli/mcp-outbound.mjs";
import { mcpWriteCalls } from "../cli/oversight-mcp.mjs";
import { docx, LABEL_ID } from "./fixtures/label-files.mjs";

const gate = (policy, tool, args, extra = {}) => mcpGateway(buildEngine(policy), policy, { tool, server: tool.split("__")[1], args: JSON.stringify(args), ...extra });
const ids = (g) => g.findings.map((f) => `${f.threatId}/${f.detectorId}`);
const localWrite = (t, a) => mcpWriteCalls(t, a).length > 0;

// Made-up values only.
const HEADING = "Release notes\n\n## API keys\n- primary: 9fK2mQ7xLp3Vz8Rt\n- backup: 4hT6nW1yBq9Cs2Dk\n";
const CARD_FILE = "id,name,card\n1,Test Person,4111 1111 1111 1111\nAWS=AKIAIOSFODNN7EXAMPLE\n";
const b64 = (s) => Buffer.from(s).toString("base64");

test("a list of keys under a heading in a multi-line value raises #39 (the serialized JSON hides its line breaks)", () => {
  const g = gate({}, "mcp__slack__post_message", { channel: "eng", text: HEADING });
  assert.ok(ids(g).includes("39/secret-heading-list"), ids(g).join(" "));
  assert.equal(g.decision, "allow", "#39 is notify by default: reported, not refused");
  const b = gate({ threatPolicy: { 39: "block" } }, "mcp__slack__post_message", { channel: "eng", text: HEADING });
  assert.equal(b.decision, "deny");
  assert.match(b.reason, /#39/);
});

test("base64 file content in an argument: the decoded text gets the data-loss detectors (#90 card, #39 key)", () => {
  const g = gate({}, "mcp__drive__upload_file", { name: "export.csv", content: b64(CARD_FILE) });
  assert.ok(ids(g).includes("90/dlp-payment-card"), ids(g).join(" "));
  assert.ok(ids(g).some((x) => x.startsWith("39/")), ids(g).join(" "));
  const d = gate({}, "mcp__drive__upload_file", { file: `data:text/csv;base64,${b64(CARD_FILE)}` });
  assert.ok(ids(d).includes("90/dlp-payment-card"), "a data: URI is decoded too");
  const blocked = gate({ threatPolicy: { 90: "block" } }, "mcp__drive__upload_file", { name: "export.csv", content: b64(CARD_FILE) });
  assert.equal(blocked.decision, "deny");
});

test("a labelled .docx sent base64-encoded gets labelPolicy's send verdict; the finding names no content", () => {
  const policy = { labelPolicy: { rules: [{ match: { id: LABEL_ID }, onSend: "block" }] } };
  const doc = docx({ custom: [{ id: LABEL_ID, name: "Highly Confidential" }] });
  const g = gate(policy, "mcp__drive__upload_file", { name: "board.docx", content: doc.toString("base64") });
  assert.equal(g.decision, "deny", g.reason);
  const f = g.findings.find((x) => x.sensitivityLabel);
  assert.ok(f, ids(g).join(" "));
  assert.deepEqual([f.threatId, f.sensitivityLabel.labelId, f.sensitivityLabel.action, f.sensitivityLabel.verdict], [1, LABEL_ID, "send", "block"]);
  assert.ok(!f.match.includes("board"), "the match is a keyed hash");
  const plain = gate(policy, "mcp__drive__upload_file", { name: "plain.docx", content: docx().toString("base64") });
  assert.ok(!plain.findings.some((x) => x.sensitivityLabel), "an unlabelled document raises nothing");
});

test("over-sharing is reported by default: a large argument, content-free (sizes and a keyed hash only)", () => {
  const big = "row of plain words\n".repeat(5000);
  const g = gate({}, "mcp__notion__create_page", { title: "dump", body: big });
  const f = g.findings.find((x) => x.detectorId === "mcp-oversharing");
  assert.ok(f, ids(g).join(" "));
  assert.equal(g.decision, "allow");
  assert.deepEqual([f.threatId, f.category], [OVERSHARE_THREAT, OVERSHARE_CATEGORY]);
  assert.deepEqual(f.oversharing.signals, ["size", "file-paste"]);
  assert.equal(f.oversharing.lines, 5001);
  const alert = JSON.stringify(oversharingAlertFields(f));
  assert.ok(!alert.includes("plain words") && !f.match.includes("plain words"), "no value leaves");
  assert.equal(gate({}, "mcp__notion__create_page", { title: "t", body: "short" }).findings.length, 0, "a small call raises nothing");
});

test("mcpOversharing.action justify asks, block refuses, false turns it off; thresholds come from the policy", () => {
  const args = { body: "x".repeat(3000) };
  assert.equal(gate({ mcpOversharing: { action: "justify", maxArgBytes: 1000 } }, "mcp__x__send", args).decision, "ask");
  const b = gate({ mcpOversharing: { action: "block", maxArgBytes: 1000 } }, "mcp__x__send", args);
  assert.equal(b.decision, "deny");
  assert.match(b.reason, /MCP over-sharing: size/);
  assert.equal(gate({ mcpOversharing: false, }, "mcp__x__send", { body: "x".repeat(70000) }).findings.filter((f) => f.detectorId === "mcp-oversharing").length, 0);
  assert.equal(gate({ mcpOversharing: { maxArgBytes: 1000 } }, "mcp__x__send", args).decision, "allow", "the default action stays notify");
  assert.deepEqual(oversharingPolicy({ mcpOversharing: { action: "bogus", maxLines: -1 } }), oversharingPolicy({}), "invalid fields keep their defaults");
});

test("a conversation pasted into an argument: chat-message objects and role-prefixed transcript lines", () => {
  const messages = [];
  for (let i = 0; i < 3; i++) messages.push({ role: "user", content: `question ${i}` }, { role: "assistant", content: `answer ${i}` });
  const g = gate({}, "mcp__share__post", { messages });
  assert.deepEqual(g.findings.find((x) => x.detectorId === "mcp-oversharing").oversharing.signals, ["conversation"]);
  const transcript = Array.from({ length: 6 }, (_, i) => `${i % 2 ? "Assistant" : "User"}: line number ${i} of the chat so far`).join("\n");
  const t = gate({}, "mcp__share__post", { text: transcript });
  assert.equal(t.findings.find((x) => x.detectorId === "mcp-oversharing").oversharing.turns, 6);
  const one = gate({}, "mcp__share__post", { text: "User: hi\nUser: still me\nUser: again\nUser: and again, a single speaker repeated four times over" + " ".repeat(200) });
  assert.ok(!one.findings.some((x) => x.detectorId === "mcp-oversharing"), "one role is not a conversation");
});

test("an encoded blob and a binary file: encoded-blob and file-paste; a local filesystem write is exempt", () => {
  const png = Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), Buffer.alloc(20000, 7)]);
  const g = gate({}, "mcp__drive__upload_file", { content: png.toString("base64") });
  const f = g.findings.find((x) => x.detectorId === "mcp-oversharing");
  assert.deepEqual([f.oversharing.signals, f.oversharing.fileType], [["encoded-blob", "file-paste"], "png"]);
  const big = { path: "/tmp/out/report.md", content: "line\n".repeat(800) };
  assert.ok(gate({}, "mcp__filesystem__write_file", big).findings.some((x) => x.detectorId === "mcp-oversharing"), "without the predicate it is reported");
  assert.ok(!gate({}, "mcp__filesystem__write_file", big, { localWrite }).findings.some((x) => x.detectorId === "mcp-oversharing"), "a local write is exempt");
});

test("a secret the JSON scan already found keeps today's verdict and is not reported twice", () => {
  const args = { text: "deploy key AKIAIOSFODNN7EXAMPLE\nnext line" };
  for (const policy of [{}, { threatPolicy: { 39: "block" } }, { threatPolicy: { 39: "justify" } }]) {
    const g = gate(policy, "mcp__slack__post_message", args);
    const before = decideText(buildEngine(policy), policy, JSON.stringify(args), "prompt", { ctx: { egress: true } });
    assert.equal(g.decision, before.decision, "the JSON scan's verdict");
    assert.deepEqual(ids(g), before.findings.map((f) => `${f.threatId}/${f.detectorId}`));
    assert.equal(g.findings.filter((f) => f.threatId === 39).length, 1);
  }
});
