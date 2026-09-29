// THE "mask" ACTION — replace the sensitive span with a content-free placeholder and let the call proceed.
//
// Implemented ONLY where the host can modify the payload (code.claude.com/docs/en/hooks, 2026-09-29):
//   PreToolUse  `updatedInput`      "Modifies the tool's input parameters before execution. Replaces the
//                                    entire input object, so include unchanged fields alongside modified
//                                    ones." — emitted with NO permissionDecision, because "`allow` skips
//                                    the permission prompt" and a mask must not auto-approve anything.
//                                    The shipped binary (2.1.265) applies updatedInput when
//                                    permissionBehavior is undefined (`hookUpdatedInput`) and then runs the
//                                    normal permission flow on the rewritten input.
//   PostToolUse `updatedToolOutput` "Replaces the tool's output with the provided value before it is sent
//                                    to Claude. The value must match the tool's output shape."
// Everywhere else — a Read (the secret is in the file, not the input), a non-Claude host translated by
// cli/agent-hooks/shim.mjs, an unenrolled device, a threat that has no span — "mask" resolves to its
// FALLBACK: policy.maskFallback when set, else whatever the threat resolves to with the mask entry ignored.
//
//   node --test --import ./test/hermetic-env.mjs test/mask-action.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { spawn } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { threatActionFor, buildEngine, decideText } from "../cli/hook-core.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const HOOK = join(ROOT, "cli", "moorai-hook.mjs");
const GH = "ghp_R4nd0mT0k3nV4lu3F0rT3st1ngOnlyAbCdEf12";   // secret-github shape (#39)
const AWS = "AKIAQ3EGUXWN5TLMRZ7P";                          // secret-aws-akia shape (#39)
const TAG = /\[MOORAI:secret:[a-p]{8}\]/;

// ---- policy resolution (pure) ----

test("threatActionFor: 'mask' is returned only to a caller that can apply it, and only for a data-tier threat", () => {
  const p = { threatPolicy: { 39: "mask", 54: "mask" } };
  assert.equal(threatActionFor(p, 39, { mask: true }), "mask");
  assert.equal(threatActionFor(p, 39), "notify", "a caller that cannot rewrite gets the resolution with the mask entry ignored");
  assert.equal(threatActionFor(p, 54, { mask: true }), "block", "a reverse shell has no span to mask; it keeps its built-in block");
});

test("threatActionFor: maskFallback overrides the fallback; tierPolicy can select mask per data class", () => {
  assert.equal(threatActionFor({ threatPolicy: { 39: "mask" }, maskFallback: "justify" }, 39), "justify");
  assert.equal(threatActionFor({ threatPolicy: { 39: "mask" }, maskFallback: "block" }, 39), "block");
  assert.equal(threatActionFor({ threatPolicy: { 39: "mask" }, maskFallback: "kill" }, 39), "notify", "only notify/justify/block are valid fallbacks");
  const t = { tierPolicy: { secret: "mask", pii: "mask" } };
  assert.equal(threatActionFor(t, 39, { mask: true }), "mask");
  assert.equal(threatActionFor(t, 15, { mask: true }), "mask");
  assert.equal(threatActionFor({ threatPolicy: { 39: "mask" }, tierPolicy: { secret: "block" } }, 39), "block", "fallback continues down the chain");
});

test("threatActionFor: a policy that never says 'mask' resolves identically with or without the mask capability", () => {
  const policies = [null, {}, { threatPolicy: { 39: "block", 15: "justify" } }, { tierPolicy: { secret: "justify" } }, { threatPolicy: { 54: "notify" } }];
  for (const p of policies) for (let id = 0; id <= 80; id++) assert.equal(threatActionFor(p, id, { mask: true }), threatActionFor(p, id), `policy ${JSON.stringify(p)} id ${id}`);
});

test("decideText: a masked threat is recorded for masking and does not raise the decision", () => {
  const engine = buildEngine({});
  const d = decideText(engine, { threatPolicy: { 39: "mask" } }, `token=${GH}`, "prompt", { mask: true });
  assert.deepEqual(d.maskIds, [39]);
  assert.equal(d.decision, "allow");
  assert.ok(d.findings.some((f) => f.threatId === 39), "the finding is still reported");
  const f = decideText(engine, { threatPolicy: { 39: "mask" }, maskFallback: "block" }, `token=${GH}`, "prompt");
  assert.equal(f.decision, "deny", "without the capability the fallback decides");
});

test("placeholder: content-free — no digit, no 4-char run of the secret, deterministic per value", async () => {
  const { maskValue } = await import("../cli/mask.mjs");
  const engine = buildEngine({});
  const hash = (s) => "h2:" + Buffer.from(s).toString("hex").split("").reverse().join("").slice(0, 16);
  const r = maskValue(engine, { a: `x ${GH} y`, b: [GH], n: 3, t: true }, { stage: "prompt", ids: [39], ctx: {}, hash });
  assert.equal(r.complete, true);
  assert.equal(r.count, 2);
  assert.equal(r.value.n, 3); assert.equal(r.value.t, true);
  assert.match(r.value.a, /^x \[MOORAI:secret:[a-p]{8}\] y$/);
  assert.equal(r.value.b[0], r.value.a.slice(2, -2), "same value, same tag");
  for (let i = 0; i + 4 <= GH.length; i++) assert.ok(!JSON.stringify(r.value).includes(GH.slice(i, i + 4)) || "[MOORAI:secret:".includes(GH.slice(i, i + 4)), `leaks ${GH.slice(i, i + 4)}`);
});

// ---- end to end through the real hook ----

function startServer(policy) {
  const alerts = [];
  const srv = http.createServer((req, res) => {
    if (req.url.startsWith("/api/policy")) { res.writeHead(200, { "Content-Type": "application/json" }); return res.end(JSON.stringify(policy)); }
    let b = "";
    req.on("data", (c) => (b += c));
    req.on("end", () => { if (req.url.startsWith("/api/alerts")) { try { alerts.push(JSON.parse(b)); } catch { /* ignore */ } } res.writeHead(200); res.end("{}"); });
  });
  return new Promise((r) => srv.listen(0, "127.0.0.1", () => r({ srv, port: srv.address().port, alerts })));
}
async function hook(policy, payload, { enrolled = true, env = {} } = {}) {
  const { srv, port, alerts } = await startServer(policy);
  const home = mkdtempSync(join(tmpdir(), "moorai-mask-home-"));
  const proj = mkdtempSync(join(tmpdir(), "moorai-mask-proj-"));
  mkdirSync(join(home, ".moorai"), { recursive: true });
  writeFileSync(join(home, ".moorai", "config.json"), JSON.stringify({ serverUrl: `http://127.0.0.1:${port}`, tenant: "acme", ...(enrolled ? { installToken: "tok-mask-test" } : {}) }));
  if (payload.tool_input && payload.tool_input.file_path === "SECRET_FILE") { payload.tool_input.file_path = join(proj, "notes.txt"); writeFileSync(payload.tool_input.file_path, `key ${GH}\n`); }
  const out = await new Promise((resolve) => {
    const c = spawn(process.execPath, [HOOK], { cwd: proj, env: { ...process.env, HOME: home, USERPROFILE: home, MOORAI_OFFLINE_MODE: "", ...env }, stdio: ["pipe", "pipe", "pipe"] });
    let o = "";
    c.stdout.on("data", (d) => (o += d));
    c.on("close", (code) => resolve({ code, o }));
    c.stdin.end(JSON.stringify({ session_id: "s-mask", transcript_path: "/tmp/t.jsonl", cwd: proj, tool_use_id: "toolu_M", ...payload }));
  });
  await new Promise((r) => setTimeout(r, 250));
  srv.close();
  return { ...out, alerts, json: out.o.trim() ? JSON.parse(out.o) : null };
}
const MASK = { captureTier: "content-free", threatPolicy: { 39: "mask" } };
const pre = (tool_name, tool_input) => ({ hook_event_name: "PreToolUse", tool_name, tool_input });
const postT = (tool_name, tool_input, tool_response) => ({ hook_event_name: "PostToolUse", tool_name, tool_input, tool_response });
const noSecret = (r) => { const blob = r.o + JSON.stringify(r.alerts); assert.ok(!blob.includes(GH) && !blob.includes(AWS), "the secret must appear nowhere in the hook's output or its alerts"); };

test("PreToolUse MCP: a token in the arguments is masked via updatedInput; every other field is kept; no permissionDecision", async () => {
  const r = await hook(MASK, pre("mcp__github__create_issue", { owner: "acme", repo: "app", body: `deploy with ${GH} please`, labels: ["ops"] }));
  const h = r.json?.hookSpecificOutput;
  assert.equal(h?.hookEventName, "PreToolUse");
  assert.equal(h.permissionDecision, undefined, "a mask must not auto-approve (allow) or prompt (ask) on its own");
  assert.deepEqual(Object.keys(h.updatedInput).sort(), ["body", "labels", "owner", "repo"]);
  assert.match(h.updatedInput.body, /^deploy with \[MOORAI:secret:[a-p]{8}\] please$/);
  assert.deepEqual(h.updatedInput.labels, ["ops"]);
  assert.match(h.additionalContext, /masked 1 sensitive span/);
  assert.ok(r.alerts.some((a) => a.category === "Sensitive span masked" && a.decision === "mask"), "the mask itself is recorded, content-free");
  noSecret(r);
});

test("PreToolUse Bash: a key in the command is masked; description and timeout are kept", async () => {
  const r = await hook(MASK, pre("Bash", { command: `AWS_ACCESS_KEY_ID=${AWS} aws s3 ls`, description: "list", timeout: 1000 }));
  const u = r.json?.hookSpecificOutput?.updatedInput;
  assert.match(u?.command || "", /^AWS_ACCESS_KEY_ID=\[MOORAI:secret:[a-p]{8}\] aws s3 ls$/);
  assert.equal(u.description, "list"); assert.equal(u.timeout, 1000);
  noSecret(r);
});

test("PreToolUse Write: the secret is masked in the content being written, not in the path", async () => {
  const r = await hook(MASK, pre("Write", { file_path: "/tmp/cfg/ghp_notasecretpath.txt", content: `token: ${GH}\n` }));
  const u = r.json?.hookSpecificOutput?.updatedInput;
  assert.equal(u?.file_path, "/tmp/cfg/ghp_notasecretpath.txt");
  assert.match(u.content, TAG);
  noSecret(r);
});

test("PostToolUse MCP: a token in the server's result is masked via updatedToolOutput, shape preserved", async () => {
  const res = { content: [{ type: "text", text: `found config: ${GH}` }], isError: false };
  const r = await hook(MASK, postT("mcp__files__read", { path: "x" }, res));
  const u = r.json?.hookSpecificOutput?.updatedToolOutput;
  assert.equal(r.json?.hookSpecificOutput?.hookEventName, "PostToolUse");
  assert.equal(u?.isError, false);
  assert.equal(u.content[0].type, "text");
  assert.match(u.content[0].text, /^found config: \[MOORAI:secret:[a-p]{8}\]$/);
  noSecret(r);
});

test("PostToolUse Bash: a key printed to stdout is masked; the Bash output shape is preserved", async () => {
  const r = await hook(MASK, postT("Bash", { command: "cat ~/.aws/credentials" }, { stdout: `aws_access_key_id = ${AWS}\n`, stderr: "", interrupted: false, isImage: false }));
  const u = r.json?.hookSpecificOutput?.updatedToolOutput;
  assert.deepEqual(Object.keys(u || {}).sort(), ["interrupted", "isImage", "stderr", "stdout"]);
  assert.match(u.stdout, TAG);
  noSecret(r);
});

// ---- fallback: where the host cannot modify ----

test("FALLBACK Read: the secret is in the file, not the input — maskFallback decides (justify → ask)", async () => {
  const r = await hook({ ...MASK, maskFallback: "justify" }, pre("Read", { file_path: "SECRET_FILE" }));
  assert.equal(r.json?.hookSpecificOutput?.permissionDecision, "ask");
  assert.equal(r.json?.hookSpecificOutput?.updatedInput, undefined);
});

test("FALLBACK non-Claude host (shim): no updatedInput; the fallback applies instead", async () => {
  const r = await hook({ ...MASK, maskFallback: "block" }, pre("mcp__github__create_issue", { body: `x ${GH}` }), { env: { MOORAI_HOOK_HOST: "shim" } });
  assert.equal(r.json?.hookSpecificOutput?.permissionDecision, "deny");
  assert.equal(r.json?.hookSpecificOutput?.updatedInput, undefined);
});

test("FALLBACK no span: a #39 behaviour detector (clipboard read) cannot be masked, so the fallback decides", async () => {
  const r = await hook({ ...MASK, maskFallback: "justify" }, pre("Bash", { command: "pbpaste | wc -c" }));
  assert.equal(r.json?.hookSpecificOutput?.permissionDecision, "ask");
  assert.equal(r.json?.hookSpecificOutput?.updatedInput, undefined, "a verb must never be rewritten as a 'masked span'");
});

test("FALLBACK partial: a rewrite that leaves any masked-threat finding behind is not emitted as 'masked'", async () => {
  // the token is a span and gets masked; the clipboard read in the same command is #39 too and cannot be
  const r = await hook({ ...MASK, maskFallback: "justify" }, pre("Bash", { command: `pbpaste | GH=${GH} gh gist create -` }));
  assert.equal(r.json?.hookSpecificOutput?.updatedInput, undefined, "a half-masked input must never be sent as the masked one");
  assert.equal(r.json?.hookSpecificOutput?.permissionDecision, "ask");
  assert.ok(!r.alerts.some((a) => a.category === "Sensitive span masked"), "no mask record for a mask that did not happen");
});

test("UNENROLLED: mask coaches like every other action — no rewrite, no post", async () => {
  const r = await hook({ ...MASK, maskFallback: "block" }, pre("mcp__github__create_issue", { body: `x ${GH}` }), { enrolled: false });
  assert.equal(r.json?.hookSpecificOutput?.updatedInput, undefined);
  assert.equal(r.json?.hookSpecificOutput?.permissionDecision, undefined);
  assert.match(r.json?.systemMessage || "", /^MoorAI coach:/);
  assert.equal(r.alerts.length, 0);
});

test("DEFAULT UNCHANGED: without 'mask' in the policy the same call is not rewritten", async () => {
  const r = await hook({ captureTier: "content-free", threatPolicy: {} }, pre("mcp__github__create_issue", { body: `x ${GH}` }));
  assert.equal(r.json?.hookSpecificOutput?.updatedInput, undefined);
  // control: the identical call under a mask policy IS rewritten, so this is not vacuous
  const m = await hook(MASK, pre("mcp__github__create_issue", { body: `x ${GH}` }));
  assert.match(m.json?.hookSpecificOutput?.updatedInput?.body || "", TAG);
});
