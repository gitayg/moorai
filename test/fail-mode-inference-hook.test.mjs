// The Inference hooks server's fail mode (cli/fail-mode.mjs surface "inferenceHook"): the admin binding
// and the policy override the operator's --fail flag, which stays the server's own default.
// Precedence: admin > policy > --fail > open. In process, with the runtime's reporter captured.
//
//   node --test --import ./test/hermetic-env.mjs test/fail-mode-inference-hook.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { join, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const imp = (rel) => import(pathToFileURL(join(ROOT, rel)).href);
const { createServer } = await imp("cli/inference-hook/server.mjs");
const { parseSecrets } = await imp("cli/inference-hook/signature.mjs");
const { promptFrame, signedRequest } = await imp("cli/inference-hook/samples.mjs");

const SECRET = "whsec_" + Buffer.alloc(32, 9).toString("base64");

async function start({ policyFail, admin = null, fail = "open", ...opts } = {}) {
  const alerts = [];
  const consoleFetch = async (url, init) => { if (String(url).endsWith("/api/alerts")) alerts.push(JSON.parse(String(init.body))); return new Response("{}", { status: 201 }); };
  const s = await createServer({
    port: 0, keys: parseSecrets(SECRET), env: {}, systemConfig: admin, fail,
    policy: { captureTier: "content-free", builtinDefault: true, ...(policyFail ? { failMode: policyFail } : {}) },
    console: { serverUrl: "http://console.invalid", tenant: "t-fm", installToken: "tok-fm-ih" }, fetch: consoleFetch,
    ...opts
  });
  return { ...s, alerts };
}
async function send(s, frame) {
  const { raw, headers } = signedRequest(SECRET, frame);
  const r = await fetch(s.url + "/", { method: "POST", headers, body: raw });
  const text = await r.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* not JSON */ }
  return { status: r.status, json, text };
}

// A frame that cannot be judged: the evaluation deadline has already passed.
const UNJUDGED = { evalTimeoutMs: -1 };

for (const [label, cfg, want, source] of [
  ["no admin, no policy: the --fail flag decides (open)", { fail: "open" }, "allow", "default"],
  ["no admin, no policy: the --fail flag decides (closed)", { fail: "closed" }, "deny", "default"],
  ["the policy beats the flag: policy closed, --fail open", { fail: "open", policyFail: { inferenceHook: "closed" } }, "deny", "policy"],
  ["the policy beats the flag: policy open, --fail closed", { fail: "closed", policyFail: { inferenceHook: "open" } }, "allow", "policy"],
  ["the policy default applies", { fail: "open", policyFail: { default: "closed" } }, "deny", "policy"],
  ["the admin binding beats the policy and the flag: admin open", { fail: "closed", policyFail: { inferenceHook: "closed" }, admin: { failMode: { inferenceHook: "open" } } }, "allow", "admin"],
  ["the admin binding beats the policy and the flag: admin closed", { fail: "open", policyFail: { inferenceHook: "open" }, admin: { failMode: { default: "closed" } } }, "deny", "admin"]
]) {
  test(`inference hook fail mode — ${label}`, async () => {
    const s = await start({ ...cfg, ...UNJUDGED });
    try {
      const r = await send(s, promptFrame("hello"));
      assert.equal(r.status, 200);
      assert.equal(r.json.action, want, r.text);
      assert.deepEqual(await s.failMode(), { mode: want === "deny" ? "closed" : "open", source });
      if (want === "deny") assert.match(r.json.deny_reason, /could not inspect/);
      await s.close();
      const a = s.alerts.find((x) => x.category === "Inference hook: content not evaluated");
      assert.ok(a, `alerts: ${JSON.stringify(s.alerts.map((x) => x.category))}`);
      assert.equal(a.failMode, want === "deny" ? "closed" : "open");
      assert.equal(a.failModeSource, source);
    } finally { await s.close().catch(() => {}); }
  });
}

test("a body the server cannot read: the policy's closed answers deny even with --fail open", async () => {
  const s = await start({ fail: "open", policyFail: { inferenceHook: "closed" }, maxBody: 2048 });
  try {
    const r = await send(s, promptFrame("a".repeat(3000))); // over maxBody, under twice it (past that the socket is dropped)
    assert.equal(r.status, 200);
    assert.equal(r.json.action, "deny");
  } finally { await s.close(); }
});
