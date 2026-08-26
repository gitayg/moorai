// In-app signup + automatic device enrollment.
//
// The dangerous shape this feature could have taken is a client that asks the server "is
// <email> verified yet?" on a loop — an unauthenticated account-enumeration oracle. It polls by
// single-use claim token instead, and the tests below pin that both behaviourally (a fetch spy sees
// the email in no request) and at the source level (the one line that builds the claim URL).
//
// The rest pins the polling contract itself: 202 means keep waiting, 200 means ready exactly once,
// 404 is terminal, and the wait is bounded — a client that spins forever on a dead token is a bug
// the user would experience as a hung app.
//
//   node --test --test-reporter=spec "test/**/*.test.mjs"
//   (bare `node --test` walks src-tauri/target/ and hangs — always pass the glob.)
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const SRC = new URL("../src/", import.meta.url);
const read = (f) => readFileSync(new URL(f, SRC), "utf8");
// Comments discuss localStorage and the console by name; the assertions below are about code.
const code = (f) => read(f).split("\n").filter((l) => !l.trim().startsWith("//")).join("\n");

// src/signup.js takes every dependency as an argument, so it imports cleanly under node — unlike
// src/api.js, which reads localStorage at module scope.
const { startSignup, pollClaim } = await import("../src/signup.js");

const BASE = "https://moorai.example";
const CLAIM = "cl_live_zzzzzzzzzzzzzzzz";
const EMAIL = "admin@acme.test";
const INSTALL = "it_live_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

const res = (status, body) => ({ status, ok: status >= 200 && status < 300, json: async () => body });
const READY = res(200, { status: "ready", tenant: "acme", installToken: INSTALL, serverUrl: BASE });
const PENDING = res(202, { status: "pending" });
const GONE = res(404, {});

// A fake clock the injected sleep advances, so a ten-minute bound is exercised in microseconds.
function fakeClock() {
  let t = 0;
  return { now: () => t, sleep: async (ms) => { t += ms; } };
}

function spy(responses) {
  const calls = [];
  return {
    calls,
    fetchImpl: async (url, opts) => {
      calls.push({ url, opts });
      const r = responses[Math.min(calls.length - 1, responses.length - 1)];
      return r;
    }
  };
}

test("SIGNUP-CLAIM: polling survives a run of 202s and resolves on the first ready", async () => {
  const { calls, fetchImpl } = spy([PENDING, PENDING, PENDING, READY]);
  const clock = fakeClock();
  const pending = [];
  const out = await pollClaim({
    base: BASE, claimToken: CLAIM, fetchImpl, sleep: clock.sleep, now: clock.now,
    intervalMs: 3000, timeoutMs: 600000, onPending: () => pending.push(clock.now())
  });
  assert.deepEqual(out, { tenant: "acme", installToken: INSTALL, serverUrl: BASE });
  assert.equal(calls.length, 4, "it must poll again after each 202, and stop on the first 200");
  assert.deepEqual(pending, [0, 3000, 6000], "onPending fires once per 202, never for the ready read");
});

test("SIGNUP-CLAIM: a 404 mid-poll is a terminal, readable error — not an endless loop", async () => {
  const { calls, fetchImpl } = spy([PENDING, GONE]);
  const clock = fakeClock();
  await assert.rejects(
    () => pollClaim({ base: BASE, claimToken: CLAIM, fetchImpl, sleep: clock.sleep, now: clock.now, intervalMs: 3000, timeoutMs: 600000 }),
    /expired or was already used/
  );
  assert.equal(calls.length, 2, "polling must stop at the 404, not keep retrying a dead token");
});

test("SIGNUP-CLAIM: the wait is bounded by timeoutMs — an unclicked email cannot spin forever", async () => {
  const { calls, fetchImpl } = spy([PENDING]);
  const clock = fakeClock();
  await assert.rejects(
    () => pollClaim({ base: BASE, claimToken: CLAIM, fetchImpl, sleep: clock.sleep, now: clock.now, intervalMs: 1000, timeoutMs: 5000 }),
    /timed out waiting for email verification/
  );
  assert.equal(calls.length, 5, "the bound must hold: 5 polls at 1s inside a 5s window");
  assert.ok(clock.now() < 5000, `slept past the deadline (${clock.now()}ms)`);
});

test("SIGNUP-CLAIM: the claim endpoint is polled by TOKEN ONLY — never by email or tenant", async () => {
  // (a) behavioural. The email is handed in deliberately, even though pollClaim has no parameter
  //     for it: a version that grew one would leak it here instead of ignoring it.
  const { calls, fetchImpl } = spy([PENDING, READY]);
  const clock = fakeClock();
  await pollClaim({ base: BASE, claimToken: CLAIM, email: EMAIL, tenant: "acme", fetchImpl, sleep: clock.sleep, now: clock.now, intervalMs: 1000, timeoutMs: 600000 });
  for (const c of calls) {
    const wire = c.url + JSON.stringify(c.opts || {});
    for (const form of [EMAIL, encodeURIComponent(EMAIL), "admin", "acme.test"]) {
      assert.ok(!wire.includes(form), `the email reached the claim endpoint: ${wire}`);
    }
    assert.ok(!wire.includes("acme"), `the tenant reached the claim endpoint: ${wire}`);
    assert.match(c.url, /\/api\/signup\/claim\?claim=/);
  }

  // (b) source-level: an enumeration oracle is a one-line regression, so the line that builds the
  //     claim request is pinned directly. It must carry the claim token and nothing else, and there
  //     must be exactly one such line.
  const src = read("signup.js");
  const hits = src.split("\n").filter((l) => l.includes("/api/signup/claim"));
  assert.equal(hits.length, 1, "there must be exactly one claim request in the client");
  const line = hits[0];
  assert.ok(line.includes("claim=${encodeURIComponent(claimToken)}"), line);
  assert.ok(!/email|tenant|user=|name/i.test(line), `the claim request names something other than the token: ${line}`);
  assert.ok(!/method:|body:/.test(line), `the claim request carries a payload: ${line}`);

  // The claim token is a bearer credential for a brand-new tenant: never persisted, never logged.
  const body = code("signup.js");
  assert.ok(!/localStorage|sessionStorage/.test(body), "the claim token must not outlive the polling session");
  assert.ok(!/console\.|nativeLog/.test(body), "the signup module must not log its tokens");
  assert.ok(!/claimToken|installToken/.test(code("app.js").match(/nativeLog\([^)]*\)/g)?.join("") || ""));
});

test("SIGNUP-CLAIM: startSignup asks for a claim token, and surfaces the server's 400 verbatim", async () => {
  const { calls, fetchImpl } = spy([res(201, { ok: true, tenant: "acme", emailed: true, claimToken: CLAIM })]);
  const out = await startSignup({ base: BASE, name: "Acme", email: EMAIL, fetchImpl });
  assert.deepEqual(out, { tenant: "acme", emailed: true, claimToken: CLAIM });
  assert.equal(calls[0].url, `${BASE}/api/signup`);
  assert.equal(calls[0].opts.method, "POST");
  const sent = JSON.parse(calls[0].opts.body);
  assert.equal(sent.claim, true, "without claim:true the server returns no claim token and the flow is dead");
  assert.deepEqual(sent, { name: "Acme", email: EMAIL, claim: true });

  const bad = spy([res(400, { error: "that email address is not valid" })]);
  await assert.rejects(
    () => startSignup({ base: BASE, name: "", email: "nope", fetchImpl: bad.fetchImpl }),
    /that email address is not valid/,
    "the user must see the server's reason, not a generic failure"
  );
});

test("SIGNUP-CLAIM: the glue hands the ready claim to the existing enroll(), and never re-implements it", () => {
  const api = read("api.js");
  assert.match(api, /export async function awaitClaim/);
  const glue = api.slice(api.indexOf("export async function awaitClaim"), api.indexOf("// Lightweight, scan-independent beacon"));
  assert.match(glue, /return await enroll\(ready\.installToken, ready\.serverUrl\)/, "provisioning must stay in enroll()");
  assert.ok(!/localStorage|save_provision/.test(glue), "the signup path must not duplicate the provisioning writes");
  // The paste-a-token path is what MDM-provisioned installs rely on; it must be untouched.
  assert.match(api, /export async function enroll\(token, serverUrl\)/);
});
