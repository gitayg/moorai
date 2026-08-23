// Two boundary bugs in controls that are supposed to CONFINE an agent, found by the Phase 3 hunt and
// reproduced here against the real functions before being fixed:
//
//   F-101  data/model-endpoints.js  endpointApproved()  used a bare h.endsWith(s), so an
//          attacker-registered `evilanthropic.com` passed an `anthropic.com` allow-list — defeating
//          the control that stops a prompt-injected agent redirecting model egress (ANTHROPIC_BASE_URL).
//   F-102  cli/hook-core.mjs        decideEnvelope()    used a bare startsWith(a), so
//          `/Users/dev/acme-app-secrets/.env` sat inside an `/Users/dev/acme-app` envelope.
//
// Both are "the lookalike is accepted" bugs, so every assertion below is about a name that SHARES a
// leading/trailing substring with an allowed one but is a different entity.
//
//   node --test --test-reporter=spec "test/**/*.test.mjs"
//   (bare `node --test` walks src-tauri/target/ and hangs — always pass the glob.)
import { test } from "node:test";
import assert from "node:assert/strict";
import { endpointApproved } from "../data/model-endpoints.js";
import { decideEnvelope, pathInScope } from "../cli/hook-core.mjs";

test("ENDPOINT: a lookalike domain is NOT approved by a suffix match", () => {
  const allow = ["anthropic.com", "openai.com"];
  for (const h of ["evilanthropic.com", "notanthropic.com", "xanthropic.com", "myopenai.com", "anthropic.com.evil.net"]) {
    assert.equal(endpointApproved(h, allow), false, `${h} was approved against ${allow}`);
  }
});

test("ENDPOINT: the real hosts and their subdomains still ARE approved", () => {
  const allow = ["anthropic.com"];
  for (const h of ["anthropic.com", "api.anthropic.com", "eu.api.anthropic.com"]) {
    assert.equal(endpointApproved(h, allow), true, `${h} should be approved`);
  }
  // Unchanged behavior: loopback always allowed, no allow-list → report-only.
  assert.equal(endpointApproved("localhost", allow), true);
  assert.equal(endpointApproved("anything.example", []), true);
});

test("ENVELOPE: a sibling directory sharing a prefix is OUT of scope", () => {
  const policy = { entitlements: { mode: "block", paths: ["/Users/dev/acme-app"] } };
  for (const p of ["/Users/dev/acme-app-secrets/.env", "/Users/dev/acme-application/k", "/Users/dev/acme-app.bak"]) {
    const d = decideEnvelope(policy, { tool: "Read", paths: [p] });
    assert.equal(d.inScope, false, `${p} was treated as in-scope`);
  }
});

test("ENVELOPE: the allowed directory and its children are still in scope", () => {
  const policy = { entitlements: { mode: "block", paths: ["/Users/dev/acme-app"] } };
  for (const p of ["/Users/dev/acme-app", "/Users/dev/acme-app/src/x.js", "/Users/dev/acme-app/deep/er/f.txt"]) {
    assert.equal(decideEnvelope(policy, { tool: "Read", paths: [p] }).inScope, true, `${p} should be in scope`);
  }
  // An absent envelope is still always in scope.
  assert.equal(decideEnvelope({}, { tool: "Read", paths: ["/anywhere"] }).inScope, true);
});

test("ENVELOPE: a JIT elevation grant does not cover a prefix-sibling either", () => {
  const policy = {
    entitlements: { mode: "block", paths: ["/Users/dev/acme-app"] },
    elevations: [{ actor: "dev", capability: "path:/Users/dev/other-app" }]
  };
  const leak = decideEnvelope(policy, { tool: "Read", paths: ["/Users/dev/other-app-secrets/.env"], actor: "dev" });
  assert.equal(leak.inScope, false, "a grant for other-app must not cover other-app-secrets");
  const ok = decideEnvelope(policy, { tool: "Read", paths: ["/Users/dev/other-app/f.js"], actor: "dev" });
  assert.equal(ok.inScope, true, "the grant must still cover its own subtree");
});

test("ENVELOPE: pathInScope handles separators and trailing slashes", () => {
  assert.equal(pathInScope("/a/b/c", "/a/b"), true);
  assert.equal(pathInScope("/a/b/c", "/a/b/"), true);      // trailing slash on the allow entry
  assert.equal(pathInScope("/a/bc", "/a/b"), false);
  assert.equal(pathInScope("C:\\proj\\src", "C:\\proj"), true);
  assert.equal(pathInScope("C:\\project", "C:\\proj"), false);
});
