// MXC denial capture -> content-free alerts (cli/mxc-denials.mjs, mirrored at launch time by
// src-tauri/src/mxc_denials.rs; both replay test/fixtures/mxc/denial-cases.json).
//
// Input format: microsoft/mxc @ 7cd00d1 docs/logging-access-denied.md "Output file the caller consumes".
// Only its documented fields are read; nothing undocumented is assumed.
//
//   node --test test/mxc-denials.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { parseDenials, denialAlerts, MXC_DENIAL_CATEGORY, MAX_GROUPS } from "../cli/mxc-denials.mjs";

const CASES = JSON.parse(readFileSync(new URL("./fixtures/mxc/denial-cases.json", import.meta.url), "utf8"));
const ENV = { USERPROFILE: "C:\\Users\\test", APPDATA: "C:\\Users\\test\\AppData\\Roaming", LOCALAPPDATA: "C:\\Users\\test\\AppData\\Local", SystemRoot: "C:\\Windows" };

// The example printed in logging-access-denied.md, verbatim.
const DOC_EXAMPLE = `{
  "denials": [
    {
      "resource": "C:\\\\Users\\\\test\\\\secret.txt",
      "resourceType": "file",
      "accessType": "read",
      "pid": 1234,
      "filetime": "132847890123456789"
    },
    {
      "resource": "internetClient",
      "resourceType": "capability",
      "accessType": "unknown",
      "pid": 1234,
      "filetime": "132847890123512345"
    }
  ],
  "summary": {
    "exitCode": 0,
    "totalDenials": 2,
    "deniedResourcesTruncated": false
  }
}`;

test("golden cases: the Node parser reproduces every expected object (Rust replays the same file)", () => {
  assert.ok(CASES.length >= 4);
  for (const c of CASES) {
    const p = parseDenials(c.text, { env: c.env, workspace: c.workspace });
    const got = p.ok ? { ok: true, alerts: denialAlerts(p, { agent: c.agent, ts: c.ts, identity: c.identity }) } : { ok: false, error: p.error };
    assert.deepStrictEqual(got, c.expected, c.name);
  }
});

test("the documented example parses into two content-free alerts", () => {
  const p = parseDenials(DOC_EXAMPLE, { env: ENV, workspace: "C:\\src\\proj" });
  assert.equal(p.ok, true);
  assert.equal(p.total, 2);
  const alerts = denialAlerts(p, { agent: "claude", ts: "t", identity: { user: "u" } });
  assert.deepEqual(alerts.map((a) => a.reasonCode).sort(), ["capability-internetClient-unknown", "user-profile-read"]);
  for (const a of alerts) {
    assert.equal(a.category, MXC_DENIAL_CATEGORY);
    assert.equal(a.category, "MXC: access denied");
    assert.equal(a.stage, "containment");
    assert.equal(a.tool, "mxc:claude");
  }
});

test("no alert carries a path, a file name, a pid or a filetime", () => {
  for (const c of CASES) {
    let doc;
    try { doc = JSON.parse(c.text); } catch { continue; }
    const p = parseDenials(c.text, { env: c.env, workspace: c.workspace });
    if (!p.ok) continue;
    const out = JSON.stringify(denialAlerts(p, { agent: "claude", ts: "t", identity: {} }));
    for (const d of doc.denials || []) {
      if (!d || typeof d !== "object" || Array.isArray(d)) continue;
      // capability NAMES are reported on purpose (well-known AppContainer identifiers); every other
      // resource must not survive in any form
      if (d.resourceType !== "capability" && typeof d.resource === "string") {
        for (const piece of d.resource.split(/[\\:]/).filter((s) => s.length > 3)) assert.ok(!out.includes(piece), `${c.name}: leaked "${piece}"`);
      }
      assert.ok(!out.includes(String(d.pid)), `${c.name}: leaked pid`);
      assert.ok(!out.includes(String(d.filetime)), `${c.name}: leaked filetime`);
    }
  }
});

test("credential and persistence classes are High; policy-tuning classes are Low", () => {
  const doc = JSON.stringify({ denials: [
    { resource: "C:\\Users\\test\\.aws\\credentials", resourceType: "file", accessType: "read" },
    { resource: "C:\\Users\\test\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\x.lnk", resourceType: "file", accessType: "write" },
    { resource: "C:\\src\\proj\\a.txt", resourceType: "file", accessType: "write" }
  ] });
  const g = Object.fromEntries(parseDenials(doc, { env: ENV, workspace: "C:\\src\\proj" }).groups.map((x) => [x.reasonCode, x.riskLevel]));
  assert.deepEqual(g, { "cloud-credentials-read": "High", "startup-folder-write": "High", "workspace-write": "Low" });
});

test("bounded: malformed input is an error, not an exception; groups are capped and flagged", () => {
  assert.deepEqual(parseDenials("{"), { ok: false, error: "malformed" });
  assert.deepEqual(parseDenials("[]"), { ok: false, error: "malformed" });
  assert.deepEqual(parseDenials(42), { ok: false, error: "not-text" });
  const many = JSON.stringify({ denials: Array.from({ length: MAX_GROUPS + 5 }, (_, k) => ({ resource: `cap${k}`, resourceType: "capability", accessType: "unknown" })) });
  const p = parseDenials(many, {});
  assert.equal(p.groups.length, MAX_GROUPS);
  assert.equal(p.droppedGroups, 5);
  assert.ok(denialAlerts(p).every((a) => a.truncated === true));
});
