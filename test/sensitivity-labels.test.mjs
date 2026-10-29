// Per-file runner:  node --test --import ./test/hermetic-env.mjs test/sensitivity-labels.test.mjs
//
// labelPolicy (cli/sensitivity-labels.mjs): a Microsoft Purview / MIP sensitivity label already on a file,
// read from the file's metadata only, and the admin's verdict for an AI agent reading or sending it.
// Every fixture is generated (test/fixtures/label-files.mjs); no real document is used.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { labelPolicy, readSensitivityLabels, decideSensitivityLabel, labelVerdict, LABEL_CAPS, LABEL_THREAT } from "../cli/sensitivity-labels.mjs";
import { scanMcpFileArgs } from "../cli/mcp-file-args.mjs";
import { buildEngine } from "../cli/hook-core.mjs";
import { rmTree } from "./fs-cleanup.mjs";
import { docx, pdf, cfb, zip, LABEL_ID, OTHER_ID, SITE_ID } from "./fixtures/label-files.mjs";

const ENGINE = buildEngine(null);
const HC = { id: LABEL_ID, name: "Highly Confidential" };

function dir(t) {
  const d = mkdtempSync(join(tmpdir(), "moorai-labels-"));
  t.after(() => rmTree(d));
  return (name, bytes) => { const p = join(d, name); writeFileSync(p, bytes); return p; };
}
const byId = (rule) => ({ labelPolicy: { rules: [{ match: { id: LABEL_ID }, ...rule }] } });
const byName = (name, rule) => ({ labelPolicy: { rules: [{ match: { name }, ...rule }] } });

test("policy: absent / null / not an object = inactive; entries validated, GUID braces and case normalised", () => {
  for (const p of [null, {}, { labelPolicy: null }]) assert.equal(labelPolicy(p).active, false);
  const warns = [];
  assert.equal(labelPolicy({ labelPolicy: "block" }, (m) => warns.push(m)).active, false);
  const lp = labelPolicy({ labelPolicy: { rules: [
    { match: { id: `{${LABEL_ID.toUpperCase()}}` }, onSend: "block" },
    { match: { name: "  Highly Confidential " }, onRead: "justify" },
    { match: { id: "not-a-guid" }, onRead: "block" },
    { match: { name: "x" }, onRead: "deny" },
    { match: {} , onRead: "block" },
    "nope"
  ], protected: { onSend: "block", onRead: "kill" }, extra: 1 } }, (m) => warns.push(m));
  assert.equal(lp.active, true);
  assert.deepEqual(lp.rules, [{ id: LABEL_ID, name: "", send: "block" }, { id: "", name: "highly confidential", read: "justify" }]);
  assert.deepEqual(lp.protected, { send: "block" });
  assert.ok(warns.some((w) => /not-a-guid|not a GUID/.test(w)) && warns.some((w) => /onRead ignored/.test(w)) && warns.some((w) => /unknown key/.test(w)), warns.join("\n"));
  assert.ok(!warns.some((w) => w.includes("Highly")), "warnings never carry a policy value");
});

test("inactive policy: no file is opened and nothing changes", (t) => {
  const put = dir(t);
  const p = put("a.docx", docx({ custom: [HC] }));
  let opened = 0;
  const read = (x) => { opened++; return readSensitivityLabels(x); };
  for (const pol of [null, {}, { labelPolicy: { rules: [] } }, { threatPolicy: { 1: "block" } }]) {
    const d = decideSensitivityLabel(ENGINE, pol, p, "read", { read });
    assert.equal(d.decision, "allow");
    assert.equal(d.findings.length, 0);
    assert.equal(d.unevaluated, false);
  }
  assert.equal(opened, 0);
});

test("docx: an enabled label in custom.xml is read (deflated and stored parts); a disabled one is ignored; no label = none", (t) => {
  const put = dir(t);
  for (const store of [false, true]) {
    const r = readSensitivityLabels(put(`l${store}.docx`, docx({ custom: [HC], store })));
    assert.equal(r.state, "labelled");
    assert.equal(r.labels.length, 1);
    assert.equal(r.labels[0].id, LABEL_ID);
    assert.equal(r.labels[0].name, "Highly Confidential");
    assert.equal(r.labels[0].siteId, SITE_ID);
    assert.equal(r.labels[0].source, "custom");
  }
  assert.equal(readSensitivityLabels(put("off.docx", docx({ custom: [{ ...HC, enabled: false }] }))).state, "none");
  assert.equal(readSensitivityLabels(put("plain.docx", docx())).state, "none");
  assert.equal(readSensitivityLabels(put("notes.txt", "MSIP_Label_" + LABEL_ID + "_Enabled true\n")).state, "none", "a text file mentioning the key is not a label");
});

test("docx LabelInfo.xml (MS-OFFCRYPTO 2.6.3): it wins for its tenant, borrows the name by GUID, removed=1 drops the tenant's label", (t) => {
  const put = dir(t);
  // LabelInfo names OTHER_ID for the tenant; custom.xml still holds the older HC for the same tenant.
  let r = readSensitivityLabels(put("li.docx", docx({ custom: [HC, { id: OTHER_ID, name: "General" }], labelInfo: [{ id: OTHER_ID }] })));
  assert.equal(r.state, "labelled");
  assert.deepEqual(r.labels.map((l) => [l.id, l.name, l.source]), [[OTHER_ID, "General", "labelinfo"]]);
  r = readSensitivityLabels(put("rm.docx", docx({ custom: [HC], labelInfo: [{ id: SITE_ID, removed: true }] })));
  assert.equal(r.state, "none", "a removed LabelInfo element stops the tenant's custom.xml label being read");
  // A custom-property label of a DIFFERENT tenant still counts.
  r = readSensitivityLabels(put("two.docx", docx({ custom: [{ ...HC, siteId: OTHER_ID }], labelInfo: [{ id: OTHER_ID }] })));
  assert.deepEqual(r.labels.map((l) => l.id).sort(), [LABEL_ID, OTHER_ID].sort());
  // LabelInfo alone: matched by GUID, no name.
  r = readSensitivityLabels(put("only.docx", docx({ labelInfo: [{ id: LABEL_ID }] })));
  assert.deepEqual(r.labels.map((l) => [l.id, l.name]), [[LABEL_ID, ""]]);
});

test("pdf: Info-dictionary keys (literal and UTF-16 hex), XMP properties, and a label past the head window", (t) => {
  const put = dir(t);
  for (const opts of [{ info: [HC] }, { info: [HC], hexName: true }, { xmp: [HC] }, { info: [HC], padding: LABEL_CAPS.pdfWindow * 2 }]) {
    const r = readSensitivityLabels(put("x.pdf", pdf(opts)));
    assert.equal(r.state, "labelled", JSON.stringify(Object.keys(opts)));
    assert.equal(r.labels[0].id, LABEL_ID);
    assert.equal(r.labels[0].name, "Highly Confidential");
    assert.equal(r.labels[0].source, "pdf");
  }
  assert.equal(readSensitivityLabels(put("d.pdf", pdf({ info: [{ ...HC, enabled: false }] }))).state, "none");
  assert.equal(readSensitivityLabels(put("n.pdf", pdf())).state, "none");
  const ip = readSensitivityLabels(put("irm.pdf", pdf({ protectedIrm: true })));
  assert.equal(ip.state, "protected");
  const both = readSensitivityLabels(put("irm2.pdf", pdf({ protectedIrm: true, info: [HC] })));
  assert.equal(both.state, "labelled");
  assert.equal(both.protected, true);
});

test("protected: an IRM-encrypted Office file (OLE, EncryptedPackage + DRMEncryptedDataSpace) is 'protected, label unknown'; password-encrypted is not", (t) => {
  const put = dir(t);
  const irm = readSensitivityLabels(put("irm.docx", cfb(["Root Entry", "EncryptedPackage", "\u0006DataSpaces", "DataSpaceMap", "DataSpaceInfo", "DRMEncryptedDataSpace", "TransformInfo", "DRMEncryptedTransform"])));
  assert.equal(irm.state, "protected");
  assert.deepEqual(irm.labels, []);
  assert.equal(readSensitivityLabels(put("bin.doc", cfb(["Root Entry", "\u0009DRMContent", "\u0006DataSpaces"]))).state, "protected");
  assert.equal(readSensitivityLabels(put("pw.docx", cfb(["Root Entry", "EncryptedPackage", "EncryptionInfo", "\u0006DataSpaces", "StrongEncryptionDataSpace"]))).state, "none");
  assert.equal(readSensitivityLabels(put("legacy.doc", cfb(["Root Entry", "WordDocument", "1Table"]))).state, "none");
});

test("fail safe: a malformed or oversized Office package is 'unreadable', a non-Office zip is not; nothing throws", (t) => {
  const put = dir(t);
  const good = docx({ custom: [HC] });
  assert.equal(readSensitivityLabels(put("trunc.docx", good.subarray(0, good.length - 30))).state, "unreadable", "no end-of-central-directory record");
  assert.equal(readSensitivityLabels(put("trunc.zip", good.subarray(0, good.length - 30))).state, "none", "not an Office candidate");
  const bad = Buffer.from(good); bad.writeUInt32LE(0xdeadbeef, good.length - 22 - 46 - "docProps/custom.xml".length); // corrupt the last central entry
  assert.equal(readSensitivityLabels(put("bad.docx", bad)).state, "unreadable");
  const tiny = { ...LABEL_CAPS, partBytes: 64 };
  const big = readSensitivityLabels(put("big.docx", good), { caps: tiny });
  assert.equal(big.state, "unreadable");
  assert.equal(big.why, "part-cap");
  assert.equal(readSensitivityLabels(put("dir.docx", good), { caps: { ...LABEL_CAPS, entries: 2 } }).why, "directory-cap");
  const enc = zip([{ name: "[Content_Types].xml", data: "<Types/>" }, { name: "docProps/custom.xml", data: "x", flags: 1 }]);
  assert.equal(readSensitivityLabels(put("enc.docx", enc)).why, "encrypted-entry");
  const brokenCfb = cfb(["Root Entry", "EncryptedPackage"]); brokenCfb.writeUInt16LE(7, 0x1e);
  assert.equal(readSensitivityLabels(put("cfb.docx", brokenCfb)).state, "unreadable");
  assert.equal(readSensitivityLabels(join(tmpdir(), "moorai-no-such-file.docx")).state, "none");
});

test("verdicts: matched by GUID and by name (case-insensitive), on read and on send; strictest wins; content-free finding", (t) => {
  const put = dir(t);
  const p = put("q.docx", docx({ custom: [HC] }));
  const hash = (s) => `h2:test(${s.length})`;
  // by GUID: block on send, notify on read
  const pol = byId({ onRead: "notify", onSend: "block" });
  const rd = decideSensitivityLabel(ENGINE, pol, p, "read", { hash });
  assert.equal(rd.decision, "allow");
  assert.equal(rd.findings.length, 1);
  const f = rd.findings[0];
  assert.equal(f.threatId, LABEL_THREAT);
  assert.equal(f.category, "Sensitivity-labelled file read by an AI agent");
  assert.deepEqual(f.sensitivityLabel, { state: "labelled", action: "read", verdict: "notify", labelId: LABEL_ID, labelNameHash: hash("label-name:highly confidential"), source: "custom" });
  assert.ok(!JSON.stringify(f.sensitivityLabel).includes("Highly"), "the label name is hashed");
  assert.ok(!JSON.stringify(f.sensitivityLabel).includes(p), "no path in the label fields");
  assert.equal(f.match, `label-path:${p}`, "the reporter's contentHash is the keyed hash of the path");
  const sd = decideSensitivityLabel(ENGINE, pol, p, "send", { hash });
  assert.equal(sd.decision, "deny");
  assert.equal(sd.findings[0].category, "Sensitivity-labelled file sent by an AI agent");
  assert.match(sd.reasons[0], /^#1 sensitivity label: your organization blocks AI agents sending it$/);
  assert.ok(sd.alternatives.length >= 1);
  // by name, case-insensitive: justify on read; no onSend = nothing on send
  const nm = byName("HIGHLY confidential", { onRead: "justify" });
  assert.equal(decideSensitivityLabel(ENGINE, nm, p, "read").decision, "ask");
  const none = decideSensitivityLabel(ENGINE, nm, p, "send");
  assert.equal(none.decision, "allow");
  assert.equal(none.findings.length, 0);
  // a rule for another label does nothing
  assert.equal(decideSensitivityLabel(ENGINE, { labelPolicy: { rules: [{ match: { id: OTHER_ID }, onRead: "block" }] } }, p, "read").findings.length, 0);
  // strictest of several matching rules
  const lp = labelPolicy({ labelPolicy: { rules: [{ match: { name: "highly confidential" }, onSend: "notify" }, { match: { id: LABEL_ID }, onSend: "justify" }] } });
  assert.equal(labelVerdict(lp, readSensitivityLabels(p), "send").verdict, "justify");
  // a disabled label and an unlabelled file never get a verdict
  for (const q of [put("off.docx", docx({ custom: [{ ...HC, enabled: false }] })), put("none.docx", docx())]) {
    const d = decideSensitivityLabel(ENGINE, byId({ onRead: "block", onSend: "block" }), q, "send");
    assert.equal(d.decision, "allow");
    assert.equal(d.findings.length, 0);
  }
});

test("verdicts: protected rule; unreadable sets unevaluated and decides nothing itself", (t) => {
  const put = dir(t);
  const irm = put("irm.xlsx", cfb(["Root Entry", "EncryptedPackage", "\u0006DataSpaces", "DRMEncryptedDataSpace"]));
  const pol = { labelPolicy: { protected: { onSend: "block" } } };
  const d = decideSensitivityLabel(ENGINE, pol, irm, "send");
  assert.equal(d.decision, "deny");
  assert.equal(d.findings[0].category, "Rights-protected file sent by an AI agent");
  assert.deepEqual(d.findings[0].sensitivityLabel, { state: "protected", action: "send", verdict: "block" });
  assert.equal(decideSensitivityLabel(ENGINE, pol, irm, "read").decision, "allow");
  const good = docx({ custom: [HC] });
  const u = decideSensitivityLabel(ENGINE, byId({ onRead: "notify" }), put("t.pptx", good.subarray(0, 100)), "read");
  assert.equal(u.unevaluated, true);
  assert.equal(u.decision, "allow");
  assert.equal(u.findings.length, 0);
});

test("MCP file arguments: an upload tool is a send, read_file a read; unevaluated propagates", (t) => {
  const put = dir(t);
  const p = put("deal.docx", docx({ custom: [HC] }));
  const pol = byId({ onRead: "justify", onSend: "block" });
  const up = scanMcpFileArgs(ENGINE, pol, { tool: "mcp__drive__upload_file", args: { path: p }, bases: [] });
  assert.equal(up.decision, "deny");
  assert.equal(up.files[0].findings.find((f) => f.threatId === 1).sensitivityLabel.action, "send");
  const rd = scanMcpFileArgs(ENGINE, pol, { tool: "mcp__fs__read_file", args: { path: p }, bases: [] });
  assert.equal(rd.decision, "ask");
  assert.equal(rd.files[0].findings.find((f) => f.threatId === 1).sensitivityLabel.action, "read");
  assert.equal(scanMcpFileArgs(ENGINE, null, { tool: "mcp__drive__upload_file", args: { path: p }, bases: [] }).decision, "allow", "no labelPolicy: unchanged");
  const bad = put("bad.docx", docx({ custom: [HC] }).subarray(0, 120));
  const u = scanMcpFileArgs(ENGINE, pol, { tool: "mcp__drive__upload_file", args: { path: bad }, bases: [] });
  assert.equal(u.unevaluated, true);
  assert.equal(u.decision, "allow");
});
