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
import { readSensitivityLabelsAt } from "../cli/sensitivity-labels.mjs";
import { docx, pdf, cfb, LABEL_ID } from "./fixtures/label-files.mjs";

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

// Encoded values not decoded whole (OUTBOUND_CAPS decodedBytes, decodedTotal) are unevaluated, whatever they are.
const LABEL_BLOCK = { labelPolicy: { rules: [{ match: { id: LABEL_ID }, onSend: "block" }] } };
const LABEL_NOTIFY = { labelPolicy: { rules: [{ match: { id: LABEL_ID }, onSend: "notify" }] } };
const HC = [{ id: LABEL_ID, name: "Highly Confidential" }];
const filler = (n) => { const b = Buffer.alloc(n); for (let i = 0; i < n; i++) b[i] = (i * 2654435761) >>> 24; return b; };
const BIG_DOC = () => docx({ custom: HC, extra: [{ name: "word/media/image1.bin", data: filler(1_200_000), store: true }] });
const MAGIC = { png: "89504e470d0a1a0a", jpeg: "ffd8ffe000104a464946", gif: "474946383961", gzip: "1f8b0800", elf: "7f454c46020101", macho: "cffaedfe" };
const ENDS = { png: "0000000049454e44ae426082", jpeg: "ffd9", gif: "3b", gzip: "", elf: "", macho: "" };
const image = (type, body) => Buffer.concat([Buffer.from(MAGIC[type], "hex"), body, Buffer.from(ENDS[type], "hex")]);
const CARDS = () => Buffer.from(CARD_FILE + "filler line of text\n".repeat(60_000));
// A character a lenient decoder skips, every `n` characters of the encoded value.
const junk = (s, n, ch) => s.replace(new RegExp(`(.{${n}})`, "g"), `$1${ch}`);

test("a value not decoded whole is unevaluated, whatever its type (an image too); the budget left is still scanned", () => {
  const block = { threatPolicy: { 90: "block" } };
  const big = gate(block, "mcp__drive__upload_file", { content: b64(CARDS().toString()) });
  assert.deepEqual([big.decision, big.unevaluated], ["deny", { why: "size", values: 1 }], "over decodedBytes: the card is in the budget scanned");
  assert.ok(ids(big).includes("90/dlp-payment-card"), ids(big).join(" "));
  const mid = b64("y".repeat(1_048_000));
  const total = gate(block, "mcp__drive__upload_file", { parts: [mid, mid, mid, mid, b64(CARD_FILE + "z".repeat(4000))] });
  assert.deepEqual([total.decision, total.unevaluated], ["deny", { why: "size", values: 1 }], "over decodedTotal: what is left of the budget is scanned");
  for (const type of Object.keys(MAGIC)) {
    const real = gate({}, "mcp__drive__upload_file", { content: image(type, filler(1_500_000)).toString("base64") });
    assert.deepEqual([real.decision, real.unevaluated], ["allow", { why: "size", values: 1 }], `a ${type} file over 1 MiB: unevaluated`);
    const fake = gate(block, "mcp__drive__upload_file", { content: Buffer.concat([Buffer.from(MAGIC[type], "hex"), CARDS()]).toString("base64") });
    assert.deepEqual([fake.decision, fake.unevaluated], ["deny", { why: "size", values: 1 }], `${type} magic in front of text`);
  }
  assert.deepEqual(gate({}, "mcp__drive__upload_file", { content: `data:image/png;base64,${image("png", filler(1_500_000)).toString("base64")}` }).unevaluated, { why: "size", values: 1 }, "a data: URI");
  assert.equal(gate({}, "mcp__drive__upload_file", { content: image("png", filler(900_000)).toString("base64") }).unevaluated, null, "an image decoded whole");
  assert.equal(gate({}, "mcp__drive__upload_file", { content: b64(CARD_FILE) }).unevaluated, null, "within the caps");
  const many = Array.from({ length: 40 }, (_, i) => b64(`note ${i} ` + "x".repeat(80)));
  assert.equal(gate({}, "mcp__drive__upload_file", { parts: many }).unevaluated, null, "no cap on the number of values");
  assert.equal(gate(block, "mcp__drive__upload_file", { parts: [...many, b64(CARD_FILE)] }).decision, "deny", "the forty-first value is scanned");
});

test("a ZIP, PDF or OLE file not decoded whole: its label is read in place, and its content is still unevaluated", () => {
  const doc = BIG_DOC();
  assert.ok(doc.length > 1_048_576);
  for (const content of [doc.toString("base64"), `data:application/vnd.openxmlformats-officedocument.wordprocessingml.document;base64,${doc.toString("base64")}`]) {
    const g = gate(LABEL_BLOCK, "mcp__drive__upload_file", { name: "board.docx", content });
    assert.equal(g.decision, "deny", ids(g).join(" "));
    assert.deepEqual(g.findings.find((f) => f.sensitivityLabel).sensitivityLabel.verdict, "block");
    assert.deepEqual(g.unevaluated, { why: "size", values: 1 });
  }
  const p = gate(LABEL_BLOCK, "mcp__drive__upload_file", { content: pdf({ info: HC, padding: 1_200_000 }).toString("base64") });
  assert.equal(p.decision, "deny", "a PDF's Info dictionary in its tail window");
  const ole = Buffer.concat([cfb(["Root Entry", "EncryptedPackage", "DRMEncryptedDataSpace"]), filler(1_100_000)]);
  const o = gate({ labelPolicy: { rules: [], protected: { onSend: "block" } } }, "mcp__drive__upload_file", { content: ole.toString("base64") });
  assert.equal(o.decision, "deny", "a rights-protected OLE file");
  const off = gate({}, "mcp__drive__upload_file", { content: doc.toString("base64") });
  assert.deepEqual([off.decision, off.unevaluated], ["allow", { why: "size", values: 1 }], "no labelPolicy: no label read, content unevaluated");
});

test("a label that could not be read: unevaluated (label); refused when a labelPolicy rule blocks sending; never lowers", () => {
  const broken = docx({ custom: HC }).subarray(0, 150).toString("base64");
  const b = gate(LABEL_BLOCK, "mcp__drive__upload_file", { name: "board.docx", content: broken });
  assert.deepEqual([b.decision, b.unevaluated], ["deny", { why: "label", values: 1 }]);
  const f = b.findings.find((x) => x.detectorId === "mcp-outbound-unevaluated");
  assert.deepEqual([f.threatId, f.match], [1, "unevaluated:label:1"], "content-free");
  assert.match(b.reason, /could not be label-checked/);
  const notify = gate(LABEL_NOTIFY, "mcp__drive__upload_file", { content: broken });
  assert.deepEqual([notify.decision, notify.unevaluated], ["allow", { why: "label", values: 1 }], "no block rule: the surface's fail mode decides");
  assert.equal(gate({}, "mcp__drive__upload_file", { content: broken }).unevaluated, null, "no labelPolicy: no label to establish");
  const nine = Array.from({ length: 9 }, () => docx().toString("base64"));
  assert.deepEqual(gate(LABEL_NOTIFY, "mcp__drive__upload_file", { parts: nine }).unevaluated, { why: "label", values: 1 }, "past labelReads");
  assert.equal(gate(LABEL_NOTIFY, "mcp__drive__upload_file", { parts: nine.slice(1) }).unevaluated, null, "within labelReads");
  const kept = gate({ ...LABEL_BLOCK, threatPolicy: { 90: "block" } }, "mcp__drive__upload_file", { parts: [b64(CARD_FILE), b64("y".repeat(1_100_000))] });
  assert.deepEqual([kept.decision, kept.unevaluated], ["deny", { why: "size", values: 1 }], "a deny stays a deny");
});

// Review: a value with characters outside the base64 alphabet was never taken for encoded, so a lenient
// decoder's reading of it was never scanned.
test("a value a lenient decoder reads past other characters is decoded the way Node and Python read it", () => {
  const block = { threatPolicy: { 90: "block" } };
  const clean = b64(CARD_FILE);
  assert.ok(!/[-_]/.test(clean));
  for (const ch of ["!", ".", "*", "é"]) {
    const v = junk(clean, 30, ch);
    assert.equal(Buffer.from(v, "base64").toString(), CARD_FILE, "Node's Buffer.from skips it");
    const g = gate(block, "mcp__drive__upload_file", { content: v });
    assert.deepEqual([g.decision, g.unevaluated], ["deny", null], `"${ch}" every 30 characters`);
    assert.ok(ids(g).includes("90/dlp-payment-card"), ids(g).join(" "));
  }
  const py = junk(clean, 30, "_");
  assert.notEqual(Buffer.from(py, "base64").toString(), CARD_FILE, "Node reads _ as base64url");
  assert.equal(gate(block, "mcp__drive__upload_file", { content: py }).decision, "deny", "Python's b64decode skips _ and -: that reading is scanned too");
  assert.equal(gate(block, "mcp__drive__upload_file", { content: `data:text/csv;base64,${junk(clean, 3, "~")}` }).decision, "deny", "a data: URI, whatever its other characters");
  assert.equal(gate(block, "mcp__drive__upload_file", { content: junk(clean, 3, "~") }).decision, "allow", "without the prefix, under 95% base64 characters is not taken for encoded");
  for (const [what, file] of [["PDF", pdf({ info: HC })], ["ZIP", docx({ custom: HC })]]) {
    const v = junk(file.toString("base64"), 40, "!");
    assert.ok(Buffer.from(v, "base64").equals(file));
    const g = gate(LABEL_BLOCK, "mcp__drive__upload_file", { content: v });
    assert.equal(g.decision, "deny", `a labelled ${what} with skipped characters, under onSend block: ${ids(g).join(" ")}`);
    assert.deepEqual(g.unevaluated, { why: "label", values: 1 });
    assert.deepEqual(gate(LABEL_NOTIFY, "mcp__drive__upload_file", { content: v }).unevaluated, { why: "label", values: 1 }, `${what}: its label is unevaluated`);
    assert.equal(gate(LABEL_NOTIFY, "mcp__drive__upload_file", { content: file.toString("base64") }).unevaluated, null, `${what} in one clean alphabet`);
    assert.equal(gate(LABEL_NOTIFY, "mcp__drive__upload_file", { content: file.toString("base64").replace(/(.{76})/g, "$1\r\n") }).unevaluated, null, `${what} with MIME line breaks`);
  }
});

// Review: every reading was cut at the first "=", as Node and Python up to 3.12 read it; GNU base64 -d decodes
// each run between "=" on its own and Python 3.14's b64decode drops a mid-value "=" and reads on, so content
// after "QQ==" went unscanned (measured: Node 22.23, Python 3.9/3.11/3.12/3.14, GNU coreutils 9.1).
test("an \"=\" before the end of a value: each run between \"=\" and the runs joined are scanned, so content after it is not hidden", () => {
  const block = { threatPolicy: { 90: "block" } };
  const after = `QQ==${b64(CARD_FILE)}`;
  assert.equal(Buffer.from(after, "base64").toString(), "A", "Node stops at the first \"=\"");
  const g = gate(block, "mcp__drive__upload_file", { content: after });
  assert.deepEqual([g.decision, g.unevaluated], ["deny", null], "a card number after a mid-value \"==\"");
  assert.ok(ids(g).includes("90/dlp-payment-card"), ids(g).join(" "));
  const clean = b64(CARD_FILE);
  const split = `${clean.slice(0, 2)}==${clean.slice(2)}`;
  assert.equal(Buffer.from(split.replace(/=/g, ""), "base64").toString(), CARD_FILE, "the runs joined: Python 3.14's reading");
  assert.equal(gate(block, "mcp__drive__upload_file", { content: split }).decision, "deny", "the runs joined");
  for (const [what, file] of [["PDF", pdf({ info: HC })], ["ZIP", docx({ custom: HC })]]) {
    const v = `QUI=${file.toString("base64")}`;
    const l = gate(LABEL_BLOCK, "mcp__drive__upload_file", { content: v });
    assert.deepEqual([l.decision, l.unevaluated], ["deny", { why: "label", values: 1 }], `a labelled ${what} after a mid-value "=" under onSend block: ${ids(l).join(" ")}`);
  }
  const past = gate(block, "mcp__drive__upload_file", { content: `QQ==${b64(CARDS().toString())}` });
  assert.deepEqual([past.decision, past.unevaluated], ["deny", { why: "size", values: 1 }], "past the caps: the run after the \"=\" is scanned within the budget");
  const bigPdf = gate(LABEL_BLOCK, "mcp__drive__upload_file", { content: `QUI=${pdf({ info: HC, padding: 1_200_000 }).toString("base64")}` });
  assert.deepEqual([bigPdf.decision, bigPdf.unevaluated], ["deny", { why: "label", values: 1 }], "past the caps: a labelled PDF after the \"=\" under onSend block");
  const pairs = ["card 4111 1111 1111 1111 exp 12/29\n", "1,Test Person,4111111111111111,ok\n"].map((t) => t.match(/.{1,2}/gs).map(b64).join(""));
  for (const v of pairs) {
    assert.match(v, /^(?:[A-Za-z0-9+/]{3}=)+/, "two bytes to a run, each with its padding");
    const r = gate(block, "mcp__drive__upload_file", { content: v });
    assert.deepEqual([r.decision, r.unevaluated], ["deny", null], `each run decoded on its own, one after another (GNU base64 -d's reading): ${ids(r).join(" ")}`);
  }
  const digests = Array.from({ length: 40 }, (_, i) => Buffer.alloc(32, i * 7 + 1).toString("base64")).join("\n");
  assert.equal(gate({}, "mcp__drive__upload_file", { content: digests }).unevaluated, null, "a list of 40 base64 digests, one per line");
  assert.deepEqual(gate({}, "mcp__drive__upload_file", { content: "1=".repeat(70) }).unevaluated, { why: "size", values: 1 }, "runs too short to decode: under half the bytes read");
  const padded = b64(`${CARD_FILE}x`);
  assert.match(padded, /^[^=]+={1,2}$/);
  for (const [what, v] of [["padding at the end", padded], ["MIME line breaks", b64(CARD_FILE.repeat(20)).replace(/(.{76})/g, "$1\r\n")]]) {
    const r = gate(block, "mcp__drive__upload_file", { content: v });
    assert.deepEqual([r.decision, r.unevaluated], ["deny", null], what);
    assert.equal(gate({}, "mcp__drive__upload_file", { content: v }).unevaluated, null, `${what}: evaluated`);
  }
});

test("past the caps, a labelled PDF whose decoding skips characters or mixes the two alphabets is refused under onSend block", () => {
  const big = pdf({ info: HC, padding: 1_200_000 }).toString("base64");
  const at = Math.floor(big.length / 8) * 4 + 1;
  const dot = `data:application/pdf;base64,${big.slice(0, at)}.${big.slice(at)}`;
  assert.ok(Buffer.from(dot.slice(dot.indexOf(",") + 1), "base64").equals(pdf({ info: HC, padding: 1_200_000 })), "a decoder that skips other characters gets the labelled PDF");
  const mixed = `${big.slice(0, 800_000).replace(/\+/g, "-").replace(/\//g, "_")}${big.slice(800_000)}`;
  for (const [what, content] of [["a skipped character", dot], ["both alphabets", mixed]]) {
    const g = gate(LABEL_BLOCK, "mcp__drive__upload_file", { content });
    assert.deepEqual([g.decision, g.unevaluated], ["deny", { why: "label", values: 1 }], what);
  }
  assert.deepEqual(gate({}, "mcp__drive__upload_file", { content: dot }).unevaluated, { why: "size", values: 1 }, "no labelPolicy");
});

test("the in-place label read: a ZIP, OLE or PDF by its magic with no structure where it was read is unreadable, whatever its name", () => {
  const reader = (b) => (p, l) => b.subarray(p, p + l);
  const noTrailer = Buffer.concat([Buffer.from("%PDF-1.7\n"), filler(1_200_000)]);
  const zipCut = docx({ custom: HC }).subarray(0, 150);
  const oleBad = Buffer.concat([cfb(["Root Entry"]).subarray(0, 0x1e), Buffer.from([7, 0]), filler(2000)]);
  for (const name of ["arg.pdf", "arg.docx", "arg.doc", "", "x.bin"]) {
    for (const [what, b] of [["pdf", noTrailer], ["zip", zipCut], ["ole", oleBad]]) {
      assert.equal(readSensitivityLabelsAt(reader(b), b.length, name).state, "unreadable", `${what} as "${name}"`);
    }
  }
  const good = pdf({ info: HC, padding: 1_200_000 });
  assert.equal(readSensitivityLabelsAt(reader(good), good.length, "arg.pdf").state, "labelled");
  const plain = pdf({ padding: 1000 });
  assert.equal(readSensitivityLabelsAt(reader(plain), plain.length, "arg.pdf").state, "none", "a PDF with its trailer and no label");
  const p = gate(LABEL_BLOCK, "mcp__drive__upload_file", { content: noTrailer.toString("base64") });
  assert.deepEqual([p.decision, p.unevaluated && p.unevaluated.why], ["deny", "label"], "past the caps, under onSend block: refused");
});
