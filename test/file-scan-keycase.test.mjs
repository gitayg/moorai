// Per-file runner:  node --test --import ./test/hermetic-env.mjs test/file-scan-keycase.test.mjs
//
// The cloud file scan (model-proxy/file-parts.mjs) reads a field the way a case-insensitive upstream does. Go's
// encoding/json, which Ollama is built on, matches an object key to a struct field ignoring case (Unicode simple
// folding: ſ is s, the Kelvin sign is k; ı and İ are not i). So {"Images": [...]}, messages[].IMAGES or
// {"Messages": ...} reach the model, and Ollama's /v1/responses decodes input_image's "type" / "image_url" the same
// way. Every file field is found under any key that folds to its name; two keys that fold to the same field are
// ambiguous (Go keeps the last one), which the proxy refuses in enforce mode, as it refuses a duplicate key.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { createProxy } from "../model-proxy/server.mjs";
import { fileParts } from "../model-proxy/file-parts.mjs";
import { startFakeProvider } from "../model-proxy/test/fake-provider.mjs";
import { request } from "../model-proxy/test/harness.mjs";
import { API, pathOf, answer } from "../model-proxy/test/text-fixtures.mjs";
import { startMetaDefender, sha256, TEST_KEY } from "./file-scan-fakes.mjs";

const BAD = Buffer.from("pretend-malicious-sample-bytes-0001");
const GOOD = Buffer.from("an ordinary harmless document body");
const b64 = (b) => b.toString("base64");
const found = (kind, body) => fileParts(kind, body).parts.map((p) => p.bytes.toString());

test("ollama: images / messages under any key Go's encoding/json folds to them are read", () => {
  for (const key of ["Images", "IMAGES", "iMaGeS", "imageſ"]) {
    assert.deepEqual(found("ollama", { model: "m", messages: [{ role: "user", content: "x", [key]: [b64(BAD)] }] }), [BAD.toString()], `messages[].${key}`);
    assert.deepEqual(found("ollama", { model: "m", prompt: "x", [key]: [b64(BAD)] }), [BAD.toString()], `top-level ${key}`);
  }
  for (const key of ["Messages", "MESSAGES", "meſſages"]) assert.deepEqual(found("ollama", { model: "m", [key]: [{ role: "user", images: [b64(BAD)] }] }), [BAD.toString()], key);
  // Not folded by Go (measured): dotless ı and dotted İ are not i.
  assert.deepEqual(found("ollama", { model: "m", messages: [{ role: "user", "ımages": [b64(BAD)] }] }), []);
});

test("any (the walk every body gets): an Ollama images array under a case variant is read too", () => {
  assert.deepEqual(found("any", { model: "m", messages: [{ role: "user", IMAGES: [b64(BAD)] }] }), [BAD.toString()]);
});

test("responses (Ollama decodes input parts with encoding/json): type / image_url / file_data under case variants are read", () => {
  assert.deepEqual(found("openai-responses", { model: "m", Input: [{ Role: "user", Content: [{ Type: "input_image", Image_URL: `data:image/png;base64,${b64(BAD)}` }] }] }), [BAD.toString()]);
  assert.deepEqual(found("any", { model: "m", input: [{ role: "user", content: [{ TYPE: "input_file", FILE_DATA: `data:application/pdf;base64,${b64(BAD)}` }] }] }), [BAD.toString()]);
});

test("two keys that fold to one file field are ambiguous (Go keeps the last; there is no safe choice)", () => {
  const r = fileParts("ollama", { model: "m", messages: [{ role: "user", images: [b64(GOOD)], Images: [b64(BAD)] }] });
  assert.ok(r.ambiguous.length > 0, JSON.stringify(r.ambiguous));
  assert.deepEqual(r.parts.map((p) => p.bytes.toString()).sort(), [BAD.toString(), GOOD.toString()].sort(), "both are still scanned");
  assert.ok(fileParts("any", { a: { images: [b64(GOOD)], IMAGES: [b64(BAD)] } }).ambiguous.length > 0);
  assert.equal(fileParts("ollama", { model: "m", messages: [{ role: "user", images: [b64(GOOD)] }] }).ambiguous.length, 0, "one spelling is not ambiguous");
});

let fp, md;
before(async () => {
  fp = await startFakeProvider();
  md = await startMetaDefender({ known: { [sha256(BAD)]: { result: 1, detected: 12, total: 30, threat: "Trojan.FakeFamily" }, [sha256(GOOD)]: { result: 0, detected: 0, total: 30 } } });
});
after(async () => { await fp?.close(); await md?.close(); });
const proxy = () => createProxy({
  port: 0, mode: "enforce", policy: { captureTier: "content-free", fileScan: { provider: "metadefender", mode: "hash" } }, systemConfig: null, env: {},
  routes: { "/ollama": fp.url }, fileScanKeys: { metadefender: TEST_KEY }, fileScanEndpoints: { metadefender: md.base }, fileScanPollMs: 5
});

test("proxy, enforce: a malicious image under messages[].Images is refused before it reaches Ollama", async () => {
  const px = await proxy();
  try {
    const n = fp.requests.length;
    answer(fp, API.ollamaChat, "Fine.", { stream: false });
    const body = { ...API.ollamaChat.body("sys", "x", false), messages: [{ role: "user", content: "what is in this picture?", Images: [b64(BAD)] }] };
    const r = await request(px.url, pathOf(API.ollamaChat, false), { body });
    assert.equal(r.status, 403, String(r.raw));
    assert.match(r.raw.toString(), /malicious file/);
    assert.equal(fp.requests.length, n, "the file reached the upstream");
    answer(fp, API.ollamaGenerate, "Fine.", { stream: false });
    const g = await request(px.url, pathOf(API.ollamaGenerate, false), { body: { ...API.ollamaGenerate.body("sys", "what is this?", false), IMAGES: [b64(BAD)] } });
    assert.equal(g.status, 403, String(g.raw));
    assert.equal(fp.requests.length, n, "generate: the file reached the upstream");
  } finally { await px.close(); }
});
