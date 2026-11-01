// F13 wiring in the real hook (cli/moorai-hook.mjs): a PreToolUse that names a credential location is
// logged by class on an enrolled device, and the daily posture heartbeat carries `credentialExposure`
// fitted under the console's size cap. Throwaway HOME, local stand-in console.
//
//   node --test test/credential-exposure-hook.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { makeSandbox } from "../cli/doctor-sandbox.mjs";
import { rmTree } from "./fs-cleanup.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const HOOK = join(ROOT, "cli", "moorai-hook.mjs");
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function until(fn, ms = 10000) { const end = Date.now() + ms; while (Date.now() < end) { if (fn()) return true; await sleep(100); } return false; }

async function consoleStub(t) {
  const posts = [];
  const srv = createServer((req, res) => {
    let b = "";
    req.on("data", (c) => (b += c));
    req.on("end", () => {
      if (req.url === "/api/agent-posture") { posts.push({ size: Buffer.byteLength(b), body: JSON.parse(b) }); res.writeHead(201); return res.end("{}"); }
      res.writeHead(404); res.end("{}");
    });
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  t.after(() => srv.close());
  return { url: `http://127.0.0.1:${srv.address().port}`, posts };
}
function box(t, url, enrolled = true) {
  const empty = mkdtempSync(join(tmpdir(), "moorai-credexp-hook-"));
  const sb = makeSandbox({ realHome: empty, config: { serverUrl: url, tenant: "acme", ...(enrolled ? { installToken: "tok-test" } : {}) } });
  t.after(() => { sb.cleanup(); rmTree(empty); });
  mkdirSync(join(sb.home, ".aws"), { recursive: true });
  writeFileSync(join(sb.home, ".aws", "credentials"), "[prod]\naws_secret_access_key = SECRETVALUE123\n");
  const run = (ti, tool = "Read") => spawnSync(process.execPath, [HOOK], {
    input: JSON.stringify({ hook_event_name: "PreToolUse", tool_name: tool, tool_input: ti, session_id: "s-1", cwd: sb.proj }),
    env: sb.env(), encoding: "utf8", timeout: 20000
  });
  return { ...sb, run };
}

test("READ LOG: a PreToolUse Read of ~/.aws/credentials is logged by kind and scope on an enrolled device", async (t) => {
  const c = await consoleStub(t);
  const b = box(t, c.url);
  b.run({ file_path: join(b.home, ".aws", "credentials") });
  const file = join(b.home, ".moorai", "credential-exposure.jsonl");
  assert.ok(existsSync(file), "read log written");
  const e = readFileSync(file, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));
  assert.ok(e.some((x) => x.t === "r" && x.k === "aws" && x.sc === "home" && x.h === "claude-code"), JSON.stringify(e));
  const raw = readFileSync(file, "utf8");
  assert.ok(!raw.includes(b.home) && !raw.includes("SECRETVALUE"), raw);
});

test("READ LOG: an unenrolled device logs nothing", async (t) => {
  const c = await consoleStub(t);
  const b = box(t, c.url, false);
  b.run({ file_path: join(b.home, ".aws", "credentials") });
  assert.equal(existsSync(join(b.home, ".moorai", "credential-exposure.jsonl")), false);
});

test("HEARTBEAT: the posture beat carries credentialExposure v1, content-free, under the size cap", async (t) => {
  const c = await consoleStub(t);
  const b = box(t, c.url);
  b.run({ command: "ls" }, "Bash");
  assert.ok(await until(() => c.posts.length === 1), "heartbeat posted");
  const { body, size } = c.posts[0];
  assert.ok(size <= 15360, `heartbeat ${size} bytes`);
  const ce = body.credentialExposure;
  assert.ok(ce, "credentialExposure present");
  assert.equal(ce.v, 1);
  assert.equal(ce.coverage, "heuristic");
  const aws = ce.items.find((i) => i.kind === "aws" && i.locationClass === "home-config");
  assert.ok(aws && aws.reachable === true && aws.prodLike === true, JSON.stringify(ce.items));
  const raw = JSON.stringify(ce);
  assert.ok(!raw.includes(b.home) && !raw.includes("SECRETVALUE") && !raw.includes("[prod]"), raw);
});
