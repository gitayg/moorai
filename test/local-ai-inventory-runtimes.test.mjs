// Local model runtimes in the AIBOM (cli/local-ai-inventory.mjs): one fixture per runtime for
// RUNNING detection (process name / distinctive port) with its listening class, INSTALLED detection
// from existence checks only, backward compatibility with cli/aibom-runtime.mjs's four runtimes, the
// content-free contract, and the moorai-aibom CLI end to end.
//
//   node --test test/local-ai-inventory-runtimes.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import { LOCAL_AI_RUNTIMES, runningRuntimes, installedRuntimes, plistVersion, localAiInventory } from "../cli/local-ai-inventory.mjs";
import { RUNTIMES, localRuntimes } from "../cli/aibom-runtime.mjs";
import { rmTree } from "./fs-cleanup.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const AIBOM = join(ROOT, "cli", "moorai-aibom.mjs");
const L = (proc, port, bind = "loopback") => ({ pid: null, proc, port, bind });
const one = (listeners, processes = []) => runningRuntimes({ listeners, processes });
const only = (rt) => rt.map(({ runtime, ports, listening, detectedBy }) => ({ runtime, ports, listening, detectedBy }));

// [runtime, listeners, processes, expected { ports, listening, detectedBy }]
const RUNNING = [
  ["ollama", [L("ollama", 11434)], ["ollama"], { ports: [11434], listening: "loopback", detectedBy: ["process", "port"] }],
  ["lmstudio", [L("llmster", 1234, "network")], [], { ports: [1234], listening: "network", detectedBy: ["process"] }],
  ["llama.cpp", [L("llama-server", 8080, "network")], [], { ports: [8080], listening: "network", detectedBy: ["process"] }],
  ["llamafile", [L("qwen3.5-0.8b-q8_0.llamafile", 8080)], [], { ports: [8080], listening: "loopback", detectedBy: ["process"] }],
  ["vllm", [L("vllm", 8000, "network")], ["vllm"], { ports: [8000], listening: "network", detectedBy: ["process"] }],
  ["localai", [L("local-ai", 8080)], [], { ports: [8080], listening: "loopback", detectedBy: ["process"] }],
  ["jan", [L("jan", 1337)], ["jan"], { ports: [1337], listening: "loopback", detectedBy: ["process"] }],
  ["gpt4all", [L("", 4891)], [], { ports: [4891], listening: "loopback", detectedBy: ["port"] }],
  ["koboldcpp", [L("koboldcpp-linux-x64", 5001, "network")], [], { ports: [5001], listening: "network", detectedBy: ["process"] }],
  ["foundry-local", [L("inference.service.agent", 5273)], [], { ports: [5273], listening: "loopback", detectedBy: ["process"] }],
  ["docker-model-runner", [L("com.docker.backend", 12434, "network")], [], { ports: [12434], listening: "network", detectedBy: ["port"] }],
  ["winml-server", [L("winmlserver", 8080)], [], { ports: [8080], listening: "loopback", detectedBy: ["process"] }]
];

for (const [runtime, listeners, processes, want] of RUNNING) {
  test(`running: ${runtime} is detected with its ports and listening class`, () => {
    assert.deepEqual(only(one(listeners, processes)), [{ runtime, ...want }]);
  });
}

test("running: generic default ports never count without the process name", () => {
  const generic = [L("node", 8080, "network"), L("python3", 8000), L("python3", 5001), L("node", 1337), L("node", 1234), L("python", 7860), L("python", 5000)];
  assert.deepEqual(one(generic, ["node", "python3", "python"]), []);
});

test("running: listening is 'none' for a process with no socket, null when sockets could not be read", () => {
  assert.deepEqual(only(one([], ["lms"])), [{ runtime: "lmstudio", ports: [], listening: "none", detectedBy: ["process"] }]);
  const r = runningRuntimes({ listeners: null, processes: ["ollama"] });
  assert.equal(r[0].listening, null);
  assert.equal(r[0].bind, "unknown");
});

test("running: one network-bound listener makes the runtime network even if others are loopback", () => {
  const r = one([L("ollama", 11434), L("ollama", 11435, "network")]);
  assert.equal(r[0].listening, "network");
  assert.equal(r[0].bind, "network");
});

test("backward compatible: the four aibom-runtime.mjs runtimes keep their ids and give the same records", () => {
  for (const old of RUNTIMES) {
    const neu = LOCAL_AI_RUNTIMES.find((r) => r.runtime === old.runtime);
    assert.ok(neu, old.runtime);
    for (const n of old.names) assert.ok(neu.names.includes(n), `${old.runtime} keeps name ${n}`);
    assert.equal(neu.portAlone, old.portAlone, `${old.runtime} portAlone`);
    if (old.portAlone) assert.deepEqual(neu.ports, old.ports);
  }
  const listeners = [L("ollama", 11434), L("lm studio", 1234), L("llama-server", 8080, "network"), L("node", 8000), L("com.docker.backend", 11434)];
  const processes = ["ollama", "lm studio", "llama-server", "node"];
  const strip = (r) => { const { listening, ...rest } = r; return rest; };
  assert.deepEqual(runningRuntimes({ listeners, processes }).map(strip), localRuntimes({ listeners, processes }));
});

test("content-free: a llamafile's model name, a path and any address never reach the record", () => {
  const rec = JSON.stringify(one([{ pid: "1", proc: "secret-finance-model-q4.llamafile", port: 8080, bind: "network" }]));
  assert.match(rec, /"runtime":"llamafile"/);
  assert.doesNotMatch(rec, /secret|finance|q4|192\.168|\//i);
});

// ---- installed ----
const fakeFs = (paths) => { const set = new Set(paths); return (p) => set.has(p.replace(/\\/g, "/")); };

test("installed: PATH binaries, macOS apps with Info.plist version, CLI plugin, install dir — class only", () => {
  const home = "/Users/dev";
  const exists = fakeFs([
    "/opt/homebrew/bin/llama-server", "/custom/bin/llamafile", "/custom/bin/local-ai", "/custom/bin/vllm", "/custom/bin/koboldcpp", "/custom/bin/foundry",
    "/Applications/LM Studio.app", "/Users/dev/Applications/Jan.app", "/Applications/Ollama.app", "/Applications/gpt4all/bin/gpt4all.app",
    "/Users/dev/.docker/cli-plugins/docker-model", "/Users/dev/text-generation-webui/server.py"
  ]);
  const plist = (v) => `<?xml version="1.0"?><plist><dict><key>CFBundleShortVersionString</key>\n<string>${v}</string></dict></plist>`;
  const readFile = (p) => {
    if (p === "/Applications/LM Studio.app/Contents/Info.plist") return plist("0.3.30");
    if (p === "/Applications/Ollama.app/Contents/Info.plist") return "bplist00\u0000binary";
    throw new Error("ENOENT");
  };
  const got = installedRuntimes({ platform: "darwin", env: { PATH: "/custom/bin:/usr/bin" }, home, exists, readFile });
  const by = Object.fromEntries(got.map((r) => [r.runtime, r]));
  assert.deepEqual(by["llama.cpp"], { runtime: "llama.cpp", via: ["path"], version: null }, "brew dir searched even off PATH");
  assert.deepEqual(by.lmstudio, { runtime: "lmstudio", via: ["app"], version: "0.3.30" });
  assert.deepEqual(by.ollama, { runtime: "ollama", via: ["app"], version: null }, "binary plist → no version, no throw");
  assert.deepEqual(by.jan, { runtime: "jan", via: ["app"], version: null });
  assert.deepEqual(by.gpt4all, { runtime: "gpt4all", via: ["app"], version: null });
  assert.deepEqual(by["docker-model-runner"], { runtime: "docker-model-runner", via: ["cli-plugin"], version: null });
  assert.deepEqual(by["text-generation-webui"], { runtime: "text-generation-webui", via: ["install-dir"], version: null });
  for (const r of ["llamafile", "localai", "vllm", "koboldcpp", "foundry-local"]) assert.deepEqual(by[r]?.via, ["path"], r);
  assert.equal(by["winml-server"], undefined, "WinMLServer is Windows-only");
  assert.doesNotMatch(JSON.stringify(got), /\/(Users|Applications|opt|custom)/, "no path is ever output");
});

test("installed: Windows — .exe on PATH, per-user install dirs, WinMLServer", () => {
  const exists = fakeFs(["C:/tools/llama-server.exe", "C:/tools/WinMLServer.exe", "C:/Users/dev/AppData/Local/Programs/Ollama/ollama.exe", "C:/Users/dev/.lmstudio/bin/lms.exe"]);
  const got = installedRuntimes({ platform: "win32", env: { Path: "C:/tools;C:/Windows" }, home: "C:/Users/dev", exists, readFile: () => { throw new Error("x"); } });
  assert.deepEqual(got.map((r) => [r.runtime, r.via]), [["ollama", ["app"]], ["lmstudio", ["path"]], ["llama.cpp", ["path"]], ["winml-server", ["path"]]]);
});

test("installed: plist version must look like a version", () => {
  assert.equal(plistVersion("<key>CFBundleShortVersionString</key><string>1.2.3-beta.1</string>"), "1.2.3-beta.1");
  assert.equal(plistVersion("<key>CFBundleShortVersionString</key><string>/Users/x/evil</string>"), null);
});

test("fail-open: every probe failing gives empty runtimes, no throw, status unavailable", () => {
  const inv = localAiInventory({ runner: () => null, platform: "linux", env: {}, home: "/nohome", exists: () => { throw new Error("boom"); }, readFile: () => { throw new Error("boom"); } });
  assert.deepEqual(inv.runtimes, []);
  assert.deepEqual(inv.installed, []);
  assert.equal(inv.windowsAi, null);
  assert.equal(inv.status, "unavailable");
});

// ---- CLI end to end ----
const LSOF = [
  "COMMAND   PID USER FD TYPE DEVICE SIZE/OFF NODE NAME",
  "ollama    2463 dev 4u IPv4 0x1 0t0 TCP 127.0.0.1:11434 (LISTEN)",
  "Qwen3.5-0.8B-Q8_ 7500 dev 6u IPv4 0x5 0t0 TCP *:8080 (LISTEN)",
  "Jan       7300 dev 9u IPv6 0x3 0t0 TCP [::1]:1337 (LISTEN)",
  ""
].join("\n");
const PS = "  2463 /opt/homebrew/bin/ollama\n  7500 /Users/dev/models/Qwen3.5-0.8B-Q8_0.llamafile\n  7300 /Applications/Jan.app/Contents/MacOS/Jan\n";

test("CLI: running + installed runtimes reach the AIBOM JSON and Markdown; nothing path-like leaks", () => {
  const home = mkdtempSync(join(tmpdir(), "moorai-localai-"));
  try {
    const bin = join(home, "bin-on-path");
    mkdirSync(bin);
    writeFileSync(join(bin, "llama-cli"), "");
    const fixture = join(home, "probe.json");
    writeFileSync(fixture, JSON.stringify({ lsof: LSOF, ps: PS }));
    const env = { ...process.env, HOME: home, USERPROFILE: home, PATH: `${bin}:${process.env.PATH}`, MOORAI_AIBOM_PROBE_FIXTURE: fixture, MOORAI_AIBOM_PLATFORM: "darwin" };
    delete env.MOORAI_AIBOM_JSON;
    const out = execFileSync(process.execPath, [AIBOM], { env, encoding: "utf8" });
    const d = JSON.parse(out);
    const by = Object.fromEntries(d.localRuntimes.map((r) => [r.runtime, r]));
    assert.equal(by.llamafile.listening, "network");
    assert.deepEqual(by.llamafile.ports, [8080]);
    assert.equal(by.jan.listening, "loopback");
    assert.equal(by.ollama.listening, "loopback");
    assert.equal(d.summary.networkLocalRuntimes, 1);
    assert.equal(d.summary.runningLocalRuntimes, d.localRuntimes.length);
    assert.ok(d.localRuntimesInstalled.some((r) => r.runtime === "llama.cpp" && r.via.includes("path")));
    assert.equal(d.summary.installedLocalRuntimes, d.localRuntimesInstalled.length);
    assert.equal(d.windowsAi, undefined, "no Windows block off Windows");
    assert.ok(!out.includes("bin-on-path") && !out.includes("Qwen3.5") && !out.includes("qwen3.5"), "no path or model name leaked");
    const md = execFileSync(process.execPath, [AIBOM, "--format", "md"], { env, encoding: "utf8" });
    assert.match(md, /## Installed local model runtimes/);
    assert.match(md, /\| llamafile \| 8080 \| network \|/);
  } finally { rmTree(home); }
});

test("CLI: on Windows the AIBOM carries the Windows AI platform block", () => {
  const home = mkdtempSync(join(tmpdir(), "moorai-localai-win-"));
  try {
    const fixture = join(home, "probe.json");
    writeFileSync(fixture, JSON.stringify({
      netstat: "  TCP    0.0.0.0:8080           0.0.0.0:0              LISTENING       4200\r\n",
      tasklist: '"WinMLServer.exe","4200","Console","1","90,000 K"\r\n',
      powershell: JSON.stringify({ p: [{ n: "Microsoft.WindowsAppRuntime.1.8", v: "8000.616.304.0" }, { n: "MicrosoftCorporationII.WinML.Qualcomm.QNN.EP.1.8", v: "1.8.27.0" }], g: [{ n: "Qualcomm(R) Adreno(TM) X1-85 GPU", m: "Qualcomm" }], a: [{ n: "Snapdragon(R) X Elite - X1E78100 - Qualcomm(R) Hexagon(TM) NPU", m: "Qualcomm" }] })
    }));
    const env = { ...process.env, HOME: home, USERPROFILE: home, MOORAI_AIBOM_PROBE_FIXTURE: fixture, MOORAI_AIBOM_PLATFORM: "win32" };
    delete env.MOORAI_AIBOM_JSON;
    const out = execFileSync(process.execPath, [AIBOM], { env, encoding: "utf8" });
    const d = JSON.parse(out);
    assert.deepEqual(d.localRuntimes.find((r) => r.runtime === "winml-server"), { runtime: "winml-server", running: true, ports: [8080], bind: "network", listening: "network", detectedBy: ["process"] });
    assert.deepEqual(d.windowsAi.appSdkRuntime, [{ name: "Microsoft.WindowsAppRuntime.1.8", version: "8000.616.304.0" }]);
    assert.deepEqual(d.windowsAi.windowsMlEps, [{ name: "MicrosoftCorporationII.WinML.Qualcomm.QNN.EP.1.8", version: "1.8.27.0", ep: "QNN" }]);
    assert.deepEqual(d.windowsAi.npu, { present: true, count: 1, vendors: ["qualcomm"] });
    assert.ok(!out.includes("X1E78100") && !out.includes("Adreno"), "device friendly names are classified, never emitted");
  } finally { rmTree(home); }
});
