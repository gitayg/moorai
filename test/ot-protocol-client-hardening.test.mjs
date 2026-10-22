// The OT protocol client check (cli/ot-protocol-client.mjs) against the ways a command can carry a client the
// first parser did not read: nested scripts (-EncodedCommand, a bare PowerShell argument, cmd /c, eval / iex,
// find -exec), grouped Python options, Node's --eval= / -pe / --require, scripts larger than the old read
// cap, decoded scripts the hook passes in, and the policy action resolved like every other threat.
// Per-file runner:  node --test --import ./test/hermetic-env.mjs test/ot-protocol-client-hardening.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { otShellFacts, otShellCheck, scriptReader, OT_THREAT } from "../cli/ot-protocol-client.mjs";
import { rmTree } from "./fs-cleanup.mjs";

const facts = (cmd, opts) => { const f = otShellFacts(cmd, opts); return f && { otProtocol: f.otProtocol, otOp: f.otOp }; };
const WRITE = { otProtocol: "modbus", otOp: "write" };
const MB_WRITE = "mbpoll -t 4 -r 1 10.0.0.5 12";
const enc = (s) => Buffer.from(s, "utf16le").toString("base64");

test("PowerShell -EncodedCommand in every accepted spelling is decoded and read", () => {
  for (const flag of ["-EncodedCommand", "-enc", "-ec", "-e", "-encodedc", "-EnCoDeD", "/enc", "--encodedcommand"]) {
    assert.deepEqual(facts(`powershell -NoProfile ${flag} ${enc(MB_WRITE)}`), WRITE, flag);
    assert.deepEqual(facts(`pwsh.exe ${flag} ${enc(MB_WRITE)}`, { shell: "ps" }), WRITE, `ps ${flag}`);
  }
});

test("PowerShell -Command: any prefix of the parameter, -CommandWithArgs, and a bare script argument", () => {
  for (const flag of ["-c", "-co", "-com", "-comm", "-comma", "-comman", "-command", "-Command", "/command", "--command", "-cwa", "-CommandWithArgs"]) {
    assert.deepEqual(facts(`pwsh -NoLogo ${flag} "${MB_WRITE}"`), WRITE, flag);
  }
  assert.deepEqual(facts(`powershell "${MB_WRITE}"`), WRITE);
  assert.deepEqual(facts(`powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden "${MB_WRITE}"`), WRITE);
});

test("cmd /c and /k, eval, Invoke-Expression and find -exec are followed", () => {
  assert.deepEqual(facts(`cmd /c ${MB_WRITE}`), WRITE);
  assert.deepEqual(facts(`cmd.exe /s /k "${MB_WRITE}"`), WRITE);
  assert.deepEqual(facts(`cmd /C ${MB_WRITE}`, { shell: "ps" }), WRITE);
  assert.deepEqual(facts(`eval "${MB_WRITE}"`), WRITE);
  assert.deepEqual(facts(`iex '${MB_WRITE}'`, { shell: "ps" }), WRITE);
  assert.deepEqual(facts(`Invoke-Expression '${MB_WRITE}'`, { shell: "ps" }), WRITE);
  assert.deepEqual(facts(`find . -name '*.cfg' -exec ${MB_WRITE} \\;`), WRITE);
  assert.deepEqual(facts(`find /srv -type f -execdir uawrite -u opc.tcp://h -n i=9 {} +`), { otProtocol: "opcua", otOp: "write" });
  assert.equal(facts("find . -name '*.py' -exec grep -l pymodbus {} +"), null);
  assert.equal(facts("cmd /c dir"), null);
});

test("Python: grouped short options are parsed character by character, -m included", () => {
  const code = "import pymodbus; c.write_register(1, 2)";
  assert.deepEqual(facts(`python3 -Ic "${code}"`), WRITE);
  assert.deepEqual(facts(`python3 -IBsc "${code}"`), WRITE);
  assert.deepEqual(facts(`python3 -I -c "${code}"`), WRITE);
  assert.deepEqual(facts(`python3 '-Icimport pymodbus; c.write_register(1, 2)'`), WRITE);
  assert.deepEqual(facts(`python3 -X dev -Wignore -OO -c "${code}"`), WRITE);
  assert.deepEqual(facts(`python3 --check-hash-based-pycs always -c "${code}"`), WRITE);
  assert.deepEqual(facts("python3 -Im pymodbus.console tcp --host 10.0.0.5"), { otProtocol: "modbus", otOp: "unknown" });
  assert.deepEqual(facts("python3 -mpymodbus.console tcp"), { otProtocol: "modbus", otOp: "unknown" });
  assert.deepEqual(facts("python3 -Im cpppo.server.enip.client --address 10.1.1.4 'Speed=(INT)1'"), { otProtocol: "enip", otOp: "write" });
  assert.equal(facts(`python3 -Ic "print('hello')"`), null);
  assert.equal(facts("python3 -Im http.server 8000"), null);
});

test("Python: arguments that cannot be parsed fail closed to a scan of every argument", () => {
  assert.deepEqual(facts(`python3 -Zc "import pymodbus; c.write_register(1, 2)"`), WRITE);
  assert.deepEqual(facts("python3 -Zm pymodbus.console"), { otProtocol: "modbus", otOp: "unknown" });
  assert.deepEqual(facts(`python3 --frobnicate=1 "import pymodbus; c.write_register(1, 2)"`), WRITE);
  assert.equal(facts(`python3 -Zc "print(1)"`), null);
});

test("Node: --eval= / --print=, combined short flags ending in e or p, and preloaded modules", () => {
  assert.deepEqual(facts(`node --eval="require('modbus-serial'); c.writeRegister(1, 2)"`), WRITE);
  assert.deepEqual(facts(`node --print="require('modbus-serial'); c.writeRegister(1, 2)"`), WRITE);
  assert.deepEqual(facts(`node -pe "require('node-opcua'); s.read(x)"`), { otProtocol: "opcua", otOp: "read" });
  assert.deepEqual(facts(`node -ie "require('jsmodbus'); c.writeCoil(1, true)"`), WRITE);
  assert.deepEqual(facts(`bun --eval="require('modbus-serial'); c.writeRegister(1, 2)"`), WRITE);
  for (const pre of ["-r modbus-serial", "--require jsmodbus", "--require=node-opcua", "--import node-opcua/client", "--import=st-ethernet-ip", "--loader=node-snap7"]) {
    const f = facts(`node ${pre} app.js`);
    assert.ok(f, pre);
    assert.equal(f.otOp, "unknown", pre);
  }
  assert.equal(facts("node -r dotenv/config app.js"), null);
  assert.equal(facts("node --import=tsx ./src/main.ts"), null);
  assert.equal(facts(`node -pe "process.version"`), null);
});

test("a script larger than the old read cap is read whole, and a very large one is never treated as clean", () => {
  const dir = mkdtempSync(join(tmpdir(), "moorai-ot-big-"));
  try {
    const pad = (n) => "# " + "x".repeat(n) + "\n";
    writeFileSync(join(dir, "mid.py"), "import pymodbus\n" + pad(80 * 1024) + "c.write_register(1, 2)\n");
    writeFileSync(join(dir, "large.py"), "import pymodbus\n" + pad(1536 * 1024) + "c.write_register(1, 2)\n");
    writeFileSync(join(dir, "huge.py"), "import pymodbus\n" + pad(9 * 1024 * 1024) + "c.read_coils(0, 1)\n");
    writeFileSync(join(dir, "huge-plain.py"), pad(9 * 1024 * 1024) + "print('ok')\n");
    const readScript = scriptReader(dir);
    assert.deepEqual(facts("python3 mid.py", { readScript }), WRITE);
    assert.deepEqual(facts("python3 large.py", { readScript }), WRITE);
    // Past the in-memory limit: the library is still named, the op is unknown, and the verdict takes the
    // stricter of the read and write actions because the write could sit in the unread part.
    const f = otShellFacts("python3 huge.py", { readScript });
    assert.equal(f.otProtocol, "modbus");
    assert.equal(f.incomplete, true);
    const preset = { threatPolicy: { [OT_THREAT.write]: "block", [OT_THREAT.read]: "notify" } };
    const v = otShellCheck({ command: "python3 huge.py", policy: preset, readScript });
    assert.equal(v.decision, "deny");
    assert.equal(v.alert.otOp, "unknown");
    assert.equal(facts("python3 huge-plain.py", { readScript }), null);
  } finally { rmTree(dir); }
});

test("decoded and embedded scripts the hook passes are checked too, and the strictest result is kept", () => {
  const preset = { threatPolicy: { [OT_THREAT.write]: "block", [OT_THREAT.read]: "notify" } };
  const v = otShellCheck({ command: "echo bWJwb2xs | base64 -d | sh", scripts: [{ text: MB_WRITE, shell: "sh" }], policy: preset });
  assert.ok(v);
  assert.equal(v.decision, "deny");
  assert.equal(v.otOp, "write");
  const r = otShellCheck({ command: "mbpoll -t 4 -r 1 10.0.0.5", scripts: [{ text: `uawrite -u opc.tcp://h -n i=9 1`, shell: "ps" }], policy: preset });
  assert.equal(r.otOp, "write");
  assert.equal(r.otProtocol, "opcua");
  assert.equal(otShellCheck({ command: "ls", scripts: [{ text: "echo hi", shell: "sh" }], policy: preset }), null);
});

test("the policy action resolves like every other threat: kill denies and ends the session, an unknown action fails closed", () => {
  const w = "mbpoll -t 4 -r 1 10.20.0.5 1200";
  let v = otShellCheck({ command: w, policy: { threatPolicy: { [OT_THREAT.write]: "kill" } } });
  assert.equal(v.decision, "deny");
  assert.equal(v.kill, true);
  assert.deepEqual(v.killIds, [OT_THREAT.write]);
  assert.equal(v.alert.decision, "deny");
  assert.equal(v.alert.riskLevel, "Blocked");
  v = otShellCheck({ command: w, policy: { threatPolicy: { [OT_THREAT.write]: "blokc" } } });
  assert.equal(v.decision, "deny");
  assert.equal(v.kill, false);
  v = otShellCheck({ command: w, policy: { threatPolicy: { [OT_THREAT.write]: "mask" }, maskFallback: "justify" } });
  assert.equal(v.decision, "ask");
  v = otShellCheck({ command: w, policy: {} });
  assert.equal(v.decision, "allow");
  assert.equal(v.kill, false);
});
