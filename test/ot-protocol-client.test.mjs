// OT protocol clients run from an agent shell (cli/ot-protocol-client.mjs, data/ot-protocol-clients.js):
// which protocol, read or write, the policy action, and that the alert is content-free.
// Per-file runner:  node --test --import ./test/hermetic-env.mjs test/ot-protocol-client.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { otShellFacts, otShellCheck, scriptReader, OT_PROTOCOL_CLIENT, OT_THREAT, OT_PROTOCOLS, OT_OPS } from "../cli/ot-protocol-client.mjs";
import { OT_BINARIES, OT_PY_LIBS, OT_NODE_LIBS } from "../data/ot-protocol-clients.js";
import { rmTree } from "./fs-cleanup.mjs";

const facts = (cmd, opts) => { const f = otShellFacts(cmd, opts); return f && { otProtocol: f.otProtocol, otOp: f.otOp }; };

test("the protocol and op enums are the contract's closed lists", () => {
  assert.deepEqual([...OT_PROTOCOLS].sort(), ["bacnet", "dnp3", "enip", "iec104", "modbus", "opcua", "s7"]);
  assert.deepEqual([...OT_OPS].sort(), ["read", "unknown", "write"]);
  assert.equal(OT_PROTOCOL_CLIENT, "OT_PROTOCOL_CLIENT");
  for (const b of Object.values(OT_BINARIES)) assert.ok(OT_PROTOCOLS.includes(b.protocol), b.protocol);
  for (const l of [...Object.values(OT_PY_LIBS), ...Object.values(OT_NODE_LIBS)]) assert.ok(OT_PROTOCOLS.includes(l.protocol), l.protocol);
});

test("mbpoll and modpoll: values after the host are a write, none is a read", () => {
  assert.deepEqual(facts("mbpoll -a 1 -t 4 -r 100 -c 2 10.20.0.5"), { otProtocol: "modbus", otOp: "read" });
  assert.deepEqual(facts("mbpoll -1 -a 1 -t 4 -r 100 10.20.0.5 1200"), { otProtocol: "modbus", otOp: "write" });
  assert.deepEqual(facts("mbpoll -m rtu -b 19200 -P none -a 3 -t 0 -r 7 /dev/ttyUSB0 1"), { otProtocol: "modbus", otOp: "write" });
  assert.deepEqual(facts("modpoll -m tcp -t 4:float -r 40001 -c 4 192.168.1.10"), { otProtocol: "modbus", otOp: "read" });
  assert.deepEqual(facts("modpoll -m tcp -r 40001 192.168.1.10 42 43"), { otProtocol: "modbus", otOp: "write" });
  assert.deepEqual(facts("/usr/local/bin/mbpoll -h"), { otProtocol: "modbus", otOp: "unknown" });
});

test("modbus-cli, OPC UA, BACnet and EtherNet/IP command-line tools", () => {
  assert.deepEqual(facts("modbus read 10.0.0.9 %MW100 10"), { otProtocol: "modbus", otOp: "read" });
  assert.deepEqual(facts("modbus write 10.0.0.9 %MW100 1 2 3"), { otProtocol: "modbus", otOp: "write" });
  assert.deepEqual(facts("uaread -u opc.tcp://plc:4840 -n 'ns=2;i=7'"), { otProtocol: "opcua", otOp: "read" });
  assert.deepEqual(facts("uawrite -u opc.tcp://plc:4840 -n 'ns=2;i=7' 55"), { otProtocol: "opcua", otOp: "write" });
  assert.deepEqual(facts("uacall -u opc.tcp://plc:4840 -n ns=2;i=1 -m ns=2;i=9"), { otProtocol: "opcua", otOp: "write" });
  assert.deepEqual(facts("bacrp 1234 analog-value 1 present-value"), { otProtocol: "bacnet", otOp: "read" });
  assert.deepEqual(facts("bacwp 1234 analog-value 1 present-value 16 -1 4 72.5"), { otProtocol: "bacnet", otOp: "write" });
  assert.deepEqual(facts("python3 -m cpppo.server.enip.client --address 10.1.1.4 'Motor_Speed=(INT)1500'"), { otProtocol: "enip", otOp: "write" });
  assert.deepEqual(facts("python3 -m cpppo.server.enip.client --address 10.1.1.4 Motor_Speed"), { otProtocol: "enip", otOp: "read" });
});

test("inline Python and Node code is read for the import and the call", () => {
  assert.deepEqual(facts(`python3 -c "from pymodbus.client import ModbusTcpClient; c=ModbusTcpClient('10.0.0.5'); c.connect(); c.write_register(10, 1500)"`), { otProtocol: "modbus", otOp: "write" });
  assert.deepEqual(facts(`python -c "import pymodbus.client as m; print(m.ModbusTcpClient('h').read_holding_registers(0, 4))"`), { otProtocol: "modbus", otOp: "read" });
  assert.deepEqual(facts(`python3 - <<'EOF'\nfrom asyncua.sync import Client\nwith Client('opc.tcp://plc:4840') as c:\n    c.get_node('ns=2;i=7').write_value(55)\nEOF`), { otProtocol: "opcua", otOp: "write" });
  assert.deepEqual(facts(`python3 -c "import snap7; p=snap7.client.Client(); p.connect('10.0.0.7',0,1); p.db_read(1,0,4)"`), { otProtocol: "s7", otOp: "read" });
  assert.deepEqual(facts(`python3 -c "import snap7; p=snap7.client.Client(); p.plc_stop()"`), { otProtocol: "s7", otOp: "write" });
  assert.deepEqual(facts(`python3 -c "import BAC0; b=BAC0.lite(); b.write('10.0.0.8 analogValue 1 presentValue 50')"`), { otProtocol: "bacnet", otOp: "write" });
  assert.deepEqual(facts(`python3 -c "from pycomm3 import LogixDriver; print(LogixDriver('10.0.0.4').read('Speed'))"`), { otProtocol: "enip", otOp: "read" });
  assert.deepEqual(facts(`python3 -c "from pydnp3 import opendnp3; master.DirectOperate(cmd, 0, cb)"`), { otProtocol: "dnp3", otOp: "write" });
  assert.deepEqual(facts(`python3 -c "import c104; client = c104.Client()"`), { otProtocol: "iec104", otOp: "unknown" });
  assert.deepEqual(facts(`node -e "const M=require('modbus-serial'); const c=new M(); c.connectTCP('10.0.0.5').then(()=>c.writeRegisters(5,[1,2]))"`), { otProtocol: "modbus", otOp: "write" });
  assert.deepEqual(facts(`node -e "const {OPCUAClient}=require('node-opcua'); s.read({nodeId})"`), { otProtocol: "opcua", otOp: "read" });
  assert.deepEqual(facts(`python3 -m pymodbus.console tcp --host 10.0.0.5`), { otProtocol: "modbus", otOp: "unknown" });
});

test("a script file the command runs is read (bounded) when a reader is given", () => {
  const dir = mkdtempSync(join(tmpdir(), "moorai-ot-"));
  try {
    mkdirSync(join(dir, "tools"));
    writeFileSync(join(dir, "tools", "setpoint.py"), "from pymodbus.client import ModbusTcpClient\nc = ModbusTcpClient('10.20.0.5')\nc.write_registers(100, [1, 2])\n");
    writeFileSync(join(dir, "poll.js"), "const ModbusRTU = require('modbus-serial');\nclient.readHoldingRegisters(0, 10);\n");
    writeFileSync(join(dir, "plain.py"), "print('hello')\n");
    const readScript = scriptReader(dir);
    assert.deepEqual(facts("python3 tools/setpoint.py --dry", { readScript }), { otProtocol: "modbus", otOp: "write" });
    assert.deepEqual(facts("python3 ./tools/setpoint.py", { readScript }), { otProtocol: "modbus", otOp: "write" });
    // A path outside the session directory is not read.
    assert.equal(facts("python3 ../outside.py", { readScript }), null);
    assert.deepEqual(facts("node poll.js", { readScript }), { otProtocol: "modbus", otOp: "read" });
    assert.equal(facts("python3 plain.py", { readScript }), null);
    assert.equal(facts("python3 missing.py", { readScript }), null);
    // No reader: a script path alone names no library.
    assert.equal(facts("python3 tools/setpoint.py"), null);
  } finally { rmTree(dir); }
});

test("silent on ordinary developer commands and on text that only mentions a client", () => {
  for (const cmd of [
    "pip install pymodbus",
    "npm install modbus-serial",
    "grep -r write_register src/",
    "cat docs/mbpoll.md",
    "echo mbpoll -t 4 -r 1 10.0.0.5 12",
    "git commit -m 'use pymodbus write_register'",
    "python3 -c \"print('pymodbus')\"",
    "ls -la && npm test",
    "man modpoll",
    "which uawrite"
  ]) assert.equal(otShellFacts(cmd), null, cmd);
});

test("wrappers and nested shells are followed", () => {
  assert.deepEqual(facts("sudo -u ops mbpoll -t 4 -r 1 10.0.0.5 12"), { otProtocol: "modbus", otOp: "write" });
  assert.deepEqual(facts("bash -c 'timeout 5 modpoll -r 1 10.0.0.5 7'"), { otProtocol: "modbus", otOp: "write" });
  assert.deepEqual(facts("cd /tmp; env FOO=1 uaread -u opc.tcp://h:4840 -n i=84"), { otProtocol: "opcua", otOp: "read" });
  // Several clients in one command: a write anywhere wins.
  assert.deepEqual(facts("mbpoll -1 -r 1 10.0.0.5 && uawrite -u opc.tcp://h -n i=9 1"), { otProtocol: "opcua", otOp: "write" });
});

test("policy action: built-in notify; threatPolicy decides read and write separately", () => {
  const w = "mbpoll -t 4 -r 1 10.20.0.5 1200";
  const r = "mbpoll -t 4 -r 1 10.20.0.5";
  assert.equal(otShellCheck({ command: "npm test", policy: {} }), null);
  let v = otShellCheck({ command: w, policy: {} });
  assert.equal(v.action, "notify");
  assert.equal(v.decision, "allow");
  assert.equal(v.alert.threatId, OT_THREAT.write);
  v = otShellCheck({ command: r, policy: null });
  assert.equal(v.action, "notify");
  assert.equal(v.alert.threatId, OT_THREAT.read);
  const preset = { threatPolicy: { [OT_THREAT.write]: "block", [OT_THREAT.read]: "notify" } };
  v = otShellCheck({ command: w, policy: preset });
  assert.equal(v.decision, "deny");
  assert.equal(v.alert.decision, "deny");
  assert.equal(v.alert.riskLevel, "Blocked");
  assert.match(v.reason, /OT protocol client \(modbus write\)/);
  v = otShellCheck({ command: r, policy: preset });
  assert.equal(v.decision, "allow");
  assert.equal(v.alert.decision, "notify");
  v = otShellCheck({ command: w, policy: { threatPolicy: { [OT_THREAT.write]: "justify" } } });
  assert.equal(v.decision, "ask");
  assert.equal(otShellCheck({ command: w, policy: { threatPolicy: { [OT_THREAT.write]: "disabled" } } }), null);
  // unknown follows the read threat (alert, not block, by the contract)
  v = otShellCheck({ command: "uaclient -u opc.tcp://h:4840", policy: preset });
  assert.equal(v.alert.otOp, "unknown");
  assert.equal(v.decision, "allow");
});

test("the alert is content-free: enums, a fixed hash token, no command, host or value", () => {
  const cmd = `python3 -c "from pymodbus.client import ModbusTcpClient; ModbusTcpClient('10.20.0.5').write_register(4242, 1500)"`;
  const v = otShellCheck({ command: cmd, policy: { threatPolicy: { [OT_THREAT.write]: "block" } }, tool: "Bash" });
  const a = v.alert;
  assert.equal(a.reasonCode, "OT_PROTOCOL_CLIENT");
  assert.equal(a.otProtocol, "modbus");
  assert.equal(a.otOp, "write");
  assert.equal(a.tool, "hook:Bash");
  assert.equal(a.contentHash, "ot:modbus:write");
  assert.deepEqual(Object.keys(a).sort(), ["category", "contentHash", "decision", "otOp", "otProtocol", "reasonCode", "riskLevel", "stage", "threatId", "tool"]);
  const s = JSON.stringify(v);
  for (const leak of ["10.20.0.5", "4242", "1500", "ModbusTcpClient", "python3"]) assert.ok(!s.includes(leak), leak);
});

test("PowerShell commands are read with the PowerShell grammar", () => {
  assert.deepEqual(facts("mbpoll.exe -t 4 -r 1 10.0.0.5 12", { shell: "ps" }), { otProtocol: "modbus", otOp: "write" });
  assert.deepEqual(facts(`python -c "import pymodbus; c.read_coils(0, 8)"`, { shell: "ps" }), { otProtocol: "modbus", otOp: "read" });
});
