// Local model servers reachable without MoorAI (cli/local-model-exposure.mjs) and the TCP table that feeds
// it (cli/local-ai-inventory.mjs tcpTable). The socket readers and the connect probe are injected, so the
// verdicts do not depend on what this machine runs; one test uses a real loopback listener for the probe.
//
//   node --test test/local-model-exposure.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:net";
import { mkdtempSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parseLsofTcp, parseNetstatTcp, parseProcTcp, procSocketOwners, tcpTable, bindClass, procHexAddr } from "../cli/local-ai-inventory.mjs";
import { localModelServers, exposureAlerts, tcpReachable, EXPOSURE_REASON, EXPOSURE_CATEGORY } from "../cli/local-model-exposure.mjs";
import { inventoryPosture } from "../cli/agent-posture.mjs";
import { rmTree } from "./fs-cleanup.mjs";

const LSOF = `COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
ollama 40155 u 3u IPv4 0x6 0t0 TCP 127.0.0.1:11434 (LISTEN)
llama-server 501 u 3u IPv4 0x6 0t0 TCP *:8080 (LISTEN)
llama-server 501 u 4u IPv6 0x6 0t0 TCP [::1]:8080 (LISTEN)
LM\\x20Studio 77 u 9u IPv4 0x6 0t0 TCP 192.168.1.78:1234 (LISTEN)
koboldcpp 88 u 9u IPv4 0x6 0t0 TCP 127.0.0.1:5001 (LISTEN)
rapportd 1014 u 11u IPv4 0x6 0t0 TCP *:64608 (LISTEN)
claude 23963 u 30u IPv4 0x4 0t0 TCP 192.168.1.78:64608->160.79.104.10:443 (ESTABLISHED)
Google\\x20Chrome\\x20Helper 9 u 30u IPv6 0x4 0t0 TCP [2001:db8::2]:5000->[2607:6bc0::10]:443 (ESTABLISHED)
curl 10 u 3u IPv4 0x4 0t0 TCP 10.0.0.2:5000->1.2.3.4:443 (SYN_SENT)
`;
const never = async () => false, always = async () => true;

test("bindClass: loopback, all-interfaces, lan", () => {
  assert.equal(bindClass("127.0.0.1"), "loopback");
  assert.equal(bindClass("[::1]"), "loopback");
  assert.equal(bindClass("::ffff:127.0.0.1"), "loopback");
  for (const h of ["*", "0.0.0.0", "::", "[::]"]) assert.equal(bindClass(h), "all-interfaces", h);
  for (const h of ["192.168.1.78", "10.0.0.5", "fe80::1%en0"]) assert.equal(bindClass(h), "lan", h);
});

test("parseLsofTcp keeps LISTEN and ESTABLISHED rows with addresses; image basename decoded; other states dropped", () => {
  const r = parseLsofTcp(LSOF);
  assert.equal(r.length, 8);
  assert.deepEqual(r[0], { pid: "40155", proc: "ollama", state: "listen", lhost: "127.0.0.1", lport: 11434, rhost: null, rport: null });
  assert.deepEqual(r[7], { pid: "9", proc: "Google Chrome Helper", state: "established", lhost: "2001:db8::2", lport: 5000, rhost: "2607:6bc0::10", rport: 443 });
  assert.ok(!r.some((x) => x.proc === "curl"));
});

test("parseNetstatTcp: all-zero foreign = listener; TIME_WAIT (pid 0) dropped; localised state words ignored", () => {
  const txt = `
  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:11434          0.0.0.0:0              ABHÖREN         4321
  TCP    [::]:8000              [::]:0                 LISTENING       99
  TCP    10.0.0.5:51234         160.79.104.10:443      HERGESTELLT     1234
  TCP    10.0.0.5:51235         160.79.104.10:443      TIME_WAIT       0
  UDP    0.0.0.0:5353           *:*                                    77
`;
  assert.deepEqual(parseNetstatTcp(txt), [
    { pid: "4321", proc: "", state: "listen", lhost: "0.0.0.0", lport: 11434, rhost: null, rport: null },
    { pid: "99", proc: "", state: "listen", lhost: "::", lport: 8000, rhost: null, rport: null },
    { pid: "1234", proc: "", state: "established", lhost: "10.0.0.5", lport: 51234, rhost: "160.79.104.10", rport: 443 }
  ]);
});

test("tcpTable on Windows names each pid from tasklist, basename only", () => {
  const runner = (cmd) => cmd === "netstat" ? "  TCP    10.0.0.5:51234    160.79.104.10:443    ESTABLISHED     1234\n" : cmd === "tasklist" ? '"RuntimeBroker.exe","1234","Console","1","10,000 K"\n' : null;
  const t = tcpTable({ runner, platform: "win32" });
  assert.equal(t.source, "netstat");
  assert.equal(t.sockets[0].proc, "RuntimeBroker.exe");
});

test("Linux: /proc/net/tcp{,6} + /proc/<pid>/fd give state, addresses and the owning comm", () => {
  assert.equal(procHexAddr("0100007F"), "127.0.0.1");
  assert.equal(procHexAddr("0000000000000000FFFF00000A00000A"), "10.0.0.10");
  assert.equal(procHexAddr("B80D0120000000000000000001000000"), "2001:db8::1");
  const tcp = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:2CAA 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 111 1 0
   1: 0500000A:C822 0A684FA0:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 222 1 0
   2: 0500000A:C823 0A684FA0:01BB 06 00000000:00000000 00:00000000 00000000  1000        0 333 1 0
`;
  assert.equal(parseProcTcp(tcp).length, 2);
  const files = { "/proc/net/tcp": tcp, "/proc/42/comm": "python3\n", "/proc/43/comm": "ollama\n" };
  const dirs = { "/proc": ["42", "43", "self", "net"], "/proc/42/fd": ["0", "5"], "/proc/43/fd": ["3"] };
  const links = { "/proc/42/fd/0": "/dev/null", "/proc/42/fd/5": "socket:[222]", "/proc/43/fd/3": "socket:[111]" };
  const io = {
    readFile: (p) => { if (p in files) return files[p]; throw Object.assign(new Error("ENOENT"), { code: "ENOENT" }); },
    readdir: (p) => { if (p in dirs) return dirs[p]; throw new Error("EACCES"); },
    readlink: (p) => { if (p in links) return links[p]; throw new Error("ENOENT"); }
  };
  assert.equal(procSocketOwners(io).get("222").proc, "python3");
  const t = tcpTable({ platform: "linux", ...io });
  assert.equal(t.source, "proc");
  assert.deepEqual(t.sockets, [
    { pid: "43", proc: "ollama", state: "listen", lhost: "127.0.0.1", lport: 11434, rhost: null, rport: null },
    { pid: "42", proc: "python3", state: "established", lhost: "10.0.0.5", lport: 51234, rhost: "160.79.104.10", rport: 443 }
  ]);
  assert.deepEqual(tcpTable({ platform: "linux", readFile: () => { throw new Error("x"); } }), { sockets: null, source: "none" });
});

test("localModelServers: runtime, widest bind, contract runtime ids; only loopback servers are probed", async () => {
  const probed = [];
  const connect = async (h, p) => { probed.push(`${h}:${p}`); return true; };
  const s = await localModelServers(parseLsofTcp(LSOF), { connect });
  assert.deepEqual(s, [
    { runtime: "llamacpp", port: 8080, bind: "all-interfaces", viaProxy: false },
    { runtime: "lmstudio", port: 1234, bind: "lan", viaProxy: false },
    { runtime: "ollama", port: 11434, bind: "loopback", viaProxy: false },
    { runtime: "other", port: 5001, bind: "loopback", viaProxy: false }
  ]);
  assert.deepEqual(probed.sort(), ["127.0.0.1:11434", "127.0.0.1:5001"]);
});

test("viaProxy is true only for a loopback server this process cannot connect to", async () => {
  const sockets = parseLsofTcp(LSOF);
  const s = await localModelServers(sockets, { connect: never });
  assert.deepEqual(s.map((x) => [x.runtime, x.viaProxy]), [["llamacpp", false], ["lmstudio", false], ["ollama", true], ["other", true]]);
  const reach = await localModelServers(sockets, { connect: always });
  assert.ok(reach.every((x) => !x.viaProxy));
});

test("tcpReachable measures a real loopback listener and a closed port", async () => {
  const srv = createServer((c) => c.destroy());
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  const port = srv.address().port;
  assert.equal(await tcpReachable("127.0.0.1", port), true);
  await new Promise((r) => srv.close(r));
  assert.equal(await tcpReachable("127.0.0.1", port), false);
});

test("LOCAL_MODEL_EXPOSED: contract fields, once per change, policy off silences", () => {
  const a = [{ runtime: "ollama", port: 11434, bind: "loopback", viaProxy: false }, { runtime: "vllm", port: 8000, bind: "loopback", viaProxy: true }];
  const first = exposureAlerts(a, { ts: "2026-10-13T00:00:00.000Z" });
  assert.equal(first.alerts.length, 1);
  const al = first.alerts[0];
  assert.equal(al.reasonCode, EXPOSURE_REASON);
  assert.equal(al.reasonCode, "LOCAL_MODEL_EXPOSED");
  assert.equal(al.category, EXPOSURE_CATEGORY);
  assert.equal(al.category, "Local model server reachable without MoorAI");
  assert.equal(al.riskLevel, "Medium");
  assert.deepEqual([al.runtime, al.port, al.bind], ["ollama", 11434, "loopback"]);
  assert.deepEqual(exposureAlerts(a, { prev: first.next }).alerts, [], "unchanged: no second alert");
  const widened = [{ runtime: "ollama", port: 11434, bind: "all-interfaces", viaProxy: false }];
  assert.equal(exposureAlerts(widened, { prev: first.next }).alerts[0].bind, "all-interfaces");
  assert.deepEqual(exposureAlerts(a, { policy: { localModelExposure: "off" } }).alerts, []);
  assert.equal(exposureAlerts(a, { policy: { localModelExposure: "alert" } }).alerts.length, 1);
});

test("inventoryPosture: top-level fields; the second scan of an unchanged device raises nothing", async (t) => {
  const root = mkdtempSync(join(tmpdir(), "moorai-inv-"));
  t.after(() => rmTree(root));
  const home = join(root, "home"); mkdirSync(home);
  const opts = { policy: null, home, machineDir: join(root, "machine"), sample: () => ({ sockets: parseLsofTcp(LSOF), source: "lsof" }), connect: always,
    lookup: async (h) => (h === "api.anthropic.com" ? [{ address: "160.79.104.10" }] : []), ts: "2026-10-13T10:00:00.000Z" };
  const a = await inventoryPosture(opts);
  assert.deepEqual(Object.keys(a.fields).sort(), ["aiApiCallers", "decoyKeys", "localModelServers"]);
  assert.equal(a.fields.localModelServers.length, 4);
  assert.deepEqual(a.fields.aiApiCallers, [{ processImage: "claude", provider: "anthropic", known: true }]);
  assert.deepEqual(a.fields.decoyKeys, { placed: 0, source: "none" });
  assert.equal(a.alerts.filter((x) => x.reasonCode === "LOCAL_MODEL_EXPOSED").length, 4);
  const b = await inventoryPosture(opts);
  assert.deepEqual(b.alerts, []);
  const ro = await inventoryPosture({ ...opts, home: join(root, "other"), write: false });
  assert.deepEqual(ro.alerts, [], "doctor mode never alerts");
});
