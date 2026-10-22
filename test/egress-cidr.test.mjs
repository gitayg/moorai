// F23 egress address ranges: the `cidr` key of an egress rule (cli/egress-rules.mjs), its text-level match in
// the hook's judge, its refusal inside workload profiles, and how each sandbox target expresses it
// (cli/sandbox-policy.mjs). The network-layer match is in test/egress-proxy-cidr-sni.test.mjs.
//
//   node --test --import ./test/hermetic-env.mjs test/egress-cidr.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { validateEgressRule, validateEgressRules, egressTargets, judgeTargets, egressAlerts, ipInCidr, EGRESS_RULE } from "../cli/egress-rules.mjs";
import { evaluateProfile, profilesFrom } from "../cli/workload-profile.mjs";
import { sandboxPolicy } from "../cli/sandbox-policy.mjs";

const chain = (rules, dflt = "allow") => ({ chain: [{ source: "policy", rules: validateEgressRules(rules).rules }], dflt });
const judge = (rules, tool, ti, dflt) => judgeTargets(egressTargets(tool, ti), chain(rules, dflt));

test("cidr validation: exactly one of host or cidr; IPv4 0-32, IPv6 0-128; normalised; host bits refused; /0 only alert or block", () => {
  const ok = (r) => { const v = validateEgressRule(r); assert.ok(v.rule, `${JSON.stringify(r)} -> ${v.error}`); return v.rule; };
  const err = (r) => validateEgressRule(r).error;
  assert.deepEqual(ok({ id: "ot-subnets", cidr: ["10.20.0.0/16", "fd00:20::/32"], port: [502, 4840], binary: "*", action: "block" }).cidrs, ["10.20.0.0/16", "fd00:20::/32"]);
  assert.deepEqual(ok({ cidr: "10.0.0.0/8", action: "block" }).cidrs, ["10.0.0.0/8"]);
  assert.deepEqual(ok({ cidr: "FD00:0020:0000::/32", action: "alert" }).cidrs, ["fd00:20::/32"]);
  assert.deepEqual(ok({ cidr: "192.168.1.7/32", action: "allow" }).cidrs, ["192.168.1.7/32"]);
  assert.deepEqual(ok({ cidr: "::ffff:10.0.0.0/104", action: "block" }).cidrs, ["10.0.0.0/8"], "an IPv4-mapped prefix is the IPv4 prefix");
  assert.equal(err({ host: "a.com", cidr: "10.0.0.0/8", action: "block" }), "host or cidr is required, not both");
  assert.equal(err({ action: "block" }), "host or cidr is required, not both");
  assert.equal(err({ cidr: "10.0.0.1/8", action: "block" }), "cidr has host bits set");
  assert.equal(err({ cidr: "fd00::1/64", action: "block" }), "cidr has host bits set");
  for (const c of ["10.0.0.0", "10.0.0.0/33", "10.0.0/8", "fd00::/129", "[fd00::]/8", "10.0.0.0/08x", "example.com/8", "", 7, "010.0.0.0/8"]) {
    assert.equal(err({ cidr: c, action: "block" }), "cidr is not an a.b.c.d/n or IPv6 x::/n prefix or a list of them", JSON.stringify(c));
  }
  assert.equal(err({ cidr: [], action: "block" }), "cidr is not an a.b.c.d/n or IPv6 x::/n prefix or a list of them");
  assert.equal(err({ cidr: Array.from({ length: 65 }, (_, i) => `10.${i}.0.0/16`), action: "block" }), "cidr is not an a.b.c.d/n or IPv6 x::/n prefix or a list of them");
  assert.equal(err({ cidr: "0.0.0.0/0", action: "allow" }), "cidr /0 is accepted only with action alert or block");
  assert.equal(err({ cidr: "::/0", action: "allow" }), "cidr /0 is accepted only with action alert or block");
  ok({ cidr: "0.0.0.0/0", action: "block" });
  ok({ cidr: ["::/0"], action: "alert" });
});

test("ipInCidr: IPv4, IPv6, IPv4-mapped IPv6 and bracketed hosts; names never match", () => {
  const r = validateEgressRule({ cidr: ["10.0.0.0/8", "fd00:20::/32"], action: "block" }).rule;
  for (const ip of ["10.0.0.1", "10.255.255.255", "fd00:20::1", "[fd00:20:ffff::9]", "::ffff:10.1.2.3", "[::ffff:a01:203]"]) assert.equal(ipInCidr(r.cidr, ip), true, ip);
  for (const ip of ["11.0.0.1", "9.255.255.255", "fd00:21::1", "::1", "example.com", "10.example.com", "", null]) assert.equal(ipInCidr(r.cidr, ip), false, String(ip));
});

test("text-level judge: an IP literal inside the range matches; a host name never matches a cidr rule (the hook does no DNS)", () => {
  const rules = [{ id: "rfc1918", cidr: ["10.0.0.0/8", "192.168.0.0/16"], action: "block" }];
  const hit = judge(rules, "Bash", { command: "curl -s http://10.1.2.3:8080/x" });
  assert.equal(hit.worst, "block");
  assert.equal(hit.verdicts[0].ruleId, "rfc1918");
  assert.equal(judge(rules, "Bash", { command: "curl -s http://[::ffff:192.168.4.4]/" }).worst, "block", "IPv4-mapped IPv6 literal");
  assert.equal(judge(rules, "Bash", { command: "ssh admin@192.168.1.10" }).worst, "block", "ssh bare host");
  assert.equal(judge(rules, "WebFetch", { url: "http://10.0.0.5/admin" }).worst, "block");
  assert.equal(judge(rules, "mcp__fetch__get", { url: "http://10.9.9.9/" }).worst, "block", "an MCP argument");
  assert.equal(judge(rules, "Bash", { command: "curl -s http://11.1.2.3/" }).worst, "allow");
  assert.equal(judge(rules, "Bash", { command: "curl -s http://intranet.corp/" }).worst, "allow", "a name is not matched (stated exception)");
  // Port and binary keys still apply to a cidr rule.
  const ot = [{ id: "ot-subnets", cidr: "10.20.0.0/16", port: [502], action: "block" }];
  assert.equal(judge(ot, "Bash", { command: "nc 10.20.1.1 502" }).worst, "block");
  assert.equal(judge(ot, "Bash", { command: "nc 10.20.1.1 22" }).worst, "allow");
  // First match decides, across host and cidr rules.
  const mixed = [{ host: "10.1.1.1", action: "allow" }, { cidr: "10.0.0.0/8", action: "block" }];
  assert.equal(judge(mixed, "Bash", { command: "curl http://10.1.1.1/" }).worst, "allow");
  assert.equal(judge(mixed, "Bash", { command: "curl http://10.1.1.2/" }).worst, "block");
  // An allow cidr rule opens an IP literal under a block default; a name still falls to the default.
  assert.equal(judge([{ cidr: "203.0.113.0/24", action: "allow" }], "Bash", { command: "curl https://203.0.113.9/" }, "block").worst, "allow");
  assert.equal(judge([{ cidr: "203.0.113.0/24", action: "allow" }], "Bash", { command: "curl https://example.com/" }, "block").worst, "block");
});

test("alerts for a cidr verdict keep the egress alert keys: egressHost is the IP literal, egressRuleId names the cidr rule", () => {
  const { verdicts } = judge([{ id: "rfc1918", cidr: "10.0.0.0/8", action: "block" }], "Bash", { command: "curl -s http://10.1.2.3/secret?q=1" });
  const [a] = egressAlerts(verdicts);
  assert.equal(a.reasonCode, EGRESS_RULE);
  assert.equal(a.egressHost, "10.1.2.3");
  assert.equal(a.egressRuleId, "rfc1918");
  assert.equal(a.egressRule, "policy#0");
  assert.ok(!JSON.stringify(a).includes("secret"), "no path or query");
});

test("evaluateProfile: a policy cidr block denies the call in the hook path, and a cidr rule inside a workload profile drops that profile", () => {
  const policy = { egressRules: [{ id: "rfc1918", cidr: "10.0.0.0/8", action: "block" }] };
  const r = evaluateProfile({ policy, tool: "Bash", toolInput: { command: "curl http://10.2.3.4/" } });
  assert.equal(r.decision, "deny");
  assert.equal(r.reasonCode, EGRESS_RULE);
  const p = profilesFrom({ policy: { workloadProfiles: [{ id: "ci", match: { serviceId: "svc" }, egressRules: [{ cidr: "10.0.0.0/8", action: "block" }] }] } });
  assert.equal(p.profiles.length, 0);
  assert.match(p.rejected[0].reason, /cidr rules are not accepted inside a workload profile/);
});

test("sandbox targets: MXC expresses a cidr natively; Seatbelt and OpenShell report it as not expressed", () => {
  const rules = { egressRules: [{ id: "ot", cidr: ["10.20.0.0/16", "fd00:20::/32"], port: [502], action: "block" }, { id: "lab", cidr: "192.0.2.0/24", action: "allow" }], egressDefault: "block" };
  const mxc = sandboxPolicy(rules, "mxc");
  assert.deepEqual(mxc.policy.egress.deny, [{ to: [{ cidr: "10.20.0.0/16" }, { cidr: "fd00:20::/32" }], ports: [{ port: 502 }] }]);
  assert.deepEqual(mxc.policy.egress.allow, [{ to: [{ cidr: "192.0.2.0/24" }], ports: [{ protocol: "tcp" }] }]);
  const sb = sandboxPolicy(rules, "seatbelt");
  assert.ok(!/10\.20/.test(sb.policy));
  assert.deepEqual(sb.unexpressed.filter((u) => u.reason === "seatbelt-cidr").map((u) => [u.index, u.effect]), [[0, "omitted"], [1, "omitted"]]);
  const os = sandboxPolicy(rules, "openshell");
  assert.deepEqual(Object.keys(os.policy.network_policies), []);
  assert.ok(os.unexpressed.some((u) => u.index === 1 && u.reason === "openshell-cidr"));
});

test("cidr match reads the numeric IPv4 spellings a URL parser and inet_aton read as an address (hex, octal, one number, short dotted), directly and on a bare ssh / nc host", () => {
  const r = validateEgressRule({ cidr: ["10.0.0.0/8"], action: "block" }).rule;
  for (const h of ["0x0a.1", "167772161", "10.1", "012.0.0.1", "0xa000001"]) assert.equal(ipInCidr(r.cidr, h), true, h);
  for (const h of ["0x0b.1", "184549377", "11.1", "013.0.0.1", "1e1", "deadbeef.example"]) assert.equal(ipInCidr(r.cidr, h), false, h);
  const rules = [{ id: "rfc1918", cidr: "10.0.0.0/8", action: "block" }];
  assert.equal(judge(rules, "Bash", { command: "ssh admin@0x0a.1" }).worst, "block", "ssh to a hex spelling");
  assert.equal(judge(rules, "Bash", { command: "nc 167772161 22" }).worst, "block", "nc to a one-number spelling");
});
