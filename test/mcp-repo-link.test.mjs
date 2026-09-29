// Repository link check for MCP server packages (cli/mcp-repo-link.mjs, data/repo-link.js).
//
//   node --test --import ./test/hermetic-env.mjs test/mcp-repo-link.test.mjs
//
// No live network. test/fixtures/mcp-repo-link/recorded.json holds real registry / code-host responses
// recorded on 2026-09-29, trimmed to the fields the check reads, and each case's result at recording
// time. Replay serves exactly those URLs; any other request throws, so a new request is a test failure
// rather than a silent trip to the network.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, mkdtempSync, mkdirSync, rmSync } from "node:fs";
import { join, dirname } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { checkRepoLink } from "../cli/mcp-repo-link.mjs";
import { parseRepoUrl, npmDeclaredRepo, pypiDeclaredRepo, manifestInfo, candidateDirs, sameName } from "../data/repo-link.js";
import { assessServer, assessServerSync } from "../cli/mcp-reputation.mjs";
import { REASON_WEIGHTS, scoreReputation } from "../data/mcp-reputation.js";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const REC = JSON.parse(readFileSync(join(ROOT, "test/fixtures/mcp-repo-link/recorded.json"), "utf8"));
const caseOf = (name) => REC.cases.find((c) => c.name === name);

function replay(responses, { override = {}, strict = true } = {}) {
  const calls = [];
  const fetchImpl = async (url, opts = {}) => {
    calls.push({ url: String(url), opts });
    const r = override[url] || responses[url];
    if (typeof r === "function") return r();
    if (!r) { if (strict) throw new Error(`unrecorded request: ${url}`); return new Response("", { status: 599 }); }
    return new Response(r.status === 200 ? r.body : "", { status: r.status, headers: r.location ? { location: r.location } : {} });
  };
  return { calls, fetchImpl };
}

// ---------------------------------------------------------------------------------------------
// recorded cases: every one reproduces the result it had against the live hosts
// ---------------------------------------------------------------------------------------------
for (const c of REC.cases) {
  test(`recorded: ${c.ecosystem} ${c.name} → ${[...c.expect.signals, ...c.expect.evidence].join(", ")}`, async () => {
    const { calls, fetchImpl } = replay(c.responses);
    const r = await checkRepoLink({ ecosystem: c.ecosystem, name: c.name, version: c.version }, { fetchImpl });
    assert.deepEqual(r, c.expect);
    assert.deepEqual(calls.map((x) => x.url).sort(), Object.keys(c.responses).sort(), "exactly the recorded requests");
  });
}

test("the recorded set covers every reason code and the provenance / manifest / monorepo proofs", () => {
  const all = REC.cases.flatMap((c) => [...c.expect.signals, ...c.expect.evidence]);
  for (const code of ["repo-mismatch", "repo-unreachable", "repo-missing", "repo-provenance", "repo-verified", "repo-monorepo"]) assert.ok(all.includes(code), code);
});

test("mismatch: a third party's republish borrowing someone else's repository", async () => {
  const c = caseOf("@iflow-mcp/cameroncooke_xcodebuildmcp");
  const { fetchImpl } = replay(c.responses);
  const r = await checkRepoLink({ ecosystem: "npm", name: c.name, version: c.version }, { fetchImpl });
  assert.deepEqual(r.signals, ["repo-mismatch"]);
});

test("provenance naming ANOTHER repository than the one declared is a mismatch", async () => {
  const c = caseOf("@modelcontextprotocol/server-filesystem");
  const attUrl = Object.keys(c.responses).find((u) => u.includes("/attestations/"));
  const att = JSON.parse(c.responses[attUrl].body);
  const st = JSON.parse(Buffer.from(att.attestations[0].bundle.dsseEnvelope.payload, "base64").toString());
  st.predicate.buildDefinition.externalParameters.workflow.repository = "https://github.com/someone-else/servers";
  att.attestations[0].bundle.dsseEnvelope.payload = Buffer.from(JSON.stringify(st)).toString("base64");
  const { fetchImpl } = replay(c.responses, { override: { [attUrl]: { status: 200, body: JSON.stringify(att) } } });
  const r = await checkRepoLink({ ecosystem: "npm", name: c.name, version: c.version }, { fetchImpl });
  assert.deepEqual(r, { signals: ["repo-mismatch"], evidence: ["repo-provenance-other-repo"] });
});

// ---------------------------------------------------------------------------------------------
// fail-open: unknown is not bad
// ---------------------------------------------------------------------------------------------
test("fail-open: transport errors, timeouts, 5xx and 429 never produce a signal", async () => {
  const thrower = async () => { throw new Error("ECONNRESET"); };
  assert.deepEqual(await checkRepoLink({ ecosystem: "npm", name: "pinecone-mcp", version: "1.0.0" }, { fetchImpl: thrower }), { signals: [], evidence: ["repo-check-failed"] });

  const c = caseOf("@upstash/context7-mcp");
  const manifestUrl = Object.keys(c.responses).find((u) => u.startsWith("https://raw.githubusercontent.com/"));
  for (const status of [500, 503, 429]) {
    const { fetchImpl } = replay(c.responses, { override: { [manifestUrl]: { status } } });
    const r = await checkRepoLink({ ecosystem: "npm", name: c.name, version: c.version }, { fetchImpl });
    assert.deepEqual(r, { signals: [], evidence: ["repo-check-failed"] }, `status ${status}`);
  }

  // A github.com page that times out after the manifest 404s: existence unknown, no signal.
  const p = caseOf("pinecone-mcp");
  const page = Object.keys(p.responses).find((u) => u.startsWith("https://github.com/"));
  const slow = replay(p.responses, { override: { [page]: () => { throw Object.assign(new Error("timeout"), { name: "TimeoutError" }); } } });
  assert.deepEqual(await checkRepoLink({ ecosystem: "npm", name: "pinecone-mcp", version: "1.0.0" }, { fetchImpl: slow.fetchImpl }), { signals: [], evidence: ["repo-check-failed"] });
});

test("bounded: request cap and wall-clock budget hold; redirects never leave the allowed hosts", async () => {
  const c = caseOf("@sentry/mcp-server");
  const { calls, fetchImpl } = replay(c.responses);
  const r = await checkRepoLink({ ecosystem: "npm", name: c.name, version: c.version }, { fetchImpl, limits: { maxRequests: 2 } });
  assert.equal(calls.length, 2);
  assert.deepEqual(r.signals, []);

  let t = 0;
  const clock = () => t;
  const late = replay(c.responses);
  const lateFetch = async (u, o) => { t += 20000; return late.fetchImpl(u, o); };
  const r2 = await checkRepoLink({ ecosystem: "npm", name: c.name, version: c.version }, { fetchImpl: lateFetch, now: clock });
  assert.equal(late.calls.length, 1, "no request after the budget is spent");
  assert.deepEqual(r2.signals, []);

  const u = caseOf("@upstash/context7-mcp");
  const manifestUrl = Object.keys(u.responses).find((x) => x.startsWith("https://raw.githubusercontent.com/"));
  const redir = replay(u.responses, { override: { [manifestUrl]: { status: 302, location: "https://evil.example/package.json" } } });
  const r3 = await checkRepoLink({ ecosystem: "npm", name: u.name, version: u.version }, { fetchImpl: redir.fetchImpl });
  assert.ok(redir.calls.every((x) => /^https:\/\/(registry\.npmjs\.org|pypi\.org|github\.com|raw\.githubusercontent\.com|gitlab\.com)\//.test(x.url)));
  assert.deepEqual(r3.signals, []);
});

test("privacy: only public package / repository names reach public hosts, with no identifying headers", async () => {
  for (const c of REC.cases) {
    const { calls, fetchImpl } = replay(c.responses);
    await checkRepoLink({ ecosystem: c.ecosystem, name: c.name, version: c.version }, { fetchImpl });
    for (const { url, opts } of calls) {
      assert.match(url, /^https:\/\/(registry\.npmjs\.org|pypi\.org|github\.com|raw\.githubusercontent\.com|gitlab\.com)\//);
      assert.equal(opts.method, "GET");
      assert.equal(opts.body, undefined);
      assert.deepEqual(Object.keys(opts.headers || {}).filter((h) => h !== "accept"), []);
    }
  }
});

// ---------------------------------------------------------------------------------------------
// reputation wiring: opt-in, cached per package+version, never on the offline path
// ---------------------------------------------------------------------------------------------
test("reputation: repo codes arrive only through the opt-in registry lookup, cached, and the offline path makes no request", async () => {
  const root = mkdtempSync(join(tmpdir(), "moorai-repolink-"));
  const home = join(root, "home"), stateDir = join(root, "state");
  mkdirSync(home, { recursive: true }); mkdirSync(stateDir, { recursive: true });
  try {
    const c = caseOf("@iflow-mcp/cameroncooke_xcodebuildmcp");
    const decl = { command: "npx", args: ["-y", `${c.name}@${c.version}`] };
    const none = async () => { throw new Error("offline path made a request"); };

    const off = await assessServer(decl, { home, stateDir, fetchImpl: none, policy: {} });
    assert.ok(!off.reasons.includes("repo-mismatch"), "no lookup without the policy");

    const { calls, fetchImpl } = replay(c.responses, { strict: false });
    const on = await assessServer(decl, { home, stateDir, fetchImpl, policy: { lookup: "registry" } });
    assert.ok(on.reasons.includes("repo-mismatch"));
    assert.ok(calls.some((x) => x.url.startsWith("https://raw.githubusercontent.com/")));

    const again = replay(c.responses, { strict: false });
    const cached = await assessServer(decl, { home, stateDir, fetchImpl: again.fetchImpl, policy: { lookup: "registry" } });
    assert.equal(again.calls.length, 0, "second sight of the same package+version is served from cache");
    assert.ok(cached.reasons.includes("repo-mismatch"));

    const sync = assessServerSync(decl, { home, stateDir });
    assert.ok(sync.reasons.includes("repo-mismatch"), "the hook's offline read reuses what the proxy cached");
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("weights: a borrowed link alone drops a server to fair; with a typosquat it is bad", () => {
  assert.equal(scoreReputation([{ code: "repo-mismatch", weight: REASON_WEIGHTS["repo-mismatch"] }]).band, "fair");
  assert.equal(scoreReputation([{ code: "repo-missing", weight: REASON_WEIGHTS["repo-missing"] }, { code: "unpinned-version", weight: 5 }]).band, "good");
  assert.equal(scoreReputation([{ code: "repo-mismatch", weight: 30 }, { code: "mcp-typosquat", weight: 45 }]).band, "bad");
});

// ---------------------------------------------------------------------------------------------
// the pure half
// ---------------------------------------------------------------------------------------------
test("parseRepoUrl: the forms npm and PyPI actually publish", () => {
  const p = (s, o) => { const r = parseRepoUrl(s, o); return r && `${r.host}/${r.owner}/${r.repo}${r.directory ? `#${r.directory}` : ""}`; };
  assert.equal(p("git+https://github.com/modelcontextprotocol/servers.git"), "github.com/modelcontextprotocol/servers");
  assert.equal(p("git+ssh://git@github.com/makenotion/notion-mcp-server.git"), "github.com/makenotion/notion-mcp-server");
  assert.equal(p("git@github.com:owner/repo.git"), "github.com/owner/repo");
  assert.equal(p("github:owner/repo"), "github.com/owner/repo");
  assert.equal(p("npm/security-holder"), "github.com/npm/security-holder");
  assert.equal(p("git://github.com/pact-foundation/pact-node.git"), "github.com/pact-foundation/pact-node");
  assert.equal(p("https://github.com/modelcontextprotocol/servers/tree/main/src/fetch"), "github.com/modelcontextprotocol/servers#src/fetch");
  assert.equal(p("https://github.com/awslabs/mcp/blob/main/src/x-server/CHANGELOG.md"), "github.com/awslabs/mcp#src/x-server");
  assert.equal(p("https://gitlab.com/group/proj/-/tree/main/pkg"), "gitlab.com/group/proj#pkg");
  assert.equal(p("git+https://github.com/upstash/context7.git", { directory: "packages/mcp" }), "github.com/upstash/context7#packages/mcp");
  assert.equal(p("git+https://github.com/o/r.git", { directory: "../../etc" }), "github.com/o/r");
  for (const bad of ["", "not a url", "https://github.com/", "ftp://github.com/o/r", "https://github.com/o", "file:///etc/passwd"]) assert.equal(parseRepoUrl(bad), null, bad);
  assert.equal(npmDeclaredRepo({}).status, "none");
  assert.equal(npmDeclaredRepo({ repository: { type: "git", url: "::::" } }).status, "malformed");
  assert.equal(pypiDeclaredRepo({ project_urls: null, home_page: null }).status, "none");
  assert.equal(pypiDeclaredRepo({ project_urls: { Homepage: "https://example.com" } }).status, "none");
});

test("manifestInfo / candidateDirs / names", () => {
  assert.deepEqual(manifestInfo("package.json", JSON.stringify({ name: "x", workspaces: ["src/*"], private: true })), { name: "x", workspaces: ["src/*"], dynamic: false, private: true });
  assert.equal(manifestInfo("pyproject.toml", '[project]\nname = "mcp-for-blender"\nversion = "2"\n').name, "mcp-for-blender");
  assert.equal(manifestInfo("pyproject.toml", '[tool.poetry]\nname = "poetry-pkg"\n').name, "poetry-pkg");
  assert.deepEqual(manifestInfo("pyproject.toml", '[tool.uv.workspace]\nmembers = ["src/*"]\n').workspaces, ["src/*"]);
  assert.equal(manifestInfo("pyproject.toml", '[project]\ndynamic = ["name", "version"]\n').dynamic, true);
  assert.equal(manifestInfo("setup.cfg", "[metadata]\nname = cfg-pkg\n").name, "cfg-pkg");
  assert.equal(manifestInfo("setup.py", 'from setuptools import setup\nsetup(\n  name="py-pkg",\n)').name, "py-pkg");
  assert.deepEqual(candidateDirs("npm", "@modelcontextprotocol/server-filesystem", ["src/*"]), ["src/server-filesystem", "src/filesystem"]);
  assert.ok(candidateDirs("pypi", "awslabs.aws-documentation-mcp-server", ["src/*"]).includes("src/aws-documentation-mcp-server"));
  assert.ok(sameName("pypi", "Mcp_Server.Fetch", "mcp-server-fetch"));
  assert.ok(!sameName("npm", "@a/x", "@b/x"));
});
