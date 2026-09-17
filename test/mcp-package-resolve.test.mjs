// resolveMcpPackages — MCP server launch command → registry package reference. Offline, pure.
//
//   node --test test/mcp-package-resolve.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";

import { resolveMcpPackages, resolveLaunch, parsePackageArg, parseCodexToml } from "../cli/mcp-package/resolve.mjs";

const r = (...argv) => resolveLaunch(argv);

test("npx forms: -y, --yes, flags before the name, scoped names, versions, dist-tags", () => {
  assert.deepEqual(r("npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp"), { ecosystem: "npm", name: "@modelcontextprotocol/server-filesystem", version: null });
  assert.deepEqual(r("npx", "--yes", "--registry", "https://r.example", "mcp-remote@0.1.2", "https://x"), { ecosystem: "npm", name: "mcp-remote", version: "0.1.2" });
  assert.deepEqual(r("npx", "-y", "@scope/pkg@1.2.3"), { ecosystem: "npm", name: "@scope/pkg", version: "1.2.3" });
  assert.deepEqual(r("npx", "pkg@latest"), { ecosystem: "npm", name: "pkg", version: "latest" });
  assert.deepEqual(r("npx", "-p", "@scope/cli-pkg", "cli-bin"), { ecosystem: "npm", name: "@scope/cli-pkg", version: null });
  assert.deepEqual(r("npx", "--package=tool@2.0.0", "tool-bin"), { ecosystem: "npm", name: "tool", version: "2.0.0" });
  assert.deepEqual(r("/usr/local/bin/npx", "-y", "srv"), { ecosystem: "npm", name: "srv", version: null });
});

test("pnpm dlx, bunx, yarn dlx, npm exec, and a Windows cmd /c wrapper", () => {
  assert.deepEqual(r("pnpm", "dlx", "@scope/a@1.0.0"), { ecosystem: "npm", name: "@scope/a", version: "1.0.0" });
  assert.deepEqual(r("bunx", "--bun", "b-server"), { ecosystem: "npm", name: "b-server", version: null });
  assert.deepEqual(r("yarn", "dlx", "-q", "c-server@3"), { ecosystem: "npm", name: "c-server", version: "3" });
  assert.deepEqual(r("npm", "exec", "--", "d-server"), { ecosystem: "npm", name: "d-server", version: null });
  assert.deepEqual(r("cmd", "/c", "npx", "-y", "e-server"), { ecosystem: "npm", name: "e-server", version: null });
});

test("uvx, uv tool run, pipx run, python -m", () => {
  assert.deepEqual(r("uvx", "mcp-server-fetch"), { ecosystem: "pypi", name: "mcp-server-fetch", version: null });
  assert.deepEqual(r("uvx", "--python", "3.12", "mcp-server-git==0.6.2", "--repository", "."), { ecosystem: "pypi", name: "mcp-server-git", version: "0.6.2" });
  assert.deepEqual(r("uvx", "--from", "awslabs.core-mcp-server@latest", "awslabs.core-mcp-server"), { ecosystem: "pypi", name: "awslabs.core-mcp-server", version: null });
  assert.deepEqual(r("uvx", "pkg[extra]>=1.0"), { ecosystem: "pypi", name: "pkg", version: null });
  assert.deepEqual(r("uv", "tool", "run", "mcp-server-time"), { ecosystem: "pypi", name: "mcp-server-time", version: null });
  assert.deepEqual(r("pipx", "run", "--spec", "x-mcp==1.1", "x"), { ecosystem: "pypi", name: "x-mcp", version: "1.1" });
  assert.deepEqual(r("python", "-m", "mcp_server_fetch"), { ecosystem: "pypi", name: "mcp-server-fetch", version: null, inferred: true });
  assert.equal(r("python3", "-m", "http.server").ecosystem, "unknown", "python -m of a non-MCP module does not imply PyPI");
});

test("docker run → docker (flags with values skipped); local paths → local", () => {
  assert.deepEqual(r("docker", "run", "-i", "--rm", "-e", "GITHUB_TOKEN", "-v", "/a:/b", "ghcr.io/github/github-mcp-server"), { ecosystem: "docker", name: "ghcr.io/github/github-mcp-server" });
  assert.deepEqual(r("node", "/Users/me/srv/index.js"), { ecosystem: "local", path: "/Users/me/srv/index.js" });
  assert.deepEqual(r("python", "server.py"), { ecosystem: "local", path: "server.py" });
  assert.deepEqual(r("./bin/server"), { ecosystem: "local", path: "./bin/server" });
  assert.deepEqual(r("uv", "run", "--directory", "/x/y", "server.py"), { ecosystem: "local", path: "/x/y" });
  assert.equal(r("npx", "-y", "./local-dir").ecosystem, "unknown");
  assert.equal(r("npx", "github:user/repo").ecosystem, "unknown");
});

test("config shapes: mcpServers, servers, context_servers (Zed), mcp.servers, nested projects, arrays, command strings", () => {
  const cfg = {
    mcpServers: { fs: { command: "npx", args: ["-y", "@modelcontextprotocol/server-filesystem"] } },
    projects: { "/some/dir": { mcpServers: { f: { command: "uvx", args: ["mcp-server-fetch"] } } } },
    mcp: { servers: { g: { command: "pnpm", args: ["dlx", "g-srv"] } } },
    context_servers: { z: { command: { path: "bunx", args: ["z-srv@1.0.0"] } } },
    servers: { d: { command: "docker", args: ["run", "-i", "img/x"] } },
    list: [{ mcpServers: [{ name: "c", command: "npx -y c-srv" }] }]
  };
  const got = resolveMcpPackages(cfg).map((x) => `${x.ecosystem}:${x.name || x.path}`).sort();
  assert.deepEqual(got, ["docker:img/x", "npm:@modelcontextprotocol/server-filesystem", "npm:c-srv", "npm:g-srv", "npm:z-srv", "pypi:mcp-server-fetch"]);
  // JSON text works the same, and duplicates collapse.
  const dup = JSON.stringify({ mcpServers: { a: { command: "npx", args: ["x-srv"] }, b: { command: "npx", args: ["-y", "x-srv"] } } });
  assert.equal(resolveMcpPackages(dup).length, 1);
});

test("Codex TOML [mcp_servers.x] with single- and multi-line args", () => {
  const toml = `model = "o3"\n\n[mcp_servers.fetch]\ncommand = "uvx"\nargs = ["mcp-server-fetch==1.0.0"]\n\n[mcp_servers.fs]\ncommand = "npx"\nargs = [\n  "-y",\n  "@modelcontextprotocol/server-filesystem",\n]\nenv = { "A" = "b" }\n\n[other]\ncommand = "npx"\nargs = ["ignored"]\n`;
  assert.equal(parseCodexToml(toml).length, 2);
  assert.deepEqual(resolveMcpPackages(toml), [
    { ecosystem: "pypi", name: "mcp-server-fetch", version: "1.0.0" },
    { ecosystem: "npm", name: "@modelcontextprotocol/server-filesystem", version: null }
  ]);
});

test("parsePackageArg: npm:/pypi: specs, and rejects anything else", () => {
  assert.deepEqual(parsePackageArg("npm:@modelcontextprotocol/server-filesystem@2025.8.21"), { ecosystem: "npm", name: "@modelcontextprotocol/server-filesystem", version: "2025.8.21" });
  assert.deepEqual(parsePackageArg("pypi:mcp-server-fetch"), { ecosystem: "pypi", name: "mcp-server-fetch", version: null });
  assert.equal(parsePackageArg("cargo:serde"), null);
  assert.equal(parsePackageArg("npm:../../etc"), null);
  assert.equal(parsePackageArg("npm:https://evil.example/x.tgz"), null);
});
