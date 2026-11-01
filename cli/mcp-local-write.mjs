// The over-sharing exemption for a local filesystem write (cli/mcp-outbound.mjs `localWrite`, #92). The server
// picks its tool names, so a write-shaped name (cli/oversight-mcp.mjs mcpWriteCalls) exempts nothing on its own:
// the server must also be
//   a local filesystem server by its launch declaration: the reference server (cli/mcp-scope.mjs
//   isFilesystemServer) and the package the launch actually runs (cli/mcp-package/resolve.mjs: npx's package,
//   not any argument that names it), its installed node_modules/.../dist/index.js run by node, or its
//   mcp-server-filesystem bin; or
//   listed by label in the signed policy's mcpOversharing.localWriteServers.
// A server declared by URL is never local. The HTTP MCP gateway does not pass `localWrite`: every upstream
// there is remote. Only the over-sharing signal is exempt; the data-loss detectors run first, on every call.
import { isFilesystemServer, FS_SERVER_PACKAGES } from "./mcp-scope.mjs";
import { resolveLaunch, unwrapGuard } from "./mcp-package/resolve.mjs";
import { mcpWriteCalls } from "./oversight-mcp.mjs";

const FS_ENTRY = /[\\/]node_modules[\\/]@modelcontextprotocol[\\/]server-filesystem[\\/]dist[\\/]index\.js$/;
const FS_BIN = "mcp-server-filesystem";
const binName = (p) => String(p).replace(/\\/g, "/").split("/").pop().replace(/\.(cmd|exe|ps1)$/i, "");

// decl: { command, args } | { url } | null (a launch declaration; cli/mcp-reputation.mjs findServerDecl's shape).
export function localFilesystemLaunch(decl) {
  if (!decl || typeof decl !== "object" || decl.url || typeof decl.command !== "string" || !decl.command) return false;
  if (!isFilesystemServer(decl)) return false;
  const ref = resolveLaunch(unwrapGuard([decl.command, ...(Array.isArray(decl.args) ? decl.args.map(String) : [])]));
  if (ref.ecosystem === "npm") return FS_SERVER_PACKAGES.includes(String(ref.name).toLowerCase());
  if (ref.ecosystem === "local") return FS_ENTRY.test(String(ref.path)) || binName(ref.path) === FS_BIN;
  if (ref.ecosystem === "unknown") return binName(ref.runner || "") === FS_BIN;
  return false;
}

// policy.mcpOversharing.localWriteServers: [server label] (signed policy).
export function listedLocalWriteServer(policy, label) {
  const o = policy && typeof policy === "object" ? policy.mcpOversharing : null;
  const list = o && typeof o === "object" && Array.isArray(o.localWriteServers) ? o.localWriteServers : [];
  return typeof label === "string" && label !== "" && list.includes(label);
}

// → mergeOutbound's localWrite: (mcp__server__tool, parsed arguments) → true for a write to this local server.
// decl may be a function, called only for a write-shaped call.
export function localWriteCheck({ policy, label, decl }) {
  return (tool, args) => {
    if (!mcpWriteCalls(tool, args).length) return false;
    if (listedLocalWriteServer(policy, label)) return true;
    return localFilesystemLaunch(typeof decl === "function" ? decl() : decl);
  };
}
