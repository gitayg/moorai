// The gateway's answer to a server -> client request it refused (../mcp-proxy/sampling-scan.mjs): a
// JSON-RPC error POSTed upstream on the client's own session, the way the Streamable HTTP transport
// carries every client -> server message. Built from the headers of the request whose response carried
// the server's request, as ./relist.mjs builds its own POST (hop-by-hop stripped, placeholder credentials
// swapped, this hop's trace; Mcp-Session-Id, MCP-Protocol-Version and Authorization as the client sent
// them), without Mcp-Method: the body is a response, not a request. Fire-and-forget: the answer is drained
// and never reaches the client; a failure leaves the server's request unanswered, as a client that went
// away would.
import http from "node:http";
import https from "node:https";

const ANSWER_TIMEOUT_MS = 10000;

export function createUpstreamReply({ target, headers, agent, lookup }) {
  return (msg) => {
    try {
      const body = Buffer.from(JSON.stringify(msg));
      const h = { ...headers, "content-length": String(body.length) };
      delete h["mcp-method"];
      const lib = target.protocol === "https:" ? https : http;
      const req = lib.request(target, { method: "POST", headers: h, agent, ...(lookup ? { lookup } : {}) });
      req.on("error", () => {});
      req.on("response", (r) => r.resume());
      req.setTimeout(ANSWER_TIMEOUT_MS, () => req.destroy());
      req.end(body);
    } catch { /* the request stays unanswered */ }
  };
}
