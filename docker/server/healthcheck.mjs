// Container health: an HTTP GET on loopback inside the container's own network namespace.
//   moorai-serve        GET http://127.0.0.1:8790/healthz must answer 200 (the default).
//   moorai-mcp-gateway  has no /healthz; set MOORAI_HEALTH_PORT=8848 MOORAI_HEALTH_PATH=/ and any answer
//                       below 500 (its 404 "No MCP route at this path") means it is listening.
const port = Number(process.env.MOORAI_HEALTH_PORT || 8790);
const path = process.env.MOORAI_HEALTH_PATH || "/healthz";
try {
  const r = await fetch(`http://127.0.0.1:${port}${path}`, { signal: AbortSignal.timeout(3000) });
  process.exit((path === "/healthz" ? r.status === 200 : r.status < 500) ? 0 : 1);
} catch {
  process.exit(1);
}
