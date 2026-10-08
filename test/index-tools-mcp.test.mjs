// Per-file runner:  node --test --import ./test/hermetic-env.mjs test/index-tools-mcp.test.mjs
//
// MCP vector-store WRITE tools (cli/index-tools.mjs): a tools/call that puts documents into a vector store
// has its document arguments scanned at the "index" stage before it is forwarded — in the Claude Desktop
// stdio proxy (mcp-proxy/moorai-mcp-guard.mjs, against the real fake MCP server over real stdio) and in
// the HTTP gateway (mcp-gateway/guard.mjs, a real gateway process over the fake remote server).
// "Reported" = a content-free alert at stage "index" reached the fake console; "blocked" = the upstream
// never received the call. The poisoned fixture is the vector-3 sample that only the index-stage
// detectors catch, so the argument scan (prompt stage) alone stays silent on it.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import http from "node:http";
import { rmTree } from "./fs-cleanup.mjs";
import { indexToolMatch } from "../cli/index-tools.mjs";
import { scenario, rpc, call, settle } from "../mcp-gateway/test/harness.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const GUARD = join(ROOT, "mcp-proxy", "moorai-mcp-guard.mjs");
const FAKE = join(ROOT, "mcp-proxy", "test-fake-mcp-server.mjs");
const V3 = JSON.parse(readFileSync(join(ROOT, "test", "redteam", "vector3-supply-chain.json"), "utf8"));
const v3 = (id) => [...V3.attacks, ...V3.benign].find((s) => s.id === id).text;
const POISONED = v3("v3-cfg-013");
const BENIGN = v3("v3-benign-019");
const REPORT = { captureTier: "content-free" };
const BLOCK = { captureTier: "content-free", indexScanAction: "block" };
const leaks = (alerts) => ["attacker-cdn", "Storybook", "fastdocs"].filter((s) => JSON.stringify(alerts).includes(s));

// ---------------------------------------------------------------------------------------------------
// recognition
// ---------------------------------------------------------------------------------------------------

test("recognition: vector-store write names match; reads, deletes and plain inserts on other servers do not", () => {
  const yes = [
    ["add_documents", "kb"], ["chroma_add_documents", "chroma"], ["index_documents", "search"], ["store_memory", "notes"],
    ["add_memory", "mem0"], ["addMemories", "openmemory"], ["upsert", "pinecone"], ["insert", "weaviate"], ["qdrant-store", "kb"], ["upsert-records", "pinecone"]
  ];
  for (const [tool, server] of yes) assert.equal(indexToolMatch({ tool, server }).match, true, `${server}/${tool}`);
  const no = [["insert", "postgres"], ["upsert", "github"], ["get_index_stats", "pinecone"], ["delete_documents", "chroma"], ["query_documents", "chroma"], ["create_issue", "github"], ["echo", "testsrv"]];
  for (const [tool, server] of no) assert.equal(indexToolMatch({ tool, server }).match, false, `${server}/${tool}`);
  assert.deepEqual(indexToolMatch({ tool: "upsert", server: "db", args: { documents: ["a"] } }), { match: true, via: "args" });
  assert.deepEqual(indexToolMatch({ tool: "kb_put", server: "x", policy: { indexTools: ["kb_put"] } }), { match: true, via: "policy" });
  assert.deepEqual(indexToolMatch({ tool: "kb_put", server: "x", policy: { indexTools: ["other/kb_put"] } }), { match: false });
  assert.equal(indexToolMatch({ tool: "add_documents", server: "kb", policy: { indexToolHeuristic: false } }).match, false, "the heuristic can be turned off");
});

// The tool names real servers register, read from their source on 2026-10-07 (repo @ commit, file). Every
// write must match under the server label an operator would give it AND under a neutral one ("kb"), since
// the label is the operator's choice; every read, search, delete and admin tool must match under neither.
const REAL = [
  // chroma-core/chroma-mcp @ 98ff675 src/chroma_mcp/server.py (function names; text: documents: List[str])
  ["chroma", ["chroma_add_documents", "chroma_update_documents"], ["chroma_list_collections", "chroma_create_collection", "chroma_peek_collection", "chroma_get_collection_info", "chroma_get_collection_count", "chroma_modify_collection", "chroma_fork_collection", "chroma_delete_collection", "chroma_query_documents", "chroma_get_documents", "chroma_delete_documents"]],
  // qdrant/mcp-server-qdrant @ c56ae5a src/mcp_server_qdrant/mcp_server.py (text: information: str)
  ["qdrant", ["qdrant-store"], ["qdrant-find"]],
  // pinecone-io/pinecone-mcp @ a15d4b9 src/tools/database/*.ts (text: records[] fields named by the index's fieldMap)
  ["pinecone", ["upsert-records"], ["list-indexes", "describe-index", "describe-index-stats", "create-index-for-model", "search-records", "rerank-documents", "cascading-search", "search-docs"]],
  // weaviate/mcp-server-weaviate @ 4db6a8f mcp.go (standalone, now deprecated; text: properties) and
  // weaviate/weaviate @ 519a9ba adapters/handlers/mcp/create/schema.go (built in; text: objects[].properties)
  ["weaviate", ["weaviate-insert-one", "weaviate-objects-upsert"], ["weaviate-query", "weaviate-query-hybrid", "weaviate-collections-get-config", "weaviate-tenants-list"]],
  // mem0ai/mem0-mcp @ 624024d src/mem0_mcp_server/server.py (text: text: str, messages)
  ["mem0", ["add_memory", "update_memory"], ["search_memories", "get_memories", "get_memory", "delete_memory", "delete_all_memories", "list_entities", "delete_entities"]],
  // mem0ai/mem0 @ 13c7f84 openmemory/api/app/mcp_server.py (removed from the repo in ea2ee07; text: text: str)
  ["openmemory", ["add_memories"], ["search_memory", "list_memories", "delete_memories", "delete_all_memories"]],
  // zilliztech/mcp-server-milvus @ 6a2bff9 src/mcp_server_milvus/server.py (text: data: list[dict])
  ["milvus", ["milvus_insert_data"], ["milvus_text_search", "milvus_list_collections", "milvus_query", "milvus_vector_search", "milvus_hybrid_search", "milvus_text_similarity_search", "milvus_create_collection", "milvus_delete_entities", "milvus_load_collection", "milvus_release_collection", "milvus_list_databases", "milvus_use_database", "milvus_get_collection_info"]],
  // elastic/mcp-server-elasticsearch @ 9e64b84 src/servers/elasticsearch/base_tools.rs (all read_only_hint)
  ["elasticsearch", [], ["list_indices", "get_mappings", "search", "esql", "get_shards"]],
  // opensearch-project/opensearch-mcp-server-py @ cd287e8 src/tools/{tools,memory_tools}.py, agentic_memory/actions.py
  ["opensearch", ["SaveMemoryTool", "AddAgenticMemoriesTool", "UpdateAgenticMemoryTool", "CreateAgenticMemorySessionTool"], ["ListIndexTool", "IndexMappingTool", "SearchIndexTool", "GetShardsTool", "GetIndexInfoTool", "GetIndexStatsTool", "CountTool", "ExplainTool", "MsearchTool", "PPLQueryTool", "SearchMemoryTool", "DeleteMemoryTool", "GetAgenticMemoryTool", "SearchAgenticMemoryTool", "DeleteAgenticMemoryByIDTool", "DeleteAgenticMemoryByQueryTool", "CreateQuerySetTool", "CreateExperimentTool", "CreateSearchConfigurationTool", "CreateJudgmentListTool", "CreateLLMJudgmentListTool"]],
  // redis/mcp-redis @ e89cff9 src/tools/{hash,json,redis_query_engine}.py: the vector write; plain key-value writes (hset, json_set, set) are not index writes
  ["redis", ["set_vector_in_hash"], ["get_vector_from_hash", "vector_search_hash", "hybrid_search", "create_vector_index_hash", "get_indexes", "get_index_info", "get_indexed_keys_number", "hset", "json_set", "hget", "hdel"]],
  // lancedb/lancedb-mcp-server @ 91a064e lancedb_mcp.py (text: docs: str | list[str])
  ["lancedb", ["ingest_docs"], ["query_table", "table_details"]],
  // modelcontextprotocol/servers @ 5abed86 src/memory/index.ts (text: entities[].observations[], observations[].contents[])
  ["memory", ["create_entities", "create_relations", "add_observations"], ["delete_entities", "delete_observations", "delete_relations", "read_graph", "search_nodes", "open_nodes"]]
];

test("recognition: the verified write tools of real vector-store and memory MCP servers match; their read, search, delete and admin tools do not", () => {
  const wrong = [];
  for (const [label, writes, others] of REAL) {
    for (const server of [label, "kb"]) {
      for (const tool of writes) if (!indexToolMatch({ tool, server }).match) wrong.push(`missed ${server}/${tool}`);
      for (const tool of others) if (indexToolMatch({ tool, server }).match) wrong.push(`matched ${server}/${tool}`);
    }
  }
  assert.deepEqual(wrong, []);
});

test("recognition: OpenSearch's generic API tool is a write only for a document-write call", () => {
  const g = (args) => indexToolMatch({ tool: "GenericOpenSearchApiTool", server: "opensearch", args }).match;
  for (const [method, path] of [["POST", "/kb/_doc"], ["PUT", "/kb/_doc/1"], ["post", "_bulk"], ["POST", "/kb/_update/1"], ["PUT", "/kb/_create/1?refresh=true"]]) assert.equal(g({ method, path, body: { text: "x" } }), true, `${method} ${path}`);
  for (const [method, path] of [["GET", "/kb/_doc/1"], [undefined, "/kb/_search"], ["POST", "/kb/_search"], ["DELETE", "/kb/_doc/1"], ["PUT", "/kb"], ["POST", "/kb/_docs_stats"]]) assert.equal(g({ method, path }), false, `${method} ${path}`);
});

// ---------------------------------------------------------------------------------------------------
// the stdio proxy
// ---------------------------------------------------------------------------------------------------

async function withSink(fn) {
  const alerts = [];
  const server = http.createServer((req, res) => {
    if (req.url.startsWith("/api/policy")) { res.writeHead(503); res.end(""); return; } // console down: the cached policy applies
    if (req.url === "/api/alerts" && req.method === "POST") {
      let b = ""; req.on("data", (c) => (b += c));
      req.on("end", () => { try { alerts.push(JSON.parse(b)); } catch { /* ignore */ } res.writeHead(200); res.end("{}"); });
      return;
    }
    res.writeHead(404); res.end();
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  try { return await fn(`http://127.0.0.1:${server.address().port}`, alerts); } finally { await new Promise((r) => server.close(r)); }
}

async function driveProxy(url, policy, label, messages) {
  const home = mkdtempSync(join(tmpdir(), "moorai-idxtools-proxy-"));
  mkdirSync(join(home, ".moorai"), { recursive: true });
  writeFileSync(join(home, ".moorai", "config.json"), JSON.stringify({ serverUrl: url, tenant: "idx", installToken: "tok" }));
  writeFileSync(join(home, ".moorai", "hook-policy.json"), JSON.stringify(policy));
  const recv = join(home, "recv.log");
  const env = { ...process.env, HOME: home, USERPROFILE: home, MoorAI_SERVER: url, MoorAI_TENANT: "idx" };
  delete env.XDG_CONFIG_HOME; delete env.XDG_STATE_HOME;
  const child = spawn(process.execPath, [GUARD, "--server", label, "--", process.execPath, FAKE, recv], { cwd: home, stdio: ["pipe", "pipe", "pipe"], env });
  child.stderr.on("data", () => {});
  const byId = new Map();
  let buf = "";
  child.stdout.on("data", (c) => {
    buf += c.toString();
    let nl;
    while ((nl = buf.indexOf("\n")) >= 0) {
      const line = buf.slice(0, nl); buf = buf.slice(nl + 1);
      try { const m = JSON.parse(line); if (m.id != null) byId.set(m.id, m); } catch { /* ignore */ }
    }
  });
  for (const m of messages) child.stdin.write(JSON.stringify(m) + "\n");
  const want = messages.map((m) => m.id);
  const deadline = Date.now() + 10000;
  while (!want.every((id) => byId.has(id)) && Date.now() < deadline) await new Promise((r) => setTimeout(r, 20));
  await new Promise((r) => setTimeout(r, 300)); // let the alert posts land
  try { child.stdin.end(); } catch { /* ignore */ }
  try { child.kill(); } catch { /* ignore */ }
  const received = existsSync(recv) ? readFileSync(recv, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l)) : [];
  rmTree(home);
  return { byId, received };
}
const rpcCall = (id, name, args) => ({ jsonrpc: "2.0", id, method: "tools/call", params: { name, arguments: args } });
const isBlocked = (m) => Boolean(m && m.result && m.result.isError === true && /MoorAI blocked/.test(String(m.result.content?.[0]?.text)));
const indexAlerts = (alerts) => alerts.filter((a) => a.stage === "index");

test("PROXY report (default): a poisoned document in a vector-store write is reported at stage index and forwarded", async () => {
  await withSink(async (url, alerts) => {
    const r = await driveProxy(url, REPORT, "chroma", [
      rpcCall(1, "chroma_add_documents", { collection_name: "kb", documents: [BENIGN, POISONED], ids: ["a", "b"] }),
      rpcCall(2, "echo", { msg: POISONED })
    ]);
    assert.ok(!isBlocked(r.byId.get(1)), "report mode must not block");
    assert.deepEqual(r.received.map((p) => p.name), ["chroma_add_documents", "echo"]);
    const idx = indexAlerts(alerts);
    assert.ok(idx.some((a) => a.threatId === 40 && a.tool === "desktop:chroma_add_documents" && a.mcpServer === "chroma" && a.riskLevel !== "Blocked"), JSON.stringify(alerts));
    assert.ok(!idx.some((a) => a.tool === "desktop:echo"), "a tool that is not a vector-store write gets no index-stage scan");
    assert.deepEqual(leaks(alerts), []);
  });
});

test("PROXY block: the poisoned write is refused before the server sees it; a benign write and an explicit indexTools name behave", async () => {
  await withSink(async (url, alerts) => {
    const r = await driveProxy(url, { ...BLOCK, indexTools: ["kb_put"] }, "chroma", [
      rpcCall(1, "upsert", { documents: [BENIGN, POISONED] }),
      rpcCall(2, "upsert", { documents: [BENIGN] }),
      rpcCall(3, "kb_put", { body: POISONED })
    ]);
    assert.ok(isBlocked(r.byId.get(1)), JSON.stringify(r.byId.get(1)));
    assert.match(r.byId.get(1).result.content[0].text, /vector-store write: #40/);
    assert.ok(!isBlocked(r.byId.get(2)), "a benign vector-store write must pass");
    assert.ok(isBlocked(r.byId.get(3)), "policy.indexTools names a tool the heuristic would not");
    assert.equal(r.received.length, 1);
    assert.deepEqual(r.received[0].arguments, { documents: [BENIGN] });
    assert.ok(alerts.some((a) => a.category === "MCP: blocked vector-store write" && a.decision === "deny"), JSON.stringify(alerts.map((a) => a.category)));
    assert.ok(indexAlerts(alerts).some((a) => a.threatId === 40 && a.riskLevel === "Blocked"));
    assert.deepEqual(leaks(alerts), []);
  });
});

// ---------------------------------------------------------------------------------------------------
// the HTTP gateway
// ---------------------------------------------------------------------------------------------------

test("GATEWAY report (default): a poisoned add_documents is reported at stage index and forwarded", async () => {
  await scenario({ policy: REPORT }, async ({ con, up, base }) => {
    const r = await rpc(base, call(1, "add_documents", { documents: [{ text: BENIGN }, { text: POISONED }] }));
    assert.equal(r.json.result.isError, false);
    assert.equal(up.calls().length, 1);
    await settle();
    const idx = indexAlerts(con.alerts);
    assert.ok(idx.some((a) => a.threatId === 40 && a.tool === "gateway:add_documents" && a.mcpServer === "remote" && a.riskLevel !== "Blocked"), JSON.stringify(con.alerts));
    assert.deepEqual(leaks(con.alerts), []);
  });
});

test("GATEWAY block: the poisoned write never reaches upstream; a benign write passes", async () => {
  await scenario({ policy: BLOCK }, async ({ con, up, base }) => {
    const bad = await rpc(base, call(1, "upsert", { documents: [BENIGN, POISONED] })); // recognised by its document-array argument
    assert.equal(bad.json.result.isError, true, bad.text);
    assert.match(bad.json.result.content[0].text, /vector-store write: #40/);
    const ok = await rpc(base, call(2, "store_memory", { memory: BENIGN }));
    assert.equal(ok.json.result.isError, false);
    assert.deepEqual(up.calls().map((c) => c.json.params.name), ["store_memory"]);
    await settle();
    assert.ok(con.alerts.some((a) => a.category === "MCP: blocked vector-store write" && a.tool === "gateway:upsert"), JSON.stringify(con.alerts.map((a) => a.category)));
    assert.ok(indexAlerts(con.alerts).some((a) => a.threatId === 40 && a.riskLevel === "Blocked"));
    assert.deepEqual(leaks(con.alerts), []);
  });
});
