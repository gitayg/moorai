// Vector-store WRITE tools seen through MCP: a tools/call that puts documents into a Chroma, Qdrant,
// Pinecone, Weaviate, Milvus or mem0 store (or any server the org names) is content headed for an index,
// so its document arguments are scanned at the "index" stage (cli/index-scan.mjs) before the call is
// forwarded. Used by the stdio proxy (mcp-proxy/moorai-mcp-guard.mjs) and the HTTP gateway
// (mcp-gateway/guard.mjs).
//
// RECOGNITION — conservative, and configurable:
//   1. policy.indexTools: explicit tool names ("add_documents", or "<server>/<tool>" for one server only),
//      matched case-insensitively. Always applies.
//   2. Unless policy.indexToolHeuristic is false, the write tools of real servers, by exact name
//      (BUILTIN, read from each server's source: test/index-tools-mcp.test.mjs lists repo and commit), so
//      they match whatever the operator labels the server; OpenSearch's generic API tool only for a
//      document-write call (POST / PUT / PATCH to _doc, _create, _update or _bulk).
//   3. The heuristic, unless policy.indexToolHeuristic is false. The tool name's words (split on
//      punctuation and camelCase) must contain a WRITE verb, and then ONE of:
//        a store noun in the name   add_documents, index_documents, store_memory, add_memories
//        a vector-store hint        qdrant-store, or upsert / insert / add on a server labelled chroma,
//                                   qdrant, pinecone, weaviate, milvus, mem0, … (VECTOR_HINTS)
//        a document-array argument  { documents: [...] } / texts / chunks / passages / memories
//      A bare `insert` on a server called "postgres" matches nothing, and neither does a name that also
//      carries a read / delete verb (get_index_stats, delete_documents), nor one that creates an index
//      (create-index-for-model, create_vector_index_hash: `index` is the thing created there). `update` and
//      `create` are not write verbs here (update_collection, create_document on a docs server): the real
//      update / create writes are in BUILTIN.
// A miss is not a gap in safety: every tools/call argument is still scanned by mcpGateway at the prompt
// stage. A match ADDS the index-stage detectors and the policy.indexScanAction rule on top.
import { decideIndexChunk } from "./index-scan.mjs";

const WRITE = new Set(["add", "upsert", "insert", "index", "store", "ingest", "embed", "remember", "save"]);
// A name that also says it reads, lists or deletes (get_index_stats, delete_documents) is not a write.
const READ = new Set(["get", "list", "query", "search", "describe", "delete", "remove", "count", "peek", "fetch", "read", "stats", "find"]);
const NOUNS = new Set(["document", "documents", "doc", "docs", "memory", "memories", "vector", "vectors", "embedding", "embeddings", "chunk", "chunks", "passage", "passages", "knowledge"]);
// Write tools of real vector-store and memory MCP servers, verified against their source (2026-10-07).
export const BUILTIN_INDEX_TOOLS = [
  "chroma_add_documents", "chroma_update_documents",                    // chroma-core/chroma-mcp
  "qdrant-store",                                                       // qdrant/mcp-server-qdrant
  "upsert-records",                                                     // pinecone-io/pinecone-mcp
  "weaviate-insert-one", "weaviate-objects-upsert",                     // weaviate standalone / built-in MCP
  "add_memory", "update_memory",                                        // mem0ai/mem0-mcp
  "add_memories",                                                       // OpenMemory (mem0ai/mem0)
  "milvus_insert_data",                                                 // zilliztech/mcp-server-milvus
  "savememorytool", "addagenticmemoriestool", "updateagenticmemorytool", "createagenticmemorysessiontool", // opensearch-mcp-server-py
  "set_vector_in_hash",                                                 // redis/mcp-redis
  "ingest_docs",                                                        // lancedb/lancedb-mcp-server
  "create_entities", "create_relations", "add_observations"             // modelcontextprotocol/servers memory
];
const BUILTIN = new Set(BUILTIN_INDEX_TOOLS);
// opensearch-mcp-server-py's GenericOpenSearchApiTool { method, path, body }: a write when it creates or
// updates documents.
const OS_DOC_WRITE = /(^|\/)_(doc|create|update|bulk)(\/|\?|$)/;
function genericOpenSearchWrite(tool, args) {
  if (String(tool || "").toLowerCase() !== "genericopensearchapitool" || !args || typeof args !== "object") return false;
  return ["POST", "PUT", "PATCH"].includes(String(args.method || "GET").toUpperCase()) && OS_DOC_WRITE.test(String(args.path || ""));
}
export const VECTOR_HINTS = ["chroma", "chromadb", "qdrant", "pinecone", "weaviate", "milvus", "zilliz", "mem0", "openmemory", "lancedb", "pgvector", "faiss", "vespa", "marqo", "turbopuffer", "vectorize", "vectordb", "vectorstore", "vector", "memory", "rag"];
const DOC_ARGS = ["documents", "docs", "texts", "chunks", "passages", "memories", "page_content", "pagecontent"];

function words(name) {
  return String(name || "")
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(Boolean);
}

function policyNamed(policy, tool, server) {
  const list = policy && Array.isArray(policy.indexTools) ? policy.indexTools : [];
  const t = String(tool || "").toLowerCase(), q = `${String(server || "").toLowerCase()}/${t}`;
  return list.some((e) => typeof e === "string" && (e.toLowerCase() === t || e.toLowerCase() === q));
}

function docArray(args) {
  if (!args || typeof args !== "object" || Array.isArray(args)) return false;
  return Object.entries(args).some(([k, v]) => DOC_ARGS.includes(k.toLowerCase()) && Array.isArray(v) && v.length > 0);
}

// → { match: false } | { match: true, via: "policy" | "builtin" | "name" | "server" | "args" }
export function indexToolMatch({ tool, server, args, policy } = {}) {
  if (policyNamed(policy, tool, server)) return { match: true, via: "policy" };
  if (policy && policy.indexToolHeuristic === false) return { match: false };
  if (BUILTIN.has(String(tool || "").toLowerCase()) || genericOpenSearchWrite(tool, args)) return { match: true, via: "builtin" };
  const w = words(tool);
  if (w.some((x) => READ.has(x))) return { match: false };
  // create_vector_index_hash, create-index-for-model: an index is being created, not written to.
  if (w.includes("create") && w.some((x) => x === "index" || x === "indexes" || x === "indices")) return { match: false };
  if (!w.some((x) => WRITE.has(x))) return { match: false };
  if (w.some((x) => NOUNS.has(x))) return { match: true, via: "name" };
  const hinted = (s) => words(s).some((x) => VECTOR_HINTS.includes(x));
  if (w.some((x) => VECTOR_HINTS.includes(x)) || hinted(server)) return { match: true, via: "server" };
  if (docArray(args)) return { match: true, via: "args" };
  return { match: false };
}

// A tools/call → null (not a vector-store write, or the scan failed: fail-open) or the index verdict
// over its arguments, every string value of them, as one chunk.
export function indexWriteScan(engine, policy, { tool, server, args } = {}) {
  try {
    if (!engine) return null;
    const m = indexToolMatch({ tool, server, args, policy });
    if (!m.match) return null;
    return { ...decideIndexChunk(engine, policy, args == null ? {} : args), via: m.via };
  } catch { return null; }
}
