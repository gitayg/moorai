// Local model servers reachable WITHOUT MoorAI: LOCAL_MODEL_EXPOSED.
//
// A local model server (Ollama, LM Studio, llama.cpp, vLLM, …) has no authentication: any process that
// can open its port can run the models, which is how an implant "lives off the AI" without touching a
// cloud key. MoorAI's model proxy (model-proxy/, route /ollama → http://127.0.0.1:11434) checks what goes
// through it, but a server that ANY local process can reach directly is not behind it.
//
//   discovery   listening sockets from the inventory's TCP table (cli/local-ai-inventory.mjs tcpTable),
//               matched to a runtime by process name or a distinctive default port (LOCAL_AI_RUNTIMES:
//               ollama 11434, lmstudio 1234, llama-server 8080, vllm 8000, and the inventory's other rows)
//   bind        loopback | all-interfaces (*, 0.0.0.0, ::) | lan (a specific non-loopback address).
//               Several sockets for one runtime+port report the widest bind.
//   viaProxy    true ONLY for a loopback-only server that this process cannot connect to: MEASURED with a
//               TCP connect from the scan, which runs as the same user an implant would. Ollama has no
//               unix-socket mode (envconfig.Host parses host:port only), so the proxy-only setup is a
//               loopback port that the firewall lets only the proxy's own account reach (docs note:
//               "proxy-only"). A loopback port the user can reach is reachable by any process the user
//               runs, so it is viaProxy false. A non-loopback bind is always false: whether other hosts
//               can reach it cannot be measured from this device.
//   alert       LOCAL_MODEL_EXPOSED (Medium) for a server with viaProxy false, unless the signed policy says
//               localModelExposure "off". Once per change: the set of exposed runtime|port|bind is kept
//               and only an entry not in the previous scan's set alerts.
// Content-free: runtime id, port, bind class, a boolean. Never an address, a pid, a path or a model name.
import { connect as netConnect } from "node:net";
import { LOCAL_AI_RUNTIMES, matches, bindClass } from "./local-ai-inventory.mjs";
import { normName } from "./listen-sockets.mjs";

export const EXPOSURE_REASON = "LOCAL_MODEL_EXPOSED";
export const EXPOSURE_CATEGORY = "Local model server reachable without MoorAI";
const CONTRACT_RUNTIME = { ollama: "ollama", lmstudio: "lmstudio", "llama.cpp": "llamacpp", vllm: "vllm" };
const WIDTH = { loopback: 0, lan: 1, "all-interfaces": 2 };

export const exposurePolicy = (policy) => (policy && policy.localModelExposure === "off" ? "off" : "alert");

// TCP connect probe → true when it connects. Nothing is sent; the socket is closed on connect.
export function tcpReachable(host, port, timeoutMs = 500) {
  return new Promise((resolve) => {
    let done = false;
    const fin = (v) => { if (!done) { done = true; try { s.destroy(); } catch { /* closed */ } resolve(v); } };
    const s = netConnect({ host, port });
    s.setTimeout(timeoutMs, () => fin(false));
    s.once("connect", () => fin(true));
    s.once("error", () => fin(false));
  });
}

// sockets: tcpTable().sockets. → [{ runtime, port, bind, viaProxy }] sorted by runtime, port.
export async function localModelServers(sockets, { connect = tcpReachable, table = LOCAL_AI_RUNTIMES } = {}) {
  if (!Array.isArray(sockets)) return [];
  const found = new Map();
  for (const s of sockets) {
    if (s.state !== "listen") continue;
    const name = normName(s.proc);
    const r = table.find((x) => matches(x, name)) || table.find((x) => x.portAlone && x.ports.includes(s.lport));
    if (!r) continue;
    const runtime = CONTRACT_RUNTIME[r.runtime] || "other";
    const key = `${runtime}|${s.lport}`;
    const e = found.get(key) || { runtime, port: s.lport, bind: "loopback", hosts: new Set() };
    const b = bindClass(s.lhost);
    if (WIDTH[b] > WIDTH[e.bind]) e.bind = b;
    if (b === "loopback") e.hosts.add(String(s.lhost).replace(/^\[|\]$/g, ""));
    found.set(key, e);
  }
  const out = [];
  for (const e of found.values()) {
    let viaProxy = false;
    if (e.bind === "loopback") {
      let reachable = false;
      for (const h of e.hosts.size ? e.hosts : ["127.0.0.1"]) { if (await connect(h, e.port)) { reachable = true; break; } }
      viaProxy = !reachable;
    }
    out.push({ runtime: e.runtime, port: e.port, bind: e.bind, viaProxy });
  }
  return out.sort((a, b) => a.runtime.localeCompare(b.runtime) || a.port - b.port);
}

const exposureKey = (s) => `${s.runtime}|${s.port}|${s.bind}`;
// Pure. prev: the previous scan's exposed keys. → { alerts, next } (next is what to store for the next scan).
export function exposureAlerts(servers, { policy = null, prev = [], ts = new Date().toISOString() } = {}) {
  if (exposurePolicy(policy) === "off") return { alerts: [], next: [] };
  const exposed = (servers || []).filter((s) => !s.viaProxy);
  const before = new Set(Array.isArray(prev) ? prev : []);
  const alerts = exposed.filter((s) => !before.has(exposureKey(s))).map((s) => ({
    threatId: 0, reasonCode: EXPOSURE_REASON, category: EXPOSURE_CATEGORY, riskLevel: "Medium", stage: "inventory", tool: "inventory:local-model",
    ts, contentHash: `local-model:${exposureKey(s)}`, runtime: s.runtime, port: s.port, bind: s.bind
  }));
  return { alerts, next: exposed.map(exposureKey).sort() };
}
