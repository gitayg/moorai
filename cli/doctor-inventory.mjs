// Doctor rows for the inventory detectors (v1.15.0): local model exposure, decoy AI keys and AI-API
// callers. Read-only: cli/agent-posture.mjs inventoryPosture with write false places nothing, removes
// nothing, keeps no state and produces no alert. The callers row resolves public host names, so it is
// skipped with --offline.
import { inventoryPosture } from "./agent-posture.mjs";
import { decoyMode } from "./decoy-keys.mjs";
import { exposurePolicy } from "./local-model-exposure.mjs";
import { callerPolicy } from "./ai-api-callers.mjs";

export async function checkInventory(policy, { offline = false, run = inventoryPosture, ...opts } = {}) {
  let r;
  try { r = await run({ policy, write: false, resolve: !offline, ...opts }); } catch (e) { r = null; }
  const rows = [];
  const g = "inventory";
  if (!r) return [{ id: "inventory", group: g, title: "Inventory detectors", status: "warn", summary: "the inventory scan failed" }];
  const { localModelServers: servers, aiApiCallers: callers, decoyKeys } = r.fields;
  const sockets = r.notes.socketSource && r.notes.socketSource !== "none";

  const lm = { id: "local-model-exposure", group: g, title: "Local model servers", details: { servers, policy: exposurePolicy(policy) } };
  const exposed = servers.filter((s) => !s.viaProxy);
  if (!sockets) rows.push({ ...lm, status: "skip", summary: "the TCP table could not be read on this device" });
  else if (!servers.length) rows.push({ ...lm, status: "ok", summary: "no local model server is listening" });
  else if (!exposed.length) rows.push({ ...lm, status: "ok", summary: `${servers.map((s) => `${s.runtime} :${s.port}`).join(", ")} reachable only through MoorAI` });
  else rows.push({ ...lm, status: exposurePolicy(policy) === "off" ? "ok" : "warn", summary: `reachable without MoorAI: ${exposed.map((s) => `${s.runtime} :${s.port} (${s.bind})`).join(", ")}${exposurePolicy(policy) === "off" ? " (policy localModelExposure off)" : ""}`, fix: "bind the server to a loopback port only MoorAI's model proxy may reach (README: proxy-only local models)" });

  const dk = { id: "decoy-keys", group: g, title: "Decoy AI keys", details: { ...decoyKeys, mode: decoyMode(policy) } };
  if (decoyMode(policy) === "place" && decoyKeys.source !== "admin" && !decoyKeys.placed) rows.push({ ...dk, status: "warn", summary: "policy says place, but no decoy is placed yet (they are placed by the next posture heartbeat)" });
  else rows.push({ ...dk, status: "ok", summary: decoyKeys.placed ? `${decoyKeys.placed} placed (${decoyKeys.source}) · policy ${decoyMode(policy)}` : `none placed · policy ${decoyMode(policy)}` });

  const ac = { id: "ai-api-callers", group: g, title: "AI API callers", details: { callers, ambiguousConnections: r.notes.ambiguousConnections ?? null, policy: callerPolicy(policy) } };
  const unknown = callers.filter((c) => !c.known);
  const amb = r.notes.ambiguousConnections ? `; ${r.notes.ambiguousConnections} connection(s) to shared front-end addresses not attributed` : "";
  if (offline) rows.push({ ...ac, status: "skip", summary: "skipped (--offline): needs DNS for the provider hosts" });
  else if (!sockets) rows.push({ ...ac, status: "skip", summary: "the TCP table could not be read on this device" });
  else if (!unknown.length) rows.push({ ...ac, status: "ok", summary: `${callers.length ? callers.map((c) => `${c.processImage}→${c.provider}`).join(", ") : "no process is connected to a known AI API"}${amb}` });
  else rows.push({ ...ac, status: callerPolicy(policy) === "off" ? "ok" : "warn", summary: `not a known AI app, agent or browser: ${unknown.map((c) => `${c.processImage}→${c.provider}`).join(", ")}${amb}`, fix: "find out what the process is; an expected one can be added to the AI catalog" });
  return rows;
}
