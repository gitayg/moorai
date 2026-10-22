// The intent's tool decisions -> one host's deny/ask tokens. Pure.
//
//   mapTools(intent, tag, { deny: map, ask: map|null })
//   map[canonicalTool]: [tokens]  the host's rule(s) for that tool
//                       null      the host runs that tool but has no rule syntax to refuse it
//                       (absent)  MoorAI's adapter for this host maps no host tool to it
// Every tool the host cannot refuse or prompt for is reported against the policy key it came from.

import { effectiveDeny } from "./intent.mjs";

const sourceOf = (intent, t) => (intent.tools.deny.includes(t) ? "tagActions" : "entitlements");

export function mapTools(intent, tag, { deny: dmap, ask: amap = null }) {
  const deny = new Set(), ask = new Set(), unexpressed = [];
  for (const t of effectiveDeny(intent)) {
    const tokens = dmap[t];
    if (tokens === undefined) { unexpressed.push({ source: sourceOf(intent, t), tool: t, effect: "omitted", reason: `${tag}-tool-not-mapped` }); continue; }
    if (tokens === null) { unexpressed.push({ source: sourceOf(intent, t), tool: t, effect: "omitted", reason: `${tag}-no-tool-deny` }); continue; }
    for (const k of tokens) deny.add(k);
  }
  for (const t of intent.tools.ask) {
    const tokens = amap ? amap[t] : null;
    if (tokens === undefined) { unexpressed.push({ source: "tagActions", tool: t, effect: "omitted", reason: `${tag}-tool-not-mapped` }); continue; }
    if (tokens === null) { unexpressed.push({ source: "tagActions", tool: t, effect: "omitted", reason: `${tag}-no-tool-ask` }); continue; }
    for (const k of tokens) if (!deny.has(k)) ask.add(k);
  }
  if (intent.tools.allowOnly) unexpressed.push({ source: "entitlements", effect: "coarsened", reason: `${tag}-allow-only-enumerated` });
  return { deny: [...deny].sort(), ask: [...ask].sort(), unexpressed };
}
