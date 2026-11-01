// Block-mode tool drift, the stale-client half (policy `mcpToolDrift: "block"`, tool-drift.mjs).
//
// Drift is judged from tools/list responses. A server can change a tool after the client's last listing,
// and a client that does not list again then calls the changed tool with nothing compared. So in block
// mode a tools/call is decided against a FRESH ENOUGH listing: when the last whole listing MoorAI judged
// for that server is older than the window, the stdio guard or the gateway first sends its OWN tools/list
// upstream (every page), judges it like any block-mode listing, and only then decides the call: a tool
// unchanged against the approved baseline forwards, one that drifted or vanished is refused.
//
//   * THE WINDOW is the signed policy's `mcpToolRecheckSeconds`, read only from the verified policy like
//     every drift field: an integer number of seconds, 0 = re-list before every call. Default 300.
//     Anything that is not an integer of at least 0 is ignored (the default applies); more than a day
//     is taken as a day.
//   * FRESHNESS is kept per server by the drift tracker (tool-drift.mjs freshWithin): a whole listing it
//     judged, the client's or its own. notifications/tools/list_changed from the server, and any listing
//     that went unjudged, mark it stale. After a listing that went unjudged the client may hold tools
//     MoorAI never saw, so every call is refused until a client listing is judged again, and no re-list
//     is sent meanwhile: what the server tells MoorAI is not what it told the client.
//   * A RE-LIST IS JUDGED, NOT REPORTED: it is complete (every page), so a tool missing from it raises
//     the usual removal alert and loses its verdict, but its fingerprints are not posted to the console,
//     whose view of a server stays the listings its clients received.
//   * ONE RE-LIST IN FLIGHT per server; concurrent calls share it.
//   * A TIME BUDGET (RECHECK_BUDGET_MS) bounds the whole re-list, every page included. A re-list that
//     fails, errors or runs out of budget is decided by the admin's fail mode for the MCP surface
//     (cli/fail-mode.mjs `mcpGateway`): closed refuses the call, open forwards it with an alert.
//   * ALERT MODE NEVER RE-LISTS: no extra request, byte-identical traffic.
//
// The transport sends the request (fetchPage); this file owns the loop, the bounds and the sharing.

export const RECHECK_DEFAULT_SECONDS = 300;
export const RECHECK_MIN_SECONDS = 0;
export const RECHECK_MAX_SECONDS = 86400;
export const RECHECK_BUDGET_MS = 2000;
export const RECHECK_MAX_PAGES = 64;
export const RECHECK_MAX_TOOLS = 4096;
// The `driftCheck` value on an alert whose drift was found by a re-list MoorAI made itself.
export const RECHECK_SOURCE = "recheck";
export const RECHECK_FAILED_CATEGORY = "MCP: tool list re-check failed";

// The window in seconds, from the verified policy.
export function recheckSeconds(policy) {
  const v = policy && policy.mcpToolRecheckSeconds;
  if (typeof v !== "number" || !Number.isInteger(v) || v < RECHECK_MIN_SECONDS) return RECHECK_DEFAULT_SECONDS;
  return Math.min(v, RECHECK_MAX_SECONDS);
}

const isTool = (t) => t && typeof t === "object" && !Array.isArray(t) && typeof t.name === "string";

// Every page of the server's tool list, inside the budget. fetchPage(cursor, { signal }) resolves to one
// page's result ({ tools, nextCursor }) and rejects on an error response, a dead transport or an abort.
// → { tools } or { error: "timeout" | "error" }. Never throws.
export async function relistAll(fetchPage, { budgetMs = RECHECK_BUDGET_MS, maxPages = RECHECK_MAX_PAGES, maxTools = RECHECK_MAX_TOOLS } = {}) {
  const ctl = new AbortController();
  let timer = null;
  const expired = new Promise((resolve) => {
    timer = setTimeout(() => { ctl.abort(); resolve({ error: "timeout" }); }, budgetMs); // ref'd: a pending re-list is work in progress
  });
  const work = (async () => {
    const tools = [];
    const cursors = new Set();
    let cursor;
    for (let page = 0; page < maxPages; page++) {
      const r = await fetchPage(cursor, { signal: ctl.signal });
      if (!r || typeof r !== "object" || !Array.isArray(r.tools)) return { error: "error" };
      for (const t of r.tools) if (isTool(t)) tools.push(t);
      if (tools.length > maxTools) return { error: "error" };
      if (r.nextCursor == null) return { tools };
      const c = typeof r.nextCursor === "string" ? r.nextCursor : JSON.stringify(r.nextCursor);
      if (cursors.has(c)) return { error: "error" }; // a server that loops its cursor never ends the listing
      cursors.add(c);
      cursor = r.nextCursor;
    }
    return { error: "error" };
  })().catch(() => ({ error: ctl.signal.aborted ? "timeout" : "error" }));
  try { return await Promise.race([work, expired]); }
  finally { clearTimeout(timer); ctl.abort(); }
}

// One per guarded server (one per guard process, one per gateway route), around its drift tracker.
export function createRecheck({ tracker, budgetMs = RECHECK_BUDGET_MS }) {
  let inflight = null;
  const due = (policy) => !tracker.awaitingClientListing() && !tracker.freshWithin(recheckSeconds(policy) * 1000);
  // judge(tools) → truthy when the listing was judged (the caller's block-mode judgement, alerts and all),
  // falsy when it could not be. → { ok: true, rechecked } | { ok: false, why }.
  function ensureFresh({ policy, fetchPage, judge }) {
    if (!due(policy)) return Promise.resolve({ ok: true, rechecked: false });
    if (inflight) return inflight;
    const run = (async () => {
      try {
        const r = await relistAll(fetchPage, { budgetMs });
        if (r.error) return { ok: false, why: r.error };
        return judge(r.tools) ? { ok: true, rechecked: true } : { ok: false, why: "error" };
      } catch { return { ok: false, why: "error" }; }
    })();
    inflight = run;
    run.finally(() => { if (inflight === run) inflight = null; });
    return run;
  }
  return { ensureFresh, due, inFlight: () => inflight !== null };
}
