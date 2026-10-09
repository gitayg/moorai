// The egress rules of cli/egress-rules.mjs, applied to a connection the proxy sees: a plain-HTTP request
// (`GET http://host/path`: host, port, method and path) or a CONNECT tunnel (`host:port` only — TLS is not
// decrypted, so a rule's `method` and `path` are unknown there).
//
// UNKNOWN FIELDS, as cli/egress-rules.mjs defines them. The binary is never known at the network layer (a
// socket does not say which program opened it), so it is null on every target. An `allow` rule that sets
// `binary` (or, for CONNECT, `method` / `path`) therefore never matches here; a `block` rule does, on the
// destination alone. An `alert` rule that sets an unknown field matches too, for the report, but it cannot
// be what lets the connection through: the connection is judged again with that rule set aside, and the
// stricter of the two outcomes stands. Otherwise an `alert` rule written for `curl` would open its host to
// every process in the workload under a `block` default.
//
// TRUST SOURCES. The rules come from the verified console policy and the root-owned machine-wide config,
// exactly as the hook reads them (egressFrom), plus the egress rules of the workload profile whose
// `match.serviceId` names this workload. There is no cwd at the network layer, so a profile that matches
// on `repo` never matches here.
//
// Pure. Never throws to the caller: an error comes back as `error` and the caller refuses the connection.
import { cachedEgress, egressChain, judgeTargets, urlTargets } from "../cli/egress-rules.mjs";
import { normalizeHost } from "./address.mjs";
import { requestPath } from "./path.mjs";
import { profilesFrom, matchProfile, rejectedAlert } from "../cli/workload-profile.mjs";

const RANK = { allow: 0, alert: 1, block: 2 };
const PROFILES = new WeakMap();
const NO_DOC = {};
function profilesOf(policy, system) {
  const k1 = policy && typeof policy === "object" ? policy : NO_DOC, k2 = system && typeof system === "object" ? system : NO_DOC;
  let inner = PROFILES.get(k1);
  if (!inner) PROFILES.set(k1, (inner = new WeakMap()));
  let r = inner.get(k2);
  if (!r) inner.set(k2, (r = profilesFrom({ policy, system })));
  return r;
}

// A network-layer target: { binary: null, scheme, host, port, method, path } (method / path null on CONNECT).
export function networkTarget({ scheme, host, port, method = null, path = null }) {
  return { binary: null, binaries: new Set(), scheme, host, port, method, path };
}

// A plain-HTTP request in absolute form → a target, or null when it is not one the proxy accepts: not
// http://, a host no rule could name, a port outside 1-65535, a URL that cli/egress-rules.mjs's two
// parsers read with different hosts (urlTargets returns both; the proxy would connect to one of them), or
// a path path.mjs refuses. The target's path is the canonical one (path.mjs), which is also what is sent.
export function httpTarget(rawUrl, method) {
  const d = httpDestination(rawUrl, method);
  const path = d ? requestPath(rawUrl) : null;
  return path === null ? null : { ...d, path };
}

// httpTarget's host and port checks alone (path null): for naming the destination of a refused path.
export function httpDestination(rawUrl, method) {
  if (!/^http:\/\//i.test(String(rawUrl || ""))) return null;
  const read = urlTargets(rawUrl, { binary: null, method });
  if (read.length !== 1 || read[0].path == null) return null;
  const host = normalizeHost(read[0].host);
  const port = read[0].port;
  if (!host || host !== read[0].host || !Number.isInteger(port) || port < 1 || port > 65535) return null;
  return networkTarget({ scheme: "http", host, port, method });
}

// A CONNECT authority (`host:port`, `[v6]:port`) → a target with method and path unknown, or null.
export function connectTarget(authority) {
  const m = /^(\[[0-9A-Fa-f:.]+\]|[^:[\]]+):(\d{1,5})$/.exec(String(authority || ""));
  const host = m ? normalizeHost(m[1]) : null;
  const port = m ? Number(m[2]) : 0;
  if (!host || port < 1 || port > 65535) return null;
  return networkTarget({ scheme: "connect", host, port });
}

// Does this rule constrain a field the target does not know?
function leansOnUnknown(rule, t) {
  return !!(rule.binary && t.binary == null) || !!(rule.method && t.method == null) || !!(rule.path && t.path == null);
}

// → { action, ref, ruleId?, grant, explicit, profileId?, rejected, error? }
//   action    allow | alert | block
//   ref       the rule that set the action ("policy#2", "profile:ci#0", "default", "loopback")
//   grant     the ref that lets the connection through when it is not blocked
//   explicit  an allow or alert rule granted the connection (never a block rule, never egressDefault, never
//             the loopback exemption)
//   exactHost explicit, and still granted when every *.suffix allow / alert rule is set aside: a rule whose
//             host is an exact name or an IP literal grants it. A private address or an IP literal is
//             reachable only then; a wildcard never vouches for one
export function judgeConnection(target, { policy = null, system = null, serviceId = "" } = {}) {
  try {
    const eg = cachedEgress(policy, system);
    const { profiles, rejected } = profilesOf(policy, system);
    const profile = serviceId ? matchProfile(profiles, { serviceId, repo: "" }) : null;
    const ch = egressChain(profile, eg);
    const strict = { dflt: ch.dflt, chain: ch.chain.map((s) => ({ ...s, rules: s.rules.filter((r) => !(r.action === "alert" && leansOnUnknown(r, target))) })) };
    // The same chain with every *.suffix allow / alert rule set aside: what an exact host grants alone.
    const exactOnly = { dflt: strict.dflt, chain: strict.chain.map((s) => ({ ...s, rules: s.rules.filter((r) => r.action === "block" || r.host.exact !== undefined) })) };
    const v1 = judgeTargets([target], ch).verdicts[0];
    const v2 = judgeTargets([target], strict).verdicts[0];
    const v3 = judgeTargets([target], exactOnly).verdicts[0];
    const granted = (v) => v.action !== "block" && v.ref !== "default" && v.ref !== "loopback";
    // v1 differs from v2 only when an alert rule that leans on an unknown field decided v1.
    const top = RANK[v1.action] > RANK[v2.action] ? v1 : v2;
    const out = {
      action: top.action,
      ref: top.ref,
      ...(top.ruleId ? { ruleId: top.ruleId } : {}),
      grant: v2.ref,
      explicit: granted(v2),
      exactHost: granted(v2) && granted(v3),
      ...(profile ? { profileId: profile.id } : {}),
      rejected: eg.rejected.length ? [...rejected, ...eg.rejected] : rejected
    };
    return out;
  } catch (e) {
    return { action: "block", ref: "error", grant: "error", explicit: false, exactHost: false, rejected: [], error: String((e && e.message) || e).slice(0, 200) };
  }
}

export { rejectedAlert };
