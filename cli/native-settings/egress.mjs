// egressRules (in policy order, first match decides) -> a host's domain allow and deny lists (unordered,
// deny wins). Shared by every host that has domain lists. Pure.
//
//   domainPlan(intent.egress, caps, tag) -> { allows:[{host, kind, ports, index}], blocks:[...], unexpressed }
//   caps: { ports: true|false, ip: "exact"|"approximated", suffix: "exact"|"approximated" }
//
// What a domain list cannot carry, reported per rule and never widened silently:
//   binary/method/path  an allow becomes domain-wide (coarsened); a block stays MoorAI's alone (omitted),
//                       because a domain-wide block would refuse traffic the rule lets through.
//   port (no port syntax) the same split: allow coarsened, block omitted.
//   an allow followed by an overlapping unconditional block: the host refuses the overlap (deny wins)
//                       where MoorAI's first match allowed it (narrowed).

const overlapHost = (a, b) => {
  const under = (x, s) => x.host === s.host || x.host.endsWith(`.${s.host}`);
  if (a.kind !== "suffix" && b.kind !== "suffix") return a.host === b.host;
  if (a.kind === "suffix" && b.kind === "suffix") return under(a, b) || under(b, a);
  const [s, x] = a.kind === "suffix" ? [a, b] : [b, a];
  return x.host.endsWith(`.${s.host}`);
};
const overlapPort = (a, b) => !a.ports || !b.ports || a.ports.some((p) => b.ports.includes(p));

export function domainPlan(eg, caps, tag) {
  const unexpressed = [], allows = [], blocks = [];
  const line = (e, fields, effect, reason) => unexpressed.push({ source: "egressRules", index: e.index, ...(e.id ? { id: e.id } : {}), fields, effect, reason });
  for (const e of eg.entries) {
    if (e.cond.length) {
      if (!e.allow) { line(e, e.cond, "omitted", `${tag}-request-fields`); continue; }
      line(e, e.cond, "coarsened", `${tag}-request-fields`);
    }
    let ports = e.ports;
    if (ports && !caps.ports) {
      if (!e.allow) { line(e, ["port"], "omitted", `${tag}-no-port-syntax`); continue; }
      line(e, ["port"], "coarsened", `${tag}-no-port-syntax`);
      ports = null;
    }
    if ((e.kind === "ip4" || e.kind === "ip6") && caps.ip !== "exact") line(e, ["host"], "approximated", `${tag}-ip-literal-unstated`);
    if (e.kind === "suffix" && caps.suffix !== "exact") line(e, ["host"], "approximated", `${tag}-wildcard-semantics-unstated`);
    const x = { index: e.index, ...(e.id ? { id: e.id } : {}), host: e.host, kind: e.kind, ports, conditional: e.cond.length > 0 };
    (e.allow ? allows : blocks).push(x);
  }
  for (const a of allows) {
    if (blocks.some((b) => b.index > a.index && overlapHost(a, b) && overlapPort(a, b))) line(a, ["host"], "narrowed", `${tag}-deny-wins`);
  }
  return { allows, blocks, unexpressed };
}

// "*.example.com" for a suffix rule; with ports, one entry per port when the host has port syntax.
export function domainStrings(x, { ports = false } = {}) {
  const h = x.kind === "suffix" ? `*.${x.host}` : x.host;
  if (!ports || !x.ports) return [h];
  return x.ports.map((p) => `${h}:${p}`);
}
