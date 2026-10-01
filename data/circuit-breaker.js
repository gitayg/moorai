// Runaway-agent circuit breaker — an agent stuck in a loop, or burning calls at machine speed.
//
// Four trips, per session (keyed by the caller on session id + sub-agent id, so parallel sub-agents do
// not add up into one another's loop):
//
//   repeat   the same tool call (tool + a keyed hash of its arguments) `repeat` times inside
//            `repeatWindowSec`, with no change in its result. A result that changes is progress: `npm
//            test` re-run while the agent fixes the code returns a different failure each time and never
//            trips. A failure counts as "no change", and so does a call whose result never reached the
//            hook (an empty output).
//   cycle    the last `cycleK` repetitions of a 2-, 3- or 4-call pattern are identical calls with
//            unchanged results — an agent flipping one edit back and forth, or alternating two failing
//            commands.
//   rate     `ratePerMin` calls inside one minute. Off unless an org sets it: under a modelled timing a
//            fast sub-agent's parallel calls (~150/min) cannot be told from a runaway loop (~155/min).
//   budget   `maxCalls` calls in the session. Off unless an org sets it.
//
// Token burn is not here: no hook event Claude Code sends to PreToolUse or PostToolUse carries token
// usage or cost (code.claude.com/docs/en/hooks, common input fields), so there is nothing to measure.
//
// policy.circuitBreaker.mode: "report" (default) posts one alert per trip kind per session and changes
// nothing; "deny" also denies the tripping call and every later call in the session until `cooldownMin`
// has passed (0 = for the rest of the session); "off". The hook coaches an unenrolled device instead.
//
// Pure and browser-safe. The caller hashes each call's signature and result with a device key; the state
// holds those hashes, timestamps and counts, never a tool argument or a byte of output.

export const CIRCUIT_DEFAULTS = {
  mode: "report",        // "report" | "deny" | "off"
  repeat: 15,            // identical calls with an unchanged result ...
  repeatWindowSec: 300,  // ... inside this window
  cycleK: 5,             // repetitions of a 2-4 call pattern with unchanged results
  cycleWindowSec: 900,
  ratePerMin: 0,         // calls inside any 60 s (0 = off)
  maxCalls: 0,           // calls in one session (0 = off)
  cooldownMin: 15,       // deny mode: how long a tripped session stays paused (0 = rest of the session)
  maxSessions: 32
};
const RING = 64;
const TTL = 24 * 3600000;

const ZERO_OK = new Set(["cooldownMin", "ratePerMin", "maxCalls"]);
export function circuitConfig(policy) {
  const p = policy && typeof policy.circuitBreaker === "object" && policy.circuitBreaker ? policy.circuitBreaker : {};
  const out = { mode: ["report", "deny", "off"].includes(p.mode) ? p.mode : CIRCUIT_DEFAULTS.mode };
  for (const k of Object.keys(CIRCUIT_DEFAULTS)) {
    if (k === "mode") continue;
    const v = p[k];
    out[k] = Number.isFinite(v) && (v > 0 || (ZERO_OK.has(k) && v === 0)) ? Math.floor(v) : CIRCUIT_DEFAULTS[k];
  }
  out.repeat = Math.max(2, out.repeat);
  out.cycleK = Math.max(2, out.cycleK);
  return out;
}

const num = (v) => typeof v === "number" && Number.isFinite(v);
const obj = (v) => v && typeof v === "object" && !Array.isArray(v);

function cleanState(state, now) {
  const out = { v: 1, sessions: {} };
  const ss = obj(state) && obj(state.sessions) ? state.sessions : {};
  for (const [k, s] of Object.entries(ss)) {
    if (!obj(s) || !num(s.last) || !num(s.n) || !Array.isArray(s.ring) || now - s.last > TTL) continue;
    const alerted = {};
    if (obj(s.alerted)) for (const [a, t] of Object.entries(s.alerted)) if (num(t)) alerted[a] = t;
    out.sessions[k] = {
      last: s.last, n: s.n,
      ring: s.ring.filter((x) => Array.isArray(x) && x.length === 3 && num(x[0]) && typeof x[1] === "string" && typeof x[2] === "string").slice(-RING),
      rate: Array.isArray(s.rate) ? s.rate.filter(num).slice(-1000) : [],
      until: num(s.until) ? s.until : 0,
      why: typeof s.why === "string" ? s.why.slice(0, 300) : "",
      kind: typeof s.kind === "string" ? s.kind.slice(0, 16) : "",
      alerted
    };
  }
  return out;
}

// Same signature `sig`, newest first, inside the window: how many in a row (the current call included)
// share one result. Only calls whose result is known count: an unknown result ("") neither breaks the run
// nor extends it, so hosts that forward no results (the Codex, Copilot, Gemini and Cursor adapters) never
// trip on a command re-run while its output changes.
function repeatRun(ring, sig, from) {
  let count = 1, ref;
  for (let i = ring.length - 1; i >= 0; i--) {
    const [ts, s, out] = ring[i];
    if (ts < from) break;
    if (s !== sig || !out) continue;
    if (ref === undefined) ref = out; else if (out !== ref) break;
    count++;
  }
  return count;
}

// The tail of the history (current call last) is `k` repetitions of a period-P pattern of not-all-equal
// signatures, and no position's result changed between repetitions.
function cycleAt(entries, k) {
  for (let p = 2; p <= 4; p++) {
    const L = p * k;
    if (entries.length < L) continue;
    const tail = entries.slice(-L);
    const pat = tail.slice(0, p).map((e) => e[1]);
    if (pat.every((s) => s === pat[0])) continue;
    let ok = true;
    for (let i = p; i < L && ok; i++) {
      if (tail[i][1] !== tail[i - p][1]) ok = false;
      else if (tail[i][2] && tail[i - p][2] && tail[i][2] !== tail[i - p][2]) ok = false;
    }
    // "Unchanged" needs evidence: with no recorded result in the tail (adapter hosts) a cycle is not shown.
    if (ok && tail.some((e) => e[2])) return p;
  }
  return 0;
}

function pauseText(cfg) { return cfg.cooldownMin > 0 ? `tool calls in this session are paused for ${cfg.cooldownMin} min` : "tool calls in this session are paused until it ends"; }
const fmtWin = (sec) => (sec % 60 === 0 ? `${sec / 60} min` : `${sec} s`);

// One PreToolUse call. `sig` is the caller's keyed hash of tool + arguments. Returns { state, alerts:
// [{ kind, alert }], deny: null | { kind, reason }, trip: "" | kind (this call tripped), why: the trip's
// reason text (fixed wording and counts), dirty }.
export function assessCall(state, session, sig, now, cfg = circuitConfig(null)) {
  const st = cleanState(state, now);
  if (cfg.mode === "off" || typeof sig !== "string" || !sig) return { state: st, alerts: [], deny: null, trip: "", why: "", dirty: false };
  let s = st.sessions[session];
  if (!s) s = st.sessions[session] = { last: now, n: 0, ring: [], rate: [], until: 0, why: "", kind: "", alerted: {} };
  s.last = now;
  s.n += 1;
  // A paused session (deny mode): every call is denied until the cooldown ends, then history restarts.
  if (s.until) {
    if (s.until === -1 || now < s.until) return { state: st, alerts: [], deny: { kind: s.kind, reason: s.why }, trip: "", why: "", dirty: true };
    s.until = 0; s.ring = []; s.rate = []; s.why = ""; s.kind = "";
  }
  s.rate = s.rate.filter((t) => now - t < 60000);
  s.rate.push(now);
  const trips = [];
  const rep = repeatRun(s.ring, sig, now - cfg.repeatWindowSec * 1000);
  if (rep >= cfg.repeat) trips.push({ kind: "repeat", sig: { kind: "repeat", count: rep, windowSec: cfg.repeatWindowSec }, why: `the same tool call ran ${rep} times in ${fmtWin(cfg.repeatWindowSec)} with no change in its result` });
  const recent = s.ring.filter((e) => e[0] >= now - cfg.cycleWindowSec * 1000);
  const period = cycleAt([...recent, [now, sig, ""]], cfg.cycleK);
  if (period) trips.push({ kind: "cycle", sig: { kind: "cycle", period, repetitions: cfg.cycleK, windowSec: cfg.cycleWindowSec }, why: `the same ${period} tool calls repeated ${cfg.cycleK} times with no change in their results` });
  if (cfg.ratePerMin && s.rate.length >= cfg.ratePerMin) trips.push({ kind: "rate", sig: { kind: "rate", count: s.rate.length, windowSec: 60 }, why: `${s.rate.length} tool calls in one minute` });
  if (cfg.maxCalls && s.n >= cfg.maxCalls) trips.push({ kind: "budget", sig: { kind: "budget", count: s.n, maxCalls: cfg.maxCalls }, why: `this session reached its budget of ${cfg.maxCalls} tool calls` });
  s.ring.push([now, sig, ""]);
  if (s.ring.length > RING) s.ring = s.ring.slice(-RING);

  const alerts = [];
  for (const t of trips) {
    if (t.kind in s.alerted) continue;
    s.alerted[t.kind] = now;
    alerts.push({ kind: t.kind, alert: { threatId: 38, category: t.kind === "rate" ? "Agent behavior: runaway call rate" : t.kind === "budget" ? "Agent behavior: session call budget reached" : "Agent behavior: runaway loop", riskLevel: cfg.mode === "deny" ? "Blocked" : "Medium", stage: "behavior", contentHash: `cb:${t.kind}`, signature: { ...t.sig, mode: cfg.mode } } });
  }
  let deny = null;
  const trip = trips[0] ? trips[0].kind : "";
  if (trips.length && cfg.mode === "deny") {
    s.until = cfg.cooldownMin > 0 ? now + cfg.cooldownMin * 60000 : -1;
    s.kind = trips[0].kind;
    s.why = `runaway-agent circuit breaker: ${trips[0].why}; ${pauseText(cfg)}`;
    deny = { kind: s.kind, reason: s.why };
  }
  const keys = Object.keys(st.sessions);
  if (keys.length > cfg.maxSessions) {
    const others = keys.filter((k) => k !== session).sort((x, y) => st.sessions[x].last - st.sessions[y].last);
    for (const k of others.slice(0, keys.length - cfg.maxSessions)) delete st.sessions[k];
  }
  return { state: st, alerts, deny, trip, why: trips[0] ? trips[0].why : "", dirty: true };
}

// A call's result (PostToolUse: a keyed hash of the output; PostToolUseFailure: "F"), attached to the
// newest call of that signature that has none yet.
export function recordOutcome(state, session, sig, outcome, now) {
  const st = cleanState(state, now);
  const s = st.sessions[session];
  if (!s || typeof outcome !== "string" || !outcome) return { state: st, dirty: false };
  for (let i = s.ring.length - 1; i >= 0; i--) {
    if (s.ring[i][1] === sig && !s.ring[i][2]) { s.ring[i][2] = outcome.slice(0, 32); return { state: st, dirty: true }; }
  }
  return { state: st, dirty: false };
}
