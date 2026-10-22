// Weakening oversight (#84) in a shell command, read structurally (data/shell-parse.js), judged on what the
// command changes:
//   * deleting or moving away a monitor / alerting / audit-log / telemetry module or directory (rm, git rm,
//     unlink, Remove-Item, mv / git mv to a name without an oversight word, or to /dev/null) -> wiring-removed;
//     the same for a test that guards oversight -> safety-test-weakened;
//   * an in-place edit (sed -i / perl -pi s///, sed '/re/d', yq -i assignments) judged like a Write / Edit of
//     that file (cli/oversight-signals.mjs);
//   * text written to a runtime config file (echo / printf / heredoc > or >> file, tee) that sets a
//     suppression switch or empties a recipient list;
//   * alertmanager silences (amtool silence add), monitoring CRDs deleted (kubectl delete prometheusrule /
//     servicemonitor / podmonitor / alertmanagerconfig), a monitoring component deleted, scaled to zero,
//     stopped or uninstalled (kubectl, helm, systemctl, service, docker);
//   * a persistent env var that turns monitoring or alerting off (setx, launchctl setenv, kubectl set env,
//     heroku config:set, fly secrets set, [Environment]::SetEnvironmentVariable).
// Not judged: an inline env prefix or `export` for one run (`OTEL_SDK_DISABLED=true npm test` is how test
// suites run), reads, and any text in a commit message or a document. The command never leaves this module.
//
// Bounded, and fail closed: a command longer than MAX, a sed / perl script longer than MAX_SCRIPT, or an
// analysis that runs past BUDGET_MS is never cut and judged clean; it raises "analysis-incomplete", which
// cli/hook-core.mjs decideOversight asks on. The sed parsers are linear scanners (no backtracking regex).
import { splitShell, commandOf } from "../data/shell-parse.js";
import { oversightEditSignals, assignedSignals, pathClass, OVERSIGHT_SIGNALS, INCOMPLETE } from "./oversight-signals.mjs";
import { protectedPathHit, protectedKeyInCommand } from "./oversight-surfaces.mjs";
import { words, switchKind, listKind, valueKind, WIRING_FAMILIES, TEST_GUARD_WORDS } from "./oversight-vocab.mjs";

const MAX = 262144;
const MAX_SCRIPT = 65536;
const BUDGET_MS = 250;
const HINT = /\b(?:rm|unlink|shred|trash|del|erase|remove-item|ri|rd|rmdir|mv|move|move-item|rename-item|git|sed|gsed|perl|yq|jq|tee|echo|printf|cat|amtool|kubectl|helm|systemctl|service|docker|podman|setx|launchctl|heroku|fly|flyctl|set-content|add-content|out-file|truncate|setenvironmentvariable)\b|>/i;
const DELETE_BINS = new Set(["rm", "unlink", "shred", "trash", "del", "erase", "remove-item", "ri", "rd", "rmdir"]);
const MOVE_BINS = new Set(["mv", "move", "move-item", "rename-item"]);
const MON_CRD = /^(?:prometheusrules?|servicemonitors?|podmonitors?|alertmanagerconfigs?|alertmanagers?|probes?|thanosrulers?)(?:\.monitoring\.coreos\.com)?(?:\/|$)/i;
const MON_COMPONENT = /(?:^|[\/\-_.])(?:alertmanager|prometheus|otel-?collector|opentelemetry-collector|otelcol(?:-contrib)?|grafana-agent|alloy|datadog(?:-agent)?|newrelic(?:-infra)?|fluent-?bit|fluentd|td-agent|promtail|node[-_]exporter|kube-state-metrics|jaeger|sentry-relay|kube-prometheus-stack|vmagent|vmalert)(?:$|[\/\-_.@:])/i;

const familyWord = (w) => WIRING_FAMILIES.some(([, ok]) => ok(w));
const oversightPath = (p) => words(p).some((w) => familyWord(w));
const guardPath = (p) => words(p).some((w) => TEST_GUARD_WORDS.test(w));
const positional = (args) => args.filter((t) => !/^-/.test(t) && !/^\$/.test(t));

// A path deleted or moved away: what it was.
function removalSignal(p, out) {
  if (!p || p === "/dev/null") return;
  const cls = pathClass(p);
  if (cls === "test" && guardPath(p)) out.add("safety-test-weakened");
  else if (cls === "code" && oversightPath(p)) out.add("wiring-removed");
}

// sed / perl substitution and delete scripts: s<d>A<d>B<d>[flags], /RE/d, /RE/,/RE/d. Linear scanners: a
// backslash takes the next character (never a line terminator), the first unescaped delimiter ends a field.
// A delimiter is any character but a backslash or a line terminator (POSIX sed). Anything else is not an edit.
const unescape = (s) => s.replace(/\\(.)/g, "$1");
const LINE_TERM = /[\n\r\u2028\u2029]/;
function sedField(p, i, delim) {
  for (let j = i; j < p.length; j++) {
    const c = p[j];
    if (c === delim) return { text: p.slice(i, j), next: j + 1 };
    if (c === "\\") { if (j + 1 >= p.length || LINE_TERM.test(p[j + 1])) return null; j++; continue; }
    if (LINE_TERM.test(c)) return null;
  }
  return null;
}
function sedSubst(p) {
  if (p.length < 2 || p[0] !== "s" || p[1] === "\\" || LINE_TERM.test(p[1])) return null;
  const a = sedField(p, 2, p[1]); if (!a) return null;
  const b = sedField(p, a.next, p[1]); if (!b) return null;
  return /^[a-zA-Z0-9]*$/.test(p.slice(b.next)) ? [a.text, b.text] : null;
}
function sedDelete(p) {
  if (p[0] !== "/") return null;
  const a = sedField(p, 1, "/"); if (!a) return null;
  const rest = p.slice(a.next);
  const comma = /^\s*,\s*\//.exec(rest);
  if (comma) { const b = sedField(rest, comma[0].length, "/"); if (b && /^\s*d$/.test(rest.slice(b.next))) return [a.text, b.text]; }
  return /^\s*d$/.test(rest) ? [a.text] : null;
}
function sedEdits(script) {
  const out = [];
  for (const part of String(script).split(/;\s*(?=s\W|\/)|\n/)) {
    const p = part.trim();
    const s = sedSubst(p);
    if (s) { out.push({ before: unescape(s[0]), after: unescape(s[1]).replace(/\\n/g, "\n") }); continue; }
    const d = sedDelete(p);
    if (d) out.push({ before: d.filter(Boolean).map(unescape).join("\n"), after: "" });
  }
  return out;
}
function sedParts(binary, args) {
  let inPlace = false, script = null;
  const files = [], scripts = [];
  for (let i = 0; i < args.length; i++) {
    const t = args[i];
    if (t === "-e" || t === "--expression") { scripts.push(args[++i] || ""); continue; }
    if (binary === "perl" && /^-[a-zA-Z]*e$/.test(t)) { if (/i/.test(t)) inPlace = true; scripts.push(args[++i] || ""); continue; }
    if (/^--in-place/.test(t) || (/^-[a-zA-Z]*i/.test(t) && !t.startsWith("--"))) { inPlace = true; continue; }
    if (t.startsWith("-")) continue;
    if (!scripts.length && script === null && binary !== "perl") { script = t; continue; }
    files.push(t);
  }
  if (script !== null) scripts.push(script);
  return { inPlace, scripts, files };
}

// yq / jq assignment expressions: .a.b = value | .c = []
function exprAssignments(expr) {
  const out = [];
  const re = /(?:^|[|(\s,])\.?([A-Za-z_][\w.\-]*(?:\[\])?)\s*\|?=\s*(\[\s*\]|\{\s*\}|""|''|"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|[^\s|),]+)/g;
  let m;
  while ((m = re.exec(String(expr))) !== null) out.push({ key: m[1].replace(/\[\]$/, ""), value: m[2] });
  return out;
}
function classifyPairs(pairs, context, out) {
  for (const { key, value } of pairs) {
    const leaf = key.includes(".") ? key.slice(key.lastIndexOf(".") + 1) : key;
    const parent = key.includes(".") ? key.slice(0, key.lastIndexOf(".")) : "";
    const sw = switchKind(leaf, parent, value);
    if (sw) out.add(sw);
    const lk = listKind(leaf, `${parent} ${context}`);
    if (lk && valueKind(value) === "empty") out.add(lk === "sink" ? "monitoring-off" : "recipients-emptied");
  }
}
const envPairs = (toks) => toks.map((t) => /^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/.exec(t)).filter(Boolean).map((m) => ({ key: m[1], value: m[2] }));

function judgeSegment(seg, all, idx, opts, out, touched) {
  const toks = seg.tokens;
  const c = commandOf(toks, seg.ps);
  const bin = c ? c.binary : "";
  const args = c ? toks.slice(c.at + 1) : [];
  const pos = positional(args);
  const lower = pos.map((t) => t.toLowerCase());
  // Redirect targets: whatever this segment prints goes into them.
  for (const w of seg.writes || []) {
    touched.add(w);
    let text = "";
    if (bin === "echo" || bin === "printf") text = pos.join(" ").replace(/\\n/g, "\n");
    else if (seg.heredoc) text = seg.heredoc;
    if (text) for (const s of assignedSignals(text, w, opts.cwd)) out.add(s);
  }
  if (!c) return;
  if (DELETE_BINS.has(bin)) { for (const p of pos) { touched.add(p); removalSignal(p, out); } return; }
  if (bin === "truncate" && /-s\s*0|--size=0/.test(args.join(" "))) { for (const p of pos.filter((x) => x !== "0")) { touched.add(p); removalSignal(p, out); } return; }
  if (MOVE_BINS.has(bin) || (bin === "git" && (lower[0] === "mv" || lower[0] === "rm"))) {
    const list = bin === "git" ? pos.slice(1) : pos;
    list.forEach((p) => touched.add(p));
    if (bin === "git" && lower[0] === "rm") { for (const p of list) removalSignal(p, out); return; }
    if (list.length < 2) return;
    const dest = list[list.length - 1];
    if (dest !== "/dev/null" && (oversightPath(dest) || guardPath(dest))) return; // a rename that keeps the name
    for (const p of list.slice(0, -1)) removalSignal(p, out);
    return;
  }
  if (bin === "sed" || bin === "gsed" || bin === "perl") {
    const { inPlace, scripts, files } = sedParts(bin, args);
    if (!inPlace) return;
    files.forEach((f) => touched.add(f));
    if (scripts.some((sc) => sc.length > MAX_SCRIPT)) { out.add(INCOMPLETE); return; }
    for (const f of files) for (const sc of scripts) for (const e of sedEdits(sc)) for (const s of oversightEditSignals({ path: f, before: e.before, after: e.after, cwd: opts.cwd })) out.add(s);
    return;
  }
  if (bin === "yq" || bin === "jq") {
    const inPlace = args.some((t) => t === "-i" || t === "--inplace" || /^-[a-zA-Z]*i$/.test(t)) || (seg.writes || []).length > 0;
    if (!inPlace) return;
    const rest = pos.filter((t) => !/^(?:e|eval|eval-all|ea)$/.test(t));
    const expr = rest.find((t) => /=/.test(t)) || "";
    const files = rest.filter((t) => t !== expr);
    files.forEach((f) => touched.add(f));
    const target = files[0] || (seg.writes || [])[0] || "";
    if (pathClass(target, opts.cwd) === "code") classifyPairs(exprAssignments(expr), target, out);
    return;
  }
  if (bin === "tee") {
    const prev = all[idx - 1];
    const pc = prev && prev.sep === "|" ? commandOf(prev.tokens, prev.ps) : null;
    const text = pc && (pc.binary === "echo" || pc.binary === "printf") ? positional(prev.tokens.slice(pc.at + 1)).join(" ").replace(/\\n/g, "\n") : prev && prev.heredoc ? prev.heredoc : "";
    for (const f of pos) { touched.add(f); if (text) for (const s of assignedSignals(text, f, opts.cwd)) out.add(s); }
    return;
  }
  if (bin === "amtool" && lower[0] === "silence" && (lower[1] === "add" || lower[1] === "import")) { out.add("suppression-flag"); return; }
  if (bin === "kubectl") {
    const verb = lower[0];
    if (verb === "delete" && (MON_CRD.test(lower[1] || "") || pos.slice(1).some((t) => MON_COMPONENT.test(t)))) out.add("wiring-removed");
    if (verb === "scale" && /--replicas[= ]0\b/.test(args.join(" ")) && pos.slice(1).some((t) => MON_COMPONENT.test(t))) out.add("wiring-removed");
    if (verb === "set" && lower[1] === "env") classifyPairs(envPairs(pos.slice(2)), "", out);
    return;
  }
  if (bin === "helm" && (lower[0] === "uninstall" || lower[0] === "delete") && pos.slice(1).some((t) => MON_COMPONENT.test(t))) { out.add("wiring-removed"); return; }
  if ((bin === "systemctl" && ["stop", "disable", "mask", "kill"].includes(lower[0])) || (bin === "service" && ["stop", "disable"].includes(lower[1]))) {
    if (pos.some((t) => MON_COMPONENT.test(t))) out.add("wiring-removed");
    return;
  }
  if ((bin === "docker" || bin === "podman") && (["stop", "rm", "kill"].includes(lower[0]) || (lower[0] === "compose" && ["stop", "rm", "down", "kill"].includes(lower[1])))) {
    if (pos.slice(1).some((t) => MON_COMPONENT.test(t))) out.add("wiring-removed");
    return;
  }
  if (bin === "setx" && pos.length >= 2) { classifyPairs([{ key: pos[0], value: pos[1] }], "", out); return; }
  if (bin === "launchctl" && lower[0] === "setenv" && pos.length >= 3) { classifyPairs([{ key: pos[1], value: pos[2] }], "", out); return; }
  if (bin === "heroku" && lower[0] === "config:set") { classifyPairs(envPairs(pos.slice(1)), "", out); return; }
  if ((bin === "fly" || bin === "flyctl") && lower[0] === "secrets" && lower[1] === "set") { classifyPairs(envPairs(pos.slice(2)), "", out); return; }
  if (bin === "set-content" || bin === "add-content" || bin === "out-file") {
    const p = (() => { for (let i = 0; i < args.length; i++) if (/^-(?:path|filepath|literalpath)$/i.test(args[i])) return args[i + 1]; return pos[0]; })();
    const v = (() => { for (let i = 0; i < args.length; i++) if (/^-value$/i.test(args[i])) return args[i + 1]; return pos[1] || ""; })();
    if (p) { touched.add(p); if (v) for (const s of assignedSignals(String(v).replace(/`n/g, "\n"), p, opts.cwd)) out.add(s); }
  }
}

// → the signals the command raises, in OVERSIGHT_SIGNALS order. opts: { ps, surfaces, cwd, now } (now: the
// clock the time budget reads, for tests).
export function oversightCommandSignals(command, { ps = false, surfaces = null, cwd = "", now = Date.now } = {}) {
  const cmd = typeof command === "string" ? command : "";
  if (!cmd || !HINT.test(cmd)) return [];
  if (cmd.length > MAX) return [INCOMPLETE];
  const deadline = now() + BUDGET_MS;
  const out = new Set(), touched = new Set();
  let segs = [];
  try { segs = splitShell(cmd, ps, 0, { segs: [] }).segs; } catch { segs = []; }
  for (let i = 0; i < segs.length; i++) {
    if (now() > deadline) { out.add(INCOMPLETE); break; }
    try { judgeSegment(segs[i], segs, i, { cwd }, out, touched); } catch { /* one segment never sinks the rest */ }
  }
  if (!out.has(INCOMPLETE) && now() > deadline) out.add(INCOMPLETE);
  // PowerShell / .NET persistent env var, read from the raw text.
  for (const m of cmd.matchAll(/SetEnvironmentVariable\(\s*["']([A-Za-z_][\w]*)["']\s*,\s*["']([^"']*)["']\s*,\s*["']?(?:\[EnvironmentVariableTarget\]::)?(?:User|Machine)/gi)) classifyPairs([{ key: m[1], value: m[2] }], "", out);
  if (surfaces) {
    if ([...touched].some((p) => protectedPathHit(p, surfaces, { cwd, real: true }))) out.add("protected-surface");
    if (protectedKeyInCommand(cmd, surfaces)) out.add("protected-surface");
  }
  return OVERSIGHT_SIGNALS.filter((s) => out.has(s));
}
