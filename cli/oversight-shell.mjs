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
//     heroku config:set, fly secrets set, [Environment]::SetEnvironmentVariable);
//   * a write onto a memory file or a protected path: besides redirects, tee, sed -i and Set-Content, a cp /
//     install / rsync / mv destination, a curl / wget download, dd of=, git checkout -- / git restore, patch and
//     a bare `> path` (cli/oversight-shell-writes.mjs). While there is a write check to run (memory files on or
//     protected paths declared), a write position whose target is not literal is "analysis-incomplete".
// Where a path lands: every path is resolved against the segment's working directory, tracked across
// segments (cd / pushd / popd / Set-Location / Push-Location / Pop-Location with a literal target; a `cd`
// inside a subshell, a pipeline or a background job does not move the shell around it), then judged relative
// to the project (cwd) as well as as written. A `cd` to a target that is not literal ($VAR, a glob, a
// subshell, ~, -) makes later relative paths unknown: judging one of them raises "analysis-incomplete".
// Redirect, sed and tee targets are also classified through their real path (a doc-named symlink to runtime
// code is runtime code; cli/oversight-signals.mjs pathClasses).
// A move (mv / git mv / Move-Item / Rename-Item, -t / --target-directory read) is a rename only when the
// destination still looks like oversight, stays inside the project, keeps the source's path class (runtime
// code or test) and keeps an importable name; a move outside the project (/tmp, ../), to a doc or fixture
// path, to a .bak / .disabled / .old / .orig name, or to a destination that is not literal is a removal.
// Not judged: an inline env prefix or `export` for one run (`OTEL_SDK_DISABLED=true npm test` is how test
// suites run), reads, and any text in a commit message or a document. The command never leaves this module.
//
// Bounded, and fail closed: a command longer than MAX, a sed / perl script longer than MAX_SCRIPT, an
// analysis that runs past BUDGET_MS, or a command the shell parser fails on is never cut and judged clean; it
// raises "analysis-incomplete", which cli/hook-core.mjs decideOversight asks on. The sed parsers are linear
// scanners (no backtracking regex).
import { statSync } from "node:fs";
import { homedir } from "node:os";
import { resolve, relative, isAbsolute, dirname, basename, join } from "node:path";
import { splitShell, commandOf } from "../data/shell-parse.js";
import { oversightEditSignals, assignedSignals, pathClass, pathClasses, OVERSIGHT_SIGNALS, INCOMPLETE } from "./oversight-signals.mjs";
import { protectedPathHit, protectedKeyInCommand, memoryPathHit, realOf } from "./oversight-surfaces.mjs";
import { words, switchKind, listKind, valueKind, WIRING_FAMILIES, TEST_GUARD_WORDS } from "./oversight-vocab.mjs";
import { writeTargets, bareRedirects, nonLiteral, nullTarget } from "./oversight-shell-writes.mjs";

const MAX = 262144;
const MAX_SCRIPT = 65536;
const BUDGET_MS = 250;
const HINT = /\b(?:rm|unlink|shred|trash|del|erase|remove-item|ri|rd|rmdir|mv|move|move-item|rename-item|git|sed|gsed|perl|yq|jq|tee|echo|printf|cat|amtool|kubectl|helm|systemctl|service|docker|podman|setx|launchctl|heroku|fly|flyctl|set-content|add-content|out-file|truncate|setenvironmentvariable|cp|install|rsync|curl|wget|dd|patch)\b|>/i;
const WRITE_BINS = new Set(["cp", "install", "rsync", "curl", "wget", "dd", "patch"]);
const DELETE_BINS = new Set(["rm", "unlink", "shred", "trash", "del", "erase", "remove-item", "ri", "rd", "rmdir"]);
const MOVE_BINS = new Set(["mv", "move", "move-item", "rename-item"]);
const MON_CRD = /^(?:prometheusrules?|servicemonitors?|podmonitors?|alertmanagerconfigs?|alertmanagers?|probes?|thanosrulers?)(?:\.monitoring\.coreos\.com)?(?:\/|$)/i;
const MON_COMPONENT = /(?:^|[\/\-_.])(?:alertmanager|prometheus|otel-?collector|opentelemetry-collector|otelcol(?:-contrib)?|grafana-agent|alloy|datadog(?:-agent)?|newrelic(?:-infra)?|fluent-?bit|fluentd|td-agent|promtail|node[-_]exporter|kube-state-metrics|jaeger|sentry-relay|kube-prometheus-stack|vmagent|vmalert)(?:$|[\/\-_.@:])/i;

const CD_BINS = new Set(["cd", "chdir", "pushd", "popd", "set-location", "sl", "push-location", "pop-location"]);
const NOT_LITERAL = /[$*?[\]{}`]|^~|^-$/;
const NON_IMPORTABLE = /\.(?:bak|disabled|old|orig)$|~$/i;
const familyWord = (w) => WIRING_FAMILIES.some(([, ok]) => ok(w));
const oversightPath = (p) => words(p).some((w) => familyWord(w));
const guardPath = (p) => words(p).some((w) => TEST_GUARD_WORDS.test(w));
const positional = (args) => args.filter((t) => !/^-/.test(t) && !/^\$/.test(t));

// Paths of one segment: resolved against its working directory (dir; null when it is not certain), and
// relative to the project. at(p) → the absolute path (marks the analysis incomplete when p is relative and
// dir is unknown); written(p) → p as written, against the project; both(p) → the two, deduplicated (every
// sink is judged at both, as removalSignal does); rel(abs) → abs relative to the project when inside it, else
// abs; realRel(abs) → abs's real path relative to the project's real path when inside it, else null.
const inside = (r) => Boolean(r) && r !== ".." && !r.startsWith("../") && !isAbsolute(r);
function pathCtx(project, dir, out) {
  const at = (p) => {
    const s = String(p);
    if (isAbsolute(s)) return resolve(s);
    if (dir === null) { out.add(INCOMPLETE); return resolve(project, s); }
    return resolve(dir, s);
  };
  const written = (p) => resolve(project, String(p));
  const both = (p) => [...new Set([at(p), written(p)])];
  const rel = (abs) => { const r = relative(project, abs).replace(/\\/g, "/"); return inside(r) ? r : abs.replace(/\\/g, "/"); };
  let realProject;
  const realRel = (abs) => {
    if (realProject === undefined) realProject = realOf(project);
    const r = realOf(abs);
    if (!r || !realProject) return null;
    const rr = relative(realProject, r).replace(/\\/g, "/");
    return inside(rr) ? rr : null;
  };
  return { project, at, written, both, rel, realRel };
}
const srcClass = (p) => { const cls = pathClass(p); return (cls === "test" && guardPath(p)) ? "test" : cls === "code" && oversightPath(p) ? "code" : ""; };
// A path deleted or moved away: what it was, as written and as resolved relative to the project.
function removalSignal(p, out, ctx) {
  if (!p || p === "/dev/null") return;
  for (const q of new Set([p, ctx ? ctx.rel(ctx.at(p)) : p])) {
    const k = srcClass(q);
    if (k === "test") out.add("safety-test-weakened");
    else if (k === "code") out.add("wiring-removed");
  }
}
// mv / git mv / Move-Item / Rename-Item → { sources, dest, destIsDir, rename } (rename: Rename-Item's -NewName, a
// name in the source's directory).
const psName = (t, full, min = 2) => { const n = t.slice(1).toLowerCase(); return n.length >= min && full.startsWith(n); };
function moveParts(bin, args, git, ps) {
  const pos = [];
  let target = null, noTarget = false, newName = null;
  for (let i = 0; i < args.length; i++) {
    const t = args[i];
    if (t === "--") { pos.push(...args.slice(i + 1)); break; }
    if (ps && /^-[A-Za-z]/.test(t)) {
      const colon = t.indexOf(":");
      const name = colon > 0 ? t.slice(0, colon) : t;
      const val = () => (colon > 0 ? t.slice(colon + 1) : args[++i]);
      if (psName(name, "destination")) target = val();
      else if (psName(name, "newname")) newName = val();
      else if (psName(name, "path", 1) || psName(name, "literalpath") || name.toLowerCase() === "-lp") pos.push(val());
      else if (["filter", "include", "exclude", "credential"].some((f) => psName(name, f))) val();
      continue;
    }
    if (!git && (t === "--target-directory" || t === "--suffix")) { const v = args[++i]; if (t === "--target-directory") target = v; continue; }
    if (!git && t.startsWith("--target-directory=")) { target = t.slice("--target-directory=".length); continue; }
    if (!git && t === "--no-target-directory") { noTarget = true; continue; }
    if (t.startsWith("--")) continue;
    if (!git && /^-[A-Za-z]/.test(t)) {
      for (let j = 1; j < t.length; j++) {
        const ch = t[j];
        if (ch === "T") noTarget = true;
        if (ch === "t" || ch === "S") { const v = j + 1 < t.length ? t.slice(j + 1) : args[++i]; if (ch === "t") target = v; break; }
      }
      continue;
    }
    if (t.startsWith("-")) continue;
    pos.push(t);
  }
  if (bin === "rename-item") {
    if (newName == null) { if (pos.length < 2) return null; newName = pos[1]; }
    return { sources: pos.slice(0, 1), dest: newName, destIsDir: false, rename: true };
  }
  if (target != null) return { sources: pos, dest: target, destIsDir: true, rename: false };
  if (pos.length < 2) return null;
  return { sources: pos.slice(0, -1), dest: pos[pos.length - 1], destIsDir: noTarget ? false : null, rename: false };
}
const isDir = (abs) => { try { return statSync(abs).isDirectory(); } catch { return false; } };
// A destination keeps the source when, lexically and through its real path, it stays inside the project with
// one of the source's classes and an importable name.
function keepsAt(final, kinds, ctx) {
  const fr = ctx.rel(final);
  if (isAbsolute(fr) || !kinds.has(srcClass(fr)) || NON_IMPORTABLE.test(fr)) return false;
  const rr = ctx.realRel(final);
  return rr !== null && kinds.has(srcClass(rr)) && !NON_IMPORTABLE.test(rr);
}
// Judged twice, the tracked directory's pair (source and destination resolved) and the as-written pair: a
// source of oversight that either pair takes away is removed.
function judgeMove(bin, args, git, opts, ctx, out, touched) {
  const m = moveParts(bin, args, git, opts.ps);
  if (!m) { for (const p of args.filter((t) => !t.startsWith("-"))) ctx.both(p).forEach((a) => touched.add(a)); return; }
  const literal = m.dest && !NOT_LITERAL.test(m.dest) && m.dest !== "/dev/null";
  // A destination (or, into a directory, a source name) that is not literal: where it writes is unknown.
  if (opts.watch && m.dest !== "/dev/null" && (!literal || m.sources.some((s) => nonLiteral(s)))) out.add(INCOMPLETE);
  const pairs = [ctx.at, ctx.written].map((place) => {
    const destAbs = literal ? place(m.dest) : null;
    if (destAbs) touched.add(destAbs);
    const dirDest = m.destIsDir ?? (m.sources.length > 1 || /[\/\\]$/.test(m.dest) || (destAbs !== null && isDir(destAbs)));
    return { place, destAbs, dirDest };
  });
  for (const s of m.sources) {
    let keeps = true;
    for (const { place, destAbs, dirDest } of pairs) {
      const srcAbs = place(s);
      touched.add(srcAbs);
      const final = destAbs ? (m.rename ? join(dirname(srcAbs), m.dest) : dirDest ? join(destAbs, basename(srcAbs)) : destAbs) : null;
      if (final) touched.add(final);
      const kinds = new Set([srcClass(ctx.rel(srcAbs)), srcClass(s)].filter(Boolean));
      if (!kinds.size) continue;
      if (!destAbs) { keeps = false; continue; }
      if (opts.linkedEarlier || !keepsAt(final, kinds, ctx)) keeps = false;
    }
    if (!keeps) removalSignal(s, out, ctx);
  }
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

// The literal destinations a copy, install, download, dd, git checkout / restore or patch writes
// (cli/oversight-shell-writes.mjs) go to the protected-path and memory-file checks, at both the tracked
// directory and as written; a directory destination receives each source under its own name. A destination
// that is not literal is analysis-incomplete when there is anything to check.
const home = (p) => (p === "~" ? homedir() : p.startsWith("~/") ? join(homedir(), p.slice(2)) : p);
function judgeWrites(wt, opts, ctx, out, touched) {
  if (wt.unknown && opts.watch) out.add(INCOMPLETE);
  for (const { dest, sources, dir } of wt.writes) {
    for (const destAbs of ctx.both(home(dest))) {
      touched.add(destAbs);
      if (!sources || !(dir ?? isDir(destAbs))) continue;
      for (const src of sources) {
        if (nonLiteral(src)) { if (opts.watch) out.add(INCOMPLETE); continue; }
        touched.add(join(destAbs, basename(home(src).replace(/[\/\\]+$/, ""))));
      }
    }
  }
}

function judgeSegment(seg, all, idx, opts, out, touched, ctx) {
  const toks = seg.tokens;
  const c = commandOf(toks, seg.ps);
  const bin = c ? c.binary : "";
  const args = c ? toks.slice(c.at + 1) : [];
  const pos = positional(args);
  const lower = pos.map((t) => t.toLowerCase());
  const P = ctx.project;
  // Redirect targets: whatever this segment prints goes into them.
  for (const w of seg.writes || []) {
    if (opts.watch && nonLiteral(w) && !nullTarget(w)) out.add(INCOMPLETE);
    let text = "";
    if (bin === "echo" || bin === "printf") text = pos.join(" ").replace(/\\n/g, "\n");
    else if (seg.heredoc) text = seg.heredoc;
    if (!text && !opts.surfacePaths && !isAbsolute(w)) { touched.add(resolve(P, w)); continue; }
    for (const abs of ctx.both(w)) { touched.add(abs); if (text) for (const s of assignedSignals(text, abs, P)) out.add(s); }
  }
  if (!c) return;
  if (WRITE_BINS.has(bin) || bin === "git") judgeWrites(writeTargets(bin, args), opts, ctx, out, touched);
  if (WRITE_BINS.has(bin)) return;
  const removed = (p) => { ctx.both(p).forEach((a) => touched.add(a)); removalSignal(p, out, ctx); };
  if (DELETE_BINS.has(bin)) { pos.forEach(removed); return; }
  if (bin === "truncate" && /-s\s*0|--size=0/.test(args.join(" "))) { pos.filter((x) => x !== "0").forEach(removed); return; }
  if (bin === "git" && lower[0] === "rm") { pos.slice(1).forEach(removed); return; }
  if (MOVE_BINS.has(bin)) { judgeMove(bin, args, false, opts, ctx, out, touched); return; }
  if (bin === "git" && lower[0] === "mv") { judgeMove("mv", args.slice(args.findIndex((t) => t.toLowerCase() === "mv") + 1), true, opts, ctx, out, touched); return; }
  if (bin === "sed" || bin === "gsed" || bin === "perl") {
    const { inPlace, scripts, files } = sedParts(bin, args);
    if (!inPlace) return;
    const abs = [...new Set(files.flatMap((f) => ctx.both(f)))];
    abs.forEach((f) => touched.add(f));
    if (scripts.some((sc) => sc.length > MAX_SCRIPT)) { out.add(INCOMPLETE); return; }
    for (const f of abs) for (const sc of scripts) for (const e of sedEdits(sc)) for (const s of oversightEditSignals({ path: f, before: e.before, after: e.after, cwd: P })) out.add(s);
    return;
  }
  if (bin === "yq" || bin === "jq") {
    const inPlace = args.some((t) => t === "-i" || t === "--inplace" || /^-[a-zA-Z]*i$/.test(t)) || (seg.writes || []).length > 0;
    if (!inPlace) return;
    const rest = pos.filter((t) => !/^(?:e|eval|eval-all|ea)$/.test(t));
    const expr = rest.find((t) => /=/.test(t)) || "";
    const files = rest.filter((t) => t !== expr);
    files.flatMap((f) => ctx.both(f)).forEach((f) => touched.add(f));
    const first = files[0] ?? (seg.writes || [])[0];
    for (const target of first ? ctx.both(first) : []) if (pathClasses(target, P).some((x) => x.cls === "code")) classifyPairs(exprAssignments(expr), ctx.rel(target), out);
    return;
  }
  if (bin === "tee") {
    const prev = all[idx - 1];
    const pc = prev && prev.sep === "|" ? commandOf(prev.tokens, prev.ps) : null;
    const text = pc && (pc.binary === "echo" || pc.binary === "printf") ? positional(prev.tokens.slice(pc.at + 1)).join(" ").replace(/\\n/g, "\n") : prev && prev.heredoc ? prev.heredoc : "";
    for (const abs of new Set(pos.flatMap((f) => ctx.both(f)))) { touched.add(abs); if (text) for (const s of assignedSignals(text, abs, P)) out.add(s); }
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
    if (p) for (const abs of ctx.both(p)) { touched.add(abs); if (v) for (const s of assignedSignals(String(v).replace(/`n/g, "\n"), abs, P)) out.add(s); }
  }
}

// The working directory a segment runs in: the nearest enclosing subshell scope that changed it, else the
// project. A copy, so a change is stored only under the segment's own scope. moved: a cd ran in that scope
// (or around it), so a later separator that does not make the cd certain leaves the directory unknown.
function dirState(dirs, scope, project) {
  for (let s = scope; ; s = s.includes("/") ? s.slice(0, s.lastIndexOf("/")) : "") {
    const st = dirs.get(s);
    if (st) return { dir: st.dir, stack: [...st.stack], moved: st.moved };
    if (!s) return { dir: project, stack: [], moved: false };
  }
}
// Only && carries a cd to the next segment (it ran only if the cd succeeded), and | (a pipeline runs after the
// && before it), and the end of a $( … ) back into the command that holds it. After ; a newline || & ( ) or
// { } the cd may have failed, or run in the background: the directory of prev's scope is unknown (after `)`,
// whose following separator the parser drops, of every scope around it too).
const CARRIES = new Set(["&&", "|"]);
const parentScope = (s) => (s.includes("/") ? s.slice(0, s.lastIndexOf("/")) : "");
function afterSeparator(prev, seg, dirs) {
  const ps = prev.scope || "";
  if (CARRIES.has(prev.sep) || (prev.sep === "" && ps !== (seg.scope || ""))) return;
  for (let sc = ps; ; sc = parentScope(sc)) {
    const st = dirs.get(sc);
    if (st && st.moved) st.dir = null;
    if (prev.sep !== ")" || !sc) return;
  }
}
const CD_WORD = /^\s*(?:cd|chdir|pushd|popd|set-location|sl|push-location|pop-location)(?:\s|$)/i;
const unknownDir = (state) => { state.dir = null; state.moved = true; return true; };
// A cd / pushd / popd / Set-Location segment: updates state and → true. Run first in a pipeline or in the
// background (POSIX) it changes nothing around it, but it is still not a command to judge. A cd is read only
// as the literal first command word (after env assignments, `command` or `builtin`); behind any other
// wrapper (sudo, env, time, eval …) or last in a pipeline (zsh, bash lastpipe run it in this shell) the
// directory is unknown.
const REPARSE_BINS = new Set(["eval", "source", ".", "iex", "invoke-expression"]);
// A link made earlier in the same command can move a destination's real path after realOf read it, so a move of
// oversight after one is judged as a removal.
const LINK_BINS = new Set(["ln", "link", "mklink"]);
// Copies that can write links, archive extraction, and interpreter one-liners can each make a link the parser
// cannot see; any of them anywhere in the command (or a background job) counts.
const COPY_LINK = { cp: /^(?:-[a-zA-Z]*[sladP][a-zA-Z]*|--(?:symbolic-link|link|links|archive|no-dereference))$/, rsync: /^(?:-[a-zA-Z]*[al][a-zA-Z]*|--(?:links|archive|copy-links))$/ };
const EXTRACT_BINS = new Set(["tar", "bsdtar", "unzip", "cpio", "7z", "7za", "ditto"]);
const INTERP = /^(?:python[0-9.]*|node|perl|ruby|php|bash|sh|zsh|dash|ksh|pwsh|powershell)$/;
function makesLink(seg) {
  const c = commandOf(seg.tokens, seg.ps);
  if (!c) return false;
  const args = seg.tokens.slice(c.at + 1);
  if (LINK_BINS.has(c.binary) || EXTRACT_BINS.has(c.binary)) return true;
  if (COPY_LINK[c.binary] && args.some((t) => COPY_LINK[c.binary].test(t))) return true;
  if (INTERP.test(c.binary) && args.some((t) => /^-(?:[a-zA-Z]*[ce]|-?command|-eval)$/i.test(t))) return true;
  return c.binary === "new-item" && seg.tokens.some((t) => /^(?:symboliclink|junction|hardlink)$/i.test(t));
}
function changeDir(seg, prev, state) {
  const c = commandOf(seg.tokens, seg.ps);
  // eval, source and . re-parse text in this shell, so any cd inside them is invisible here: unknown.
  const first = seg.tokens.find((t) => !/^[A-Za-z_][A-Za-z0-9_]*=/.test(t) && t !== "command" && t !== "builtin");
  if (REPARSE_BINS.has(String(first).toLowerCase()) || (c && REPARSE_BINS.has(c.binary))) return unknownDir(state);
  if (!c || !CD_BINS.has(c.binary)) return false;
  if (!seg.ps && (seg.sep === "|" || seg.sep === "&")) return true;
  if (!seg.ps && prev && prev.sep === "|") return unknownDir(state);
  if (seg.tokens.slice(0, c.at).some((t) => !/^[A-Za-z_][A-Za-z0-9_]*=/.test(t) && !["command", "builtin"].includes(t))) return unknownDir(state);
  state.moved = true;
  const args = seg.tokens.slice(c.at + 1);
  if (c.binary === "popd" || c.binary === "pop-location") { state.dir = state.stack.length ? state.stack.pop() : null; return true; }
  let target = null;
  for (let i = 0; i < args.length; i++) {
    const t = args[i];
    if (t === "--") { target = args[i + 1] ?? null; break; }
    if (seg.ps && /^-(?:path|literalpath|lp)$/i.test(t)) { target = args[i + 1] ?? null; break; }
    if (t !== "-" && t.startsWith("-")) continue;
    target = t; break;
  }
  if (c.binary === "pushd" || c.binary === "push-location") state.stack.push(state.dir);
  if (target === null || target === "" || NOT_LITERAL.test(target)) { state.dir = null; return true; }
  state.dir = isAbsolute(target) ? resolve(target) : state.dir === null ? null : resolve(state.dir, target);
  return true;
}

// → the signals the command raises, in OVERSIGHT_SIGNALS order. opts: { ps, surfaces, cwd, now, parse } (now:
// the clock the time budget reads; parse: the shell splitter; both for tests).
export function oversightCommandSignals(command, { ps = false, surfaces = null, cwd = "", now = Date.now, parse = splitShell } = {}) {
  const cmd = typeof command === "string" ? command : "";
  if (!cmd || !HINT.test(cmd)) return [];
  if (cmd.length > MAX) return [INCOMPLETE];
  const deadline = now() + BUDGET_MS;
  const out = new Set(), touched = new Set();
  let segs = [];
  // A parser fault never leaves the command judged clean: it is analysis-incomplete.
  try { segs = parse(cmd, ps, 0, { segs: [], heredocs: [] }).segs; } catch { out.add(INCOMPLETE); segs = []; }
  const project = resolve(typeof cwd === "string" && cwd ? cwd : process.cwd());
  const opts = { ps, surfacePaths: Boolean(surfaces && surfaces.paths && surfaces.paths.length) };
  // watch: there is a write check to run (memory files on, or protected paths declared).
  opts.watch = Boolean(surfaces && (surfaces.memory || opts.surfacePaths));
  const dirs = new Map(); // subshell scope -> { dir, stack }
  // Execution order is not parse order (a later segment, a background job): a link-maker anywhere counts.
  opts.linkedEarlier = segs.some((s) => { try { return makesLink(s) || (!s.ps && s.sep === "&"); } catch { return true; } });
  for (let i = 0; i < segs.length; i++) {
    if (now() > deadline) { out.add(INCOMPLETE); break; }
    const seg = segs[i];
    const scope = seg.scope || "";
    try {
      const prev = segs[i - 1];
      if (prev) afterSeparator(prev, seg, dirs);
      const state = dirState(dirs, scope, project);
      if (changeDir(seg, segs[i - 1], state)) { dirs.set(scope, state); continue; }
      judgeSegment(seg, segs, i, opts, out, touched, pathCtx(project, state.dir, out));
    } catch { /* one segment never sinks the rest */ }
  }
  if (!out.has(INCOMPLETE) && now() > deadline) out.add(INCOMPLETE);
  // A redirect with no command word (`> f`): the parser keeps no segment for it, so it is read from the text.
  if (opts.watch) {
    try {
      for (const t of bareRedirects(cmd, ps)) {
        if (nullTarget(t)) continue;
        if (nonLiteral(t)) { out.add(INCOMPLETE); continue; }
        for (const abs of new Set([resolve(project, home(t)), resolve(project, t)])) touched.add(abs);
      }
    } catch { out.add(INCOMPLETE); }
  }
  // PowerShell / .NET persistent env var, read from the raw text.
  for (const m of cmd.matchAll(/SetEnvironmentVariable\(\s*["']([A-Za-z_][\w]*)["']\s*,\s*["']([^"']*)["']\s*,\s*["']?(?:\[EnvironmentVariableTarget\]::)?(?:User|Machine)/gi)) classifyPairs([{ key: m[1], value: m[2] }], "", out);
  if (surfaces) {
    if ([...touched].some((p) => protectedPathHit(p, surfaces, { cwd, real: true }))) out.add("protected-surface");
    if (protectedKeyInCommand(cmd, surfaces)) out.add("protected-surface");
    if (!out.has("protected-surface") && [...touched].some((p) => memoryPathHit(p, surfaces, { cwd, real: true }))) out.add("memory-file");
  }
  return OVERSIGHT_SIGNALS.filter((s) => out.has(s));
}
