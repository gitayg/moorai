// #22 — org-defined detector packs. An admin ships extra patterns (internal project codenames,
// customer-ID formats, etc.) as DATA — pattern strings, never code — distributed via the policy
// server. They're compiled here into the same detector shape the built-ins use, so they flow through
// the exact same policy resolution (threatAction / redact). Each pack detector maps to an EXISTING
// threat id so severity + response + data-tier all resolve unchanged; an unknown id simply yields no
// finding.
//
// Untrusted input, so the pattern goes through the shared ReDoS guard in src/safe-regex.js — the same
// one the MCP argument rules use. It replaces the weaker local pair this file used to carry, which
// missed the overlapping-alternation family (`(a|a)+$` measured at 28144 ms) and the polynomial one
// (`.*.*=` at 8546 ms), and which falsely refused `[*+]{3}x` because its adjacency rule was not
// character-class aware. Patterns are compiled as RegExp, never eval'd.

import { safeRegex } from "../src/safe-regex.js";

// Pack flags are sanitized rather than passed through: an invalid flag makes RegExp throw, which
// would silently drop the whole pattern. Empty string, not safeRegex's "i" default — pack patterns
// have always been case-sensitive unless the pack says otherwise.
function safePattern(src, flags) {
  return safeRegex(src, String(flags || "").replace(/[^gimsuy]/g, ""));
}

const slug = (s, fallback) => String(s || fallback).replace(/[^\w-]/g, "").slice(0, 40) || fallback;

// Compile a list of packs ({ packId, detectors: [{ detectorId, threatId, stage, mode, hint, patterns,
// flags }] }) into detector objects. Anything malformed is skipped, never thrown.
export function compilePacks(packs) {
  const out = [];
  for (const pack of Array.isArray(packs) ? packs : []) {
    const pid = slug(pack?.packId, "pack");
    for (const d of Array.isArray(pack?.detectors) ? pack.detectors : []) {
      const threatId = Number(d?.threatId);
      if (!Number.isInteger(threatId)) continue;
      const patterns = (Array.isArray(d?.patterns) ? d.patterns : []).map((p) => safePattern(p, d?.flags)).filter(Boolean);
      if (!patterns.length) continue;
      out.push({
        detectorId: `pack:${pid}:${slug(d?.detectorId, "rule")}`,
        threatId,
        stage: d?.stage === "output" ? "output" : "prompt",
        mode: d?.mode === "coach" ? "coach" : "warn",
        hint: String(d?.hint || "Custom (org policy) pattern matched").slice(0, 160),
        patterns
      });
    }
  }
  return out;
}
