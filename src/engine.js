import { safeRegex } from "./safe-regex.js";
import { normalizeVariants } from "../data/normalize.js";

const LEVEL_RANK = { Critical: 4, High: 3, Medium: 2, Low: 1 };

// Detectors re-run over DECODED / NORMALIZED variants (see _scanNormalized). Scoped to the
// instruction-override / jailbreak / extraction / exfil / reverse-shell family — the payloads that
// red-team encoders (CipherChat/FlipAttack/h4rm3l) hide — so re-scanning decoded blobs cannot
// resurface the noisier DLP/PII/legal/citation detectors on incidental decoded bytes.
const RESCAN_ON_VARIANT = (d) =>
  /^(inj|sysprompt)/.test(d.detectorId) ||
  d.detectorId === "idx-hidden-instructions" ||
  d.detectorId === "exec-reverse-shell";

export class DetectionEngine {
  constructor(threatData, detectors, contentRules = []) {
    this.sources = threatData.sources || {};
    this._baseDetectors = detectors;
    this.detectors = detectors;
    this.contentRules = contentRules;
    this.threatsById = new Map(threatData.threats.map((t) => [t.id, t]));
  }

  // #22 — merge org-defined detector packs (already compiled) on top of the built-ins. Idempotent:
  // re-applying replaces the previous packs rather than stacking, so a policy refresh stays clean.
  applyPacks(compiled) {
    this.detectors = compiled && compiled.length ? [...this._baseDetectors, ...compiled] : this._baseDetectors;
  }

  // #5 — a file's or index-payload's content is DLP-equivalent to a prompt, so "file" and "index"
  // stages also run the "prompt" detectors (secrets/PII/injection). Without this, dropped files and
  // OCR'd images were never threat-scanned. Prompt/output stay isolated.
  _wantStages(stage) { return (stage === "file" || stage === "index") ? ["prompt", stage] : [stage]; }
  _inStage(d, want) { return (d.stages || [d.stage]).some((s) => want.includes(s)); }

  // #5 — scan content headed for a local vector store / RAG index before it's embedded. Single
  // choke-point contract for a future embedding writer; today it's reachable via the file path.
  scanForIndex(text) { return this.scan(text, "index"); }

  // #21 — optional, policy-gated semantic escalation. Regex/entropy above stays the fast path and OWNS
  // enforcement; this awaits a bounded, fail-open second opinion from an on-device model ONLY when the
  // caller injects the escalator (`escalate` from src/semantic.js) — which is the ambiguity gate's async
  // sibling to `_matchDetector`'s sync `refine`. Injection (not import) keeps this class free of the
  // node-only provider code, so the browser bundle that imports engine.js never pulls it in. No escalator
  // → identical to `scan` (fail-open). See src/semantic.js for the gating, backends, and content-free
  // reduction; the caller must run this AFTER any deny decision (F-301 ordering).
  async scanSemantic(text, stage, policy, escalate, opts) {
    const base = this.scan(text, stage);
    if (typeof escalate !== "function") return base;
    return escalate(this, base, text, stage, policy, opts);
  }

  // Parental-control content review (profanity, sexual, violence, etc.) — separate from
  // the security threat scan. Returns matched content categories.
  scanContent(text, categories) {
    if (!text || !text.trim()) return [];
    const allow = categories ? new Set(categories) : null;
    const out = [];
    for (const r of this.contentRules) {
      if (allow && !allow.has(r.id)) continue;
      const m = this._firstMatch(text, r.patterns);
      if (m) out.push({ ruleId: r.id, label: r.label, severity: r.severity, match: this._clip(m) });
    }
    return out;
  }

  threat(id) {
    return this.threatsById.get(id);
  }

  sourceLinks(threat) {
    return (threat.sources || []).map((key) => ({ key, url: this.sources[key] }));
  }

  scan(text, stage) {
    if (!text || !text.trim()) return [];
    const byThreat = new Map();
    const want = this._wantStages(stage);

    for (const d of this.detectors) {
      if (!this._inStage(d, want)) continue;
      const match = this._matchDetector(text, d);
      if (!match) continue;

      const threat = this.threat(d.threatId);
      if (!threat) continue;

      const finding = {
        detectorId: d.detectorId,
        mode: d.mode || "warn",
        hint: d.hint,
        match: this._clip(match),
        threat
      };

      const prev = byThreat.get(threat.id);
      if (!prev || finding.mode === "warn") byThreat.set(threat.id, finding);
    }

    // Normalization / decode pre-pass — catch instructions hidden behind an encoding, a reversal, or
    // layers of both. Purely ADDITIVE: it only adds findings for threats the raw scan didn't already
    // flag, and is wrapped fail-open so a normalization error can never change the raw decision.
    try { this._scanNormalized(text, want, byThreat); } catch { /* fail-open: keep the raw result */ }

    return [...byThreat.values()].sort(
      (a, b) =>
        (LEVEL_RANK[b.threat.riskLevel] - LEVEL_RANK[a.threat.riskLevel]) ||
        (b.threat.riskScore - a.threat.riskScore)
    );
  }

  // Re-run the instruction-family detectors over bounded decoded/normalized variants of the input, and
  // raise an obfuscation signal when an encoded blob decodes to hidden natural-language text. Adds a
  // finding ONLY for a threat the raw scan missed (`!byThreat.has`), so it never overrides or reorders
  // an existing raw finding — the raw result stays byte-for-byte the same when nothing was hidden.
  _scanNormalized(text, want, byThreat) {
    const variants = normalizeVariants(text);
    if (!variants.length) return;
    const rescan = this.detectors.filter((d) => this._inStage(d, want) && RESCAN_ON_VARIANT(d));

    for (const v of variants) {
      // (a) obfuscation signal: an encoded blob that decodes to concealed prose (threat #50, LLM08).
      if (v.nl) {
        const t50 = this.threat(50);
        if (t50 && !byThreat.has(t50.id)) {
          byThreat.set(t50.id, {
            detectorId: "obf-encoded-payload", mode: "warn",
            hint: `Encoded (${v.kind}) content decodes to hidden natural-language text (obfuscation).`,
            match: this._clip(v.text), threat: t50, obfuscated: v.kind
          });
        }
      }
      // (b) decoded-reveals-a-detector: the hidden instruction, now in cleartext, trips a detector.
      for (const d of rescan) {
        const threat = this.threat(d.threatId);
        if (!threat || byThreat.has(threat.id)) continue;
        const match = this._matchDetector(v.text, d);
        if (!match) continue;
        byThreat.set(threat.id, {
          detectorId: d.detectorId, mode: d.mode || "warn", hint: d.hint,
          match: this._clip(match), threat, obfuscated: v.kind
        });
      }
    }
  }

  // Multi-turn injection review. A jailbreak is often split across turns (persona setup in one
  // message, the payload in a later one) to slip past single-prompt scanning. Given the recent
  // window of user turns (oldest→newest strings), this: (a) runs prompt-stage injection detectors
  // over the joined window to catch split payloads, (b) runs session-stage scaffolding detectors,
  // and (c) flags persistence when injection signals recur across separate turns.
  scanSession(turns, windowSize = 6) {
    const recent = (turns || []).filter((t) => t && t.trim()).slice(-windowSize);
    if (recent.length < 2) return [];
    const joined = recent.join("\n");
    const byThreat = new Map();

    const add = (finding) => {
      if (!finding.threat) return;
      const prev = byThreat.get(finding.threat.id);
      if (!prev || finding.mode === "warn") byThreat.set(finding.threat.id, finding);
    };

    // (a) prompt-stage injection detectors over the whole window (split payloads)
    // (b) session-stage scaffolding detectors
    for (const d of this.detectors) {
      const injPrompt = d.stage === "prompt" && d.detectorId.startsWith("inj");
      if (!injPrompt && d.stage !== "session") continue;
      const match = this._firstMatch(joined, d.patterns);
      if (!match) continue;
      const threat = this.threat(d.threatId);
      if (!threat) continue;
      add({ detectorId: d.detectorId, mode: d.mode || "warn", hint: d.hint, match: this._clip(match), threat, multiTurn: true });
    }

    // (c) persistence: injection signals in ≥2 distinct turns
    const injDetectors = this.detectors.filter((d) => d.stage === "prompt" && d.detectorId.startsWith("inj"));
    const flagged = recent.filter((t) => injDetectors.some((d) => this._firstMatch(t, d.patterns)));
    if (flagged.length >= 2) {
      const threat = this.threat(3);
      if (threat) add({ detectorId: "inj-persistent", mode: "warn", hint: `Repeated injection attempts across ${flagged.length} turns.`, match: `${flagged.length} turns`, threat, multiTurn: true });
    }

    return [...byThreat.values()].sort(
      (a, b) =>
        (LEVEL_RANK[b.threat.riskLevel] - LEVEL_RANK[a.threat.riskLevel]) ||
        (b.threat.riskScore - a.threat.riskScore)
    );
  }

  // Replaces matched sensitive spans with redaction tags. Skips coach-mode detectors
  // (contextual, not redactable). Used by the pre-flight guard before forwarding to the agent.
  redact(text, stage) {
    let out = text;
    const want = this._wantStages(stage);
    for (const d of this.detectors) {
      if (!this._inStage(d, want) || d.mode === "coach") continue;
      for (const p of d.patterns) {
        const g = new RegExp(p.source, p.flags.includes("g") ? p.flags : p.flags + "g");
        // Honor refine so an entropy-gated detector never over-redacts a benign long string — scan
        // and redact must agree on what's a secret.
        out = out.replace(g, (m) => (d.refine && !d.refine(m, text)) ? m : `[REDACTED:#${d.threatId}]`);
      }
    }
    return out;
  }

  _firstMatch(text, patterns) {
    for (const p of patterns) {
      const m = text.match(p);
      if (m) return m[0];
    }
    return null;
  }

  // #7 — like _firstMatch, but if the detector has a `refine(match)` predicate (entropy/allowlist
  // gate for shapeless secrets), keep scanning occurrences until one passes. No refine → identical to
  // _firstMatch, so existing detectors are unaffected. refine also receives the FULL scanned text as
  // a second arg (ignored by string-only refines), so a proximity gate like taint-lite can look
  // beyond the matched span for a nearby source without widening the pattern.
  _matchDetector(text, d) {
    if (!d.refine) return this._firstMatch(text, d.patterns);
    for (const p of d.patterns) {
      const g = safeRegex(p.source, p.flags.includes("g") ? p.flags : p.flags + "g");
      if (!g) continue;
      let m;
      while ((m = g.exec(text)) !== null) {
        if (d.refine(m[0], text)) return m[0];
        if (m.index === g.lastIndex) g.lastIndex++; // guard against zero-width matches
      }
    }
    return null;
  }

  _clip(s, max = 48) {
    s = s.replace(/\s+/g, " ").trim();
    return s.length > max ? s.slice(0, max) + "…" : s;
  }
}
