const LEVEL_RANK = { Critical: 4, High: 3, Medium: 2, Low: 1 };

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

    return [...byThreat.values()].sort(
      (a, b) =>
        (LEVEL_RANK[b.threat.riskLevel] - LEVEL_RANK[a.threat.riskLevel]) ||
        (b.threat.riskScore - a.threat.riskScore)
    );
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
      const g = new RegExp(p.source, p.flags.includes("g") ? p.flags : p.flags + "g");
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
