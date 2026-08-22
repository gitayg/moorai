import { contentHash } from "./content-hash.js";

const KEY = "raiseme.audit";
const MAX = 100;

export class Audit {
  constructor(store = localStorage) {
    this.store = store;
  }

  all() {
    try {
      return JSON.parse(this.store.getItem(KEY)) || [];
    } catch {
      return [];
    }
  }

  // A logged decision, plus the redacted alert that would be reported to the server.
  // persist=false builds the entry (for a server report) without storing it in the local,
  // user-visible log — used by silent "alert" actions.
  record({ action, stage, tool, finding, content }, persist = true) {
    const ts = new Date().toISOString();
    const entry = { ts, action, stage, tool };

    if (finding) {
      entry.threatId = finding.threat.id;
      entry.category = finding.threat.category;
      entry.riskLevel = finding.threat.riskLevel;
      entry.mode = finding.mode;
      entry.alert = {
        threatId: finding.threat.id,
        category: finding.threat.category,
        riskLevel: finding.threat.riskLevel,
        stage,
        tool,
        ts,
        contentHash: content ? contentHash(content) : null
      };
    }

    if (persist) {
      const next = [entry, ...this.all()].slice(0, MAX);
      this.store.setItem(KEY, JSON.stringify(next));
    }
    return entry;
  }

  clear() {
    this.store.removeItem(KEY);
  }
}
