// The console surface docs/IR_PLAYBOOKS.md may cite, read from a checkout of the management console:
// the API paths its server code names, the dashboard views with the panel headings each one renders,
// and the reason codes it stores. test/fixtures/console-surface.json is this function's output for the
// console the playbooks were written against; test/ir-playbooks.test.mjs checks the doc against that
// fixture, and against a live checkout as well when MOORAI_CONSOLE_DIR names one.
//
//   node -e 'import("./test/ir-console-surface.mjs").then((m) => console.log(JSON.stringify(m.consoleSurface(process.argv[1]), null, 1)))' <console dir>
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";

const ent = (t) => t.replace(/&amp;/g, "&").replace(/&mdash;/g, "—").trim();
const h2s = (s) => [...s.matchAll(/<h2[^>]*>([^<]+)/g)].map((m) => ent(m[1]));

export function consoleSurface(dir) {
  const srv = join(dir, "server");
  const src = Object.fromEntries(readdirSync(srv).filter((f) => f.endsWith(".js")).map((f) => [f, readFileSync(join(srv, f), "utf8")]));
  const paths = new Set();
  for (const s of Object.values(src)) for (const m of s.matchAll(/["'`](\/(?:api|compliance)\/[A-Za-z0-9/_.:-]*)/g)) paths.add(m[1]);
  const consts = {};
  for (const [f, s] of Object.entries(src)) if (f.startsWith("dashboard")) for (const m of s.matchAll(/export const ([A-Z][A-Z0-9_]*) = `([\s\S]*?)`;/g)) consts[m[1]] = m[2];
  const parts = src["dashboard.js"].split(/id="view-([a-z]+)"/);
  const panels = {};
  for (let i = 1; i < parts.length; i += 2) {
    const set = new Set(h2s(parts[i + 1]));
    for (const m of parts[i + 1].matchAll(/\$\{([A-Z][A-Z0-9_]*)\}/g)) for (const h of h2s(consts[m[1]] || "")) set.add(h);
    panels[parts[i]] = [...set].sort();
  }
  const views = [...src["dashboard-views.js"].matchAll(/\{ key: "([a-z]+)", label: "([^"]+)" \}/g)].map((m) => ({ key: m[1], label: m[2], panels: panels[m[1]] || [] }));
  const reasonCodes = new Set();
  for (const s of Object.values(src)) for (const m of s.matchAll(/export const (?:[A-Z]+_)?REASON_CODES = Object\.freeze\(\[([\s\S]*?)\]\);/g)) for (const c of m[1].matchAll(/"([A-Z][A-Z0-9_]+)"/g)) reasonCodes.add(c[1]);
  const pkg = JSON.parse(readFileSync(join(dir, "package.json"), "utf8"));
  return { console: pkg.version, views, paths: [...paths].sort(), reasonCodes: [...reasonCodes].sort() };
}
