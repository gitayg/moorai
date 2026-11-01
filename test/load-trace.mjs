// Test-only preload (node --import): records the URL of every module the process loads and, on exit, writes
// them as a JSON array to the file named by MOORAI_LOAD_TRACE. Needs module.registerHooks (Node 22.15+);
// without it the preload records nothing and the file holds null.
import module from "node:module";
import { writeFileSync } from "node:fs";

const seen = [];
const on = typeof module.registerHooks === "function";
if (on) module.registerHooks({ load(url, ctx, next) { seen.push(url); return next(url, ctx); } });
process.on("exit", () => { if (process.env.MOORAI_LOAD_TRACE) writeFileSync(process.env.MOORAI_LOAD_TRACE, JSON.stringify(on ? seen : null)); });
