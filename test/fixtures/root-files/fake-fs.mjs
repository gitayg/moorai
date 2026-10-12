// node:fs for cli/hook-core.mjs under test (preload.mjs): the paths in MOORAI_TEST_ROOT_FILES stat as a
// root-owned 0644 regular file and read as the given content; every other path is the real filesystem.
import * as real from "node:fs";
export * from "node:fs";
const MAP = (() => { try { return JSON.parse(process.env.MOORAI_TEST_ROOT_FILES || "{}"); } catch { return {}; } })();
const has = (p) => typeof p === "string" && Object.prototype.hasOwnProperty.call(MAP, p);
export function statSync(p, ...rest) {
  if (!has(p)) return real.statSync(p, ...rest);
  const size = Buffer.byteLength(MAP[p]);
  return { uid: 0, gid: 0, mode: 0o100644, size, mtimeMs: Date.now() - 1000, isFile: () => true, isDirectory: () => false, isSymbolicLink: () => false };
}
export function readFileSync(p, ...rest) {
  if (!has(p)) return real.readFileSync(p, ...rest);
  const enc = typeof rest[0] === "string" ? rest[0] : rest[0] && rest[0].encoding;
  return enc ? MAP[p] : Buffer.from(MAP[p]);
}
