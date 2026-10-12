// Resolve hook: cli/hook-core.mjs's `node:fs` becomes ./fake-fs.mjs (see preload.mjs). Every other
// importer, fake-fs.mjs included, gets the real module.
const FAKE = new URL("./fake-fs.mjs", import.meta.url).href;
export async function resolve(specifier, context, next) {
  if ((specifier === "node:fs" || specifier === "fs") && context.parentURL && /\/cli\/hook-core\.mjs$/.test(context.parentURL)) return { url: FAKE, shortCircuit: true };
  return next(specifier, context);
}
