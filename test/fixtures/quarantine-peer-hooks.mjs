// Resolve hook for test/fixtures/quarantine-peer-register.mjs: cli/quarantine-owner.mjs, as imported by the reader,
// becomes test/fixtures/quarantine-owner-other-user.mjs.
export async function resolve(specifier, context, next) {
  if (/(?:^|\/)quarantine-owner\.mjs$/.test(specifier) && context.parentURL && !context.parentURL.includes("/test/fixtures/")) {
    return { url: new URL("./quarantine-owner-other-user.mjs", import.meta.url).href, shortCircuit: true };
  }
  return next(specifier, context);
}
