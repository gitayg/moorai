// Test-only: `node --import <this> cli/moorai-hook.mjs` makes the hook's root-owned-file reads
// (cli/hook-core.mjs readRootOwned) see the files named in MOORAI_TEST_ROOT_FILES ({ path: content }) as
// root-owned, mode 0644. Nothing in production reads that variable: it is read here, by a loader that only
// a test passes on the command line, and the loader swaps node:fs for cli/hook-core.mjs alone. This is the
// injected-reader pattern of cli/server-mode.mjs (read = readRootOwned) carried into a spawned process,
// so an e2e can exercise /etc/moorai/config.json without root and without a production override.
import { register } from "node:module";
register("./loader.mjs", import.meta.url);
