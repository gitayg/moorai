// Test-only preload (`node --import` on the hook a test spawns): the quarantined reader's listener check sees the
// stub model as running under a different OS user (its uids + 1000), as a model runtime under its own service
// account would. Everything else in the check runs for real. Tests cannot create OS users, so this is how the
// cross-user path is driven; the hook as installed is never started with it.
import { register } from "node:module";
register(new URL("./quarantine-peer-hooks.mjs", import.meta.url));
