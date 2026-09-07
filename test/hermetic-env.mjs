// Preloaded into every unit-test process by `npm run test:unit` (`node --test --import ...`).
//
// WHY THIS EXISTS, measured rather than assumed. 27 test files build a throwaway HOME and spawn the
// hook with `{ ...process.env, HOME: sandbox }`. That is NOT enough to isolate the device's state:
// cli/state-dirs.mjs resolves two of its three user-scope write legs from base-directory variables
// that are INDEPENDENT of HOME —
//
//     LATCH_DIR      = $XDG_CONFIG_HOME/moorai   (Windows: %APPDATA%\MoorAI)
//     BREADCRUMB_DIR = $XDG_STATE_HOME/moorai    (Windows: %LOCALAPPDATA%\MoorAI)
//
// — so on any machine that sets them (every XDG-configured Linux desktop, and every GitHub Actions
// Ubuntu runner) the policy-key pin, the last-known-good policy and the posture latch escape the
// sandbox into ONE directory shared by every test process in the run. MEASURED on this repo, node 22
// in a Linux container, `--test-concurrency=4`: with XDG_CONFIG_HOME exported the suite went from
// 872/873 to 863/873, and the shared latch ended up holding a policy pin listing the signing keys of
// two different tenants written by two different test files.
//
// Deleting the variables here — in the test runner process, before any test file loads — is inherited
// by every `{ ...process.env }` spawn, so all 27 files become hermetic at one point instead of 27.
// The variables are only unset for tests; a test that wants to exercise a specific base directory sets
// it explicitly on the child it spawns (test/posture.test.mjs does exactly that).
for (const v of ["XDG_CONFIG_HOME", "XDG_STATE_HOME", "APPDATA", "LOCALAPPDATA"]) delete process.env[v];
