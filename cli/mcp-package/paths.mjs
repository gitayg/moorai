// Which paths inside an artifact are NOT the thing you are deciding whether to install.
//
// This matters far more for a repository (`--package github:<owner>/<repo>`) than for a published
// package: a repo carries its test suite, its examples, its docs and its own CI and dev-environment
// tooling, none of which runs when you install or run the server. Block-tier evidence there is still
// reported, with its path — but at REVIEW, not as a DO-NOT-INSTALL verdict, because a
// DO-NOT-INSTALL on a published catalogue is a public accusation about the PRODUCT.
//
// Measured, not guessed. Two real repositories produced a DO-NOT-INSTALL from a file nobody installing
// them ever executes:
//   metabase  .github/actions/create-backport/create-backport-test.sh — a CI test drives git through
//             `pty.spawn` so an editor launch fails; the reverse-shell detector sees pty.spawn + a shell.
//             There is no socket anywhere in the file.
//   posthog   .flox/env/direnv-setup.sh — a developer bootstrap that really does
//             `curl -sfL https://direnv.net/install.sh | bash` when neither brew, apt nor dnf is present.
// The first is a false alarm outright; the second is a true `curl | sh` that is worth a look and is not
// the server's behaviour. Both land on REVIEW under these rules.

// Tests, fixtures, examples, docs and benchmarks. Wider than a published package needs, because a
// repository carries all of it and a `curl … | sh` in an example is a sample, not behaviour.
export const TEST_PATH = /(^|\/)(tests?|__tests__|__mocks__|__fixtures__|spec|specs|e2e|integration|fixtures?|testdata|test[-_]data|examples?|samples?|demos?|docs?|benchmarks?|bench)\/|(^|\/)test_[^/]+\.py$|_test\.py$|\.(test|spec)\.[cm]?[jt]sx?$/i;

// The repository's own CI and developer-environment tooling. Every entry is a dot-directory that no
// published package contains and that no install or run step of the server ever executes.
export const TOOLING_PATH = /(^|\/)\.(github|gitlab|circleci|devcontainer|flox|husky|buildkite|vscode|idea|azure-pipelines|teamcity)\//i;

// Developer utility scripts a repository ships for its own contributors (a setup wizard, a release
// helper). They are not what an MCP client runs, and they routinely install a toolchain the honest
// way a human would — `curl … | sh` of a vendor installer. Block-tier evidence here is reported at
// review level with the reason, not as a verdict on the product. `bin/` is deliberately NOT here:
// that is where a package's real entry point lives.
export const DEV_SCRIPT_PATH = /(^|\/)(etc\/scripts|scripts|tools|hack|contrib|dev|build-support)\//i;

// → "repo-tooling" | "test-code" | null. The label is appended to the finding's intentLabels, so a
// report always says WHY a piece of block-tier evidence is being shown at review level.
export function notRuntimeReason(rel, { devScripts = false } = {}) {
  if (!rel) return null;
  if (TOOLING_PATH.test(rel)) return "repo-tooling";
  // Only when the target is a whole source repository: inside a published package or a skill, a
  // scripts/ directory can be the thing that actually runs.
  if (devScripts && DEV_SCRIPT_PATH.test(rel)) return "repo-tooling";
  if (TEST_PATH.test(rel)) return "test-code";
  return null;
}
