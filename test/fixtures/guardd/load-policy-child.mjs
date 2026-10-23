// Runs the hook's own policy loader (cli/hook-core.mjs loadVerifiedPolicy) once, in a child whose HOME is a
// sandbox, and prints what it resolved. argv[2]: JSON { config, actor, helper }. The helper's connect
// options name an injected test tree (test/fixtures/guardd/fake-helper.mjs, or moorai-guardd-test's root).
import { loadVerifiedPolicy } from "../../../cli/hook-core.mjs";

const { config, actor = "", helper = null } = JSON.parse(process.argv[2]);
const t0 = Date.now();
const r = await loadVerifiedPolicy(config, { actor, helper });
process.stdout.write(JSON.stringify({
  source: r.source, via: r.via || "", ms: Date.now() - t0, rejected: r.rejected,
  approvals: r.policy && Array.isArray(r.policy.approvals) ? r.policy.approvals : null,
  marker: r.policy && r.policy.marker
}));
