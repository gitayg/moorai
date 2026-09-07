// Accepted-failure baseline for the shipped adversarial corpus (test/redteam/corpus.json).
//
// WHY THIS FILE EXISTS. A harness with one permanently-red case is not a gate: `npm run redteam` sat
// at 101/102 and exited 1 on every run, so a red exit code carried no information and a NEW miss
// would have looked identical to the old one. The same disease as printing ✗ and exiting 0 — the
// signal is there, but nothing can act on it.
//
// The contract, which is xfail-STRICT on purpose:
//   * an id listed here may fail            -> the run still passes
//   * any id NOT listed here fails          -> the run fails
//   * an id listed here that PASSES         -> the run fails, demanding the entry be deleted
// The third rule is what stops this list becoming the next stale canary. It is loud and it tells you
// exactly what to delete; a detector improvement making the build red for one commit is the price of
// the list never silently outliving the bug it documents.
//
// Do NOT add an entry to make a red run green. An entry is a statement that the miss is understood
// and accepted, with the reason written down.

export const ACCEPTED_CORPUS_FAILURES = {
  "sec-generic-entropy":
    'expects threat #39 on `API_KEY = "<32-char base62>"` — a generic high-entropy blob with no vendor ' +
    "prefix. The shipped secret detectors are vendor-prefixed (AKIA…, ghp_…, sk-…); a bare entropy " +
    "heuristic broad enough to catch this fires on hashes, UUIDs and base64 blobs across the benign " +
    "corpus. Pre-existing and deliberate: measured as a known miss at v0.78.0 (redteam 101/102)."
};

// failedIds: ids the harness actually scored as failing this run.
// allIds:    every id the harness scored, so an allowlist entry naming a case that no longer exists
//            in the corpus is caught too (a renamed case would otherwise silently keep its excuse).
export function classifyFailures(failedIds, allIds) {
  const failed = new Set(failedIds);
  const present = new Set(allIds);
  const accepted = Object.keys(ACCEPTED_CORPUS_FAILURES);
  return {
    unexpected: [...failed].filter((id) => !(id in ACCEPTED_CORPUS_FAILURES)),
    expected: accepted.filter((id) => failed.has(id)),
    // Listed, present in the corpus, and passing → the excuse outlived the bug.
    stale: accepted.filter((id) => present.has(id) && !failed.has(id)),
    // Listed but no longer in the corpus at all → the excuse outlived the case.
    missing: accepted.filter((id) => !present.has(id))
  };
}

// One shared renderer + verdict so redteam.mjs and benchmark.mjs cannot drift apart on what "green"
// means for the same corpus.
export function reportAcceptedFailures(cls, log = console.log) {
  const r = (s) => `\x1b[31m${s}\x1b[0m`;
  const y = (s) => `\x1b[33m${s}\x1b[0m`;
  const dim = (s) => `\x1b[2m${s}\x1b[0m`;
  for (const id of cls.expected) {
    log(`  ${y("!")} ${id} ${dim("— accepted known failure")}`);
    log(`      ${dim(ACCEPTED_CORPUS_FAILURES[id])}`);
  }
  for (const id of cls.stale) {
    log(r(`  ✗ ${id} now PASSES but is still listed in scripts/accepted-failures.mjs — delete the entry.`));
  }
  for (const id of cls.missing) {
    log(r(`  ✗ ${id} is listed in scripts/accepted-failures.mjs but is not in the corpus — delete the entry.`));
  }
  return cls.unexpected.length + cls.stale.length + cls.missing.length === 0;
}
