// AMTSO labelling: corpus-immutability invariant + label integrity.
//
// The FIRST suite is the safety deliverable. A corpus silently corrupted by a
// labelling pass would invalidate every published number in this project, so it
// is proved — against the committed baseline, not against a copy in memory —
// that the AMTSO work changed nothing:
//   * same sample count           * same set of ids
//   * byte-identical sample text  * every pre-existing field unchanged
//   * byte-identical file         (sha256 of the whole file vs `git show HEAD:`)
//
// Falsification: mutate one character of any sample's `text` and
// "sample fields are unchanged", "sample texts are byte-identical" and
// "file bytes are identical to HEAD" all fail. Verified by deliberate
// corruption before this test was accepted.
import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import {
  CORPORA,
  TAXONOMY,
  SEVERITY_CRITERIA,
  METHOD,
  labelAll,
  loadCorpora,
} from '../scripts/amtso-coverage.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const sha = (b) => createHash('sha256').update(b).digest('hex');
const head = (p) =>
  execFileSync('git', ['show', `HEAD:${p}`], { cwd: ROOT, maxBuffer: 64 * 1024 * 1024 });

const FILES = CORPORA.map((c) => c.file);
const KEYS = Object.fromEntries(CORPORA.map((c) => [c.file, c.keys]));

// ---------------------------------------------------------------------------
test('corpus immutability invariant', async (t) => {
  await t.test('every corpus file is present in HEAD', () => {
    for (const f of FILES) assert.ok(head(f).length > 0, `${f} missing from HEAD`);
  });

  await t.test('file bytes are identical to HEAD', () => {
    for (const f of FILES) {
      assert.equal(
        sha(readFileSync(join(ROOT, f))),
        sha(head(f)),
        `${f} differs from the committed baseline — the AMTSO pass must not touch corpus files`,
      );
    }
  });

  await t.test('sample counts are unchanged', () => {
    for (const f of FILES) {
      const now = JSON.parse(readFileSync(join(ROOT, f), 'utf8'));
      const was = JSON.parse(head(f).toString('utf8'));
      for (const k of KEYS[f]) {
        assert.equal(now[k].length, was[k].length, `${f}#${k} sample count changed`);
      }
    }
  });

  await t.test('id sets are unchanged', () => {
    for (const f of FILES) {
      const now = JSON.parse(readFileSync(join(ROOT, f), 'utf8'));
      const was = JSON.parse(head(f).toString('utf8'));
      for (const k of KEYS[f]) {
        assert.deepEqual(
          now[k].map((s) => s.id),
          was[k].map((s) => s.id),
          `${f}#${k} ids changed`,
        );
      }
    }
  });

  await t.test('sample texts are byte-identical', () => {
    for (const f of FILES) {
      const now = JSON.parse(readFileSync(join(ROOT, f), 'utf8'));
      const was = JSON.parse(head(f).toString('utf8'));
      for (const k of KEYS[f]) {
        for (let i = 0; i < was[k].length; i++) {
          const a = was[k][i];
          const b = now[k][i];
          assert.equal(
            sha(Buffer.from(JSON.stringify(a.text ?? a.turns ?? null), 'utf8')),
            sha(Buffer.from(JSON.stringify(b.text ?? b.turns ?? null), 'utf8')),
            `${f}#${k}[${i}] (${a.id}) sample text changed`,
          );
        }
      }
    }
  });

  await t.test('every pre-existing field is unchanged (additive-only)', () => {
    for (const f of FILES) {
      const now = JSON.parse(readFileSync(join(ROOT, f), 'utf8'));
      const was = JSON.parse(head(f).toString('utf8'));
      for (const k of KEYS[f]) {
        for (let i = 0; i < was[k].length; i++) {
          for (const [field, value] of Object.entries(was[k][i])) {
            assert.deepEqual(
              now[k][i][field],
              value,
              `${f}#${k}[${i}] (${was[k][i].id}) field "${field}" changed or was removed`,
            );
          }
        }
      }
    }
  });

  await t.test('heldout-v2-test.json — the locked generalization measure — is untouched', () => {
    const f = 'test/redteam/heldout-v2-test.json';
    assert.equal(sha(readFileSync(join(ROOT, f))), sha(head(f)));
    const d = JSON.parse(readFileSync(join(ROOT, f), 'utf8'));
    assert.equal(d.attacks.length, 44);
    assert.equal(d.benign.length, 10);
  });
});

// ---------------------------------------------------------------------------
test('AMTSO sidecar integrity', async (t) => {
  const sidecar = JSON.parse(readFileSync(join(ROOT, 'test/redteam/amtso-labels.json'), 'utf8'));
  const samples = loadCorpora();
  const DIMS = [
    'attackVector',
    'targetOfProtection',
    'environmentType',
    'harmType',
    'severity',
    'requiredCapability',
  ];

  await t.test('every corpus sample is labelled, and nothing else is', () => {
    assert.deepEqual(
      Object.keys(sidecar.labels).sort(),
      samples.map((s) => s.id).sort(),
    );
  });

  await t.test('sample ids are globally unique across the seven corpora', () => {
    assert.equal(new Set(samples.map((s) => s.id)).size, samples.length);
  });

  await t.test('every dimension value is declared in the taxonomy', () => {
    for (const [id, l] of Object.entries(sidecar.labels)) {
      for (const d of DIMS) {
        const known = [...TAXONOMY[d].amtso, ...TAXONOMY[d].ext];
        assert.ok(known.includes(l[d]), `${id}: undeclared ${d} value "${l[d]}"`);
      }
      assert.ok(['high', 'medium', 'low'].includes(l.confidence), `${id}: bad confidence`);
      assert.ok(
        ['agentic', 'code-security', 'data-protection', 'benign-control'].includes(l.scope),
        `${id}: bad scope`,
      );
    }
  });

  await t.test('the sidecar is in sync with the rules in scripts/amtso-coverage.mjs', () => {
    const { labels } = labelAll();
    assert.deepEqual(labels, sidecar.labels, 'run: node scripts/amtso-coverage.mjs --emit');
  });

  await t.test('the disclosed severity criteria are published in the artifact', () => {
    for (const level of ['critical', 'high', 'medium', 'low']) {
      assert.ok(
        sidecar._severityCriteria.levels[level]?.length > 80,
        `severity criterion for "${level}" is missing or too thin to be a disclosure`,
      );
    }
    assert.ok(sidecar._severityCriteria.ratedOn.length > 40);
    assert.ok(sidecar._severityCriteria.invariants.length >= 3);
    assert.ok(sidecar._severityCriteria.knownLimitation.includes('not by an independent tester'));
    assert.deepEqual(sidecar._severityCriteria, SEVERITY_CRITERIA);
    assert.deepEqual(sidecar._method, METHOD);
  });

  await t.test('benign labelling agrees with each corpus\'s own ground truth', () => {
    // scope "benign-control" must hold for exactly the samples the corpora say
    // must NOT produce a detection. A drift here would silently move a false
    // positive into the attack column, or vice versa.
    for (const s of samples) {
      const mustDetect =
        'shouldDetect' in s ? s.shouldDetect : s.none === true ? false : 'expect' in s;
      assert.equal(
        sidecar.labels[s.id].scope === 'benign-control',
        !mustDetect,
        `${s.id}: scope "${sidecar.labels[s.id].scope}" contradicts the corpus verdict`,
      );
    }
  });

  await t.test('benign controls carry no attack vector, harm or severity', () => {
    for (const [id, l] of Object.entries(sidecar.labels)) {
      if (l.scope !== 'benign-control') continue;
      assert.equal(l.attackVector, '+none (benign control)', id);
      assert.equal(l.harmType, '+none (benign control)', id);
      assert.equal(l.severity, '+none (benign control)', id);
    }
  });

  await t.test('no attack sample is left with an unresolved payload core', () => {
    const unresolved = Object.entries(sidecar.labels).filter(([, l]) => l.core === 'unresolved');
    assert.deepEqual(unresolved.map(([id]) => id), [], 'unresolved payload cores need review');
  });

  await t.test('severity respects its disclosed obfuscation invariant', () => {
    // "Obfuscation never changes severity. Only the decoded payload does."
    // heldout-v3 re-encodes 26 semantic cores across 23 obfuscation axes, so it
    // is the direct test: every sample sharing a coreId must share a severity.
    const v3 = JSON.parse(readFileSync(join(ROOT, 'test/redteam/heldout-v3.json'), 'utf8'));
    const byCore = new Map();
    for (const s of [...v3.attacks, ...v3.benign]) {
      const sev = sidecar.labels[s.id].severity;
      if (!byCore.has(s.coreId)) byCore.set(s.coreId, sev);
      assert.equal(
        byCore.get(s.coreId),
        sev,
        `${s.id}: obfuscation axis "${s.axis}" changed severity for core ${s.coreId}`,
      );
    }
    assert.ok(byCore.size >= 20, 'expected the full set of heldout-v3 cores');
  });

  await t.test('indirect-content carriers are classified as indirect, not direct', () => {
    const v3 = JSON.parse(readFileSync(join(ROOT, 'test/redteam/heldout-v3.json'), 'utf8'));
    const carried = v3.attacks.filter((s) => /carrier:(code-comment|blockquote|json-value|html-comment|md-table|git-trailer|changelog|fake-system)/.test(s.chain ?? ''));
    assert.ok(carried.length > 0);
    for (const s of carried) {
      assert.equal(sidecar.labels[s.id].attackVector, 'indirect content', s.id);
    }
  });
});
