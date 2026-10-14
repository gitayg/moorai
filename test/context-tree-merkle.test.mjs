// context.tree Merkle core (cli/context-tree.mjs) against RFC 6962 / Certificate Transparency known answers.
//
// Fixture: test/context-tree-ct-vectors.json, taken verbatim (hex re-encoded) from transparency-dev/merkle at
// commit c39fbf350a405f68571bf4c42a6a518eb0a46a4b (Apache-2.0, Google LLC): testonly/constants.go
// (LeafInputs, NodeHashes, RootHashes) and the testdata/inclusion/**/*.json probes that the library's own
// proof/verify_test.go TestVerifyInclusionProbes runs. Then property tests over random sizes 1..300.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { ContextTree, hashLeafData, verifyLeafHash, leafHash, leafOf } from "../cli/context-tree.mjs";

const V = JSON.parse(readFileSync(new URL("./context-tree-ct-vectors.json", import.meta.url), "utf8"));
const hx = (h) => Buffer.from(h, "hex");
const sha = (...b) => { const h = createHash("sha256"); for (const x of b) h.update(x); return h.digest(); };

// An independent oracle: RFC 6962 section 2.1 MTH, written straight from the RFC's recursion.
function mth(hashes) {
  if (hashes.length === 0) return sha(Buffer.alloc(0));
  if (hashes.length === 1) return hashes[0];
  let k = 1; while (k * 2 < hashes.length) k *= 2;
  return sha(Buffer.from([1]), mth(hashes.slice(0, k)), mth(hashes.slice(k)));
}

test("CT vectors: leaf hashes, every complete subtree node and every root for sizes 0..8", () => {
  const t = new ContextTree();
  assert.equal(t.root(), V.rootHashesHex[0], "empty root");
  V.leafInputsHex.forEach((inp, i) => {
    const lh = hashLeafData(hx(inp));
    assert.equal(lh.toString("hex"), V.nodeHashesHex[0][i], `leaf hash ${i}`);
    t.appendHash(lh);
    assert.equal(t.root(), V.rootHashesHex[i + 1], `root at size ${i + 1}`);
  });
  for (let lv = 0; lv < V.nodeHashesHex.length; lv++)
    V.nodeHashesHex[lv].forEach((h, j) => assert.equal(t.levels[lv][j].toString("hex"), h, `node level ${lv} index ${j}`));
  for (let m = 0; m <= 8; m++) assert.equal(t.rootAt(m), V.rootHashesHex[m], `rootAt(${m})`);
});

test("CT inclusion probes: every published probe verifies or is refused exactly as the reference says", () => {
  assert.equal(V.inclusionProbes.length, 98);
  const wrong = [];
  for (const p of V.inclusionProbes) {
    const ok = verifyLeafHash(p.leafHash || "", p.leafIdx, p.treeSize, p.proof, p.root || "");
    if (ok === p.wantErr) wrong.push(`${p.file}: ${p.desc} (wantErr=${p.wantErr}, verified=${ok})`);
  }
  assert.deepEqual(wrong, []);
});

test("CT inclusion probes: the proofs this tree generates equal the published happy-path proofs", () => {
  const t = new ContextTree();
  for (const inp of V.leafInputsHex) t.appendHash(hashLeafData(hx(inp)));
  const happy = V.inclusionProbes.filter((p) => !p.wantErr && /^testdata\/inclusion\/\d\//.test(p.file));
  assert.ok(happy.length >= 4, "fixture holds happy-path probes over the 8 leaf inputs");
  for (const p of happy) {
    assert.equal(t.levels[0][p.leafIdx].toString("hex"), p.leafHash, `${p.file} leaf`);
    assert.deepEqual(t.proof(p.leafIdx, p.treeSize), p.proof, `${p.file} proof`);
    assert.equal(t.rootAt(p.treeSize), p.root, `${p.file} root`);
  }
});

// mulberry32: seeded so a failure reproduces.
function rng(seed) { return () => { seed |= 0; seed = (seed + 0x6d2b79f5) | 0; let t = Math.imul(seed ^ (seed >>> 15), 1 | seed); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296; }; }
const flipBit = (hex, bit) => { const b = hx(hex); b[bit >> 3] ^= 1 << (bit & 7); return b.toString("hex"); };

test("property: random sizes 1..300, every index's proof verifies, a flipped bit anywhere fails", () => {
  const r = rng(0x16c0);
  const sizes = new Set([1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 256, 257, 300]);
  while (sizes.size < 60) sizes.add(1 + Math.floor(r() * 300));
  const t = new ContextTree();
  const hashes = [];
  for (let i = 0; i < 300; i++) { const h = hashLeafData(Buffer.from(`leaf-${i}-${r()}`)); hashes.push(h); t.appendHash(h); }
  let checked = 0;
  for (const n of [...sizes].sort((a, b) => a - b)) {
    const root = t.rootAt(n);
    assert.equal(root, mth(hashes.slice(0, n)).toString("hex"), `root at ${n} equals the RFC recursion`);
    for (let i = 0; i < n; i++) {
      const lh = hashes[i].toString("hex");
      const proof = t.proof(i, n);
      assert.ok(verifyLeafHash(lh, i, n, proof, root), `size ${n} index ${i} verifies`);
      assert.equal(verifyLeafHash(flipBit(lh, Math.floor(r() * 256)), i, n, proof, root), false, `leaf bit flip ${n}/${i}`);
      assert.equal(verifyLeafHash(lh, i, n, proof, flipBit(root, Math.floor(r() * 256))), false, `root bit flip ${n}/${i}`);
      if (proof.length) {
        const j = Math.floor(r() * proof.length);
        const bad = proof.slice(); bad[j] = flipBit(bad[j], Math.floor(r() * 256));
        assert.equal(verifyLeafHash(lh, i, n, bad, root), false, `proof bit flip ${n}/${i}/${j}`);
        assert.equal(verifyLeafHash(lh, i, n, proof.slice(0, -1), root), false, `truncated proof ${n}/${i}`);
      }
      if (n > 1) assert.equal(verifyLeafHash(lh, (i + 1) % n, n, proof, root), false, `wrong index ${n}/${i}`);
      checked++;
    }
  }
  assert.ok(checked > 5000, `checked ${checked} proofs`);
});

test("incremental append: the root after every append equals the RFC recursion over all leaves so far", () => {
  const t = new ContextTree();
  const hashes = [];
  for (let i = 0; i < 300; i++) {
    const h = hashLeafData(Buffer.from([i & 0xff, i >> 8]));
    hashes.push(h);
    t.appendHash(h);
    assert.equal(t.root(), mth(hashes).toString("hex"), `size ${i + 1}`);
  }
});

test("context leaves: leaf hash is SHA-256(0x00 || canonical JSON), and static verify takes the leaf object", () => {
  const leaves = Array.from({ length: 13 }, (_, i) => leafOf({ stage: "web", source: `https://example.test/p${i}`, bytes: "x".repeat(300 + i), tenantKey: Buffer.alloc(32, 7), ts: "2026-10-13T00:00:00.000Z" }));
  const l0 = leaves[0];
  const canon = `{"blobHash":"${l0.blobHash}","blobHashKind":"sha256","size":300,"sourceHash":"${l0.sourceHash}","sourceKind":"url","stage":"web","ts":"2026-10-13T00:00:00.000Z"}`;
  assert.equal(leafHash(l0).toString("hex"), sha(Buffer.from([0]), Buffer.from(canon)).toString("hex"));
  assert.equal(leafHash({ ...l0, extra: "ignored" }).toString("hex"), leafHash(l0).toString("hex"), "only the leaf fields are hashed");
  const t = new ContextTree();
  for (const l of leaves) { const r = t.append(l); assert.equal(r.root, t.root()); }
  for (let i = 0; i < leaves.length; i++) {
    assert.ok(ContextTree.verify(leaves[i], i, 13, t.proof(i), t.root()));
    assert.equal(ContextTree.verify({ ...leaves[i], size: leaves[i].size + 1 }, i, 13, t.proof(i), t.root()), false, "an edited leaf fails");
  }
  assert.throws(() => t.append({ ...l0, sourceHash: "/etc/passwd" }), /content-free/);
});
