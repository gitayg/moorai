// Which `threatcl` the Stop check runs (#85): only the signed policy's threatModel.threatclPath, and only when
// every path component from / to it is root-owned and not group- or world-writable. PATH is never searched.
// "Not run" is a fake that writes a marker file when executed and the marker staying absent; "run" is the
// Stop result (tmv) of a root-owned stand-in: /usr/bin/true is "pass", /usr/bin/false is "fail".
//
//   node --test --import ./test/hermetic-env.mjs test/boundary-threatcl.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, chmodSync, symlinkSync, existsSync, statSync, realpathSync } from "node:fs";
import { join, dirname } from "node:path";
import { tmpdir } from "node:os";
import { boundaryAtStop, boundaryWriteFields } from "../cli/boundary-stop.mjs";
import { rootOwnedChain } from "../cli/boundary-model.mjs";

const win = process.platform === "win32";
const rootOwned = (p) => { try { const st = statSync(p); return st.uid === 0 && !(st.mode & 0o022); } catch { return false; } };
const TRUE = "/usr/bin/true", FALSE = "/usr/bin/false";
const noStandIn = win || !rootOwned(TRUE) || !rootOwned(FALSE);
const tmp = (tag) => mkdtempSync(join(tmpdir(), `moorai-tcl-${tag}-`));
function put(dir, rel, text) { const p = join(dir, rel); mkdirSync(dirname(p), { recursive: true }); writeFileSync(p, text); return p; }
const TM_HCL = `spec_version = "0.1.15"\n\nthreatmodel "Payments" {\n  author = "@sec"\n  description = "card flow"\n}\n`;

// A repository with a threatcl model, and the ledger rows of one turn that edited it.
function project(threatModel) {
  const policy = threatModel ? { threatModel: { v: 1, ...threatModel } } : {};
  const proj = tmp("proj");
  put(proj, ".git/HEAD", "ref: refs/heads/main\n");
  const f = put(proj, "security/payments.hcl", TM_HCL);
  const fields = boundaryWriteFields("Edit", { file_path: f, old_string: "card flow", new_string: "card flow v2" }, f, proj, policy);
  assert.equal(fields.tm, 1, "the edit is a threat-model write");
  const rows = [{ ev: "prompt" }, { ev: "pre", tool: "Edit", decision: "allow", u: "t1", ...fields }];
  return { proj, rows, policy };
}
// An executable `threatcl` owned by the current user in a 0755 directory outside the project.
function fake(dir = join(tmp("fake"), "bin")) {
  mkdirSync(dir, { recursive: true });
  chmodSync(dir, 0o755);
  const marker = join(tmp("mark"), "ran");
  const p = join(dir, "threatcl");
  writeFileSync(p, `#!/bin/sh\necho ran >> "${marker}"\nexit 0\n`);
  chmodSync(p, 0o755);
  return { dir, bin: p, ran: () => existsSync(marker) };
}
const stop = ({ proj, rows, policy }, cwd = proj) => boundaryAtStop({ rows, scope: rows, cwd, policy, threatclTimeoutMs: 3000 }).validation;
function withPath(path, fn) {
  const was = process.env.PATH;
  process.env.PATH = path;
  try { return fn(); } finally { process.env.PATH = was; }
}

test("no threatclPath: nothing runs, even with an executable threatcl on PATH", { skip: win }, () => {
  const onPath = fake();
  const v = withPath(`${onPath.dir}:${process.env.PATH}`, () => stop(project()));
  assert.equal(onPath.ran(), false, "a threatcl on PATH ran without threatclPath");
  assert.deepEqual(v, { result: "unset", files: 0 });
});

test("a threatclPath owned by the current user is not run (0755, outside the repository)", { skip: win }, () => {
  const mine = fake();
  const v = stop(project({ threatclPath: mine.bin }));
  assert.equal(mine.ran(), false, "a user-owned threatclPath ran");
  assert.equal(v.result, "untrusted");
});

test("a root-owned binary reached through a user-writable ancestor directory is not run", { skip: noStandIn }, () => {
  const dir = tmp("anc");
  chmodSync(dir, 0o755);
  // ".." is resolved physically (from the real directory), as the kernel does.
  const viaDir = `${dir}/${"../".repeat(realpathSync.native(dir).split("/").filter(Boolean).length)}usr/bin/true`;
  assert.equal(realpathSync.native(viaDir), TRUE, "the path through the user-owned directory reaches /usr/bin/true");
  assert.equal(stop(project({ threatclPath: viaDir })).result, "untrusted", "a user-owned ancestor was accepted");
  const link = join(dir, "threatcl");
  symlinkSync(TRUE, link);
  assert.equal(stop(project({ threatclPath: link })).result, "untrusted", "a user-owned symlink to a root binary was accepted");
});

test("rootOwnedChain: every component visited must be uid 0, every directory and the file not group- or world-writable", () => {
  const D = (uid = 0, mode = 0o755) => ({ uid, mode: 0o040000 | mode, isDirectory: () => true, isFile: () => false, isSymbolicLink: () => false });
  const F = (uid = 0, mode = 0o755) => ({ uid, mode: 0o100000 | mode, isDirectory: () => false, isFile: () => true, isSymbolicLink: () => false });
  const L = (uid = 0) => ({ uid, mode: 0o120777, isDirectory: () => false, isFile: () => false, isSymbolicLink: () => true });
  const fs = (tree, links = {}) => ({ lstat: (p) => { if (!(p in tree)) throw new Error("ENOENT"); return tree[p]; }, readlink: (p) => links[p] });
  const base = { "/": D(), "/opt": D(), "/opt/tc": D(), "/opt/tc/threatcl": F() };
  assert.deepEqual(rootOwnedChain("/opt/tc/threatcl", fs(base)), { state: "ok", real: "/opt/tc/threatcl" });
  assert.equal(rootOwnedChain("/opt/tc/threatcl", fs({ ...base, "/opt": D(0, 0o775) })).state, "untrusted", "group-writable ancestor");
  assert.equal(rootOwnedChain("/opt/tc/threatcl", fs({ ...base, "/opt": D(0, 0o777) })).state, "untrusted", "world-writable ancestor");
  assert.equal(rootOwnedChain("/opt/tc/threatcl", fs({ ...base, "/": D(0, 0o1777) })).state, "untrusted", "world-writable root");
  assert.equal(rootOwnedChain("/opt/tc/threatcl", fs({ ...base, "/opt/tc": D(501) })).state, "untrusted", "user-owned ancestor");
  assert.equal(rootOwnedChain("/opt/tc/threatcl", fs({ ...base, "/opt/tc/threatcl": F(501) })).state, "untrusted", "user-owned binary");
  assert.equal(rootOwnedChain("/opt/tc/threatcl", fs({ ...base, "/opt/tc/threatcl": F(0, 0o775) })).state, "untrusted", "group-writable binary");
  assert.equal(rootOwnedChain("/opt/tc/missing", fs(base)).state, "absent");
  assert.equal(rootOwnedChain("opt/tc/threatcl", fs(base)).state, "untrusted", "relative");
  const linked = { ...base, "/usr": D(), "/usr/local": D(), "/usr/local/bin": D(), "/usr/local/bin/threatcl": L() };
  assert.deepEqual(rootOwnedChain("/usr/local/bin/threatcl", fs(linked, { "/usr/local/bin/threatcl": "../../../opt/tc/threatcl" })), { state: "ok", real: "/opt/tc/threatcl" });
  assert.equal(rootOwnedChain("/usr/local/bin/threatcl", fs({ ...linked, "/usr/local/bin/threatcl": L(501) }, { "/usr/local/bin/threatcl": "/opt/tc/threatcl" })).state, "untrusted", "user-owned symlink");
  assert.equal(rootOwnedChain("/usr/local/bin/threatcl", fs({ ...linked, "/home": D(), "/home/u": D(501), "/home/u/threatcl": F() }, { "/usr/local/bin/threatcl": "/home/u/threatcl" })).state, "untrusted", "root symlink into a user-owned directory");
  const loop = { "/": D(), "/a": L() };
  assert.equal(rootOwnedChain("/a", fs(loop, { "/a": "/a" })).state, "untrusted", "symlink loop");
});

test("a threatclPath inside the repository is not run, and PATH is not searched instead", { skip: win }, () => {
  const onPath = fake();
  const pre = project();
  const inRepo = fake(join(pre.proj, "tools"));
  const v = withPath(onPath.dir, () => stop({ ...pre, policy: { threatModel: { v: 1, threatclPath: inRepo.bin } } }));
  assert.equal(inRepo.ran(), false);
  assert.equal(onPath.ran(), false, "fell back to PATH");
  assert.equal(v.result, "untrusted");
});

test("a relative threatclPath is dropped: nothing runs", { skip: win }, () => {
  const onPath = fake();
  const v = withPath(onPath.dir, () => stop(project({ threatclPath: "bin/threatcl" })));
  assert.equal(onPath.ran(), false);
  assert.equal(v.result, "unset");
});

test("a root-owned threatclPath IS run: /usr/bin/true records pass, /usr/bin/false records fail", { skip: noStandIn }, () => {
  assert.deepEqual(stop(project({ threatclPath: TRUE })), { result: "pass", files: 1 });
  assert.deepEqual(stop(project({ threatclPath: FALSE })), { result: "fail", files: 1 });
});

test("win32: the hook never runs threatcl, even a root-owned threatclPath (tmv unsupported)", { skip: noStandIn }, () => {
  const p = project({ threatclPath: TRUE });
  assert.deepEqual(boundaryAtStop({ rows: p.rows, scope: p.rows, cwd: p.proj, policy: p.policy, platform: "win32" }).validation, { result: "unsupported", files: 0 });
  assert.deepEqual(boundaryAtStop({ rows: p.rows, scope: p.rows, cwd: p.proj, policy: p.policy }).validation, { result: "pass", files: 1 }, "the same policy runs it off Windows");
});
