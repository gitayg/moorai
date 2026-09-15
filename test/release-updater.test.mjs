// scripts/release-updater.mjs: the release must publish a version sidecar next to the updater
// tarball, because the server's updater manifest reads the desktop version from it. Pinned:
//   1. MoorAI.app.tar.gz.version is uploaded with content `${version}\n`, AFTER the tarball + sig.
//   2. The same file is written to dist/ (the server's dev fallback).
//   3. A failed tarball upload never uploads the sidecar.
//
//   node --test test/release-updater.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { uploadUpdater } from "../scripts/release-updater.mjs";

const sha = (buf) => createHash("sha256").update(buf).digest("hex");

function fixture() {
  const root = mkdtempSync(join(tmpdir(), "release-updater-"));
  const macDir = join(root, "macos"), distDir = join(root, "dist");
  mkdirSync(macDir); mkdirSync(distDir);
  writeFileSync(join(macDir, "MoorAI.app.tar.gz"), Buffer.from([1, 2, 3, 4]));
  writeFileSync(join(macDir, "MoorAI.app.tar.gz.sig"), "sig-text");
  return { macDir, distDir };
}

function recorder({ failTarball = false } = {}) {
  const calls = [];
  const mcp = async (name, args) => {
    calls.push({ name, ...args });
    const buf = Buffer.from(args.content, args.encoding === "base64" ? "base64" : "utf-8");
    if (failTarball && args.path === "MoorAI.app.tar.gz") throw new Error("upload failed");
    return { sha256: sha(buf), bytes: buf.length, container_path: `/data/${args.path}` };
  };
  return { calls, mcp };
}

test("uploads the version sidecar last, with the released version and a trailing newline", async () => {
  const { macDir, distDir } = fixture();
  const { calls, mcp } = recorder();
  await uploadUpdater({ mcp, macDir, distDir, slug: "moorai", version: "0.83.3" });
  assert.deepEqual(calls.map((c) => c.path), ["MoorAI.app.tar.gz", "MoorAI.app.tar.gz.sig", "MoorAI.app.tar.gz.version"]);
  const side = calls[2];
  assert.equal(side.name, "appcrane_set_data_blob");
  assert.equal(side.env, "production");
  assert.equal(side.slug, "moorai");
  assert.equal(Buffer.from(side.content, side.encoding === "base64" ? "base64" : "utf-8").toString("utf8"), "0.83.3\n");
});

test("writes dist/MoorAI.app.tar.gz.version locally", async () => {
  const { macDir, distDir } = fixture();
  await uploadUpdater({ mcp: recorder().mcp, macDir, distDir, slug: "moorai", version: "0.83.3" });
  assert.equal(readFileSync(join(distDir, "MoorAI.app.tar.gz.version"), "utf8"), "0.83.3\n");
});

test("a failed tarball upload never uploads the sidecar", async () => {
  const { macDir, distDir } = fixture();
  const { calls, mcp } = recorder({ failTarball: true });
  await assert.rejects(uploadUpdater({ mcp, macDir, distDir, slug: "moorai", version: "0.83.3" }));
  assert.ok(!calls.some((c) => c.path === "MoorAI.app.tar.gz.version"));
});
