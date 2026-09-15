// Section 2b of scripts/release.mjs: upload the Tauri updater artifact + signature to AppCrane /data.
// Split out with an injected `mcp` so test/release-updater.test.mjs can drive it without a network.
import { readFileSync, writeFileSync, copyFileSync, readdirSync } from "node:fs";
import { createHash } from "node:crypto";
import { join } from "node:path";

const sha256 = (buf) => createHash("sha256").update(buf).digest("hex");

export async function uploadUpdater({ mcp, macDir, distDir, slug, version, log = () => {} }) {
  const tgzName = readdirSync(macDir).find((f) => f.endsWith(".app.tar.gz"));
  const sigName = readdirSync(macDir).find((f) => f.endsWith(".app.tar.gz.sig"));
  if (!tgzName || !sigName) {
    console.log("  ⚠ no updater artifact — check the 'updater' bundle target + TAURI_SIGNING_PRIVATE_KEY");
    return false;
  }
  log("Uploading updater artifact + signature");
  const tgz = readFileSync(join(macDir, tgzName));
  copyFileSync(join(macDir, tgzName), join(distDir, "MoorAI.app.tar.gz"));
  copyFileSync(join(macDir, sigName), join(distDir, "MoorAI.app.tar.gz.sig"));
  const ut = await mcp("appcrane_set_data_blob", { slug, env: "production", path: "MoorAI.app.tar.gz", encoding: "base64", content: tgz.toString("base64") });
  if (ut.sha256 !== sha256(tgz)) throw new Error("updater artifact sha mismatch");
  await mcp("appcrane_set_data_blob", { slug, env: "production", path: "MoorAI.app.tar.gz.sig", encoding: "utf-8", content: readFileSync(join(macDir, sigName), "utf8") });
  console.log(`  ${ut.container_path} (${ut.bytes} B) + signature ✓`);
  // Sidecar goes LAST: a failed tarball/sig upload must never advertise a version whose artifact isn't there.
  const ver = `${version}\n`;
  writeFileSync(join(distDir, "MoorAI.app.tar.gz.version"), ver);
  const uv = await mcp("appcrane_set_data_blob", { slug, env: "production", path: "MoorAI.app.tar.gz.version", encoding: "utf-8", content: ver });
  if (uv.sha256 !== sha256(Buffer.from(ver, "utf-8"))) throw new Error("updater version sidecar sha mismatch");
  console.log(`  ${uv.container_path} = ${version} ✓`);
  return true;
}
