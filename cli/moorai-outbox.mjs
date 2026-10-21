#!/usr/bin/env node
// moorai-outbox: the alert outbox (cli/alert-outbox.mjs) from the command line.
//
//   moorai-outbox status [--json]                       what is queued, dropped and last delivered
//   moorai-outbox flush                                 start the delivery worker now
//   moorai-outbox export --out <file.zip> [--include-trail]
//                                                       a device bundle for a console this device cannot reach
//
// THE DEVICE BUNDLE. A stored (uncompressed) zip holding manifest.json, manifest.mac, VERIFY.txt,
// alerts.jsonl (one queued alert per line, with delivery.via "bundle") and, with --include-trail,
// actions.jsonl (the allow-trail queue). manifest.json lists each other file's SHA-256. manifest.mac is
// base64 HMAC-SHA256, keyed with this device's install token, over
// "moorai-device-bundle|v1|<sha256 hex of manifest.json>": the same assurance as a live POST, which the
// console authenticates by that token. The device holds no signing key of its own. The bundle carries the
// login name and host name exactly as a live alert does (the console pseudonymises them on import), so
// handle the file like the device's config. Export copies: the outbox keeps every entry, and a later online
// delivery of the same alerts is deduplicated by the console.
import { readFileSync, writeFileSync, realpathSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import { createHash, createHmac, randomUUID } from "node:crypto";
import { crc32 } from "node:zlib";
import os from "node:os";
import { STATE_DIR } from "./state-dirs.mjs";
import { readOutboxEntries, readOutboxState, outboxPosture, claimOutboxFlush } from "./alert-outbox.mjs";

export const DEVICE_BUNDLE_SCHEMA = "moorai.device-bundle/1", DEVICE_SIGNED_PREFIX = "moorai-device-bundle|v1|";
const sha256hex = (s) => createHash("sha256").update(s).digest("hex");
const TRAIL_FILE = "action-trail.jsonl";

function verifyText(includeTrail) {
  const files = ["VERIFY.txt", "alerts.jsonl", ...(includeTrail ? ["actions.jsonl"] : [])].join(" ");
  return [
    "MoorAI device bundle (moorai.device-bundle/1)",
    "",
    "manifest.mac is base64 HMAC-SHA256 over the text below, keyed with this device's install token.",
    "It is token-authenticated, the same assurance as an alert the device posts live.",
    "",
    "1. Recompute the MAC (needs the install token) and compare it with manifest.mac:",
    `printf '${DEVICE_SIGNED_PREFIX}%s' "$(openssl dgst -sha256 -r manifest.json | cut -c1-64)" > signed-message.txt`,
    "openssl dgst -sha256 -mac HMAC -macopt key:<install token> -binary signed-message.txt | openssl base64 -A",
    "",
    "2. Compare each file's SHA-256 with its entry in manifest.json \"files\":",
    `openssl dgst -sha256 -r ${files}`,
    ""
  ].join("\n");
}

// The bundle's files as strings, its manifest and the manifest's SHA-256. Throws when there is no install
// token to authenticate it with. bundleId, identity and appVersion are injectable for a deterministic build.
export function buildDeviceBundle({ config, dir = STATE_DIR, now = new Date(), includeTrail = false, bundleId, identity, appVersion: version } = {}) {
  const token = config && typeof config.installToken === "string" ? config.installToken.trim() : "";
  if (!token) throw new Error("no install token: a device bundle is authenticated with this device's install token (enrol the device first)");
  const entries = readOutboxEntries(dir);
  const alerts = entries.map((e) => JSON.stringify({ ...e.alert, delivery: { v: 1, via: "bundle", oid: e.oid, queuedAt: new Date(e.queuedAt || 0).toISOString(), captureStripped: e.captureStripped === true, ...(e.captureStripped === true && typeof e.rhash === "string" ? { rhash: e.rhash } : {}) } }) + "\n").join("");
  const files = { "VERIFY.txt": verifyText(includeTrail), "alerts.jsonl": alerts };
  if (includeTrail) {
    let raw = "";
    try { raw = readFileSync(join(dir, TRAIL_FILE), "utf8"); } catch { raw = ""; }
    files["actions.jsonl"] = raw.split("\n").filter((l) => { try { const r = JSON.parse(l); return r && typeof r === "object" && !Array.isArray(r); } catch { return false; } }).map((l) => l + "\n").join("");
  }
  const numbered = entries.filter((e) => e.seq !== null).map((e) => e.seq);
  let head = null;
  try { const h = JSON.parse(readFileSync(join(dir, ".chain-alerts.head.json"), "utf8")); if (typeof h.chash === "string" && /^[0-9a-f]{64}$/.test(h.chash)) head = h.chash; } catch { head = null; }
  const latest = entries.length ? entries[entries.length - 1].alert : {};
  const id = identity && typeof identity === "object" ? identity : {
    user: typeof latest.user === "string" ? latest.user : os.userInfo().username,
    device: typeof latest.device === "string" ? latest.device : os.hostname(),
    platform: typeof latest.platform === "string" ? latest.platform : os.platform()
  };
  const st = readOutboxState(dir);
  const order = ["VERIFY.txt", "alerts.jsonl", ...(includeTrail ? ["actions.jsonl"] : [])];
  const manifest = {
    schema: DEVICE_BUNDLE_SCHEMA,
    kind: "device",
    bundleId: typeof bundleId === "string" && bundleId ? bundleId : randomUUID(),
    tenant: typeof config.tenant === "string" ? config.tenant : "",
    createdAt: now.toISOString(),
    appVersion: typeof version === "string" ? version : appVersion(),
    identity: { user: id.user, device: id.device, platform: id.platform },
    seq: { from: numbered.length ? Math.min(...numbered) : null, to: numbered.length ? Math.max(...numbered) : null, count: numbered.length, unnumbered: entries.length - numbered.length, chainHeadAtExport: head },
    outbox: { dropped: { ...st.dropped }, droppedRanges: st.droppedRanges },
    auth: { alg: "hmac-sha256", tokenId: sha256hex(token).slice(0, 16), signedMessage: `${DEVICE_SIGNED_PREFIX}<sha256 hex of manifest.json>` },
    files: order.map((path) => ({ path, sha256: sha256hex(files[path]), bytes: Buffer.byteLength(files[path]) }))
  };
  const manifestJson = JSON.stringify(manifest, null, 2) + "\n";
  const manifestSha256 = sha256hex(manifestJson);
  const mac = createHmac("sha256", token).update(DEVICE_SIGNED_PREFIX + manifestSha256).digest("base64");
  return { files: { "manifest.json": manifestJson, "manifest.mac": mac, ...files }, manifest, manifestSha256, createdAt: now };
}

function appVersion() {
  try { const v = JSON.parse(readFileSync(join(dirname(fileURLToPath(import.meta.url)), "..", "package.json"), "utf8")).version; return typeof v === "string" ? v : ""; } catch { return ""; }
}

function dosTime(d) {
  const time = (d.getUTCHours() << 11) | (d.getUTCMinutes() << 5) | Math.floor(d.getUTCSeconds() / 2);
  const date = ((Math.max(1980, d.getUTCFullYear()) - 1980) << 9) | ((d.getUTCMonth() + 1) << 5) | d.getUTCDate();
  return { time, date };
}
// Stored entries (method 0), UTF-8 names, one fixed timestamp (the bundle's createdAt): the same files and
// time give the same bytes. Order: manifest.json, manifest.mac, then the manifest's files.
export function deviceBundleZip(bundle) {
  const when = bundle.createdAt instanceof Date ? bundle.createdAt : new Date(bundle.manifest.createdAt);
  const { time, date } = dosTime(when);
  const names = ["manifest.json", "manifest.mac", ...bundle.manifest.files.map((f) => f.path)];
  const locals = [], centrals = [];
  let offset = 0;
  for (const n of names) {
    const name = Buffer.from(n, "utf8"), data = Buffer.from(bundle.files[n], "utf8"), crc = crc32(data) >>> 0;
    const lh = Buffer.alloc(30);
    lh.writeUInt32LE(0x04034b50, 0); lh.writeUInt16LE(20, 4); lh.writeUInt16LE(0x0800, 6); lh.writeUInt16LE(0, 8);
    lh.writeUInt16LE(time, 10); lh.writeUInt16LE(date, 12); lh.writeUInt32LE(crc, 14);
    lh.writeUInt32LE(data.length, 18); lh.writeUInt32LE(data.length, 22); lh.writeUInt16LE(name.length, 26);
    const ch = Buffer.alloc(46);
    ch.writeUInt32LE(0x02014b50, 0); ch.writeUInt16LE(20, 4); ch.writeUInt16LE(20, 6); ch.writeUInt16LE(0x0800, 8); ch.writeUInt16LE(0, 10);
    ch.writeUInt16LE(time, 12); ch.writeUInt16LE(date, 14); ch.writeUInt32LE(crc, 16);
    ch.writeUInt32LE(data.length, 20); ch.writeUInt32LE(data.length, 24); ch.writeUInt16LE(name.length, 28); ch.writeUInt32LE(offset, 42);
    locals.push(lh, name, data);
    centrals.push(ch, name);
    offset += 30 + name.length + data.length;
  }
  const cd = Buffer.concat(centrals);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(names.length, 8); end.writeUInt16LE(names.length, 10);
  end.writeUInt32LE(cd.length, 12); end.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, cd, end]);
}

function statusText(p, st) {
  const out = [
    `alert outbox: ${p.state}, ${p.pending} queued (${p.bytes} bytes)${p.oldestQueuedAt ? `, oldest since ${p.oldestQueuedAt}` : ""}`,
    `last delivered: ${p.lastDeliveredSeq ? `seq ${p.lastDeliveredSeq}` : "none"}${p.lastDeliveredAt ? ` (${p.lastDeliveredAt})` : ""}`,
    `dropped before delivery: full ${p.dropped.full}, aged ${p.dropped.aged}, rejected ${p.dropped.rejected}, oversize ${p.dropped.oversize}${p.droppedRanges.length ? `; seq ranges ${p.droppedRanges.map((r) => (r[0] === r[1] ? r[0] : `${r[0]}-${r[1]}`)).join(", ")}` : ""}`
  ];
  if (st.retryAt > Date.now()) out.push(`next retry: ${new Date(st.retryAt).toISOString()}`);
  if (st.mode === "single") out.push("console has no batch route: posting one alert at a time");
  return out.join("\n");
}

async function main(argv) {
  const [cmd, ...rest] = argv;
  if (cmd === "status") {
    const p = outboxPosture();
    process.stdout.write(rest.includes("--json") ? JSON.stringify(p) + "\n" : statusText(p, readOutboxState()) + "\n");
    return 0;
  }
  if (cmd === "flush") {
    if (!claimOutboxFlush({ force: true })) { process.stdout.write("nothing to send, or a delivery worker is already running\n"); return 0; }
    const hook = join(dirname(fileURLToPath(import.meta.url)), "moorai-hook.mjs");
    spawn(process.execPath, [hook, "alertpost"], { detached: true, stdio: "ignore" }).unref();
    process.stdout.write("delivery worker started; `moorai-outbox status` shows the result\n");
    return 0;
  }
  if (cmd === "export") {
    const i = rest.indexOf("--out");
    const out = i >= 0 ? rest[i + 1] : "";
    if (!out) { process.stderr.write("usage: moorai-outbox export --out <file.zip> [--include-trail]\n"); return 2; }
    const { loadConfig } = await import("./config.mjs");
    let b;
    try { b = buildDeviceBundle({ config: loadConfig(), includeTrail: rest.includes("--include-trail") }); }
    catch (e) { process.stderr.write(`moorai-outbox: ${e.message}\n`); return 1; }
    try { writeFileSync(out, deviceBundleZip(b), { mode: 0o600, flag: "wx" }); }
    catch (e) { process.stderr.write(`moorai-outbox: cannot write ${out}: ${e.code === "EEXIST" ? "the file exists (never overwritten)" : e.message}\n`); return 1; }
    const m = b.manifest;
    process.stdout.write(`wrote ${out}: ${m.seq.count} numbered and ${m.seq.unnumbered} unnumbered alerts${m.seq.from ? ` (seq ${m.seq.from}-${m.seq.to})` : ""}, manifest sha256 ${b.manifestSha256}\nThe file names this device's user and host, like a live alert: handle it like the device's config.\n`);
    return 0;
  }
  process.stderr.write("usage: moorai-outbox status [--json] | flush | export --out <file.zip> [--include-trail]\n");
  return 2;
}

const invoked = (() => { try { return realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url)); } catch { return false; } })();
if (invoked) {
  main(process.argv.slice(2)).then((code) => { process.exitCode = code; }, (e) => { process.stderr.write(`moorai-outbox: ${e && e.message}\n`); process.exitCode = 1; });
}
