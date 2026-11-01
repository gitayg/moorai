// cli/file-origin.mjs: where a file came from, from its mark alone. macOS quarantine / kMDItemWhereFroms (real
// attributes set with xattr -w on a fixture this test creates), the Windows Zone.Identifier parser (a string: it
// cannot run here), the Linux XDG download directory, the cache, and fail-closed errors.
//
//   node --test --import ./test/hermetic-env.mjs test/file-origin.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";
import { fileOrigin, parseQuarantine, parseZoneIdentifier, parseWhereFroms, hostOf, xdgDownloadDir, downloadDirs, underDir } from "../cli/file-origin.mjs";
import { rmTree } from "./fs-cleanup.mjs";

const MAC = process.platform === "darwin";
// A real kMDItemWhereFroms value: a binary plist holding ["https://web.whatsapp.com/"].
const WHERE_HEX = "62706c6973743030a1015f101968747470733a2f2f7765622e77686174736170702e636f6d2f080a00000000000001010000000000000002000000000000000000000000000000" + "26";
const hash = (s) => `H(${s.length})`;
function quarantine(f, { where = true } = {}) {
  assert.equal(spawnSync("/usr/bin/xattr", ["-w", "com.apple.quarantine", "0081;6adca4d1;Chrome;FB371173-B671-4DB8-BB86-AF9A746F0860", f]).status, 0);
  if (where) assert.equal(spawnSync("/usr/bin/xattr", ["-wx", "com.apple.metadata:kMDItemWhereFroms", WHERE_HEX, f]).status, 0);
}
function memCache() { const m = new Map(); return { m, get: (k) => (m.has(k) ? m.get(k) : undefined), set: (k, v) => m.set(k, v) }; }

test("parsers: quarantine record, Zone.Identifier (UTF-8 and UTF-16LE), WhereFroms plist, host", () => {
  assert.deepEqual(parseQuarantine("0081;6adca4d1;Chrome;FB371173-B671-4DB8-BB86-AF9A746F0860"), { flags: "0081", app: "Chrome" });
  assert.deepEqual(parseQuarantine("0083;6adca4d1;;"), { flags: "0083", app: null });
  assert.equal(parseQuarantine("0081;1;<script>;x").app, "other", "an app field that is not a plain name is not kept");
  assert.equal(parseQuarantine(""), null);
  const zi = "[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=https://web.whatsapp.com/\r\nHostUrl=https://media.example-cdn.net/f/abc\r\n";
  assert.deepEqual(parseZoneIdentifier(zi), { zoneId: 3, hostUrl: "https://media.example-cdn.net/f/abc", referrerUrl: "https://web.whatsapp.com/" });
  const u16 = Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(zi, "utf16le")]);
  assert.equal(parseZoneIdentifier(u16).zoneId, 3);
  assert.equal(parseZoneIdentifier("[ZoneTransfer]\nZoneId=2\n").zoneId, 2);
  assert.equal(parseZoneIdentifier("ZoneId=3"), null, "no [ZoneTransfer] section");
  assert.equal(parseZoneIdentifier("[ZoneTransfer]\nZoneId=x\n"), null);
  assert.deepEqual(parseWhereFroms(Buffer.from(WHERE_HEX, "hex")), ["https://web.whatsapp.com/"]);
  assert.deepEqual(parseWhereFroms(Buffer.from('<plist><array><string>https://a.example/x</string><string>https://b.example/</string></array></plist>')), ["https://a.example/x", "https://b.example/"]);
  assert.deepEqual(parseWhereFroms(Buffer.from("bplist00garbage")), []);
  assert.equal(hostOf("https://Web.WhatsApp.com/"), "web.whatsapp.com");
  assert.equal(hostOf("not a url"), null);
});

test("Linux: XDG_DOWNLOAD_DIR from user-dirs.dirs, else ~/Downloads; both watched", () => {
  const files = { "/home/u/.config/user-dirs.dirs": '# written by xdg-user-dirs-update\nXDG_DESKTOP_DIR="$HOME/Desktop"\nXDG_DOWNLOAD_DIR="$HOME/Téléchargements"\n' };
  const readFile = (p) => { if (p in files) return files[p]; const e = new Error("ENOENT"); e.code = "ENOENT"; throw e; };
  assert.equal(xdgDownloadDir({ home: "/home/u", env: {}, readFile }), "/home/u/Téléchargements");
  assert.deepEqual(downloadDirs({ platform: "linux", home: "/home/u", env: {}, readFile }), ["/home/u/Downloads", "/home/u/Téléchargements"]);
  assert.equal(xdgDownloadDir({ home: "/home/u", env: { XDG_CONFIG_HOME: "/etc/cfg" }, readFile }), null, "XDG_CONFIG_HOME moves the file");
  files["/etc/cfg/user-dirs.dirs"] = 'XDG_DOWNLOAD_DIR="/data/dl"\n';
  assert.equal(xdgDownloadDir({ home: "/home/u", env: { XDG_CONFIG_HOME: "/etc/cfg" }, readFile }), "/data/dl");
  assert.deepEqual(downloadDirs({ platform: "linux", home: "/home/x", env: {}, readFile }), ["/home/x/Downloads"], "no file: ~/Downloads only");
  // fileOrigin on Linux: no attribute is read; the path decides.
  const stat = () => ({ isFile: () => true, dev: 1, ino: 2, mtimeMs: 3, size: 4 });
  const spawn = () => { throw new Error("no spawn on Linux"); };
  assert.deepEqual(fileOrigin("/home/u/Téléchargements/a.docx", { platform: "linux", home: "/home/u", env: {}, readFile, stat, spawn }), { source: "download-dir", app: null, hostHash: null });
  assert.equal(fileOrigin("/home/u/src/a.docx", { platform: "linux", home: "/home/u", env: {}, readFile, stat, spawn }), null);
  assert.equal(underDir("/home/u/Downloads", ["/home/u/Downloads"], { platform: "linux" }), false, "the directory itself is not inside it");
});

test("Windows: Zone.Identifier stream read with fs; ZoneId >= 3 is outside, the host is hashed", () => {
  const streams = {
    "C:\\Users\\u\\Desktop\\a.docx:Zone.Identifier": Buffer.from("[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=https://web.whatsapp.com/\r\nHostUrl=https://media.example-cdn.net/x\r\n"),
    "C:\\Users\\u\\Desktop\\intranet.docx:Zone.Identifier": Buffer.from("[ZoneTransfer]\r\nZoneId=1\r\n")
  };
  const readFile = (p) => { if (p in streams) return streams[p]; const e = new Error("ENOENT"); e.code = "ENOENT"; throw e; };
  const stat = () => ({ isFile: () => true, dev: 1, ino: 2, mtimeMs: 3, size: 4 });
  const spawn = () => { throw new Error("no process on Windows"); };
  const o = { platform: "win32", home: "C:\\Users\\u", env: {}, readFile, stat, spawn, hash };
  assert.deepEqual(fileOrigin("C:\\Users\\u\\Desktop\\a.docx", o), { source: "zone", app: null, hostHash: "H(21)" }, "HostUrl's host (media.example-cdn.net), hashed");
  assert.equal(fileOrigin("C:\\Users\\u\\Desktop\\intranet.docx", o), null, "zone 1 is local intranet");
  assert.equal(fileOrigin("C:\\Users\\u\\Desktop\\plain.txt", o), null);
  assert.deepEqual(fileOrigin("C:\\Users\\u\\Downloads\\plain.txt", o), { source: "download-dir", app: null, hostHash: null });
  const denied = { ...o, readFile: () => { const e = new Error("EACCES"); e.code = "EACCES"; throw e; } };
  assert.deepEqual(fileOrigin("C:\\Users\\u\\Downloads\\locked.docx", denied), { source: "download-dir", app: null, hostHash: null }, "an unreadable stream in Downloads fails closed");
  assert.equal(fileOrigin("C:\\Users\\u\\Desktop\\locked.docx", denied), null);
});

test("macOS: a quarantined fixture reads as quarantine (app, hashed host); a plain file does not; cache and errors", { skip: !MAC && "macOS xattr" }, () => {
  const home = mkdtempSync(join(tmpdir(), "moorai-origin-"));
  try {
    mkdirSync(join(home, "work")); mkdirSync(join(home, "Downloads"));
    const q = join(home, "work", "q.docx"), plain = join(home, "work", "plain.txt"), dl = join(home, "Downloads", "unmarked.pdf"), stripped = join(home, "work", "stripped.docx");
    for (const f of [q, plain, dl, stripped]) writeFileSync(f, "x\n");
    quarantine(q);
    quarantine(stripped);
    spawnSync("/usr/bin/xattr", ["-d", "com.apple.quarantine", stripped]);
    let spawns = 0;
    const spawn = (...a) => { spawns++; return spawnSync(...a); };
    const cache = memCache();
    const o = { home, cache, hash, spawn };
    assert.deepEqual(fileOrigin(q, o), { source: "quarantine", app: "Chrome", hostHash: "H(16)" }, "the WhereFroms host web.whatsapp.com, hashed");
    assert.equal(spawns, 2, "xattr -l, then xattr -px for the WhereFroms value");
    assert.deepEqual(fileOrigin(q, o), { source: "quarantine", app: "Chrome", hostHash: "H(16)" });
    assert.equal(spawns, 2, "a cache hit starts no process");
    assert.ok(![...cache.m.values()].some((v) => JSON.stringify(v).includes("whatsapp")), "the cache holds no host");
    assert.equal(fileOrigin(plain, o), null);
    assert.equal(spawns, 3, "a plain file costs one spawn");
    assert.deepEqual(fileOrigin(dl, o), { source: "download-dir", app: null, hostHash: null }, "~/Downloads without the attribute is outside");
    assert.deepEqual(fileOrigin(stripped, o), { source: "where-froms", app: null, hostHash: "H(16)" }, "quarantine removed, the download record remains");
    assert.equal(fileOrigin(join(home, "work", "missing.docx"), o), null);
    assert.equal(fileOrigin(join(home, "work"), o), null, "a directory");
    // The mark removed after the check: the cached verdict stands (mtime unchanged).
    spawnSync("/usr/bin/xattr", ["-c", q]);
    assert.equal(fileOrigin(q, o).source, "quarantine");
    // Errors fail closed in a download directory, and are not cached.
    const broken = { home, cache: memCache(), hash, spawn: () => ({ error: new Error("ETIMEDOUT"), status: null }) };
    assert.deepEqual(fileOrigin(dl, broken), { source: "download-dir", app: null, hostHash: null });
    assert.equal(fileOrigin(plain, broken), null);
    assert.equal(broken.cache.m.size, 0);
    const late = { home, cache: memCache(), hash, deadline: -1 };
    assert.deepEqual(fileOrigin(dl, late), { source: "download-dir", app: null, hostHash: null }, "past the spawn deadline: same rule");
  } finally { rmTree(home); }
});
