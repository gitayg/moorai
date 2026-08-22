// Windows ACL evaluation for readRootOwned (moorai-hook.mjs).
//
// THE HOLE: on POSIX, readRootOwned trusts a "system" file only when the OS says the user cannot have
// written it (root-owned, not group/world-writable). On win32 it returned the file's contents
// UNCONDITIONALLY — so %ProgramData%\MoorAI\breakglass.pub, policy.pub and offline-posture were all
// trusted on Windows with no verification whatsoever. That is not theoretical: %ProgramData% carries an
// inherited CREATOR OWNER ACE, so a file created there by a NON-elevated process ends up with a
// `MACHINE\user:(I)(F)` entry — the very "the agent can rewrite it" property the POSIX check exists to
// exclude. An attacker who can drop a file at that path owns the break-glass and policy trust anchors.
//
// The contract these tests pin: the ACL is parsed, write access by anyone who is not an administrator
// makes the file UNTRUSTED, and anything that cannot be evaluated is untrusted too (fail CLOSED) —
// exactly how a user-writable POSIX file is already treated.
//
// SCOPE — stated plainly: these test the PURE evaluation of captured `icacls` output. No Windows host
// was available, so the spawn path (windowsFileIsProtected in moorai-hook.mjs) and the real-world shape
// of icacls output on a live machine are UNVERIFIED. The samples below are written to match documented
// icacls formatting, including the inherited-ACE `(I)` marker, inheritance flags, the specific-rights
// comma form, and the trailing "Successfully processed" summary.
//
//   node --test --test-reporter=spec "test/**/*.test.mjs"
//   (bare `node --test` walks src-tauri/target/ and hangs — always pass the glob.)
import { test } from "node:test";
import assert from "node:assert/strict";
import { parseIcacls, icaclsPermissive, normalizeAclPrincipal } from "../cli/hook-core.mjs";

const P = "C:\\ProgramData\\MoorAI\\policy.pub";
const TAIL = "\r\nSuccessfully processed 1 files; Failed processing 0 files\r\n";
const acl = (...lines) => `${P} ${lines[0]}\r\n` + lines.slice(1).map((l) => `${" ".repeat(P.length + 1)}${l}`).join("\r\n") + TAIL;

// What an elevated installer leaves behind: only SYSTEM and Administrators can write.
const SECURE = acl(
  "NT AUTHORITY\\SYSTEM:(I)(F)",
  "BUILTIN\\Administrators:(I)(F)",
  "BUILTIN\\Users:(I)(RX)"
);

// The actual failure mode: the file was created under %ProgramData% by the logged-in (non-elevated)
// user, so the inherited CREATOR OWNER ACE materialized as a full-control ACE for that user.
const USER_WRITABLE = acl(
  "DESKTOP-JOL2MB8\\itay:(I)(F)",
  "NT AUTHORITY\\SYSTEM:(I)(F)",
  "BUILTIN\\Administrators:(I)(F)",
  "BUILTIN\\Users:(I)(RX)"
);

// ---- the hole itself ----

test("ACL: an administrator-only ProgramData file is NOT permissive", () => {
  const r = icaclsPermissive(SECURE, P);
  assert.equal(r.permissive, false, `reasons: ${JSON.stringify(r.reasons)}`);
  assert.deepEqual(r.reasons, []);
});

test("ACL: a file the logged-in user has (F) on IS permissive — the ProgramData CREATOR OWNER case", () => {
  const r = icaclsPermissive(USER_WRITABLE, P);
  assert.equal(r.permissive, true, "a user-writable anchor must never be trusted");
  assert.deepEqual(r.reasons, ["ITAY:F"]);
});

test("ACL: explicit write grants to the well-known ordinary-user principals are permissive", () => {
  for (const [who, right, reason] of [
    ["BUILTIN\\Users", "F", "USERS:F"],
    ["BUILTIN\\Users", "M", "USERS:M"],
    ["BUILTIN\\Users", "W", "USERS:W"],
    ["Everyone", "F", "EVERYONE:F"],
    ["Everyone", "M", "EVERYONE:M"],
    ["NT AUTHORITY\\Authenticated Users", "M", "AUTHENTICATED USERS:M"],
    ["NT AUTHORITY\\INTERACTIVE", "W", "INTERACTIVE:W"]
  ]) {
    const out = acl(`${who}:(${right})`, "NT AUTHORITY\\SYSTEM:(I)(F)", "BUILTIN\\Administrators:(I)(F)");
    const r = icaclsPermissive(out, P);
    assert.equal(r.permissive, true, `${who}:(${right}) must be permissive`);
    assert.deepEqual(r.reasons, [reason]);
  }
});

// ---- fail CLOSED whenever the guarantee cannot be established ----

test("ACL: output with no parseable ACE is permissive — an unevaluable ACL is never trusted", () => {
  for (const out of [
    "",
    "   ",
    `${P}: Access is denied.\r\nSuccessfully processed 0 files; Failed processing 1 files\r\n`,
    "Invalid parameter \"C:\\nope\"\r\n",
    "The system cannot find the file specified.\r\n"
  ]) {
    const r = icaclsPermissive(out, P);
    assert.equal(r.permissive, true, `must fail closed on: ${JSON.stringify(out)}`);
    assert.deepEqual(r.reasons, ["no-acl-entries"]);
  }
});

test("ACL: a named account that is not an administrator is permissive — the allow-list is closed", () => {
  // Deliberate design choice: any write grant outside the privileged set counts, INCLUDING service
  // accounts and domain users. A wrongly-refused ACL degrades the device to "no anchor" (safe); a
  // wrongly-accepted one is a silent enforcement bypass.
  const out = acl("CORP\\jdoe:(M)", "NT AUTHORITY\\SYSTEM:(I)(F)", "BUILTIN\\Administrators:(I)(F)");
  assert.equal(icaclsPermissive(out, P).permissive, true);
});

// ---- things that must NOT be read as permissive ----

test("ACL: privileged principals with full control are fine, domain admin variants included", () => {
  const out = acl(
    "NT AUTHORITY\\SYSTEM:(I)(F)",
    "BUILTIN\\Administrators:(I)(F)",
    "CORP\\Domain Admins:(F)",
    "NT SERVICE\\TrustedInstaller:(F)",
    "BUILTIN\\Users:(I)(RX)"
  );
  assert.equal(icaclsPermissive(out, P).permissive, false);
});

test("ACL: an INHERIT-ONLY (IO) ACE governs children, not this file, and must be ignored", () => {
  // CREATOR OWNER:(OI)(CI)(IO)(F) is present on virtually every inherited ProgramData ACL. Reading its
  // (F) as a grant on the file itself would make EVERY correctly-secured anchor look permissive.
  const out = acl(
    "NT AUTHORITY\\SYSTEM:(I)(F)",
    "BUILTIN\\Administrators:(I)(F)",
    "CREATOR OWNER:(I)(OI)(CI)(IO)(F)",
    "BUILTIN\\Users:(I)(OI)(CI)(IO)(F)",
    "BUILTIN\\Users:(I)(RX)"
  );
  const r = icaclsPermissive(out, P);
  assert.equal(r.permissive, false, `reasons: ${JSON.stringify(r.reasons)}`);
});

test("ACL: CREATOR OWNER is NOT privileged — an effective grant to it is permissive", () => {
  // It resolves to whoever created the file, which under %ProgramData% is precisely the ordinary user
  // this check exists to exclude. Only the inherit-ONLY form above is harmless.
  const out = acl("CREATOR OWNER:(F)", "NT AUTHORITY\\SYSTEM:(I)(F)", "BUILTIN\\Administrators:(I)(F)");
  const r = icaclsPermissive(out, P);
  assert.equal(r.permissive, true);
  assert.deepEqual(r.reasons, ["CREATOR OWNER:F"]);
});

test("ACL: read-only SPECIFIC rights (the comma form) are not write access", () => {
  const out = acl("BUILTIN\\Users:(Rc,S,RA,REA,RD,X)", "NT AUTHORITY\\SYSTEM:(F)", "BUILTIN\\Administrators:(F)");
  assert.equal(icaclsPermissive(out, P).permissive, false);
});

test("ACL: write-bearing SPECIFIC rights ARE write access, even without F/M/W", () => {
  // The bypass a naive "look for (F)/(M)/(W)" scan would miss: WD (write data) and AD (append data)
  // are enough to replace an anchor's contents.
  const out = acl("BUILTIN\\Users:(Rc,S,RD,WD,AD,X)", "NT AUTHORITY\\SYSTEM:(F)", "BUILTIN\\Administrators:(F)");
  const r = icaclsPermissive(out, P);
  assert.equal(r.permissive, true, "WD/AD let the holder rewrite the file");
  assert.deepEqual(r.reasons, ["USERS:WD+AD"]);
});

// ---- parsing details ----

test("PARSE: the file path on the first line is stripped, not read as a principal", () => {
  const aces = parseIcacls(SECURE, P);
  assert.deepEqual(aces.map((a) => a.principal), ["NT AUTHORITY\\SYSTEM", "BUILTIN\\Administrators", "BUILTIN\\Users"]);
  assert.deepEqual(aces[0].rights, ["F"]);
  assert.deepEqual(aces[2].rights, ["RX"]);
});

test("PARSE: the summary trailer is not an ACE", () => {
  assert.equal(parseIcacls(SECURE, P).length, 3);
  assert.ok(!parseIcacls(SECURE, P).some((a) => /Successfully processed/i.test(a.principal)));
});

test("PARSE: works with LF line endings too, and when filePath is not supplied", () => {
  const lf = SECURE.replace(/\r\n/g, "\n");
  assert.equal(icaclsPermissive(lf, P).permissive, false);
  // No filePath: the first line still resolves to SYSTEM via last-backslash normalization.
  assert.equal(icaclsPermissive(lf).permissive, false);
  assert.equal(icaclsPermissive(USER_WRITABLE.replace(/\r\n/g, "\n")).permissive, true);
});

test("PARSE: inheritance flags are not mistaken for rights", () => {
  const [ace] = parseIcacls(acl("BUILTIN\\Users:(I)(OI)(CI)(NP)(RX)"), P);
  assert.deepEqual(ace.rights, ["RX"]);
  assert.equal(ace.inheritOnly, false);
});

test("NORMALIZE: a principal reduces to its bare name, upper-cased", () => {
  assert.equal(normalizeAclPrincipal("NT AUTHORITY\\Authenticated Users"), "AUTHENTICATED USERS");
  assert.equal(normalizeAclPrincipal("BUILTIN\\Users"), "USERS");
  assert.equal(normalizeAclPrincipal("Everyone"), "EVERYONE");
  assert.equal(normalizeAclPrincipal("CREATOR OWNER"), "CREATOR OWNER");
  assert.equal(normalizeAclPrincipal("  DESKTOP-1\\itay  "), "ITAY");
  assert.equal(normalizeAclPrincipal(""), "");
  assert.equal(normalizeAclPrincipal(null), "");
});
