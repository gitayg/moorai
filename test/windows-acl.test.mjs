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
// SCOPE — stated plainly: these test the PURE evaluation of captured `icacls` output. The spawn path
// itself (windowsFileIsProtected in moorai-hook.mjs) is not exported and is still not exercised here.
// What HAS changed since this file was written: the parser was run against a real Windows 11 box
// (DESKTOP-JOL2MB8) over 10 captures and returned the correct verdict on all 10. The fixtures in the
// "REAL WINDOWS 11 CAPTURES" section below come from that machine and are the authority on output
// shape; the older hand-written samples above/below them remain as targeted unit cases.
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

// ===========================================================================================
// REAL WINDOWS 11 CAPTURES  (DESKTOP-JOL2MB8, Windows 11)
// ===========================================================================================
//
// Everything in this section is verbatim `icacls` output from a live machine, not hand-written to
// match the documentation. The parser returned the correct verdict on all of them when it was run
// there, so these are REGRESSION PROTECTION for formats now known to be real — not a bug fix.
//
// Three shapes appeared on the real box that no hand-written fixture above contains:
//   1. `NT SERVICE\TrustedInstaller:(F)` — the ONLY full-control ACE on C:\Program Files and on
//      System32 binaries. If it were ever demoted out of ICACLS_PRIVILEGED, every legitimate system
//      anchor on the machine would flip to untrusted at once. That makes it load-bearing in the
//      opposite direction from the rest of this file, which is why it gets its own test.
//   2. `APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES` and `...ALL RESTRICTED APPLICATION
//      PACKAGES` — present on essentially every file under C:\Program Files.
//   3. Comma-grouped SPECIFIC rights in the wild: `BUILTIN\Users:(CI)(WD,AD,WEA,WA)` is the real ACE
//      on C:\ProgramData itself, i.e. the exact grant that lets a non-elevated process drop a file
//      into the directory the trust anchors live in.

// Captured verbatim. A probe file created under %ProgramData% that carries an (I)(F) ACE for the
// interactive user `it` — this is the ATTACK CASE, and it must read as UNTRUSTED.
const REAL_PROGRAMDATA_USER_OWNED =
  "C:\\ProgramData\\MoorAIAclProbe\\policy.pub NT AUTHORITY\\SYSTEM:(I)(F)\r\n" +
  "                                         BUILTIN\\Administrators:(I)(F)\r\n" +
  "                                         DESKTOP-JOL2MB8\\it:(I)(F)\r\n" +
  "                                         BUILTIN\\Users:(I)(RX)\r\n" +
  "\r\n" +
  "Successfully processed 1 files; Failed processing 0 files\r\n";
const REAL_PROBE_PATH = "C:\\ProgramData\\MoorAIAclProbe\\policy.pub";

// The ACL on C:\ProgramData itself. The load-bearing line is the comma-grouped specific-rights ACE
// `BUILTIN\Users:(CI)(WD,AD,WEA,WA)`, captured verbatim: write-data / append-data / write-EA /
// write-attributes for every ordinary user. The surrounding ACEs are the Windows 11 default set.
const REAL_PROGRAMDATA_DIR =
  "C:\\ProgramData NT AUTHORITY\\SYSTEM:(OI)(CI)(F)\r\n" +
  "               BUILTIN\\Administrators:(OI)(CI)(F)\r\n" +
  "               BUILTIN\\Users:(OI)(CI)(RX)\r\n" +
  "               BUILTIN\\Users:(CI)(WD,AD,WEA,WA)\r\n" +
  "               CREATOR OWNER:(OI)(CI)(IO)(F)\r\n" +
  "\r\n" +
  "Successfully processed 1 files; Failed processing 0 files\r\n";

// A genuine system binary. TrustedInstaller holds the only (F); everyone else is read/execute.
const REAL_DEFENDER_BINARY =
  "C:\\Program Files\\Windows Defender\\MpCmdRun.exe NT SERVICE\\TrustedInstaller:(F)\r\n" +
  "                                                 NT AUTHORITY\\SYSTEM:(I)(RX)\r\n" +
  "                                                 BUILTIN\\Administrators:(I)(RX)\r\n" +
  "                                                 BUILTIN\\Users:(I)(RX)\r\n" +
  "                                                 APPLICATION PACKAGE AUTHORITY\\ALL APPLICATION PACKAGES:(I)(RX)\r\n" +
  "                                                 APPLICATION PACKAGE AUTHORITY\\ALL RESTRICTED APPLICATION PACKAGES:(I)(RX)\r\n" +
  "\r\n" +
  "Successfully processed 1 files; Failed processing 0 files\r\n";
const REAL_DEFENDER_PATH = "C:\\Program Files\\Windows Defender\\MpCmdRun.exe";

test("REAL: a %ProgramData% anchor with an (I)(F) ACE for the interactive user is UNTRUSTED", () => {
  const r = icaclsPermissive(REAL_PROGRAMDATA_USER_OWNED, REAL_PROBE_PATH);
  assert.equal(r.permissive, true, "the anchor-forgery case must never be trusted");
  assert.deepEqual(r.reasons, ["IT:F"]);
});

test("REAL: the C:\\ProgramData directory ACL is permissive via the comma-grouped specific rights", () => {
  // BUILTIN\Users:(CI)(WD,AD,WEA,WA) — no F, no M, no W. A scan that only looked for the simple
  // rights letters would call this directory administrator-only, which it very much is not.
  const r = icaclsPermissive(REAL_PROGRAMDATA_DIR, "C:\\ProgramData");
  assert.equal(r.permissive, true);
  assert.deepEqual(r.reasons, ["USERS:WD+AD+WEA+WA"]);
});

test("REAL: CREATOR OWNER:(OI)(CI)(IO)(F) on C:\\ProgramData is inherit-only and is skipped", () => {
  // Same ACE, two lives. On the DIRECTORY it is (IO) and contributes nothing — if it were counted,
  // C:\ProgramData would report two reasons instead of one and the (IO) skip would be untested at
  // the one place it actually appears. On the CHILD it materializes as a named-user ACE, which is
  // the `IT:F` reason the first test in this section pins.
  const aces = parseIcacls(REAL_PROGRAMDATA_DIR, "C:\\ProgramData");
  const co = aces.find((a) => a.principal === "CREATOR OWNER");
  assert.ok(co, `CREATOR OWNER not parsed out of: ${JSON.stringify(aces.map((a) => a.principal))}`);
  assert.equal(co.inheritOnly, true);
  assert.deepEqual(co.rights, ["F"]);
  assert.equal(icaclsPermissive(REAL_PROGRAMDATA_DIR, "C:\\ProgramData").reasons.length, 1);
});

test("REAL: NT SERVICE\\TrustedInstaller holding the only (F) keeps a system binary TRUSTED", () => {
  // The inverse-risk case for this whole file. TrustedInstaller is the sole full-control ACE on
  // C:\Program Files and on System32 binaries; demote it and every real system anchor goes dark.
  const r = icaclsPermissive(REAL_DEFENDER_BINARY, REAL_DEFENDER_PATH);
  assert.equal(r.permissive, false, `reasons: ${JSON.stringify(r.reasons)}`);
  assert.deepEqual(r.reasons, []);
  const [first] = parseIcacls(REAL_DEFENDER_BINARY, REAL_DEFENDER_PATH);
  assert.equal(first.principal, "NT SERVICE\\TrustedInstaller");
  assert.deepEqual(first.rights, ["F"]);
  assert.equal(normalizeAclPrincipal("NT SERVICE\\TrustedInstaller"), "TRUSTEDINSTALLER");
});

test("REAL: the APPLICATION PACKAGE AUTHORITY principals parse, and are NOT privileged", () => {
  // At (RX) they are harmless and must not produce a reason — that is the shipping case, and it is
  // covered by the MpCmdRun.exe test above. What is pinned here is that the allow-list stays closed
  // around them: an app-container package with write access is an ordinary-user write.
  const aces = parseIcacls(REAL_DEFENDER_BINARY, REAL_DEFENDER_PATH);
  assert.deepEqual(aces.map((a) => normalizeAclPrincipal(a.principal)), [
    "TRUSTEDINSTALLER", "SYSTEM", "ADMINISTRATORS", "USERS",
    "ALL APPLICATION PACKAGES", "ALL RESTRICTED APPLICATION PACKAGES"
  ]);
  for (const who of [
    "APPLICATION PACKAGE AUTHORITY\\ALL APPLICATION PACKAGES",
    "APPLICATION PACKAGE AUTHORITY\\ALL RESTRICTED APPLICATION PACKAGES"
  ]) {
    const out = acl(`${who}:(M)`, "NT AUTHORITY\\SYSTEM:(I)(F)", "BUILTIN\\Administrators:(I)(F)");
    const r = icaclsPermissive(out, P);
    assert.equal(r.permissive, true, `${who} with write must be permissive`);
    assert.deepEqual(r.reasons, [`${normalizeAclPrincipal(who)}:M`]);
  }
});

test("REAL: the path prefix is stripped and the blank line before the trailer is not an ACE", () => {
  // Every real capture has a blank line before the summary; none of the hand-written fixtures above
  // did. Asserting the exact principal LIST rather than just the count, so that a regression in the
  // first-line path strip shows up here too — the blank line alone is over-defended (the ACE regex
  // requires a `principal:(rights)` colon form, so an empty line could not match it even if the
  // explicit blank-line guard were deleted; that break is a measured no-op).
  assert.deepEqual(parseIcacls(REAL_PROGRAMDATA_USER_OWNED, REAL_PROBE_PATH).map((a) => a.principal), [
    "NT AUTHORITY\\SYSTEM", "BUILTIN\\Administrators", "DESKTOP-JOL2MB8\\it", "BUILTIN\\Users"
  ]);
  assert.equal(parseIcacls(REAL_DEFENDER_BINARY, REAL_DEFENDER_PATH).length, 6);
});

test("REAL: mixed \\r\\n and \\n line endings in one capture parse identically", () => {
  const mixed = REAL_PROGRAMDATA_USER_OWNED.split("\r\n").map((l, i) => l + (i % 2 ? "\n" : "\r\n")).join("");
  const r = icaclsPermissive(mixed, REAL_PROBE_PATH);
  assert.equal(r.permissive, true);
  assert.deepEqual(r.reasons, ["IT:F"]);
  assert.equal(icaclsPermissive(REAL_DEFENDER_BINARY.replace(/\r\n/g, "\n"), REAL_DEFENDER_PATH).permissive, false);
});

test("REAL: icacls echoes the path argument VERBATIM, so a case-mismatched path still resolves", () => {
  // Observed on the real box: icacls does not canonicalise the path, it prints back exactly what was
  // on the command line. windowsFileIsProtected passes the same string to both, so the exact prefix
  // strip normally hits. This pins the OTHER direction — if the two ever diverge in case, the
  // last-backslash normalization must still land on the right principal rather than inventing one.
  const lower = REAL_PROBE_PATH.toLowerCase();
  const lowerOut = REAL_PROGRAMDATA_USER_OWNED.replace(REAL_PROBE_PATH, lower);
  assert.deepEqual(icaclsPermissive(lowerOut, lower).reasons, ["IT:F"]);   // both lowercase: strips
  assert.deepEqual(icaclsPermissive(lowerOut, REAL_PROBE_PATH).reasons, ["IT:F"]); // mismatch: still IT
  assert.deepEqual(icaclsPermissive(REAL_PROGRAMDATA_USER_OWNED, lower).reasons, ["IT:F"]);
});

test("REAL: icacls failure output — exit 2 (no such file) and exit 5 (denied) are both UNTRUSTED", () => {
  // execFileSync throws on a nonzero exit so windowsFileIsProtected already fails closed, but the
  // stdout it captured on the way must not parse into an ACE either — belt and braces, because a
  // future caller that tolerates the exit code would otherwise silently trust a blank verdict.
  const denied =
    "C:\\ProgramData\\MoorAI\\policy.pub: Access is denied.\r\n" +
    "Successfully processed 0 files; Failed processing 1 files\r\n";
  const missing =
    "C:\\ProgramData\\MoorAI\\nope.pub: The system cannot find the file specified.\r\n" +
    "Successfully processed 0 files; Failed processing 1 files\r\n";
  for (const [label, out] of [["exit 5 / access denied", denied], ["exit 2 / not found", missing]]) {
    const r = icaclsPermissive(out, P);
    assert.equal(r.permissive, true, `${label} must fail closed`);
    assert.deepEqual(r.reasons, ["no-acl-entries"], label);
  }
});
