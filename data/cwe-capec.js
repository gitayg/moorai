// The MITRE CWE and CAPEC tags a rule in data/threats.json carries, beside `atlas` and `attack`:
//
//   cwe    the weakness (or weaknesses) the threat exploits — MITRE CWE.
//   capec  the attack pattern (or patterns) the threat is — MITRE CAPEC.
//
// Both tags are always arrays of { id, title }, possibly empty: an empty array is a reviewed "no honest
// mapping", and the rule then says why in `cweNote` / `capecNote`. A person's choice of what to paste
// into an AI tool, or a reader relying on a wrong answer, is not a software weakness, and no adversary
// acts in it, so those rules carry [] and a note instead of a stretched id.
//
// The id → title tables hold only the ids a rule credits, each with its canonical MITRE name, and are
// the only ids a rule may carry; test/cwe-capec.test.mjs pins every credit's title to them.
//
// CWE: MITRE CWE version 4.20, each entry read on https://cwe.mitre.org/data/definitions/<id>.html on
// 2026-10-26 for its exact name, abstraction and vulnerability-mapping usage. No category, view or
// deprecated entry is used. CWE-1426 "Improper Validation of Generative AI Output" is deliberately not
// used: MITRE marks it DISCOURAGED for mapping in 4.20 (potential major changes, frequent misuse).
//
// CAPEC: names from the OWASP Threat Model Library's capec-names.json (MIT licence; CAPEC 3.9), the
// abstraction of each id checked on https://capec.mitre.org/data/definitions/<id>.html on 2026-10-26.
// A Meta pattern is used only where no Standard or Detailed pattern fits.

export const CWE_TITLES = Object.freeze({
  15: "External Control of System or Configuration Setting",
  94: "Improper Control of Generation of Code ('Code Injection')",
  201: "Insertion of Sensitive Information Into Sent Data",
  250: "Execution with Unnecessary Privileges",
  306: "Missing Authentication for Critical Function",
  308: "Use of Single-factor Authentication",
  312: "Cleartext Storage of Sensitive Information",
  352: "Cross-Site Request Forgery (CSRF)",
  441: "Unintended Proxy or Intermediary ('Confused Deputy')",
  451: "User Interface (UI) Misrepresentation of Critical Information",
  494: "Download of Code Without Integrity Check",
  497: "Exposure of Sensitive System Information to an Unauthorized Control Sphere",
  502: "Deserialization of Untrusted Data",
  732: "Incorrect Permission Assignment for Critical Resource",
  770: "Allocation of Resources Without Limits or Throttling",
  829: "Inclusion of Functionality from Untrusted Control Sphere",
  1427: "Improper Neutralization of Input Used for LLM Prompting"
});

export const CAPEC_TITLES = Object.freeze({
  13: "Subverting Environment Variable Values",
  62: "Cross Site Request Forgery",
  75: "Manipulating Writeable Configuration Files",
  98: "Phishing",
  130: "Excessive Allocation",
  154: "Resource Location Spoofing",
  164: "Mobile Phishing",
  169: "Footprinting",
  185: "Malicious Software Download",
  195: "Principal Spoof",
  268: "Audit Log Manipulation",
  479: "Malicious Root Certificate",
  578: "Disable Security Software",
  586: "Object Injection",
  600: "Credential Stuffing",
  636: "Hiding Malicious Data or Code within Files",
  639: "Probe System Files",
  656: "Voice Phishing",
  698: "Install Malicious Extension"
});

