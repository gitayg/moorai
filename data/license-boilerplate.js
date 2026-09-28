// Standard open-source licence texts, removed before persuasion scoring. MIT's "without restriction …
// without limitation … WITHOUT WARRANTY" reads, word by word, like a request to drop the rules, and woke
// persuasion-jailbreak (#2) on every LICENSE file. Only a span that starts at a licence's own opening
// phrase and ends at its own closing phrase, within a bounded length, is removed, so text around it —
// including anything appended after the licence — is still scored.
const SPANS = [
  // MIT / Expat
  { start: /Permission\s{1,4}is\s{1,4}hereby\s{1,4}granted,\s{1,4}free\s{1,4}of\s{1,4}charge/i, end: /OTHER\s{1,4}DEALINGS\s{1,4}IN\s{1,4}(?:THE\s{1,4})?SOFTWARE\.?/i, max: 2500 },
  // ISC
  { start: /Permission\s{1,4}to\s{1,4}use,\s{1,4}copy,\s{1,4}modify,\s{1,4}and\/or\s{1,4}distribute\s{1,4}this\s{1,4}software/i, end: /PERFORMANCE\s{1,4}OF\s{1,4}THIS\s{1,4}SOFTWARE\.?/i, max: 1500 },
  // BSD 2/3-clause
  { start: /Redistribution\s{1,4}and\s{1,4}use\s{1,4}in\s{1,4}source\s{1,4}and\s{1,4}binary\s{1,4}forms/i, end: /POSSIBILITY\s{1,4}OF\s{1,4}SUCH\s{1,4}DAMAGE\.?/i, max: 3500 },
  // Apache-2.0 notice header
  { start: /Licensed\s{1,4}under\s{1,4}the\s{1,4}Apache\s{1,4}License,\s{1,4}Version\s{1,4}2\.0/i, end: /limitations\s{1,4}under\s{1,4}the\s{1,4}License\.?/i, max: 1500 },
  // Apache-2.0 full text
  { start: /Apache\s{1,4}License\s{1,40}Version\s{1,4}2\.0,\s{1,4}January\s{1,4}2004/i, end: /END\s{1,4}OF\s{1,4}TERMS\s{1,4}AND\s{1,4}CONDITIONS/i, max: 12000 }
];

export function stripLicenseBoilerplate(text) {
  let s = String(text);
  for (const { start, end, max } of SPANS) {
    for (let guard = 0; guard < 8; guard++) {
      const a = start.exec(s);
      if (!a) break;
      const window = s.slice(a.index, a.index + max);
      const b = end.exec(window);
      if (!b) break;
      s = s.slice(0, a.index) + " " + s.slice(a.index + b.index + b[0].length);
    }
  }
  return s;
}
