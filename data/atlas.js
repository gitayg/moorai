// The MITRE ATLAS tag on a threat is `string | string[]` — one rule credits every technique it
// genuinely implements, and most implement more than one. Every consumer reads the tag through
// atlasIds(), so neither shape can reach a template, a join, or an `===` comparison.
//
// atlasPartial marks a credit that is bounded: the technique is implemented, but only over part of
// what its ATLAS definition covers, and the bound is stated rather than left for a reader to assume.
// The limit string is the same short phrase the public comparison page prints.

export function atlasIds(threat) {
  const a = threat?.atlas;
  if (!a) return [];
  return Array.isArray(a) ? a.filter(Boolean) : [a];
}

export function atlasPartialNote(threat, id) {
  return threat?.atlasPartial?.[id] || null;
}

// "AML.T0051 · AML.T0054 (text/markup only)" — the display form, partial bounds included.
export function atlasLabel(threat) {
  return atlasIds(threat)
    .map((id) => { const p = atlasPartialNote(threat, id); return p ? `${id} (${p})` : id; })
    .join(" · ");
}
