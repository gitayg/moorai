// #90 — what makes a digit run a payment-card number: 13 to 19 digits, the Luhn check digit, and leading
// digits (the issuer identification number, IIN / BIN) inside a range one of the major networks issues from,
// at a length that network issues. Written from the networks' own published numbering, not copied from a
// list. A run that passes Luhn but starts outside every range below (an order number, a tracking id, one in
// ten random digit runs) is not reported as a card.
//
// Each range is [low, high] over the first N digits, N = the number of digits in `low`. Networks not listed
// (Mir 2200-2204, RuPay outside the shared ranges, Troy, Verve, private-label store cards) are not detected.
//
// browser-ext/detectors.js carries a copy (an MV3 content script cannot import); browser-ext/test-detectors.mjs
// fails if the two differ.
export const CARD_NETWORKS = Object.freeze([
  { network: "visa", ranges: [[4, 4]], lengths: [13, 16, 19] },
  { network: "mastercard", ranges: [[51, 55], [2221, 2720]], lengths: [16] },
  { network: "amex", ranges: [[34, 34], [37, 37]], lengths: [15] },
  { network: "discover", ranges: [[6011, 6011], [644, 649], [65, 65], [622126, 622925]], lengths: [16, 17, 18, 19] },
  { network: "jcb", ranges: [[3528, 3589]], lengths: [16, 17, 18, 19] },
  { network: "diners", ranges: [[300, 305], [3095, 3095], [36, 36], [38, 39]], lengths: [14, 15, 16, 17, 18, 19] },
  { network: "unionpay", ranges: [[62, 62], [8100, 8171]], lengths: [16, 17, 18, 19] },
  { network: "maestro", ranges: [[5018, 5018], [5020, 5020], [5038, 5038], [5893, 5893], [6304, 6304], [6759, 6759], [6761, 6763]], lengths: [13, 14, 15, 16, 17, 18, 19] }
]);

export const CARD_MIN_DIGITS = 13;
export const CARD_MAX_DIGITS = 19;

export function luhnValid(digits) {
  let sum = 0;
  for (let i = 0; i < digits.length; i++) {
    let n = digits.charCodeAt(digits.length - 1 - i) - 48;
    if (i % 2) { n *= 2; if (n > 9) n -= 9; }
    sum += n;
  }
  return sum % 10 === 0;
}

// The network whose range and length the digits fit, or null.
export function cardNetwork(digits) {
  for (const n of CARD_NETWORKS) {
    if (!n.lengths.includes(digits.length)) continue;
    for (const [lo, hi] of n.ranges) {
      const p = Number(digits.slice(0, String(lo).length));
      if (p >= lo && p <= hi) return n.network;
    }
  }
  return null;
}

// dlp-payment-card's refine: the matched span, separators and all.
export function cardNumberValid(m) {
  const d = String(m).replace(/\D/g, "");
  if (d.length < CARD_MIN_DIGITS || d.length > CARD_MAX_DIGITS) return false;
  return luhnValid(d) && cardNetwork(d) !== null;
}
