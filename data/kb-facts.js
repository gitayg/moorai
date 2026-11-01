// Conflicting facts in retrieved context: two chunks of the SAME request stating different values for the
// same entity and attribute — one product, two prices; one payee, two account numbers. A planted
// knowledge-base entry that addresses no one and orders nothing (AIGoat ctf3: "PRICE UPDATE: The LLM Red
// Team Hoodie now costs $3.33 …") carries no phrasing tell, but the retrieval that puts it in front of the
// model usually puts the real catalog entry beside it, and the two disagree. data/detectors-poisoning.js
// turns a conflict into a #21 finding (kb-fact-conflict).
//
// A NARROW, BOUNDED EXTRACTOR, not a parser. It reads (entity, attribute, value) triples of two kinds:
//   price    a point price bound to one named thing, by a price verb ("The X now costs $3.33", "the X is
//            now $12.99", "The price of the X is $5") or by a catalog line ("- X: … | price USD 41.99",
//            "X — $41.99", "| X | $41.99 |"); the attribute carries the currency and any period (/month).
//   account  an IBAN, an account / routing number or sort code, or a crypto wallet, bound to a payee named
//            in capitals ("Acme Ltd's IBAN is …", "IBAN for Acme Ltd: …", "- Acme Ltd: IBAN …").
// What it refuses to read as a point price: a range ("$10 - $20", "from $349 to $4999", "between $10 and
// $20", "$10 or $12"), a bound ("from", "up to", "under", "about", "≈"), an old price ("was $14.99",
// "previously", "regular", "instead of"), and an amount off ("$5 off", "save $5").
//
// CHUNKS. A chunk is one line (a hard-wrapped line continued in lower case is joined to the line above);
// blank lines and separator lines (---, ===, ***) only end chunks. Retrieval prompts put one chunk per
// paragraph or per line, and a vector store's results arrive one per line through the inbound harvest.
// Within one chunk an entity with two values for the same attribute is ambiguous and dropped ("$41.99,
// members $35.99"); a conflict needs two chunks. Values are compared exactly, after normalisation
// (1,299 = 1299.00), and only within one currency and period: "$10 (€9.20)" is never a conflict.
//
// PRECISION LIMITS, stated so nobody reads more into a pass. A GENUINE price update retrieved beside the
// stale catalog entry it supersedes is a conflict too; so are two quotes for one product from two
// vendors, a member price written as its own sentence, and two invoices that name the same payee with
// different account numbers. Entities match only when their names normalise to the same words: "LLM Red
// Team Hoodie" and "the Red Team hoodie" are different entities, so a forger who renames the product is
// not caught here. Policy values (a refund window) and phone numbers are not extracted.
//
// Content-free: conflicts are reported as attribute kinds and counts, never the entity or a value.
const MAX = 131072;
const MAX_LINE = 4000;
const MAX_FACTS = 2000;
const WINDOW = 160;

// A money amount. Two regexes rather than one, to keep each under the ReDoS guard's length cap.
const MONEY_PREFIX = /(?:\b(US|CA|AU|NZ|HK|C|A)\$|(\$|€|£|¥|₹)|\b(USD|EUR|GBP|JPY|CAD|AUD|NZD|CHF|INR)\b)[ \t]?(\d{1,3}(?:,\d{3}){1,4}|\d{1,9})(\.\d{1,2})?(?![\d,.]\d)(?:[ \t]?(k|m|bn|million|billion|thousand)\b)?/gi;
const MONEY_SUFFIX = /\b(\d{1,3}(?:,\d{3}){1,4}|\d{1,9})(\.\d{1,2})?[ \t]?(USD|EUR|GBP|CAD|AUD|CHF|INR|dollars|euros|pounds)\b/gi;
const CURRENCY = { "$": "USD", "US$": "USD", "USD": "USD", "DOLLARS": "USD", "€": "EUR", "EUR": "EUR", "EUROS": "EUR", "£": "GBP", "GBP": "GBP", "POUNDS": "GBP",
  "¥": "JPY", "JPY": "JPY", "₹": "INR", "INR": "INR", "CA$": "CAD", "C$": "CAD", "CAD": "CAD", "AU$": "AUD", "A$": "AUD", "AUD": "AUD", "NZ$": "NZD", "NZD": "NZD", "HK$": "HKD", "CHF": "CHF" };
const MAGNITUDE = { k: 1e3, thousand: 1e3, m: 1e6, million: 1e6, bn: 1e9, billion: 1e9 };

// Around an amount (each tested on a bounded slice).
const RANGE_GAP = /^[ \t]{0,3}(?:-|–|—|to|and|or|\/)[ \t]{0,3}$/i;
const BOUND_BEFORE = /(?:\bbetween|\bfrom|\bstarting\sat|\bstarts\sat|\bas\slow\sas|\bas\smuch\sas|\bup\sto|\bunder|\bover|\bbelow|\babove|\bless\sthan|\bmore\sthan|\bat\sleast|\bat\smost|\baround|\babout|\bapprox\.?|\bapproximately|\broughly|\bnearly|\balmost|~|≈|>|<|≥|≤)[ \t(]{0,3}$/i;
const OLD_BEFORE = /(?:\bwas|\bwere|\bpreviously|\bformerly|\boriginally|\bregular(?:ly)?|\breg\.?|\blist\sprice|\bmsrp|\brrp|\bused\sto\s(?:cost|be)|\binstead\sof|\bdown\sfrom|\breduced\sfrom|\bold\sprice|\bnormally|\busually|~~)[ \t]{0,3}:?[ \t(]{0,3}$/i;
const OLD_TAIL = /[ \t,]{0,3}\b(?:was|were|previously|formerly|originally|regularly|used\sto\scost)[ \t]{1,3}(?:only[ \t]{1,3})?[^ \t]{1,24}[ \t,]{0,3}(?:\b(?:and|but)\b)?[ \t]{0,3}$/i;
const SAVE_BEFORE =/\b(?:save|saving|extra|additional|plus|minus)[ \t]{0,3}$/i;
const OFF_AFTER = /^[ \t]?(?:off|discount|savings?|cheaper|less|more|extra|rebate|credit|cash\s?back|back|deposit|fee|shipping|tax)\b/i;
const PERIOD_AFTER = /^[ \t]?(?:\/|per\b|a\b|an\b|each\b)[ \t]?(month|mo|year|yr|annum|week|day|hour|hr|user|seat|person|night|unit|item|piece|license|licence|gb|kg|lb)\b/i;
const PERIOD = { mo: "month", yr: "year", annum: "year", hr: "hour", licence: "license" };

// Words a price-verb phrase is made of, walked back from the amount ("now costs", "is now priced at").
const VERB_WORDS = new Set(["now", "currently", "only", "just", "is", "are", "costs", "cost", "priced", "at", "sells", "sell", "for", "retails", "retail", "goes", "go", "drops", "drop", "dropped", "to", "reduced", "discounted", "lowered", "cut", "changed", "has", "have", "been", "will", "be", "today", "available", "on", "sale", "effective", "immediately", "officially"]);
const CORE_VERBS = new Set(["costs", "cost", "priced", "sells", "sell", "retails", "retail", "is", "are", "drops", "dropped", "reduced", "discounted", "lowered", "cut", "changed", "goes", "go"]);
const LEAD_STOP = new Set(["the", "a", "an", "our", "all", "every", "each", "new", "this", "that", "these", "those", "your", "its", "their", "my", "price", "prices", "cost", "of", "for", "now", "updated", "current"]);
const TRAIL_STOP = new Set(["price", "prices", "cost", "costs", "s"]);
const PRONOUN = new Set(["it", "they", "this", "that", "which", "what", "who", "everything", "something", "anything", "nothing", "one", "he", "she", "we", "you", "i", "there", "here"]);
// Labels and subjects that name a field, not a thing: two invoices' "Total" differ and that is no conflict.
const GENERIC_FIRST = new Set(["price", "prices", "update", "updated", "note", "notice", "clearance", "promotion", "promo", "sale", "announcement", "important", "news", "reminder", "total", "subtotal", "amount", "balance", "fee", "fees", "tax", "vat", "shipping", "discount", "was", "now", "old", "new", "before", "after", "regular", "special", "offer", "deal", "cost", "costs", "budget", "revenue", "salary", "rent", "payment", "deposit", "refund", "credit", "charge", "charges", "value", "sum", "item", "items", "product", "products", "order", "orders", "plan", "plans", "account", "iban", "bank", "routing", "wallet", "sort", "swift", "bic", "aba", "acct", "beneficiary", "payee"]);

const BULLET = /^[ \t]{0,8}(?:[-*•+]|\d{1,3}[.)]|\|)[ \t]?/;
const SEPARATOR_LINE = /^[ \t]{0,8}(?:-{3,40}|={3,40}|\*{3,40}|_{3,40})[ \t]{0,8}$/;
const LABEL_SEP = /[:|]|[ \t][-–—][ \t]/;
const BOUNDARY = /[!?;:,(|[\]{}]|\.(?=[ \t])|[ \t][-–—][ \t]/g;

// ---- chunks ----
export function retrievedChunks(text) {
  const t = typeof text === "string" ? (text.length > MAX ? text.slice(0, MAX) : text) : "";
  const out = [];
  let cur = null;
  for (const raw of t.split(/\r?\n/)) {
    const line = raw.length > MAX_LINE ? raw.slice(0, MAX_LINE) : raw;
    if (!line.trim() || SEPARATOR_LINE.test(line)) { cur = null; continue; }
    // A hard-wrapped continuation: the line above did not end a sentence or a field, and this one starts
    // in lower case and is not a list item.
    if (cur !== null && /^[ \t]{0,8}[a-z]/.test(line) && !BULLET.test(line) && !/[.!?:;|]\s*$/.test(out[cur])) {
      out[cur] = `${out[cur]} ${line.trim()}`;
      continue;
    }
    out.push(line);
    cur = out.length - 1;
  }
  return out;
}

// ---- entity names ----
export function normalizeEntity(s) {
  const words = String(s || "").toLowerCase().replace(/[“”"'’‘`]/g, "").replace(/&/g, " and ").replace(/[^a-z0-9]+/g, " ").trim().split(" ").filter(Boolean);
  while (words.length && LEAD_STOP.has(words[0])) words.shift();
  while (words.length && TRAIL_STOP.has(words[words.length - 1])) words.pop();
  if (!words.length || words.length > 8) return null;
  if (PRONOUN.has(words[0]) || GENERIC_FIRST.has(words[0])) return null;
  if (words.includes("and") || words.includes("or")) return null;
  const name = words.join(" ");
  if (name.length < 3 || !/[a-z]/.test(name)) return null;
  return name;
}

function lastBoundaryEnd(s) {
  let end = 0;
  BOUNDARY.lastIndex = 0;
  let m;
  while ((m = BOUNDARY.exec(s)) !== null) end = m.index + m[0].length;
  return end;
}

// The subject of a price verb ending right before the amount: "The X now costs " → "x". null when the
// words before the amount are not a price-verb phrase.
function verbSubject(before) {
  const words = before.split(/[ \t]+/);
  if (words.length && words[words.length - 1] === "") words.pop();
  let i = words.length, core = false, n = 0;
  while (i > 0 && n < 6) {
    const w = words[i - 1].toLowerCase();
    if (!VERB_WORDS.has(w)) break;
    if (CORE_VERBS.has(w)) core = true;
    i--; n++;
  }
  if (!core || i === 0) return null;
  // "The X was $41.99 and is now …": the old-price clause sits between the subject and the verb.
  let head = words.slice(0, i).join(" ").replace(OLD_TAIL, "");
  head = head.slice(lastBoundaryEnd(head));
  // "The X's price is …", "the price of the X is …"
  head = head.replace(/['’]s\s(?:new\s|current\s)?(?:price|cost)$/i, "");
  const tail = head.trim().split(/\s+/).slice(-8).join(" ");
  return normalizeEntity(tail);
}

// The label of a catalog-style line: "- X: …", "X — …", "| X | …".
function labelName(line) {
  const body = line.replace(BULLET, "");
  if (/^[ \t]{0,8}\|/.test(line)) {
    const cell = line.split("|").map((c) => c.trim()).find(Boolean);
    return cell ? { name: cell, sepEnd: line.indexOf(cell) + cell.length } : null;
  }
  const m = LABEL_SEP.exec(body);
  if (!m || m.index === 0 || m.index > 120) return null;
  return { name: body.slice(0, m.index), sepEnd: line.length - body.length + m.index + m[0].length };
}

function amountsIn(line) {
  const out = [];
  for (const m of line.matchAll(MONEY_PREFIX)) {
    const cur = CURRENCY[(m[1] ? `${m[1]}$` : m[2] || m[3] || "").toUpperCase()] || CURRENCY[m[2]];
    out.push({ start: m.index, end: m.index + m[0].length, cur, int: m[4], frac: m[5], mag: m[6] });
  }
  for (const m of line.matchAll(MONEY_SUFFIX)) {
    if (out.some((o) => m.index < o.end && o.start < m.index + m[0].length)) continue;
    out.push({ start: m.index, end: m.index + m[0].length, cur: CURRENCY[m[3].toUpperCase()], int: m[1], frac: m[2], mag: null });
  }
  out.sort((a, b) => a.start - b.start);
  for (let i = 0; i + 1 < out.length; i++) {
    if (RANGE_GAP.test(line.slice(out[i].end, out[i + 1].start))) { out[i].range = true; out[i + 1].range = true; }
  }
  return out.filter((a) => a.cur);
}

function amountValue(a) {
  const n = Number(`${a.int.replace(/,/g, "")}${a.frac || ""}`) * (a.mag ? MAGNITUDE[a.mag.toLowerCase()] || 1 : 1);
  return Number.isFinite(n) ? n.toFixed(2) : null;
}

function priceFacts(line) {
  const facts = [];
  const amounts = amountsIn(line);
  if (!amounts.length) return facts;
  const points = [];
  for (const a of amounts) {
    if (a.range) continue;
    const before = line.slice(Math.max(0, a.start - WINDOW), a.start);
    const after = line.slice(a.end, a.end + 40);
    if (BOUND_BEFORE.test(before) || OLD_BEFORE.test(before) || SAVE_BEFORE.test(before) || OFF_AFTER.test(after)) continue;
    const per = PERIOD_AFTER.exec(after);
    const period = per ? PERIOD[per[1].toLowerCase()] || per[1].toLowerCase() : "";
    const value = amountValue(a);
    if (value === null) continue;
    points.push({ ...a, before, value, attr: `price:${a.cur}${period ? `/${period}` : ""}` });
  }
  const labelled = [];
  for (const p of points) {
    const subject = verbSubject(p.before);
    if (subject) facts.push({ entity: subject, attr: p.attr, value: p.value });
    else labelled.push(p);
  }
  // A catalog line names one thing and gives it one price.
  if (labelled.length === 1 && points.length === 1) {
    const lab = labelName(line);
    const p = labelled[0];
    if (lab && p.start >= lab.sepEnd && (BULLET.test(line) || /\bprice\b/i.test(line) || p.start - lab.sepEnd <= 4)) {
      const entity = normalizeEntity(lab.name);
      if (entity) facts.push({ entity, attr: p.attr, value: p.value });
    }
  }
  return facts;
}

// ---- accounts ----
const IBAN = /\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,3})?\b/g;
const ACCT = /\b(account\s(?:number|no\.?|#)|acct\.?\s?(?:no\.?|#)?|routing\s(?:number|no\.?)|sort\scode|aba)[ \t]?[:#]?[ \t]?(\d[\d -]{4,22}\d)\b/gi;
const WALLET = /\b(?:0x[0-9a-fA-F]{40}|bc1[0-9a-z]{25,59})\b/g;
const NAMED = /(?:^|[ \t(])(?:[Ff]or|[Oo]f|[Tt]o|[Pp]ay|[Pp]ayee:?|[Bb]eneficiary:?)[ \t]([A-Z][\w&.'-]{0,30}(?:[ \t](?:[A-Z][\w&.'-]{0,30}|of|&)){0,5})/g;
const POSSESSIVE = /([A-Z][\w&.-]{0,30}(?:[ \t][A-Z][\w&.-]{0,30}){0,4})['’]s[ \t]([^ \t]{1,20}(?:[ \t][^ \t]{1,20}){0,2})/g;
const ACCOUNT_WORD = /\b(?:account|iban|details|banking|routing|sort\scode|wallet|payment)\b/i;

function payee(line, start) {
  const before = line.slice(Math.max(0, start - WINDOW), start);
  let name = null;
  for (const m of before.matchAll(POSSESSIVE)) if (ACCOUNT_WORD.test(m[2])) name = normalizeEntity(m[1]) || name;
  if (name) return name;
  for (const m of before.matchAll(NAMED)) name = normalizeEntity(m[1]) || name;
  if (name) return name;
  const lab = labelName(line);
  return lab && start >= lab.sepEnd && /^[ \t]{0,8}(?:[-*•+]|\d{1,3}[.)]|\|)?[ \t]?[A-Z]/.test(line) ? normalizeEntity(lab.name) : null;
}

function accountFacts(line) {
  const facts = [];
  const add = (start, kind, raw) => {
    const entity = payee(line, start);
    if (entity) facts.push({ entity, attr: `account:${kind}`, value: raw.replace(/[\s-]/g, "").toUpperCase() });
  };
  for (const m of line.matchAll(IBAN)) add(m.index, "iban", m[0]);
  for (const m of line.matchAll(ACCT)) {
    const k = m[1].toLowerCase();
    add(m.index, k.startsWith("routing") || k === "aba" ? "routing" : k.startsWith("sort") ? "sortcode" : "number", m[2]);
  }
  for (const m of line.matchAll(WALLET)) add(m.index, "wallet", m[0]);
  return facts;
}

// ---- facts and conflicts ----
// text → [{ chunk, entity, attr, value }]. Entities with two values for one attribute inside one chunk
// are dropped (ambiguous), so every fact is one chunk's single statement.
export function extractFacts(text) {
  const facts = [];
  const chunks = retrievedChunks(text);
  for (let c = 0; c < chunks.length && facts.length < MAX_FACTS; c++) {
    const line = chunks[c];
    if (!/\d/.test(line)) continue;
    const seen = new Map();
    for (const f of [...priceFacts(line), ...accountFacts(line)]) {
      const k = `${f.entity}\0${f.attr}`;
      if (!seen.has(k)) seen.set(k, new Set());
      seen.get(k).add(f.value);
    }
    for (const [k, vals] of seen) {
      if (vals.size !== 1) continue;
      const [entity, attr] = k.split("\0");
      facts.push({ chunk: c, entity, attr, value: [...vals][0] });
    }
  }
  return facts;
}

// text → [{ attribute: "price" | "account", values: n }] — one entry per (entity, attribute) that two
// chunks state differently. Content-free: no entity and no value leaves.
export function factConflicts(text) {
  const by = new Map();
  for (const f of extractFacts(text)) {
    const k = `${f.entity}\0${f.attr}`;
    if (!by.has(k)) by.set(k, new Set());
    by.get(k).add(f.value);
  }
  // extractFacts keeps one value per entity and attribute per chunk, so two values are two chunks.
  const out = [];
  for (const [k, vals] of by) if (vals.size > 1) out.push({ attribute: k.split("\0")[1].split(":")[0], values: vals.size });
  return out;
}

// Every regex this module compiles, for the ReDoS tests (test/kb-provenance.test.mjs).
export const KB_FACT_PATTERNS = Object.freeze([MONEY_PREFIX, MONEY_SUFFIX, RANGE_GAP, BOUND_BEFORE, OLD_BEFORE, OLD_TAIL, SAVE_BEFORE, OFF_AFTER, PERIOD_AFTER, BULLET, SEPARATOR_LINE, LABEL_SEP, BOUNDARY, IBAN, ACCT, WALLET, NAMED, POSSESSIVE, ACCOUNT_WORD]);
