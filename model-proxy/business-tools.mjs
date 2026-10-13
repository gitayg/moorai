// The built-in business-impact catalogue: a function the model asks a function-calling client to run is
// classed by its NAME (never its arguments) into the impact classes below. A class's built-in action is
// "alert" (reported, never blocked), so the shipped default changes no traffic; a signed policy raises or
// silences a class:
//
//   "businessToolActions": { "money": "block", "bulk-data": "ask", "identity": "ask", "destructive": "alert", "delegation": "allow" }
//
// Vocabulary as functionToolActions': allow | alert | ask | block (anything else, or a class not listed,
// keeps the built-in alert). A functionToolActions key that names the function itself — an exact name, or a
// wildcard with a real prefix — wins over its class, "allow" included (the most specific rule wins); a
// namespace-only wildcard (`tools.*`) is not specific and only ever adds to the class action (check.mjs).
//
//   money        refunds, payouts, payments, transfers, charges, credits, coupon / discount / promo
//                application, price and balance changes
//   bulk-data    export, dump, every / all / any / bulk customer or user data, download all
//   identity     role / permission / admin grants, password / MFA resets, account delete / disable /
//                suspend, impersonation
//   destructive  delete, purge, wipe, destroy, truncate, erase; drop of a table / database / collection
//   delegation   handoffs, fan-out, spawning or delegating to other agents (transfer_to_<agent> included)
//
// MATCHING. The name is normalized as function-rules.mjs does (normalizeName: NFKC, invisible characters and
// a `functions.` / `default_api.` prefix removed), camelCase is split, and the result is lower-cased and cut
// into words at every non-alphanumeric character. A class matches on whole WORDS, so `get_coupon_list` is not
// `apply_coupon`: money needs a money action (refund, payout …), a money verb as the first word (charge, pay,
// wire …), or a money verb beside a money object (apply + coupon, set + price, transfer + funds). A name led
// by a read verb (get, list, check, validate, is …) or ending in a read noun (status, policy, history,
// details …) is a lookup and is not classed, except for bulk-data, where reading everything is the impact
// (get_all_users) — a read-noun ending still excludes it (get_export_status).
import { normalizeName } from "./function-rules.mjs";

export const BUSINESS_CLASSES = Object.freeze(["money", "bulk-data", "identity", "destructive", "delegation"]);
const ACTIONS = new Set(["allow", "alert", "ask", "block"]);
const RANK = { allow: 0, alert: 1, ask: 2, block: 3 };
const S = (...w) => new Set(w);

const READ_LEAD = S("get", "list", "read", "view", "show", "search", "find", "lookup", "look", "query", "check", "describe", "count", "preview", "validate", "verify", "calculate", "calc", "estimate", "is", "has", "can", "explain", "summarize", "summarise", "inspect", "track", "fetch", "retrieve", "print", "display", "peek", "watch", "monitor");
const READ_TAIL = S("status", "policy", "policies", "history", "info", "details", "detail", "list", "lookup", "summary", "count", "eligibility", "preview", "quote", "estimate", "options");

const MONEY_ACTION = S("refund", "refunds", "payout", "payouts", "reimburse", "reimbursement", "disburse", "disbursement", "withdraw", "withdrawal", "chargeback");
const MONEY_LEAD = S("charge", "pay", "wire", "debit", "credit", "remit");
const MONEY_VERB = S("issue", "process", "create", "make", "send", "initiate", "execute", "approve", "apply", "grant", "add", "give", "award", "redeem", "transfer", "move", "set", "update", "change", "override", "adjust", "modify", "edit", "lower", "reduce", "raise", "increase", "decrease", "capture", "release", "top", "wire");
const MONEY_OBJECT = S("payment", "payments", "funds", "fund", "money", "cash", "coupon", "coupons", "discount", "discounts", "promo", "promos", "promotion", "voucher", "vouchers", "price", "prices", "pricing", "credit", "credits", "balance", "wallet", "giftcard", "transfer");

const BULK_ACTION = S("export", "exports", "dump", "exfiltrate", "exfil");
const BULK_QUANT = S("all", "any", "every", "bulk", "entire", "mass", "everything", "everyone");
const BULK_DATA = S("customer", "customers", "user", "users", "client", "clients", "contact", "contacts", "email", "emails", "account", "accounts", "member", "members", "employee", "employees", "patient", "patients", "pii", "data", "record", "records", "database", "databases", "db", "table", "tables", "everything", "everyone");
const BULK_COPY = S("download", "copy", "extract", "scrape", "sync", "backup", "mirror");

const ID_ACTION = S("impersonate", "impersonation", "sudo");
const ROLE_VERB = S("grant", "assign", "add", "give", "elevate", "escalate", "promote", "make", "set", "change", "update", "modify", "edit", "revoke", "remove");
const ROLE_OBJECT = S("role", "roles", "permission", "permissions", "privilege", "privileges", "admin", "admins", "administrator", "superuser", "scope", "scopes", "acl", "acls", "owner");
const CRED_VERB = S("reset", "change", "set", "update", "disable", "remove", "bypass", "clear", "delete");
const CRED_OBJECT = S("password", "passwords", "passwd", "mfa", "2fa", "otp", "totp", "passcode", "credential", "credentials", "recovery");
const ACCOUNT_VERB = S("delete", "remove", "disable", "deactivate", "suspend", "close", "terminate", "ban", "lock", "erase", "purge", "wipe", "destroy");
const ACCOUNT_OBJECT = S("account", "accounts", "user", "users", "member", "members", "profile", "identity", "login");

const DESTROY_ACTION = S("delete", "purge", "wipe", "destroy", "truncate", "erase", "shred", "nuke", "obliterate");
const DROP_OBJECT = S("table", "tables", "database", "databases", "db", "collection", "collections", "schema", "schemas", "index", "indexes", "bucket", "keyspace");

const DELEGATE_ACTION = S("handoff", "handoffs", "fanout", "delegate", "delegation", "spawn");
const AGENT_VERB = S("call", "invoke", "run", "dispatch", "launch", "start", "create", "assign", "route", "forward", "send", "ask", "consult", "spawn", "delegate");
const AGENT_OBJECT = S("agent", "agents", "subagent", "subagents", "worker", "workers", "crew", "swarm");

export function wordsOf(name) {
  return normalizeName(name).replace(/([a-z0-9])([A-Z])/g, "$1_$2").toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
}
const any = (w, set) => w.some((x) => set.has(x));
const pair = (w, verbs, objects) => w.some((v, i) => verbs.has(v) && w.some((o, j) => j !== i && objects.has(o)));
const seq = (w, a, b) => w.some((x, i) => x === a && w[i + 1] === b);

// The classes `name` falls in, in BUSINESS_CLASSES order; [] for none.
export function classifyBusinessTool(name) {
  const w = wordsOf(name);
  if (!w.length) return [];
  const out = [];
  const lookup = READ_TAIL.has(w[w.length - 1]);
  const read = lookup || READ_LEAD.has(w[0]);
  if (!read && (any(w, MONEY_ACTION) || MONEY_LEAD.has(w[0]) || pair(w, MONEY_VERB, MONEY_OBJECT))) out.push("money");
  if (!lookup && (any(w, BULK_ACTION) || pair(w, BULK_QUANT, BULK_DATA) || w.some((x) => x === "everything" || x === "everyone") || pair(w, BULK_COPY, BULK_QUANT))) out.push("bulk-data");
  if (!read && (any(w, ID_ACTION) || seq(w, "login", "as") || pair(w, ROLE_VERB, ROLE_OBJECT) || pair(w, CRED_VERB, CRED_OBJECT) || pair(w, ACCOUNT_VERB, ACCOUNT_OBJECT))) out.push("identity");
  if (!read && (any(w, DESTROY_ACTION) || (w.includes("drop") && any(w, DROP_OBJECT)))) out.push("destructive");
  if (!read && (any(w, DELEGATE_ACTION) || seq(w, "hand", "off") || seq(w, "fan", "out") || (w[0] === "transfer" && w[1] === "to") || pair(w, AGENT_VERB, AGENT_OBJECT))) out.push("delegation");
  return out;
}

// { money, "bulk-data", identity, destructive, delegation } → action, the policy's where it gives a valid one.
const cache = new WeakMap();
export function businessToolActionsFrom(policy) {
  if (policy && typeof policy === "object" && cache.has(policy)) return cache.get(policy);
  const m = policy && typeof policy === "object" ? policy.businessToolActions : undefined;
  const ok = m && typeof m === "object" && !Array.isArray(m);
  const out = Object.fromEntries(BUSINESS_CLASSES.map((c) => [c, ok && ACTIONS.has(m[c]) ? m[c] : "alert"]));
  if (policy && typeof policy === "object") cache.set(policy, out);
  return out;
}

// { classes, cls, act } for a classed name — `cls` the class whose action is the strictest (the first such
// class on a tie) — or null for a name in no class.
export function businessActionFor(policy, name) {
  const classes = classifyBusinessTool(name);
  if (!classes.length) return null;
  const acts = businessToolActionsFrom(policy);
  let cls = classes[0];
  for (const c of classes) if (RANK[acts[c]] > RANK[acts[cls]]) cls = c;
  return { classes, cls, act: acts[cls] };
}
