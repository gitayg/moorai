// egressRules / egressDefault -> the network part of the kernel sandboxes the desktop host launches into:
// MXC on Windows (mxc.rs build_policy) and Seatbelt on macOS (platform.rs sandbox_profile). Launch-time
// mirror of cli/sandbox-policy.mjs (mxcEgress, seatbeltEgress): same validation as cli/egress-rules.mjs
// validateEgressRule, same decisions, same `unexpressed` report. Both replay
// test/fixtures/mxc/sandbox-cases.json, so a change to one without the other fails `cargo test` or
// `node --test`. Hosts are normalised with the `url` crate, the same WHATWG host parser Node's URL uses,
// so `010.0.0.1` and `8.0.0.1` are one address here as they are in MoorAI's own check.
//
// Declared from mxc.rs (`#[path = "mxc_egress.rs"] pub mod egress`), so it needs no line in lib.rs.

use serde_json::{json, Value};
use std::collections::BTreeMap;

const MAX_RULES: usize = 512;
const MAX_LIST: usize = 64;

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Ip4,
    Ip6,
    Name,
    Suffix,
}

struct Entry {
    index: usize,
    id: Option<String>,
    action: String,
    allow: bool,
    kind: Kind,
    host: String,
    ports: Option<Vec<u32>>,
    cond: Vec<&'static str>,
}

#[derive(Default)]
struct Notes {
    slots: BTreeMap<usize, Vec<Value>>,
    list: Vec<Value>,
}

impl Notes {
    fn note(&mut self, e: &Entry, fields: &[&str], effect: &str, reason: &str) {
        let mut line = json!({ "index": e.index, "action": e.action, "fields": fields, "effect": effect, "reason": reason });
        if let Some(id) = &e.id {
            line["id"] = json!(id);
        }
        let slot = self.slots.entry(e.index).or_default();
        if !slot.iter().any(|x| x["reason"] == json!(reason)) {
            slot.push(line);
        }
    }
    fn report(self, tail: Vec<Value>) -> Vec<Value> {
        let mut out: Vec<Value> = self.slots.into_values().flatten().collect();
        out.extend(self.list);
        out.extend(tail);
        out
    }
}

// JavaScript's \s, which String.prototype.trim and the path check in cli/egress-rules.mjs use.
fn js_ws(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\u{0b}' | '\u{0c}' | '\r' | ' ' | '\u{a0}' | '\u{1680}' | '\u{2000}'..='\u{200a}' | '\u{2028}' | '\u{2029}' | '\u{202f}' | '\u{205f}' | '\u{3000}' | '\u{feff}')
}
fn js_trim(s: &str) -> &str {
    s.trim_matches(js_ws)
}

fn id_ok(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty() && b.len() <= 64 && b[0].is_ascii_alphanumeric() && b.iter().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
}

fn as_list(v: &Value) -> Vec<&Value> {
    match v {
        Value::Array(a) => a.iter().collect(),
        x => vec![x],
    }
}

// cli/egress-rules.mjs ruleHost: (kind, WHATWG host) or None.
fn rule_host(v: &Value) -> Option<(Kind, String)> {
    let raw = v.as_str()?;
    let lower = js_trim(raw).to_lowercase();
    let s = lower.strip_suffix('.').unwrap_or(&lower);
    let parse = |h: &str| url::Url::parse(&format!("http://{h}/")).ok().and_then(|u| match u.host() {
        Some(url::Host::Ipv4(_)) => Some((Kind::Ip4, u.host_str()?.to_string())),
        Some(url::Host::Ipv6(_)) => Some((Kind::Ip6, u.host_str()?.to_string())),
        Some(url::Host::Domain(_)) => Some((Kind::Name, u.host_str()?.to_string())),
        None => None,
    });
    let inner = s.strip_prefix('[').and_then(|x| x.strip_suffix(']'));
    if let Some(i) = inner {
        if !i.is_empty() && i.bytes().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase() || c == b':' || c == b'.') {
            return parse(s);
        }
    }
    let (wild, base) = match s.strip_prefix("*.") {
        Some(b) => (true, b),
        None => (false, s),
    };
    let label_ok = |l: &str| !l.is_empty() && l.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-');
    if !base.split('.').all(label_ok) {
        return None;
    }
    let (kind, h) = parse(base)?;
    if wild {
        Some((Kind::Suffix, format!(".{h}")))
    } else {
        Some((kind, h))
    }
}

fn path_ok(v: &Value) -> bool {
    let Some(p) = v.as_str() else { return false };
    if !p.starts_with('/') || p.encode_utf16().count() > 1024 || p.chars().any(|c| js_ws(c) || c == '?' || c == '#') {
        return false;
    }
    match p.find('*') {
        None => true,
        Some(i) => i == p.len() - 1,
    }
}

fn list_ok(v: &Value, each: &dyn Fn(&Value) -> bool) -> bool {
    let l = as_list(v);
    !l.is_empty() && l.len() <= MAX_LIST && l.iter().all(|x| each(x))
}

fn port_of(v: &Value) -> Option<u32> {
    let f = v.as_f64()?;
    (f.fract() == 0.0 && (1.0..=65535.0).contains(&f)).then_some(f as u32)
}

const RULE_KEYS: &[&str] = &["id", "binary", "host", "port", "method", "path", "action", "description"];

// cli/egress-rules.mjs validateEgressRule, reduced to what a sandbox needs.
fn validate(index: usize, r: &Value) -> Option<Entry> {
    let o = r.as_object()?;
    if o.keys().any(|k| !RULE_KEYS.contains(&k.as_str())) {
        return None;
    }
    let action = o.get("action")?.as_str().filter(|a| matches!(*a, "allow" | "alert" | "block"))?.to_string();
    let id = match o.get("id") {
        None => None,
        Some(v) => Some(v.as_str().filter(|s| id_ok(s))?.to_string()),
    };
    let (kind, host) = rule_host(o.get("host")?)?;
    if let Some(b) = o.get("binary") {
        let bin_ok = |x: &Value| x.as_str().map(js_trim).map(|t| !t.is_empty() && t.len() <= 256 && t.bytes().all(|c| c.is_ascii_alphanumeric() || b"_.*+:/\\-".contains(&c))).unwrap_or(false);
        if !list_ok(b, &bin_ok) {
            return None;
        }
    }
    let ports = match o.get("port") {
        None => None,
        Some(p) => {
            if !list_ok(p, &|x| port_of(x).is_some()) {
                return None;
            }
            let mut l: Vec<u32> = as_list(p).into_iter().filter_map(port_of).collect();
            l.sort_unstable();
            l.dedup();
            Some(l)
        }
    };
    if let Some(m) = o.get("method") {
        let verb_ok = |x: &Value| x.as_str().map(|s| (1..=16).contains(&s.len()) && s.bytes().all(|c| c.is_ascii_alphabetic())).unwrap_or(false);
        if !list_ok(m, &verb_ok) {
            return None;
        }
    }
    if let Some(p) = o.get("path") {
        if !path_ok(p) {
            return None;
        }
    }
    let cond = ["binary", "method", "path"].into_iter().filter(|k| o.contains_key(*k)).collect();
    Some(Entry { index, id, allow: action != "block", action, kind, host, ports, cond })
}

fn present(v: Option<&Value>) -> Option<&Value> {
    v.filter(|x| !x.is_null())
}

fn read_rules(raw: Option<&Value>, notes: &mut Notes) -> Vec<Entry> {
    let Some(raw) = present(raw) else { return vec![] };
    let Some(arr) = raw.as_array() else {
        notes.list.push(json!({ "index": -1, "fields": ["egressRules"], "effect": "invalid", "reason": "not-a-list" }));
        return vec![];
    };
    let mut out = vec![];
    for (index, r) in arr.iter().take(MAX_RULES).enumerate() {
        match validate(index, r) {
            Some(e) => out.push(e),
            None => {
                let mut line = json!({ "index": index, "fields": ["rule"], "effect": "invalid", "reason": "invalid-rule" });
                if let Some(id) = r.get("id").and_then(|v| v.as_str()).filter(|s| id_ok(s)) {
                    line["id"] = json!(id);
                }
                notes.slots.insert(index, vec![line]);
            }
        }
    }
    if arr.len() > MAX_RULES {
        notes.list.push(json!({ "index": MAX_RULES, "fields": ["egressRules"], "effect": "invalid", "reason": "too-many-rules" }));
    }
    out
}

// true when egressDefault is "block"; an invalid value is reported and treated as unset (allow).
fn read_default(raw: Option<&Value>, tail: &mut Vec<Value>) -> bool {
    match present(raw) {
        None => false,
        Some(Value::String(s)) if matches!(s.as_str(), "allow" | "alert" | "block") => s == "block",
        Some(_) => {
            tail.push(json!({ "index": -1, "fields": ["egressDefault"], "effect": "invalid", "reason": "invalid-default" }));
            false
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
enum By {
    Rule,
    Coarse,
    Default,
}

#[derive(Clone, Copy)]
struct Decision {
    allow: bool,
    by: By,
}

fn decide(list: &[&Entry], port: Option<u32>, fallthrough_allow: bool, notes: &mut Notes, tag: &str) -> Decision {
    let mut maybe: Vec<&Entry> = vec![];
    for e in list {
        let hit = match (&e.ports, port) {
            (None, _) => true,
            (Some(ps), Some(p)) => ps.contains(&p),
            (Some(_), None) => false,
        };
        if !hit {
            continue;
        }
        if !e.cond.is_empty() {
            if e.allow {
                maybe.push(e);
            }
            continue;
        }
        if e.allow {
            return Decision { allow: true, by: By::Rule };
        }
        for m in &maybe {
            notes.note(m, &m.cond, "narrowed", &format!("{tag}-block-wins"));
        }
        return Decision { allow: false, by: By::Rule };
    }
    if !maybe.is_empty() {
        return Decision { allow: true, by: By::Coarse };
    }
    Decision { allow: fallthrough_allow, by: By::Default }
}

fn atoms(list: &[&Entry], fallthrough_allow: bool, notes: &mut Notes, tag: &str) -> (Decision, Vec<(u32, Decision)>) {
    let mut ports: Vec<u32> = list.iter().flat_map(|e| e.ports.clone().unwrap_or_default()).collect();
    ports.sort_unstable();
    ports.dedup();
    let other = decide(list, None, fallthrough_allow, notes, tag);
    let each = ports.into_iter().map(|p| (p, decide(list, Some(p), fallthrough_allow, notes, tag))).collect();
    (other, each)
}

fn loopback_range(kind: Kind, host: &str) -> bool {
    (kind == Kind::Ip4 && host.starts_with("127.")) || (kind == Kind::Ip6 && host == "[::1]") || (kind == Kind::Name && host == "localhost")
}

fn is_private(kind: Kind, host: &str) -> bool {
    if kind == Kind::Ip4 {
        let o: Vec<u32> = host.split('.').filter_map(|x| x.parse().ok()).collect();
        let (a, b) = (o.first().copied().unwrap_or(0), o.get(1).copied().unwrap_or(0));
        return a == 10 || (a == 172 && (16..=31).contains(&b)) || (a == 192 && b == 168) || (a == 169 && b == 254);
    }
    let first = u32::from_str_radix(host.trim_start_matches('[').split(':').next().filter(|s| !s.is_empty()).unwrap_or("0"), 16).unwrap_or(0);
    (first & 0xfe00) == 0xfc00 || (first & 0xffc0) == 0xfe80
}

fn complement(ports: &[u32]) -> Vec<Value> {
    let mut out = vec![];
    let mut lo = 1u32;
    for &p in ports {
        if p > lo {
            out.push(if p - 1 == lo { json!({ "port": lo }) } else { json!({ "port": lo, "endPort": p - 1 }) });
        }
        lo = p + 1;
    }
    if lo <= 65535 {
        out.push(if lo == 65535 { json!({ "port": lo }) } else { json!({ "port": lo, "endPort": 65535 }) });
    }
    out
}

pub struct MxcEgress {
    pub allow: Vec<Value>,
    pub deny: Vec<Value>,
    pub unexpressed: Vec<Value>,
}

// cli/sandbox-policy.mjs mxcEgress: numeric allow/deny rules for MXC's network.egress, whose default stays
// "deny" (egressDefault never opens it).
pub fn mxc_egress(rules: Option<&Value>, dflt: Option<&Value>) -> MxcEgress {
    let mut notes = Notes::default();
    let mut tail = vec![];
    let entries = read_rules(rules, &mut notes);
    if !read_default(dflt, &mut tail) {
        tail.push(json!({ "index": -1, "fields": ["egressDefault"], "effect": "narrowed", "reason": "mxc-default-deny" }));
    }
    let mut by_addr: Vec<(String, Vec<&Entry>)> = vec![];
    for e in &entries {
        if loopback_range(e.kind, &e.host) {
            notes.note(e, &["host"], "omitted", "mxc-loopback");
            continue;
        }
        if matches!(e.kind, Kind::Name | Kind::Suffix) {
            notes.note(e, &["host"], "omitted", "mxc-host-name");
            continue;
        }
        if !e.cond.is_empty() {
            notes.note(e, &e.cond, if e.allow { "coarsened" } else { "omitted" }, "mxc-l7-fields");
        }
        if e.allow && is_private(e.kind, &e.host) {
            notes.note(e, &["host"], "may-be-inert", "mxc-private-network");
        }
        match by_addr.iter_mut().find(|(h, _)| *h == e.host) {
            Some((_, l)) => l.push(e),
            None => by_addr.push((e.host.clone(), vec![e])),
        }
    }
    let (mut allow, mut deny) = (vec![], vec![]);
    for (host, list) in &by_addr {
        let cidr = match host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
            Some(v6) => format!("{v6}/128"),
            None => format!("{host}/32"),
        };
        let to = json!([{ "cidr": cidr }]);
        let (other, each) = atoms(list, false, &mut notes, "mxc");
        let allowed: Vec<u32> = each.iter().filter(|(_, d)| d.allow).map(|(p, _)| *p).collect();
        if other.allow {
            allow.push(json!({ "to": to, "ports": [{ "protocol": "tcp" }] }));
            let denied: Vec<Value> = each.iter().filter(|(_, d)| !d.allow).map(|(p, _)| json!({ "port": p })).collect();
            if !denied.is_empty() {
                deny.push(json!({ "to": to, "ports": denied }));
            }
            continue;
        }
        if !allowed.is_empty() {
            let ports: Vec<Value> = allowed.iter().map(|p| json!({ "protocol": "tcp", "port": p })).collect();
            allow.push(json!({ "to": to, "ports": ports }));
        }
        if other.by == By::Rule {
            deny.push(if allowed.is_empty() { json!({ "to": to }) } else { json!({ "to": to, "ports": complement(&allowed) }) });
        } else {
            let rule_denied: Vec<Value> = each.iter().filter(|(_, d)| !d.allow && d.by == By::Rule).map(|(p, _)| json!({ "port": p })).collect();
            if !rule_denied.is_empty() {
                deny.push(json!({ "to": to, "ports": rule_denied }));
            }
        }
    }
    MxcEgress { allow, deny, unexpressed: notes.report(tail) }
}

// cli/sandbox-policy.mjs seatbeltEgress: SBPL network rules appended to the Seatbelt profile. Only
// loopback can be named (sandbox-exec: "host must be * or localhost in network address").
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub fn seatbelt_egress(rules: Option<&Value>, dflt: Option<&Value>) -> (String, Vec<Value>) {
    let mut notes = Notes::default();
    let mut tail = vec![];
    let entries = read_rules(rules, &mut notes);
    let deny_default = read_default(dflt, &mut tail);
    let mut lo: Vec<&Entry> = vec![];
    for e in &entries {
        if e.kind == Kind::Suffix || !matches!(e.host.as_str(), "localhost" | "127.0.0.1" | "[::1]") {
            notes.note(e, &["host"], "omitted", "seatbelt-host");
            continue;
        }
        if e.host != "localhost" {
            notes.note(e, &["host"], if e.allow { "coarsened" } else { "narrowed" }, "seatbelt-localhost-alias");
        }
        if !e.cond.is_empty() {
            notes.note(e, &e.cond, if e.allow { "coarsened" } else { "omitted" }, "seatbelt-l7-fields");
        }
        lo.push(e);
    }
    let (other, each) = atoms(&lo, true, &mut notes, "seatbelt");
    let verb = |allow: bool| if allow { "allow" } else { "deny" };
    let mut lines = vec![";; egress: generated by MoorAI from egressRules/egressDefault (cli/sandbox-policy.mjs)".to_string()];
    if deny_default {
        lines.push("(deny network-outbound)".into());
        lines.push("(allow network-outbound (remote unix-socket))".into());
    }
    if other.allow == deny_default {
        lines.push(format!("({} network-outbound (remote ip \"localhost:*\"))", verb(other.allow)));
    }
    for (p, d) in &each {
        if d.allow != other.allow {
            lines.push(format!("({} network-outbound (remote ip \"localhost:{p}\"))", verb(d.allow)));
        }
    }
    (lines.join("\n") + "\n", notes.report(tail))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Shared with test/sandbox-policy.test.mjs, which replays the same file against cli/sandbox-policy.mjs.
    const CASES: &str = include_str!("../../test/fixtures/mxc/sandbox-cases.json");

    #[test]
    fn golden_sandbox_cases_match_the_node_reference() {
        let cases: Vec<Value> = serde_json::from_str(CASES).expect("sandbox-cases.json parses");
        assert!(cases.len() >= 10, "fixture lost its cases");
        for c in &cases {
            let (rules, dflt) = (c["input"].get("egressRules"), c["input"].get("egressDefault"));
            let m = mxc_egress(rules, dflt);
            assert_eq!(json!({ "allow": m.allow, "deny": m.deny, "unexpressed": m.unexpressed }), c["mxc"], "mxc: case {}", c["name"]);
            let (text, unexpressed) = seatbelt_egress(rules, dflt);
            assert_eq!(json!({ "text": text, "unexpressed": unexpressed }), c["seatbelt"], "seatbelt: case {}", c["name"]);
        }
    }

    // JSON 443.0 and 4.43e2 are integers to JavaScript's Number.isInteger, so they are valid ports there and
    // here; JSON.stringify writes them as 443, which is why the shared fixture cannot carry this case.
    #[test]
    fn integral_float_ports_are_ports() {
        let rules: Value = serde_json::from_str(r#"[{"host":"203.0.113.1","port":443.0,"action":"allow"},{"host":"203.0.113.2","port":[4.43e2],"action":"allow"},{"host":"203.0.113.3","port":443.5,"action":"allow"}]"#).unwrap();
        let m = mxc_egress(Some(&rules), Some(&json!("block")));
        let to = |ip: &str| json!({ "to": [{ "cidr": format!("{ip}/32") }], "ports": [{ "protocol": "tcp", "port": 443 }] });
        assert_eq!(m.allow, vec![to("203.0.113.1"), to("203.0.113.2")]);
        assert_eq!(m.unexpressed, vec![json!({ "index": 2, "fields": ["rule"], "effect": "invalid", "reason": "invalid-rule" })]);
    }

    // cli/egress-rules.mjs reads at most 512 rules; the 513th is reported and never mapped.
    #[test]
    fn rules_past_512_are_reported_and_ignored() {
        let mut rules: Vec<Value> = (1..=512).map(|p| json!({ "host": "203.0.113.1", "port": p, "action": "block" })).collect();
        rules.push(json!({ "host": "203.0.113.1", "action": "allow" }));
        let m = mxc_egress(Some(&json!(rules)), Some(&json!("block")));
        assert!(m.allow.is_empty(), "rule 513 must not open anything");
        assert_eq!(m.unexpressed, vec![json!({ "index": 512, "fields": ["egressRules"], "effect": "invalid", "reason": "too-many-rules" })]);
    }
}
