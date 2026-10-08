// Listening TCP sockets → Listener { pid, proc_name, port, bind }, read WITHOUT admin rights — the Rust
// mirror of cli/listen-sockets.mjs (same probes, same parsers, same fallback order). Only a process
// NAME, a port and loopback-vs-network are kept; no address beyond that class, no argv, no environment.
//
//   macOS / Linux  lsof +c 0 -iTCP -sTCP:LISTEN -nP      (+ ps -A -o pid=,comm= to name the PID)
//   Linux          ss -ltnp                              when lsof is missing
//   Linux          /proc/net/tcp + /proc/net/tcp6        when ss is missing too (no process names)
//   Windows        netstat -ano                          (+ tasklist /FO CSV /NH to name the PID)
//
// test/aibom-rust-parity.test.mjs checks the probe argv against the JS file; the parsers replay
// test/fixtures/local-ai/sockets.json, which the JS tests replay too.
use crate::ai_runtime::{Runner, TIMEOUT};
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

#[derive(Debug, Clone, PartialEq)]
pub struct Listener { pub pid: Option<String>, pub proc_name: String, pub port: u16, pub bind: &'static str }

// basename, no .exe, lsof's \x20 escapes decoded, lower-case (normName)
pub fn norm_name(s: &str) -> String {
    static HEX: OnceLock<Regex> = OnceLock::new();
    let hex = HEX.get_or_init(|| Regex::new(r"\\x([0-9a-fA-F]{2})").unwrap());
    let decoded = hex.replace_all(s, |c: &regex::Captures| char::from(u8::from_str_radix(&c[1], 16).unwrap()).to_string());
    let base = decoded.trim().rsplit(['/', '\\']).next().unwrap_or("").to_string();
    let base = if base.len() >= 4 && base.is_char_boundary(base.len() - 4) && base[base.len() - 4..].eq_ignore_ascii_case(".exe") { base[..base.len() - 4].to_string() } else { base };
    base.to_lowercase()
}

// "127.0.0.1" | "[::1]" | "::ffff:127.0.0.1" | "127.0.0.53%lo" | "localhost" → loopback; anything else
// ("*", "0.0.0.0", "[::]", a LAN address) → network.
pub fn bind_of(host: &str) -> &'static str {
    let h = host.strip_prefix('[').unwrap_or(host);
    let mut h = h.strip_suffix(']').unwrap_or(h).to_lowercase();
    if let Some(z) = h.find('%') {
        let zone = &h[z + 1..];
        if zone.starts_with("lo") && zone[2..].chars().all(|c| c.is_ascii_digit()) { return "loopback"; }
        h.truncate(z);
    }
    let h = h.strip_prefix("::ffff:").unwrap_or(&h);
    if h.starts_with("127.") || h == "::1" || h == "localhost" { "loopback" } else { "network" }
}

// "127.0.0.1:11434" / "*:8080" / "[::1]:8000" → (host, port)
pub fn split_addr(a: &str) -> Option<(&str, u16)> {
    let i = a.rfind(':')?;
    let port: u32 = a[i + 1..].parse().ok()?;
    if port > 0 && port < 65536 { Some((&a[..i], port as u16)) } else { None }
}

fn rec(pid: Option<&str>, proc_name: &str, addr: &str) -> Option<Listener> {
    let (host, port) = split_addr(addr)?;
    Some(Listener { pid: pid.map(str::to_string), proc_name: norm_name(proc_name), port, bind: bind_of(host) })
}

// `lsof +c 0 -iTCP -sTCP:LISTEN -nP`
pub fn parse_lsof(txt: &str) -> Vec<Listener> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r"^(\S+)\s+(\d+)\s.*(?-u:\b)TCP\s+(\S+)\s+\(LISTEN\)\s*$").unwrap());
    txt.split('\n').filter_map(|l| re.captures(l).and_then(|m| rec(Some(&m[2]), &m[1], &m[3]))).collect()
}

// `ss -ltnp`: users:() is filled only for the caller's own processes without root; others keep port + bind.
pub fn parse_ss(txt: &str) -> Vec<Listener> {
    static RE: OnceLock<Regex> = OnceLock::new();
    static USERS: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r"^LISTEN\s+\d+\s+\d+\s+(\S+)\s+\S+(?:\s+(.*))?$").unwrap());
    let users = USERS.get_or_init(|| Regex::new(r#"users:\(\("((?:[^"\\]|\\.)*)",pid=(\d+)"#).unwrap());
    let mut out = vec![];
    for line in txt.split('\n') {
        let Some(m) = re.captures(line) else { continue };
        let rest = m.get(2).map(|x| x.as_str()).unwrap_or("");
        let u = users.captures(rest);
        let r = rec(u.as_ref().map(|u| u.get(2).unwrap().as_str()), u.as_ref().map(|u| u.get(1).unwrap().as_str()).unwrap_or(""), &m[1]);
        if let Some(r) = r { out.push(r); }
    }
    out
}

// /proc/net/tcp{,6}: addresses as little-endian hex words; state 0A = LISTEN. No process names.
fn proc_hex_loopback(hex: &str) -> bool {
    let mut bytes: Vec<u8> = vec![];
    for w in (0..hex.len()).step_by(8) {
        let word = &hex[w..(w + 8).min(hex.len())];
        for b in [6usize, 4, 2, 0] {
            if b + 2 <= word.len() { bytes.push(u8::from_str_radix(&word[b..b + 2], 16).unwrap_or(0)); }
        }
    }
    if bytes.len() == 4 { return bytes[0] == 127; }
    if bytes.len() != 16 { return false; }
    let zero = |from: usize, to: usize| bytes[from..to].iter().all(|x| *x == 0);
    if zero(0, 15) && bytes[15] == 1 { return true; } // ::1
    zero(0, 10) && bytes[10] == 0xff && bytes[11] == 0xff && bytes[12] == 127 // ::ffff:127.x
}
pub fn parse_proc_net_tcp(txt: &str) -> Vec<Listener> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r"^([0-9A-Fa-f]{8}|[0-9A-Fa-f]{32}):([0-9A-Fa-f]{4})$").unwrap());
    let mut out = vec![];
    for line in txt.split('\n') {
        let t: Vec<&str> = line.split_whitespace().collect();
        if t.len() < 4 || t[3] != "0A" { continue; }
        let Some(m) = re.captures(t[1]) else { continue };
        let port = u16::from_str_radix(&m[2], 16).unwrap_or(0);
        if port > 0 { out.push(Listener { pid: None, proc_name: String::new(), port, bind: if proc_hex_loopback(&m[1]) { "loopback" } else { "network" } }); }
    }
    out
}

// `netstat -ano`: TCP <local> <foreign> <state> <pid>. Listening = all-zero foreign address (the state
// word is localised, so it is not read).
pub fn parse_netstat(txt: &str) -> Vec<Listener> {
    static FOREIGN: OnceLock<Regex> = OnceLock::new();
    let foreign = FOREIGN.get_or_init(|| Regex::new(r"^(0\.0\.0\.0|\[::\]):0$").unwrap());
    let mut out = vec![];
    for line in txt.split('\n') {
        let t: Vec<&str> = line.split_whitespace().collect();
        if t.len() < 5 || t[0] != "TCP" || !foreign.is_match(t[2]) { continue; }
        if let Some(r) = rec(Some(t[t.len() - 1]), "", t[1]) { out.push(r); }
    }
    out
}

#[derive(Debug, Default)]
pub struct Procs { pub by_pid: HashMap<String, String>, pub names: Vec<String> }

fn uniq(v: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    v.into_iter().filter(|n| seen.insert(n.clone())).collect()
}

// `ps -A -o pid=,comm=` → pid → name. A comm-only line (no pid) is still kept as a name.
pub fn parse_ps(txt: &str) -> Procs {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r"^\s*(\d+)\s+(.+?)\s*$").unwrap());
    let mut p = Procs::default();
    let mut names = vec![];
    for line in txt.split('\n') {
        let m = re.captures(line);
        let name = norm_name(m.as_ref().map(|m| m.get(2).unwrap().as_str()).unwrap_or(line));
        if name.is_empty() { continue; }
        if let Some(m) = &m { p.by_pid.insert(m[1].to_string(), name.clone()); }
        names.push(name);
    }
    p.names = uniq(names);
    p
}

// `tasklist /FO CSV /NH` → pid → name
pub fn parse_tasklist(csv: &str) -> Procs {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r#"^"([^"]*)","(\d+)""#).unwrap());
    let mut order: Vec<String> = vec![];
    let mut p = Procs::default();
    for line in csv.split('\n') {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if let Some(m) = re.captures(line) {
            if !p.by_pid.contains_key(&m[2]) { order.push(m[2].to_string()); }
            p.by_pid.insert(m[2].to_string(), norm_name(&m[1]));
        }
    }
    p.names = uniq(order.iter().map(|pid| p.by_pid[pid].clone()).collect());
    p
}

// `source` (lsof | ss | proc | netstat | none) mirrors the JS socketSource; only the tests read it.
pub struct Sockets { pub listeners: Option<Vec<Listener>>, pub processes: Option<Vec<String>>, #[cfg_attr(not(test), allow(dead_code))] pub source: &'static str }

// A probe that could not run is None — never an empty list that would read as "nothing listens".
pub fn probe_sockets(runner: Runner, platform: &str, read_file: &dyn Fn(&str) -> Option<String>) -> Sockets {
    let (mut listeners, mut procs, mut source): (Option<Vec<Listener>>, Option<Procs>, &'static str) = (None, None, "none");
    if platform == "win32" {
        if let Some(ns) = runner("netstat", &["-ano"], TIMEOUT) { listeners = Some(parse_netstat(&ns)); source = "netstat"; }
        if let Some(tl) = runner("tasklist", &["/FO", "CSV", "/NH"], TIMEOUT) { procs = Some(parse_tasklist(&tl)); }
    } else {
        if let Some(t) = runner("lsof", &["+c", "0", "-iTCP", "-sTCP:LISTEN", "-nP"], TIMEOUT) { listeners = Some(parse_lsof(&t)); source = "lsof"; }
        if listeners.is_none() && platform == "linux" {
            if let Some(t) = runner("ss", &["-ltnp"], TIMEOUT) { listeners = Some(parse_ss(&t)); source = "ss"; }
        }
        if listeners.is_none() && platform == "linux" {
            let (t4, t6) = (read_file("/proc/net/tcp"), read_file("/proc/net/tcp6"));
            if t4.is_some() || t6.is_some() {
                let mut l = parse_proc_net_tcp(t4.as_deref().unwrap_or(""));
                l.extend(parse_proc_net_tcp(t6.as_deref().unwrap_or("")));
                listeners = Some(l);
                source = "proc";
            }
        }
        if let Some(t) = runner("ps", &["-A", "-o", "pid=,comm="], TIMEOUT) { procs = Some(parse_ps(&t)); }
    }
    if let (Some(ls), Some(p)) = (listeners.as_mut(), procs.as_ref()) {
        for l in ls.iter_mut() {
            if let Some(n) = l.pid.as_ref().and_then(|pid| p.by_pid.get(pid)) { l.proc_name = n.clone(); }
        }
    }
    let listeners = listeners.map(|ls| {
        let mut seen = HashSet::new();
        ls.into_iter().filter(|l| seen.insert(format!("{}|{}|{}", l.proc_name, l.port, l.bind))).collect()
    });
    Sockets { listeners, processes: procs.map(|p| p.names), source }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};
    use std::time::Duration;

    const FX: &str = include_str!("../../test/fixtures/local-ai/sockets.json");
    fn fx() -> Value { serde_json::from_str(FX).unwrap() }
    fn txt(v: &Value) -> String { v.as_array().map(|a| a.iter().map(|l| l.as_str().unwrap()).collect::<Vec<_>>().join("\n")).unwrap_or_else(|| v.as_str().unwrap_or("").to_string()) }
    fn as_json(ls: &[Listener]) -> Value { json!(ls.iter().map(|l| json!({ "pid": l.pid, "proc": l.proc_name, "port": l.port, "bind": l.bind })).collect::<Vec<_>>()) }

    #[test]
    fn bind_class_matches_the_shared_fixture() {
        let f = fx();
        for h in f["bind"]["loopback"].as_array().unwrap() { assert_eq!(bind_of(h.as_str().unwrap()), "loopback", "{h}"); }
        for h in f["bind"]["network"].as_array().unwrap() { assert_eq!(bind_of(h.as_str().unwrap()), "network", "{h}"); }
    }

    #[test]
    fn parsers_match_the_shared_fixture() {
        let f = fx();
        let netstat = txt(&f["netstat"]).replace('\n', "\r\n");
        assert_eq!(as_json(&parse_lsof(&txt(&f["lsof"]))), f["expect"]["lsof"]);
        assert_eq!(as_json(&parse_ss(&txt(&f["ss"]))), f["expect"]["ss"]);
        assert_eq!(as_json(&parse_proc_net_tcp(&txt(&f["procTcp"]))), f["expect"]["procTcp"]);
        assert_eq!(as_json(&parse_proc_net_tcp(&txt(&f["procTcp6"]))), f["expect"]["procTcp6"]);
        assert_eq!(as_json(&parse_netstat(&netstat)), f["expect"]["netstat"]);
    }

    #[test]
    fn ps_renames_a_truncated_lsof_command_by_pid() {
        let f = fx();
        let lsof = txt(&f["lsof"]);
        let ps = "  7500 /Users/dev/models/Qwen3.5-0.8B-Q8_0.llamafile\n";
        let r = |cmd: &str, _: &[&str], _: Duration| match cmd { "lsof" => Some(lsof.clone()), "ps" => Some(ps.to_string()), _ => None };
        let s = probe_sockets(&r, "darwin", &|_| None);
        assert_eq!(s.listeners.unwrap().iter().find(|l| l.pid.as_deref() == Some("7500")).unwrap().proc_name, "qwen3.5-0.8b-q8_0.llamafile");
        assert_eq!(parse_ps(ps).by_pid["7500"], "qwen3.5-0.8b-q8_0.llamafile");
    }

    #[test]
    fn linux_fallback_chain_and_macos_never_falls_back() {
        let f = fx();
        let (ss, t4, t6) = (txt(&f["ss"]), txt(&f["procTcp"]), txt(&f["procTcp6"]));
        let calls = std::cell::RefCell::new(vec![]);
        let only_ss = |cmd: &str, args: &[&str], _: Duration| { calls.borrow_mut().push(std::iter::once(cmd).chain(args.iter().copied()).map(String::from).collect::<Vec<_>>()); (cmd == "ss").then(|| ss.clone()) };
        let via_ss = probe_sockets(&only_ss, "linux", &|_| None);
        assert_eq!(via_ss.source, "ss");
        assert!(calls.borrow().iter().any(|c| c == &["ss", "-ltnp"]));
        let none = |_: &str, _: &[&str], _: Duration| None;
        let files = |p: &str| match p { "/proc/net/tcp" => Some(t4.clone()), "/proc/net/tcp6" => Some(t6.clone()), _ => None };
        let via_proc = probe_sockets(&none, "linux", &files);
        assert_eq!((via_proc.source, via_proc.listeners.as_ref().map(|l| l.len())), ("proc", Some(5)));
        assert!(probe_sockets(&none, "linux", &|_| None).listeners.is_none(), "unreadable sockets are None, not an empty list");
        assert!(probe_sockets(&only_ss, "darwin", &files).listeners.is_none(), "macOS never falls back to ss or /proc");
    }

    #[test]
    fn windows_netstat_joined_to_tasklist_names_only() {
        let f = fx();
        let netstat = txt(&f["netstat"]).replace('\n', "\r\n");
        let tl = "\"ollama.exe\",\"4100\",\"Console\",\"1\",\"45,000 K\"\r\n\"llama-server.exe\",\"4200\",\"Console\",\"1\",\"90,000 K\"\r\n";
        let calls = std::cell::RefCell::new(vec![]);
        let r = |cmd: &str, args: &[&str], _: Duration| { calls.borrow_mut().push(std::iter::once(cmd).chain(args.iter().copied()).map(String::from).collect::<Vec<_>>()); match cmd { "netstat" => Some(netstat.clone()), "tasklist" => Some(tl.to_string()), _ => None } };
        let s = probe_sockets(&r, "win32", &|_| None);
        let l = s.listeners.unwrap();
        assert_eq!(l.iter().find(|x| x.port == 8080).map(|x| (x.proc_name.as_str(), x.bind)), Some(("llama-server", "network")));
        assert_eq!(l.iter().find(|x| x.port == 11434).map(|x| (x.proc_name.as_str(), x.bind)), Some(("ollama", "loopback")));
        let mut p = s.processes.unwrap();
        p.sort();
        assert_eq!(p, ["llama-server", "ollama"]);
        assert_eq!(*calls.borrow(), vec![vec!["netstat", "-ano"], vec!["tasklist", "/FO", "CSV", "/NH"]]);
    }

    #[test]
    fn norm_name_rules() {
        assert_eq!(norm_name("LM\\x20Studio"), "lm studio");
        assert_eq!(norm_name("C:\\Program Files\\Ollama\\ollama.EXE"), "ollama");
        assert_eq!(norm_name("  /usr/bin/llama-server \n"), "llama-server");
    }
}
