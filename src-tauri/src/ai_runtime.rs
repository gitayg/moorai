// RUNNING local model servers and local HTTP/SSE MCP servers — the Rust host's mirror of
// cli/aibom-runtime.mjs (read that file for the sources behind each runtime rule). Same probes, same
// 5 s timeout each, same fail-open, same output shapes; test/aibom-rust-parity.test.mjs pins RUNTIMES
// to the JS table.
//   macOS / Linux  lsof +c 0 -iTCP -sTCP:LISTEN -nP   → command NAME + port
//                  ps -A -o comm=                       → command NAMES (never args / environ)
//   Windows        netstat -ano                         → PID + port
//                  tasklist /FO CSV /NH                 → image NAME per PID
// Only process names and port numbers are kept.
use regex::Regex;
use serde::Serialize;
use std::collections::HashSet;
use std::io::Read;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

// (runtime, process names, default ports, a listener on the port counts on its own)
pub const RUNTIMES: &[(&str, &[&str], &[u16], bool)] = &[
    ("ollama", &["ollama", "ollama app"], &[11434], true),
    ("lmstudio", &["lm studio", "lms"], &[], false),
    ("llama.cpp", &["llama-server"], &[8080], false),
    ("vllm", &["vllm"], &[8000], false),
];

pub const TIMEOUT: Duration = Duration::from_secs(5);
const MAX_BUFFER: usize = 8 * 1024 * 1024;

// The probe seam: (command, args) → stdout, or None when it could not run. Tests pass canned output.
pub type Runner<'a> = &'a dyn Fn(&str, &[&str]) -> Option<String>;

// execFileSync twin: stdin/stderr ignored, 5 s timeout (child killed), 8 MB cap. A non-zero exit that
// still printed something returns what it printed (lsof exits 1 when it has nothing more to list).
pub fn default_runner(cmd: &str, args: &[&str]) -> Option<String> {
    use std::process::{Command, Stdio};
    let mut c = Command::new(cmd);
    c.args(args).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        c.creation_flags(0x0800_0000); // CREATE_NO_WINDOW — the windowsHide of the Node probe
    }
    let mut child = c.spawn().ok()?;
    let mut stdout = child.stdout.take()?;
    let buf = Arc::new(Mutex::new(Vec::<u8>::new()));
    let sink = buf.clone();
    let reader = std::thread::spawn(move || {
        let mut chunk = [0u8; 16384];
        while let Ok(n) = stdout.read(&mut chunk) {
            if n == 0 { break; }
            let mut b = sink.lock().unwrap();
            if b.len() + n > MAX_BUFFER { break; }
            b.extend_from_slice(&chunk[..n]);
        }
    });
    let deadline = Instant::now() + TIMEOUT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break Some(s),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            _ => { let _ = child.kill(); let _ = child.wait(); break None; }
        }
    };
    // bounded wait for the reader: a grandchild holding the pipe open must not hang the report
    let t = Instant::now();
    while !reader.is_finished() && t.elapsed() < Duration::from_millis(500) { std::thread::sleep(Duration::from_millis(10)); }
    let out = String::from_utf8_lossy(&buf.lock().unwrap()).into_owned();
    match status {
        Some(s) if s.success() => Some(out),
        _ => if out.is_empty() { None } else { Some(out) },
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Listener { pub proc_name: String, pub port: u16, pub bind: &'static str }

// basename, no .exe, lsof's \x20 escapes decoded, lower-case (normName)
pub fn norm_name(s: &str) -> String {
    static HEX: OnceLock<Regex> = OnceLock::new();
    let hex = HEX.get_or_init(|| Regex::new(r"\\x([0-9a-fA-F]{2})").unwrap());
    let decoded = hex.replace_all(s, |c: &regex::Captures| char::from(u8::from_str_radix(&c[1], 16).unwrap()).to_string());
    let base = decoded.trim().rsplit(['/', '\\']).next().unwrap_or("").to_string();
    let base = if base.len() >= 4 && base[base.len() - 4..].eq_ignore_ascii_case(".exe") { base[..base.len() - 4].to_string() } else { base };
    base.to_lowercase()
}

fn bind_of(host: &str) -> &'static str {
    let h = host.strip_prefix('[').unwrap_or(host);
    let h = h.strip_suffix(']').unwrap_or(h).to_lowercase();
    if h.starts_with("127.") || h == "::1" || h == "localhost" { "loopback" } else { "network" }
}

// "127.0.0.1:11434" / "*:8080" / "[::1]:8000" → (host, port)
fn split_addr(a: &str) -> Option<(&str, u16)> {
    let i = a.rfind(':')?;
    let port: u32 = a[i + 1..].parse().ok()?;
    if port > 0 && port < 65536 { Some((&a[..i], port as u16)) } else { None }
}

fn pid_names(csv: Option<&str>) -> Vec<(String, String)> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r#"^"([^"]*)","(\d+)""#).unwrap());
    let mut out: Vec<(String, String)> = vec![];
    for line in csv.unwrap_or("").split('\n') {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if let Some(m) = re.captures(line) {
            let (name, pid) = (m[1].to_string(), m[2].to_string());
            // Map.set: a repeated pid keeps its insertion slot, takes the latest name
            if let Some(e) = out.iter_mut().find(|(p, _)| *p == pid) { e.1 = name; } else { out.push((pid, name)); }
        }
    }
    out
}

// → listeners, or None when the probe could not run.
pub fn probe_listeners(runner: Runner, windows: bool) -> Option<Vec<Listener>> {
    let mut out: Vec<Listener> = vec![];
    let mut seen: HashSet<String> = HashSet::new();
    let mut add = |proc_name: &str, addr: &str| {
        let Some((host, port)) = split_addr(addr) else { return };
        let rec = Listener { proc_name: norm_name(proc_name), port, bind: bind_of(host) };
        if seen.insert(format!("{}|{}|{}", rec.proc_name, rec.port, rec.bind)) { out.push(rec); }
    };
    if windows {
        let ns = runner("netstat", &["-ano"])?;
        let names = pid_names(runner("tasklist", &["/FO", "CSV", "/NH"]).as_deref());
        static FOREIGN: OnceLock<Regex> = OnceLock::new();
        let foreign = FOREIGN.get_or_init(|| Regex::new(r"^(0\.0\.0\.0|\[::\]):0$").unwrap());
        for line in ns.split('\n') {
            let t: Vec<&str> = line.split_whitespace().collect();
            // TCP <local> <foreign> <state> <pid>. Listening = all-zero foreign address (state word is localised).
            if t.len() < 5 || t[0] != "TCP" || !foreign.is_match(t[2]) { continue; }
            let pid = t[t.len() - 1];
            let name = names.iter().find(|(p, _)| p == pid).map(|(_, n)| n.as_str()).unwrap_or("");
            add(name, t[1]);
        }
        return Some(out);
    }
    let txt = runner("lsof", &["+c", "0", "-iTCP", "-sTCP:LISTEN", "-nP"])?;
    static LSOF: OnceLock<Regex> = OnceLock::new();
    let re = LSOF.get_or_init(|| Regex::new(r"^(\S+)\s+\d+\s.*(?-u:\b)TCP\s+(\S+)\s+\(LISTEN\)\s*$").unwrap());
    for line in txt.split('\n') {
        if let Some(m) = re.captures(line) { add(&m[1], &m[2]); }
    }
    Some(out)
}

// → normalised process names, or None when the probe could not run. Command NAME only.
pub fn probe_processes(runner: Runner, windows: bool) -> Option<Vec<String>> {
    let names: Vec<String> = if windows {
        pid_names(Some(&runner("tasklist", &["/FO", "CSV", "/NH"])?)).into_iter().map(|(_, n)| norm_name(&n)).collect()
    } else {
        runner("ps", &["-A", "-o", "comm="])?.split('\n').map(norm_name).filter(|n| !n.is_empty()).collect()
    };
    let mut seen = HashSet::new();
    Some(names.into_iter().filter(|n| seen.insert(n.clone())).collect())
}

#[derive(Serialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LocalRuntime { pub runtime: String, pub running: bool, pub ports: Vec<u16>, pub bind: String, pub detected_by: Vec<String> }

pub fn local_runtimes(listeners: Option<&[Listener]>, processes: Option<&[String]>) -> Vec<LocalRuntime> {
    let l = listeners.unwrap_or(&[]);
    let p: HashSet<&str> = processes.unwrap_or(&[]).iter().map(|s| s.as_str()).collect();
    let mut out = vec![];
    for (runtime, names, ports, port_alone) in RUNTIMES {
        let by_name: Vec<&Listener> = l.iter().filter(|x| names.contains(&x.proc_name.as_str())).collect();
        let by_port: Vec<&Listener> = if *port_alone { l.iter().filter(|x| ports.contains(&x.port)).collect() } else { vec![] };
        let proc_seen = names.iter().any(|n| p.contains(n)) || !by_name.is_empty();
        if !proc_seen && by_port.is_empty() { continue; }
        let ls: Vec<&Listener> = by_name.iter().chain(by_port.iter()).copied().collect();
        let mut ps: Vec<u16> = ls.iter().map(|x| x.port).collect::<HashSet<_>>().into_iter().collect();
        ps.sort_unstable();
        let bind = if ls.is_empty() { "unknown" } else if ls.iter().any(|x| x.bind == "network") { "network" } else { "loopback" };
        let mut detected_by = vec![];
        if proc_seen { detected_by.push("process".to_string()); }
        if !by_port.is_empty() { detected_by.push("port".to_string()); }
        out.push(LocalRuntime { runtime: runtime.to_string(), running: true, ports: ps, bind: bind.into(), detected_by });
    }
    out
}

// An MCP server declared with a URL in the configs the AIBOM reads — in memory only.
pub struct McpDecl { pub name: String, pub scope: String, pub url: String, pub typ: Option<String>, pub transport: Option<String> }

// Same files, order and dedupe as cli/moorai-aibom.mjs mcpServers(): ~/.claude.json (global, then each
// project), ~/.cursor/mcp.json; first `${scope}:${name}` wins; only entries whose `url` is a string.
pub fn mcp_decls(home: &str) -> Vec<McpDecl> {
    let mut out = vec![];
    let mut seen = HashSet::new();
    let mut add = |map: Option<&serde_json::Map<String, serde_json::Value>>, scope: &str| {
        for (name, cfg) in map.into_iter().flatten() {
            if name.is_empty() || !seen.insert(format!("{scope}:{name}")) { continue; }
            let s = |k: &str| cfg.get(k).and_then(|v| v.as_str()).map(str::to_string);
            if let Some(url) = s("url") { out.push(McpDecl { name: name.clone(), scope: scope.into(), url, typ: s("type"), transport: s("transport") }); }
        }
    };
    let read = |p: String| std::fs::read_to_string(p).ok().and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok());
    if let Some(j) = read(format!("{home}/.claude.json")) {
        add(j.get("mcpServers").and_then(|v| v.as_object()), "claude");
        for pv in j.get("projects").and_then(|v| v.as_object()).into_iter().flat_map(|m| m.values()) {
            add(pv.get("mcpServers").and_then(|v| v.as_object()), "claude");
        }
    }
    if let Some(j) = read(format!("{home}/.cursor/mcp.json")) { add(j.get("mcpServers").and_then(|v| v.as_object()), "cursor"); }
    out
}

#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct McpListener { pub name: String, pub scope: String, pub transport: String, pub port: u16, pub running: Option<bool> }

// Only servers declared on a localhost URL; `running` null when the probe is unavailable. The URL is
// never echoed — its query string can carry a token.
pub fn local_mcp_listeners(decls: &[McpDecl], listeners: Option<&[Listener]>) -> Vec<McpListener> {
    const LOCAL_HOSTS: &[&str] = &["localhost", "127.0.0.1", "[::1]", "::1", "0.0.0.0"];
    let mut out = vec![];
    for d in decls {
        let Ok(u) = url::Url::parse(&d.url) else { continue };
        let scheme = u.scheme();
        if scheme != "http" && scheme != "https" { continue; }
        let host = u.host_str().unwrap_or("").to_lowercase();
        if !LOCAL_HOSTS.contains(&host.as_str()) { continue; }
        let port = u.port().filter(|p| *p != 0).unwrap_or(if scheme == "https" { 443 } else { 80 });
        let path = u.path().to_ascii_lowercase();
        let sse = d.typ.as_deref() == Some("sse") || d.transport.as_deref() == Some("sse") || path.ends_with("/sse") || path.ends_with("/sse/");
        let running = listeners.map(|l| l.iter().any(|x| x.port == port));
        out.push(McpListener { name: d.name.clone(), scope: d.scope.clone(), transport: if sse { "sse" } else { "http" }.into(), port, running });
    }
    out
}

// The device-report entry point: one probe pass, both signals.
pub fn collect(home: &str) -> (Vec<LocalRuntime>, Vec<McpListener>) {
    let windows = cfg!(windows);
    let listeners = probe_listeners(&default_runner, windows);
    let processes = probe_processes(&default_runner, windows);
    let runtimes = local_runtimes(listeners.as_deref(), processes.as_deref());
    let mcp = local_mcp_listeners(&mcp_decls(home), listeners.as_deref());
    (runtimes, mcp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    // Same canned output as test/aibom-runtime.test.mjs.
    const LSOF: &str = "COMMAND                       PID       USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
ollama                      64889 dev    4u  IPv4 0xd74f2b7e8dff72c6      0t0  TCP 127.0.0.1:11434 (LISTEN)
LM\\x20Studio                 7001 dev   40u  IPv4 0x0000000000000001      0t0  TCP 127.0.0.1:1234 (LISTEN)
llama-server                7100 dev    3u  IPv4 0x0000000000000002      0t0  TCP *:8080 (LISTEN)
node                        7200 dev   17u  IPv6 0x0000000000000003      0t0  TCP [::1]:8000 (LISTEN)
node                        7201 dev   18u  IPv4 0x0000000000000004      0t0  TCP 127.0.0.1:3333 (LISTEN)
";
    const PS: &str = "/Applications/Ollama.app/Contents/Resources/ollama
/Applications/LM Studio.app/Contents/MacOS/LM Studio
/usr/local/bin/llama-server
/usr/local/bin/node
/bin/zsh
";
    const NETSTAT: &str = "\r\nActive Connections\r\n\r\n  Proto  Local Address          Foreign Address        State           PID\r\n  TCP    127.0.0.1:11434        0.0.0.0:0              LISTENING       4100\r\n  TCP    0.0.0.0:8080           0.0.0.0:0              LISTENING       4200\r\n  TCP    [::1]:1234             [::]:0                 ABH\u{d6}REN         4300\r\n  TCP    127.0.0.1:50000        127.0.0.1:11434        ESTABLISHED     9999\r\n  UDP    0.0.0.0:5353           *:*                                    4400\r\n";
    const TASKLIST: &str = "\"ollama.exe\",\"4100\",\"Console\",\"1\",\"45,000 K\"\r\n\"llama-server.exe\",\"4200\",\"Console\",\"1\",\"90,000 K\"\r\n\"LM Studio.exe\",\"4300\",\"Console\",\"1\",\"300,000 K\"\r\n\"svchost.exe\",\"4400\",\"Services\",\"0\",\"9,000 K\"\r\n";

    fn canned(outputs: &'static [(&'static str, &'static str)]) -> (impl Fn(&str, &[&str]) -> Option<String>, std::rc::Rc<RefCell<Vec<Vec<String>>>>) {
        let calls = std::rc::Rc::new(RefCell::new(vec![]));
        let c = calls.clone();
        (move |cmd: &str, args: &[&str]| {
            c.borrow_mut().push(std::iter::once(cmd.to_string()).chain(args.iter().map(|a| a.to_string())).collect());
            outputs.iter().find(|(k, _)| *k == cmd).map(|(_, v)| v.to_string())
        }, calls)
    }
    fn lis(p: &str, port: u16, bind: &'static str) -> Listener { Listener { proc_name: p.into(), port, bind } }
    fn rt(runtime: &str, ports: &[u16], bind: &str, by: &[&str]) -> LocalRuntime {
        LocalRuntime { runtime: runtime.into(), running: true, ports: ports.to_vec(), bind: bind.into(), detected_by: by.iter().map(|s| s.to_string()).collect() }
    }

    #[test]
    fn posix_lsof_listeners_parsed_names_decoded() {
        let (r, _) = canned(&[("lsof", LSOF)]);
        let l = probe_listeners(&r, false).unwrap();
        let at = |port| l.iter().find(|x| x.port == port).cloned().unwrap();
        assert_eq!(at(11434), lis("ollama", 11434, "loopback"));
        assert_eq!(at(1234), lis("lm studio", 1234, "loopback"));
        assert_eq!(at(8080), lis("llama-server", 8080, "network"));
        assert_eq!(at(8000), lis("node", 8000, "loopback"));
    }

    #[test]
    fn posix_process_probe_asks_for_the_command_name_only() {
        let (r, calls) = canned(&[("ps", PS)]);
        let names = probe_processes(&r, false).unwrap();
        for n in ["ollama", "lm studio", "llama-server"] { assert!(names.contains(&n.to_string()), "{n}"); }
        assert_eq!(calls.borrow()[0], ["ps", "-A", "-o", "comm="]);
    }

    #[test]
    fn runtimes_process_plus_distinctive_port_generic_ports_need_the_name() {
        let (r1, _) = canned(&[("lsof", LSOF)]);
        let (r2, _) = canned(&[("ps", PS)]);
        let l = probe_listeners(&r1, false).unwrap();
        let p = probe_processes(&r2, false).unwrap();
        let out = local_runtimes(Some(&l), Some(&p));
        assert_eq!(out, vec![
            rt("ollama", &[11434], "loopback", &["process", "port"]),
            rt("lmstudio", &[1234], "loopback", &["process"]),
            rt("llama.cpp", &[8080], "network", &["process"]),
        ], "a node dev server on :8000 is NOT vLLM");
        let json = serde_json::to_string(&out[0]).unwrap();
        assert_eq!(json, r#"{"runtime":"ollama","running":true,"ports":[11434],"bind":"loopback","detectedBy":["process","port"]}"#);
    }

    #[test]
    fn ollama_default_port_counts_alone_generic_port_never_does() {
        assert_eq!(local_runtimes(Some(&[lis("com.docker.backend", 11434, "loopback")]), Some(&[])),
            vec![rt("ollama", &[11434], "loopback", &["port"])]);
        assert!(local_runtimes(Some(&[lis("python3", 8000, "loopback")]), Some(&["python3".into()])).is_empty());
    }

    #[test]
    fn windows_netstat_and_tasklist_joined_by_pid() {
        let (r, calls) = canned(&[("netstat", NETSTAT), ("tasklist", TASKLIST)]);
        let l = probe_listeners(&r, true).unwrap();
        assert_eq!(l.iter().find(|x| x.port == 11434).cloned().unwrap(), lis("ollama", 11434, "loopback"));
        assert_eq!(l.iter().find(|x| x.port == 1234).cloned().unwrap(), lis("lm studio", 1234, "loopback"));
        assert!(!l.iter().any(|x| x.port == 50000), "established connection is not a listener");
        assert!(!l.iter().any(|x| x.port == 5353), "UDP ignored");
        let p = probe_processes(&r, true).unwrap();
        let mut names: Vec<String> = local_runtimes(Some(&l), Some(&p)).into_iter().map(|x| x.runtime).collect();
        names.sort();
        assert_eq!(names, ["llama.cpp", "lmstudio", "ollama"]);
        for c in calls.borrow().iter() { assert!(!c.iter().any(|a| a == "/V" || a == "/v" || a.contains("args")), "no verbose/args flags: {c:?}"); }
    }

    #[test]
    fn fail_open_missing_tool_yields_none_and_no_runtimes() {
        let (r, _) = canned(&[]);
        assert_eq!(probe_listeners(&r, false), None);
        assert_eq!(probe_processes(&r, false), None);
        assert_eq!(probe_listeners(&r, true), None);
        assert!(local_runtimes(None, None).is_empty());
    }

    #[test]
    fn default_runner_missing_binary_is_none_and_timeout_is_bounded() {
        assert_eq!(default_runner("moorai-definitely-not-a-command", &[]), None);
        #[cfg(unix)]
        {
            let t = Instant::now();
            let out = default_runner("sh", &["-c", "echo partial; sleep 30"]);
            assert!(t.elapsed() < Duration::from_secs(7), "5 s timeout enforced, took {:?}", t.elapsed());
            assert_eq!(out.as_deref(), Some("partial\n"), "partial output kept, like execFileSync's e.stdout");
        }
    }

    #[test]
    fn local_mcp_over_http_sse_matched_to_listeners_url_never_echoed() {
        let d = |name: &str, scope: &str, url: &str, typ: Option<&str>| McpDecl { name: name.into(), scope: scope.into(), url: url.into(), typ: typ.map(Into::into), transport: None };
        let decls = vec![
            d("local-http", "claude", "http://localhost:3333/mcp?token=SECRETMCPTOKEN", Some("http")),
            d("local-sse", "cursor", "http://127.0.0.1:4444/sse", None),
            d("remote", "claude", "https://mcp.example.com/mcp", Some("http")),
            d("bad-url", "claude", "not a url", None),
            d("v6", "claude", "https://[::1]/mcp", None),
        ];
        let l = [lis("node", 3333, "loopback")];
        let out = local_mcp_listeners(&decls, Some(&l));
        assert_eq!(out, vec![
            McpListener { name: "local-http".into(), scope: "claude".into(), transport: "http".into(), port: 3333, running: Some(true) },
            McpListener { name: "local-sse".into(), scope: "cursor".into(), transport: "sse".into(), port: 4444, running: Some(false) },
            McpListener { name: "v6".into(), scope: "claude".into(), transport: "http".into(), port: 443, running: Some(false) },
        ]);
        assert!(local_mcp_listeners(&decls, None).iter().all(|x| x.running.is_none()), "probe unavailable → unknown");
        let json = serde_json::to_string(&local_mcp_listeners(&decls, None)).unwrap();
        assert!(json.contains(r#""running":null"#));
        assert!(!json.contains("SECRETMCPTOKEN") && !json.contains("localhost"), "URL never echoed: {json}");
    }

    #[test]
    fn mcp_decls_read_the_same_files_as_the_cli() {
        let dir = std::env::temp_dir().join(format!("moorai-rs-mcp-{}", std::process::id()));
        std::fs::create_dir_all(dir.join(".cursor")).unwrap();
        std::fs::write(dir.join(".claude.json"), r#"{"mcpServers":{"local-http":{"type":"http","url":"http://localhost:3333/mcp","headers":{"Authorization":"Bearer SECRETHEADER"}},"stdio":{"command":"npx"}},"projects":{"/p":{"mcpServers":{"local-http":{"url":"http://localhost:9999/x"},"proj":{"url":"http://127.0.0.1:5555/sse"}}}}}"#).unwrap();
        std::fs::write(dir.join(".cursor/mcp.json"), r#"{"mcpServers":{"cur":{"url":"http://localhost:6666/mcp","transport":"sse"}}}"#).unwrap();
        let decls = mcp_decls(dir.to_str().unwrap());
        let got: Vec<(String, String, String)> = decls.iter().map(|d| (d.name.clone(), d.scope.clone(), d.url.clone())).collect();
        assert_eq!(got, vec![
            ("local-http".into(), "claude".into(), "http://localhost:3333/mcp".into()),
            ("proj".into(), "claude".into(), "http://127.0.0.1:5555/sse".into()),
            ("cur".into(), "cursor".into(), "http://localhost:6666/mcp".into()),
        ], "global wins over a same-named project entry; stdio entries have no URL");
        let out = local_mcp_listeners(&decls, Some(&[lis("node", 6666, "loopback")]));
        assert_eq!(out.iter().map(|m| (m.name.as_str(), m.transport.as_str(), m.port, m.running)).collect::<Vec<_>>(),
            vec![("local-http", "http", 3333, Some(false)), ("proj", "sse", 5555, Some(false)), ("cur", "sse", 6666, Some(true))]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn norm_name_rules() {
        assert_eq!(norm_name("LM\\x20Studio"), "lm studio");
        assert_eq!(norm_name("C:\\Program Files\\Ollama\\ollama.EXE"), "ollama");
        assert_eq!(norm_name("  /usr/bin/llama-server \n"), "llama-server");
    }
}
