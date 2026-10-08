// RUNNING local model servers and local HTTP/SSE MCP servers, and the shared probe runner. The local-AI
// half lives in listen_sockets.rs (sockets + process names), local_ai.rs (runtime table, installed
// runtimes) and local_ai_windows.rs (Windows AI platform, ODR agent connectors) — the Rust mirrors of
// cli/listen-sockets.mjs, cli/local-ai-inventory.mjs and cli/local-ai-windows.mjs. This file keeps the
// runner (execFileSync twin), the MCP-listener match (cli/aibom-runtime.mjs localMcpListeners) and
// collect(), the one probe pass the device report runs. Only process names and port numbers are kept.
use crate::listen_sockets::{probe_sockets, Listener};
use crate::local_ai::{installed_runtimes, running_runtimes, InstallEnv, InstalledRuntime};
use serde::Serialize;
use std::collections::HashSet;
use std::io::Read;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const TIMEOUT: Duration = Duration::from_secs(5);
const MAX_BUFFER: usize = 8 * 1024 * 1024;

// The probe seam: (command, args, timeout) → stdout, or None when it could not run. Tests pass canned output.
pub type Runner<'a> = &'a dyn Fn(&str, &[&str], Duration) -> Option<String>;

// execFileSync twin: stdin/stderr ignored, timeout (child killed), 8 MB cap. A non-zero exit that
// still printed something returns what it printed (lsof exits 1 when it has nothing more to list).
pub fn default_runner(cmd: &str, args: &[&str], timeout: Duration) -> Option<String> {
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
    let deadline = Instant::now() + timeout;
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

// The process probe's platform name, spelled like Node's process.platform.
pub fn platform_name() -> &'static str {
    if cfg!(windows) { "win32" } else if cfg!(target_os = "macos") { "darwin" } else { "linux" }
}

#[derive(Serialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LocalRuntime { pub runtime: String, pub running: bool, pub ports: Vec<u16>, pub bind: String, pub listening: Option<String>, pub detected_by: Vec<String> }

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

// The device-report entry point: one probe pass for every local-AI signal. The two Windows probes
// (PowerShell up to 10 s, odr.exe up to 5 s) run on their own threads beside the socket probe, so the
// report waits for the slowest probe, not their sum. device_ai_assets is an async command, so none of
// this runs on the UI thread or delays app start.
pub struct LocalAiReport {
    pub runtimes: Vec<LocalRuntime>,
    pub mcp: Vec<McpListener>,
    pub installed: Vec<InstalledRuntime>,
    pub windows_ai: Option<serde_json::Value>,
    pub agent_connectors: Option<serde_json::Value>,
    // "unavailable" when neither sockets nor process names could be read (the JS AIBOM's runtimeProbe)
    pub runtime_probe: &'static str,
}

pub fn collect(home: &str) -> LocalAiReport {
    let platform = platform_name();
    let windows = platform == "win32";
    std::thread::scope(|sc| {
        let win_ai = windows.then(|| sc.spawn(|| crate::local_ai_windows::windows_ai_platform(&default_runner)));
        let odr = windows.then(|| sc.spawn(|| crate::local_ai_windows::odr_agent_connectors(&default_runner)));
        let sockets = probe_sockets(&default_runner, platform, &|p| std::fs::read_to_string(p).ok());
        let env = |k: &str| std::env::var(k).ok();
        let exists = |p: &str| std::path::Path::new(p).exists();
        let read = |p: &str| std::fs::read_to_string(p).ok();
        let installed = installed_runtimes(&InstallEnv { platform, home, env: &env, exists: &exists, read_file: &read });
        let runtime_probe = if sockets.listeners.is_none() && sockets.processes.is_none() { "unavailable" } else { "ok" };
        LocalAiReport {
            runtime_probe,
            runtimes: running_runtimes(sockets.listeners.as_deref(), sockets.processes.as_deref()),
            mcp: local_mcp_listeners(&mcp_decls(home), sockets.listeners.as_deref()),
            installed,
            windows_ai: win_ai.and_then(|h| h.join().ok().flatten()),
            agent_connectors: odr.and_then(|h| h.join().ok().flatten()),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local_ai::running_runtimes;

    // Same canned output as test/aibom-runtime.test.mjs, now with the pid-carrying ps the new probe asks for.
    const LSOF: &str = "COMMAND                       PID       USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
ollama                      64889 dev    4u  IPv4 0xd74f2b7e8dff72c6      0t0  TCP 127.0.0.1:11434 (LISTEN)
LM\\x20Studio                 7001 dev   40u  IPv4 0x0000000000000001      0t0  TCP 127.0.0.1:1234 (LISTEN)
llama-server                7100 dev    3u  IPv4 0x0000000000000002      0t0  TCP *:8080 (LISTEN)
node                        7200 dev   17u  IPv6 0x0000000000000003      0t0  TCP [::1]:8000 (LISTEN)
node                        7201 dev   18u  IPv4 0x0000000000000004      0t0  TCP 127.0.0.1:3333 (LISTEN)
";
    const PS: &str = "64889 /Applications/Ollama.app/Contents/Resources/ollama
 7001 /Applications/LM Studio.app/Contents/MacOS/LM Studio
 7100 /usr/local/bin/llama-server
 7200 /usr/local/bin/node
  900 /bin/zsh
";

    fn canned(outputs: &'static [(&'static str, &'static str)]) -> impl Fn(&str, &[&str], Duration) -> Option<String> {
        move |cmd: &str, _: &[&str], _: Duration| outputs.iter().find(|(k, _)| *k == cmd).map(|(_, v)| v.to_string())
    }
    fn lis(p: &str, port: u16, bind: &'static str) -> Listener { Listener { pid: None, proc_name: p.into(), port, bind } }
    fn rt(runtime: &str, ports: &[u16], bind: &str, by: &[&str]) -> LocalRuntime {
        LocalRuntime { runtime: runtime.into(), running: true, ports: ports.to_vec(), bind: bind.into(), listening: Some(bind.into()), detected_by: by.iter().map(|s| s.to_string()).collect() }
    }

    #[test]
    fn runtimes_process_plus_distinctive_port_generic_ports_need_the_name() {
        let r = canned(&[("lsof", LSOF), ("ps", PS)]);
        let s = probe_sockets(&r, "darwin", &|_| None);
        let out = running_runtimes(s.listeners.as_deref(), s.processes.as_deref());
        assert_eq!(out, vec![
            rt("ollama", &[11434], "loopback", &["process", "port"]),
            rt("lmstudio", &[1234], "loopback", &["process"]),
            rt("llama.cpp", &[8080], "network", &["process"]),
        ], "a node dev server on :8000 is NOT vLLM");
        let json = serde_json::to_string(&out[0]).unwrap();
        assert_eq!(json, r#"{"runtime":"ollama","running":true,"ports":[11434],"bind":"loopback","listening":"loopback","detectedBy":["process","port"]}"#);
    }

    #[test]
    fn ollama_default_port_counts_alone_generic_port_never_does() {
        assert_eq!(running_runtimes(Some(&[lis("com.docker.backend", 11434, "loopback")]), Some(&[])),
            vec![rt("ollama", &[11434], "loopback", &["port"])]);
        assert!(running_runtimes(Some(&[lis("python3", 8000, "loopback")]), Some(&["python3".into()])).is_empty());
    }

    #[test]
    fn windows_netstat_and_tasklist_joined_by_pid() {
        const NETSTAT: &str = "\r\nActive Connections\r\n\r\n  Proto  Local Address          Foreign Address        State           PID\r\n  TCP    127.0.0.1:11434        0.0.0.0:0              LISTENING       4100\r\n  TCP    0.0.0.0:8080           0.0.0.0:0              LISTENING       4200\r\n  TCP    [::1]:1234             [::]:0                 ABH\u{d6}REN         4300\r\n  TCP    127.0.0.1:50000        127.0.0.1:11434        ESTABLISHED     9999\r\n  UDP    0.0.0.0:5353           *:*                                    4400\r\n";
        const TASKLIST: &str = "\"ollama.exe\",\"4100\",\"Console\",\"1\",\"45,000 K\"\r\n\"llama-server.exe\",\"4200\",\"Console\",\"1\",\"90,000 K\"\r\n\"LM Studio.exe\",\"4300\",\"Console\",\"1\",\"300,000 K\"\r\n\"svchost.exe\",\"4400\",\"Services\",\"0\",\"9,000 K\"\r\n";
        let r = canned(&[("netstat", NETSTAT), ("tasklist", TASKLIST)]);
        let s = probe_sockets(&r, "win32", &|_| None);
        let l = s.listeners.clone().unwrap();
        assert!(!l.iter().any(|x| x.port == 50000), "established connection is not a listener");
        assert!(!l.iter().any(|x| x.port == 5353), "UDP ignored");
        let mut names: Vec<String> = running_runtimes(Some(&l), s.processes.as_deref()).into_iter().map(|x| x.runtime).collect();
        names.sort();
        assert_eq!(names, ["llama.cpp", "lmstudio", "ollama"]);
    }

    #[test]
    fn fail_open_missing_tool_yields_none_and_no_runtimes() {
        let r = canned(&[]);
        for p in ["darwin", "linux", "win32"] {
            let s = probe_sockets(&r, p, &|_| None);
            assert!(s.listeners.is_none() && s.processes.is_none(), "{p}");
        }
        assert!(running_runtimes(None, None).is_empty());
    }

    #[test]
    fn default_runner_missing_binary_is_none_and_timeout_is_bounded() {
        assert_eq!(default_runner("moorai-definitely-not-a-command", &[], TIMEOUT), None);
        #[cfg(unix)]
        {
            let t = Instant::now();
            let out = default_runner("sh", &["-c", "echo partial; sleep 30"], TIMEOUT);
            assert!(t.elapsed() < Duration::from_secs(7), "5 s timeout enforced, took {:?}", t.elapsed());
            assert_eq!(out.as_deref(), Some("partial\n"), "partial output kept, like execFileSync's e.stdout");
            let t = Instant::now();
            let _ = default_runner("sh", &["-c", "sleep 30"], Duration::from_millis(300));
            assert!(t.elapsed() < Duration::from_secs(2), "per-call timeout honoured, took {:?}", t.elapsed());
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

}
