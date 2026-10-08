// Local AI inventory — the Rust mirror of cli/local-ai-inventory.mjs (read that file for the source
// behind every port and process-name rule). Which local model runtimes are RUNNING, on which ports and
// whether each listens beyond loopback; which are INSTALLED (existence checks only, nothing executed).
// Content-free: runtime names, versions, ports, counts and classes. Never a path, a model file name,
// an address beyond loopback/network, a command line or an environment value.
//
// test/aibom-rust-parity.test.mjs reads LOCAL_AI_RUNTIMES and LOCAL_AI_INSTALLS out of this file and
// asserts they equal the JS tables; test/fixtures/local-ai/runtimes.json is replayed by both sides.
use crate::ai_runtime::LocalRuntime;
use crate::listen_sockets::Listener;
use regex::Regex;
use serde::Serialize;
use std::collections::{BTreeSet, HashSet};
use std::sync::OnceLock;

// A listener on a DEFAULT port counts on its own only where the port is distinctive (port_alone).
pub struct RuntimeRule { pub runtime: &'static str, pub names: &'static [&'static str], pub prefixes: &'static [&'static str], pub suffixes: &'static [&'static str], pub ports: &'static [u16], pub port_alone: bool }

pub const LOCAL_AI_RUNTIMES: &[RuntimeRule] = &[
    RuntimeRule { runtime: "ollama", names: &["ollama", "ollama app"], prefixes: &[], suffixes: &[], ports: &[11434], port_alone: true },
    RuntimeRule { runtime: "lmstudio", names: &["lm studio", "lms", "llmster"], prefixes: &[], suffixes: &[], ports: &[1234], port_alone: false },
    RuntimeRule { runtime: "llama.cpp", names: &["llama-server"], prefixes: &[], suffixes: &[], ports: &[8080], port_alone: false },
    RuntimeRule { runtime: "vllm", names: &["vllm"], prefixes: &[], suffixes: &[], ports: &[8000], port_alone: false },
    RuntimeRule { runtime: "llamafile", names: &["llamafile"], prefixes: &[], suffixes: &[".llamafile"], ports: &[8080], port_alone: false },
    RuntimeRule { runtime: "localai", names: &["local-ai"], prefixes: &[], suffixes: &[], ports: &[8080], port_alone: false },
    RuntimeRule { runtime: "jan", names: &["jan"], prefixes: &[], suffixes: &[], ports: &[1337], port_alone: false },
    RuntimeRule { runtime: "gpt4all", names: &["gpt4all"], prefixes: &[], suffixes: &[], ports: &[4891], port_alone: true },
    RuntimeRule { runtime: "koboldcpp", names: &["koboldcpp"], prefixes: &["koboldcpp"], suffixes: &[], ports: &[5001], port_alone: false },
    RuntimeRule { runtime: "foundry-local", names: &["inference.service.agent", "foundry"], prefixes: &[], suffixes: &[], ports: &[], port_alone: false },
    RuntimeRule { runtime: "docker-model-runner", names: &[], prefixes: &[], suffixes: &[], ports: &[12434], port_alone: true },
    RuntimeRule { runtime: "winml-server", names: &["winmlserver"], prefixes: &[], suffixes: &[], ports: &[8080], port_alone: false },
];

fn matches(r: &RuntimeRule, name: &str) -> bool {
    !name.is_empty() && (r.names.contains(&name) || r.prefixes.iter().any(|p| name.starts_with(p)) || r.suffixes.iter().any(|s| name.ends_with(s)))
}

// `bind` keeps the shape the console already validates (loopback | network | unknown); `listening` is
// the same fact with "none" for "running, no listening socket", and None when sockets could not be read.
pub fn running_runtimes(listeners: Option<&[Listener]>, processes: Option<&[String]>) -> Vec<LocalRuntime> {
    let l = listeners.unwrap_or(&[]);
    let p = processes.unwrap_or(&[]);
    let mut out = vec![];
    for r in LOCAL_AI_RUNTIMES {
        let by_name: Vec<&Listener> = l.iter().filter(|x| matches(r, &x.proc_name)).collect();
        let by_port: Vec<&Listener> = if r.port_alone { l.iter().filter(|x| r.ports.contains(&x.port)).collect() } else { vec![] };
        let proc_seen = p.iter().any(|n| matches(r, n)) || !by_name.is_empty();
        if !proc_seen && by_port.is_empty() { continue; }
        let ls: Vec<&Listener> = by_name.iter().chain(by_port.iter()).copied().collect();
        let ports: Vec<u16> = ls.iter().map(|x| x.port).collect::<BTreeSet<_>>().into_iter().collect();
        let bind = if ls.is_empty() { "unknown" } else if ls.iter().any(|x| x.bind == "network") { "network" } else { "loopback" };
        let listening = listeners.map(|_| if ls.is_empty() { "none".to_string() } else { bind.to_string() });
        let mut detected_by = vec![];
        if proc_seen { detected_by.push("process".to_string()); }
        if !by_port.is_empty() { detected_by.push("port".to_string()); }
        out.push(LocalRuntime { runtime: r.runtime.into(), running: true, ports, bind: bind.into(), listening, detected_by });
    }
    out
}

// Install locations. bins: names looked up on PATH and the usual bin dirs (existence only). apps: macOS
// .app bundles under /Applications and ~/Applications. files_all / files_win32: fixed [path, class]
// pairs ("~" = home, "%LOCALAPPDATA%" = that variable). Each hit reports a CLASS, never the path.
pub struct InstallRule { pub runtime: &'static str, pub bins: &'static [&'static str], pub apps: &'static [&'static str], pub files_all: &'static [(&'static str, &'static str)], pub files_win32: &'static [(&'static str, &'static str)], pub plugins: &'static [&'static str], pub dirs: &'static [&'static str], pub only: Option<&'static str> }

pub const LOCAL_AI_INSTALLS: &[InstallRule] = &[
    InstallRule { runtime: "ollama", bins: &["ollama"], apps: &["Ollama.app"], files_all: &[], files_win32: &[("%LOCALAPPDATA%/Programs/Ollama/ollama.exe", "app")], plugins: &[], dirs: &[], only: None },
    InstallRule { runtime: "lmstudio", bins: &["lms"], apps: &["LM Studio.app"], files_all: &[("~/.lmstudio/bin/lms", "path"), ("~/.lmstudio/bin/lms.exe", "path")], files_win32: &[("%LOCALAPPDATA%/Programs/LM Studio/LM Studio.exe", "app")], plugins: &[], dirs: &[], only: None },
    InstallRule { runtime: "llama.cpp", bins: &["llama-server", "llama-cli"], apps: &[], files_all: &[], files_win32: &[], plugins: &[], dirs: &[], only: None },
    InstallRule { runtime: "llamafile", bins: &["llamafile"], apps: &[], files_all: &[], files_win32: &[], plugins: &[], dirs: &[], only: None },
    InstallRule { runtime: "vllm", bins: &["vllm"], apps: &[], files_all: &[], files_win32: &[], plugins: &[], dirs: &[], only: None },
    InstallRule { runtime: "localai", bins: &["local-ai"], apps: &[], files_all: &[], files_win32: &[], plugins: &[], dirs: &[], only: None },
    InstallRule { runtime: "jan", bins: &[], apps: &["Jan.app"], files_all: &[], files_win32: &[], plugins: &[], dirs: &[], only: None },
    InstallRule { runtime: "gpt4all", bins: &[], apps: &["gpt4all/bin/gpt4all.app"], files_all: &[], files_win32: &[("~/gpt4all/bin/chat.exe", "app")], plugins: &[], dirs: &[], only: None },
    InstallRule { runtime: "koboldcpp", bins: &["koboldcpp"], apps: &[], files_all: &[], files_win32: &[], plugins: &[], dirs: &[], only: None },
    InstallRule { runtime: "text-generation-webui", bins: &[], apps: &[], files_all: &[], files_win32: &[], plugins: &[], dirs: &["~/text-generation-webui/server.py"], only: None },
    InstallRule { runtime: "foundry-local", bins: &["foundry"], apps: &[], files_all: &[], files_win32: &[], plugins: &[], dirs: &[], only: None },
    InstallRule { runtime: "docker-model-runner", bins: &[], apps: &[], files_all: &[], files_win32: &[], plugins: &["~/.docker/cli-plugins/docker-model", "/Applications/Docker.app/Contents/Resources/cli-plugins/docker-model", "/usr/libexec/docker/cli-plugins/docker-model", "/usr/local/lib/docker/cli-plugins/docker-model", "C:/Program Files/Docker/Docker/resources/cli-plugins/docker-model.exe", "~/.docker/cli-plugins/docker-model.exe"], dirs: &[], only: None },
    InstallRule { runtime: "winml-server", bins: &["WinMLServer"], apps: &[], files_all: &[], files_win32: &[], plugins: &[], dirs: &[], only: Some("win32") },
];

#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct InstalledRuntime { pub runtime: String, pub via: Vec<String>, pub version: Option<String> }

// CFBundleShortVersionString from an XML Info.plist; a binary plist (or anything else) → None.
pub fn plist_version(txt: &str) -> Option<String> {
    static KEY: OnceLock<Regex> = OnceLock::new();
    static VER: OnceLock<Regex> = OnceLock::new();
    let key = KEY.get_or_init(|| Regex::new(r"<key>CFBundleShortVersionString</key>\s*<string>([^<]*)</string>").unwrap());
    let ver = VER.get_or_init(|| Regex::new(r"^[0-9][0-9A-Za-z.+-]{0,31}$").unwrap());
    let v = key.captures(txt)?.get(1)?.as_str().trim().to_string();
    ver.is_match(&v).then_some(v)
}

fn join(a: &str, b: &str) -> String { format!("{}/{}", a.trim_end_matches(['/', '\\']), b) }

pub struct InstallEnv<'a> {
    pub platform: &'a str,
    pub home: &'a str,
    pub env: &'a dyn Fn(&str) -> Option<String>,
    pub exists: &'a dyn Fn(&str) -> bool,
    pub read_file: &'a dyn Fn(&str) -> Option<String>,
}

pub fn installed_runtimes(e: &InstallEnv) -> Vec<InstalledRuntime> {
    let win = e.platform == "win32";
    let local_app = (e.env)("LOCALAPPDATA").filter(|v| !v.is_empty()).unwrap_or_else(|| join(&join(e.home, "AppData"), "Local"));
    let expand = |p: &str| -> String {
        let p = if p == "~" || p.starts_with("~/") { format!("{}{}", e.home, &p[1..]) } else { p.to_string() };
        p.replace("%LOCALAPPDATA%", &local_app)
    };
    let path_var = (e.env)("PATH").filter(|v| !v.is_empty()).or_else(|| (e.env)("Path")).unwrap_or_default();
    let mut bin_dirs: Vec<String> = path_var.split(if win { ';' } else { ':' }).filter(|d| !d.is_empty()).map(String::from).collect();
    if !win {
        for d in ["/opt/homebrew/bin".to_string(), "/usr/local/bin".into(), "/usr/bin".into(), join(&join(e.home, ".local"), "bin"), join(e.home, "bin")] { bin_dirs.push(d); }
    }
    let mut seen = HashSet::new();
    bin_dirs.retain(|d| seen.insert(d.clone()));
    let app_dirs: Vec<String> = if e.platform == "darwin" { vec!["/Applications".into(), join(e.home, "Applications")] } else { vec![] };
    let mut out = vec![];
    for r in LOCAL_AI_INSTALLS {
        if r.only.is_some_and(|o| o != e.platform) { continue; }
        let mut via: BTreeSet<String> = BTreeSet::new();
        let mut version = None;
        for b in r.bins {
            let file = if win { format!("{b}.exe") } else { b.to_string() };
            if bin_dirs.iter().any(|d| (e.exists)(&join(d, &file))) { via.insert("path".into()); }
        }
        for a in r.apps {
            for d in &app_dirs {
                let app = join(d, a);
                if !(e.exists)(&app) { continue; }
                via.insert("app".into());
                if version.is_none() { version = (e.read_file)(&join(&join(&app, "Contents"), "Info.plist")).and_then(|t| plist_version(&t)); }
            }
        }
        let files = r.files_all.iter().chain(if win { r.files_win32.iter() } else { [].iter() });
        for (f, cls) in files { if (e.exists)(&expand(f)) { via.insert(cls.to_string()); } }
        for f in r.plugins { if (e.exists)(&expand(f)) { via.insert("cli-plugin".into()); } }
        for f in r.dirs { if (e.exists)(&expand(f)) { via.insert("install-dir".into()); } }
        if !via.is_empty() { out.push(InstalledRuntime { runtime: r.runtime.into(), via: via.into_iter().collect(), version }); }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    const FX: &str = include_str!("../../test/fixtures/local-ai/runtimes.json");
    fn fx() -> Value { serde_json::from_str(FX).unwrap() }
    fn listeners(v: &Value) -> Vec<Listener> {
        v.as_array().unwrap().iter().map(|l| Listener {
            pid: l["pid"].as_str().map(String::from),
            proc_name: l["proc"].as_str().unwrap().into(),
            port: l["port"].as_u64().unwrap() as u16,
            bind: if l["bind"] == "network" { "network" } else { "loopback" },
        }).collect()
    }
    fn strs(v: &Value) -> Vec<String> { v.as_array().unwrap().iter().map(|s| s.as_str().unwrap().to_string()).collect() }

    #[test]
    fn running_cases_match_the_shared_fixture() {
        let f = fx();
        for c in f["running"].as_array().unwrap() {
            let l = c["listeners"].as_null().map(|_| None).unwrap_or_else(|| Some(listeners(&c["listeners"])));
            let p = strs(&c["processes"]);
            let got = serde_json::to_value(running_runtimes(l.as_deref(), Some(&p))).unwrap();
            assert_eq!(got, c["expect"], "{}", c["name"]);
        }
    }

    #[test]
    fn content_free_a_llamafile_model_name_never_reaches_the_record() {
        let l = [Listener { pid: Some("1".into()), proc_name: "secret-finance-model-q4.llamafile".into(), port: 8080, bind: "network" }];
        let rec = serde_json::to_string(&running_runtimes(Some(&l), Some(&[]))).unwrap();
        assert!(rec.contains(r#""runtime":"llamafile""#), "{rec}");
        for leak in ["secret", "finance", "q4", "/"] { assert!(!rec.contains(leak), "{leak} in {rec}"); }
    }

    #[test]
    fn installed_cases_match_the_shared_fixture() {
        let f = fx();
        for c in f["installed"].as_array().unwrap() {
            let files: HashSet<String> = strs(&c["exists"]).into_iter().collect();
            let plists = c["plists"].clone();
            let env = c["env"].clone();
            let exists = |p: &str| files.contains(&p.replace('\\', "/"));
            let read = |p: &str| plists.get(p).and_then(|v| v.as_str()).map(String::from);
            let envf = |k: &str| env.get(k).and_then(|v| v.as_str()).map(String::from);
            let ie = InstallEnv { platform: c["platform"].as_str().unwrap(), home: c["home"].as_str().unwrap(), env: &envf, exists: &exists, read_file: &read };
            let got = serde_json::to_value(installed_runtimes(&ie)).unwrap();
            assert_eq!(got, c["expect"], "{}", c["name"]);
            let s = got.to_string();
            for leak in ["/Users", "/Applications", "/opt", "/custom", "C:/"] { assert!(!s.contains(leak), "{leak} leaked: {s}"); }
        }
    }

    #[test]
    fn plist_version_must_look_like_a_version() {
        assert_eq!(plist_version("<key>CFBundleShortVersionString</key><string>1.2.3-beta.1</string>").as_deref(), Some("1.2.3-beta.1"));
        assert_eq!(plist_version("<key>CFBundleShortVersionString</key><string>/Users/x/evil</string>"), None);
        assert_eq!(plist_version("bplist00\u{0}binary"), None);
    }

    #[test]
    fn listening_is_null_when_sockets_unreadable() {
        let got = running_runtimes(None, Some(&["ollama".into()]));
        assert_eq!(serde_json::to_value(&got).unwrap(), json!([{ "runtime": "ollama", "running": true, "ports": [], "bind": "unknown", "listening": null, "detectedBy": ["process"] }]));
    }
}
