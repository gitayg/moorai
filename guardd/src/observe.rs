//! Independent process observation (contract §8.2): which agent hosts are running, and "agent active,
//! hook silent" when a host's process has run for HOOK_SILENT_AFTER_SEC with zero IPC `call`s.
//! The table is shared with the quarantine target rule (crate::quarantine).

use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, HashMap, HashSet};

pub const SCAN_INTERVAL_SEC: u64 = 15;
pub const HOOK_SILENT_AFTER_SEC: u64 = 120;
/// Sessions mapped from `call`s are forgotten after this long without a call.
pub const SESSION_TTL_MS: u64 = 24 * 3600 * 1000;
/// Bound on the session map (a hostile peer can invent session hashes).
pub const MAX_SESSIONS: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcInfo {
    pub pid: u32,
    /// Parent pid as the kernel reports it (a link is only trusted when the parent started first).
    pub ppid: u32,
    pub uid: u32,
    /// Process start time in ms since the epoch (Windows: creation FILETIME converted).
    pub start_ms: u64,
    /// Full executable path from the kernel (proc_pidpath, /proc/<pid>/exe, QueryFullProcessImageNameW).
    pub image: String,
    /// argv[1] for interpreter-hosted agents (KERN_PROCARGS2, /proc/<pid>/cmdline, PEB); None if unreadable.
    pub script: Option<String>,
}

/// OS process enumeration, implemented per OS in crate::platform. Must not follow user-controlled
/// state (no /proc/<pid>/root walks, no env reads beyond what is listed in the contract).
pub trait ProcessSource {
    fn list(&self) -> std::io::Result<Vec<ProcInfo>>;
    fn get(&self, pid: u32) -> std::io::Result<Option<ProcInfo>>;
}

/// One agent-host signature. A process matches when its image basename (case-insensitive on
/// Windows/macOS, without ".exe") is in `images`, OR its image basename is in `interpreters` and its
/// argv[1] ends with one of `scripts` (path separators normalised to '/').
#[derive(Debug, Clone, Copy)]
pub struct AgentHost {
    pub host: &'static str,
    pub images: &'static [&'static str],
    pub interpreters: &'static [&'static str],
    pub scripts: &'static [&'static str],
}

/// Best-effort and name-based (contract §8.2; design §5 residual risk 3). Entries must be confirmed
/// against real installs by the platform agents before release.
pub const AGENT_HOSTS: &[AgentHost] = &[
    AgentHost { host: "claude-code", images: &["claude"], interpreters: &["node", "bun"], scripts: &["@anthropic-ai/claude-code/cli.js"] },
    AgentHost { host: "codex", images: &["codex"], interpreters: &["node"], scripts: &["@openai/codex/bin/codex.js"] },
    AgentHost { host: "gemini", images: &["gemini"], interpreters: &["node"], scripts: &["@google/gemini-cli/dist/index.js"] },
    AgentHost { host: "copilot", images: &["copilot"], interpreters: &["node"], scripts: &["@github/copilot/index.js"] },
    AgentHost { host: "cursor", images: &["cursor", "cursor-agent"], interpreters: &[], scripts: &[] },
];

const CASE_INSENSITIVE: bool = cfg!(any(target_os = "macos", windows));

fn fold(s: &str, ci: bool) -> String {
    if ci {
        s.to_lowercase()
    } else {
        s.to_string()
    }
}

/// Basename of an image path ('/' or '\\' separated), without a trailing ".exe" (any case).
pub fn image_basename(image: &str) -> &str {
    let base = image.rsplit(['/', '\\']).next().unwrap_or(image);
    if base.len() > 4 && base[base.len() - 4..].eq_ignore_ascii_case(".exe") {
        &base[..base.len() - 4]
    } else {
        base
    }
}

/// The §8.2 matching rule, with the OS's case rule.
pub fn match_host(p: &ProcInfo) -> Option<&'static AgentHost> {
    match_host_with(p, CASE_INSENSITIVE)
}

pub fn match_host_with(p: &ProcInfo, case_insensitive: bool) -> Option<&'static AgentHost> {
    let base = fold(image_basename(&p.image), case_insensitive);
    let script = p.script.as_deref().map(|s| fold(&s.replace('\\', "/"), case_insensitive));
    AGENT_HOSTS.iter().find(|h| {
        h.images.iter().any(|i| fold(i, case_insensitive) == base)
            || (h.interpreters.iter().any(|i| fold(i, case_insensitive) == base)
                && script.as_deref().is_some_and(|s| h.scripts.iter().any(|x| s.ends_with(&fold(x, case_insensitive)))))
    })
}

/// A process identified by pid and start time, so a reused pid is never confused with the original.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ProcKey {
    pub pid: u32,
    pub start_ms: u64,
}

impl From<&ProcInfo> for ProcKey {
    fn from(p: &ProcInfo) -> Self {
        ProcKey { pid: p.pid, start_ms: p.start_ms }
    }
}

/// The nearest ancestor-or-self of `pid` that matches AGENT_HOSTS, walking parent links only while the
/// parent started no later than the child (a reused pid cannot be spliced into the chain), at most
/// `max_depth` steps.
pub fn agent_ancestor(src: &dyn ProcessSource, pid: u32, max_depth: usize) -> std::io::Result<Option<(ProcInfo, &'static AgentHost)>> {
    let Some(mut cur) = src.get(pid)? else { return Ok(None) };
    for _ in 0..=max_depth {
        if let Some(h) = match_host(&cur) {
            return Ok(Some((cur, h)));
        }
        if cur.ppid == 0 || cur.ppid == cur.pid {
            return Ok(None);
        }
        let Some(parent) = src.get(cur.ppid)? else { return Ok(None) };
        if parent.start_ms > cur.start_ms {
            return Ok(None);
        }
        cur = parent;
    }
    Ok(None)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionTree {
    pub host: String,
    pub agent: ProcKey,
    pub last_call_ms: u64,
}

/// A newly observed silent agent process: the helper raises one signed local alert per process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SilentEvent {
    pub host: String,
    pub proc: ProcKey,
    pub since_sec: u64,
}

impl SilentEvent {
    pub fn alert(&self, now_ms: u64) -> Map<String, Value> {
        json!({
            "kind": "hookSilent",
            "severity": "high",
            "host": self.host,
            "sinceSec": self.since_sec,
            "ts": crate::clock::iso_ms(now_ms as i64),
        })
        .as_object()
        .cloned()
        .unwrap_or_default()
    }
}

/// Tracks per-host process presence against IPC `call`s and yields the beat's agentProcs/hookSilent.
pub struct Observer {
    started_ms: u64,
    /// Agent processes seen by the last scan, with their host.
    procs: HashMap<ProcKey, &'static str>,
    last_call: HashMap<String, u64>,
    alerted: HashSet<ProcKey>,
    sessions: HashMap<String, SessionTree>,
}

impl Observer {
    /// `started_ms`: when the helper started; a process is only counted silent for the time the
    /// helper has been able to see its calls.
    pub fn new(started_ms: u64) -> Self {
        Observer { started_ms, procs: HashMap::new(), last_call: HashMap::new(), alerted: HashSet::new(), sessions: HashMap::new() }
    }

    /// Record a `call`. `agent` is the helper's own derivation (agent_ancestor of the peer pid), never
    /// the request's `agentPid` hint; it maps the session to its agent tree for console quarantine.
    pub fn on_call(&mut self, host: &str, session_hash: &str, agent: Option<ProcKey>, now_ms: u64) {
        self.last_call.insert(host.to_string(), now_ms);
        if let Some(a) = agent {
            if self.sessions.len() >= MAX_SESSIONS && !self.sessions.contains_key(session_hash) {
                if let Some(oldest) = self.sessions.iter().min_by_key(|(_, t)| t.last_call_ms).map(|(k, _)| k.clone()) {
                    self.sessions.remove(&oldest);
                }
            }
            self.sessions.insert(session_hash.to_string(), SessionTree { host: host.to_string(), agent: a, last_call_ms: now_ms });
        }
    }

    pub fn session(&self, session_hash: &str) -> Option<&SessionTree> {
        self.sessions.get(session_hash)
    }

    /// One scan: refresh the agent-process table and return the processes that have just become
    /// silent (each reported once per process lifetime).
    pub fn scan(&mut self, src: &dyn ProcessSource, now_ms: u64) -> std::io::Result<Vec<SilentEvent>> {
        let list = src.list()?;
        self.procs = list.iter().filter_map(|p| match_host(p).map(|h| (ProcKey::from(p), h.host))).collect();
        self.alerted.retain(|k| self.procs.contains_key(k));
        self.sessions.retain(|_, t| now_ms.saturating_sub(t.last_call_ms) < SESSION_TTL_MS);
        let mut out = Vec::new();
        let mut keys: Vec<&ProcKey> = self.procs.keys().collect();
        keys.sort();
        for k in keys {
            let host = self.procs[k];
            if let Some(since) = self.silent_since(k, host, now_ms) {
                if !self.alerted.contains(k) {
                    out.push(SilentEvent { host: host.to_string(), proc: *k, since_sec: since });
                }
            }
        }
        for e in &out {
            self.alerted.insert(e.proc);
        }
        Ok(out)
    }

    fn silent_since(&self, k: &ProcKey, host: &str, now_ms: u64) -> Option<u64> {
        let from = k.start_ms.max(self.started_ms);
        if self.last_call.get(host).is_some_and(|t| *t >= from) {
            return None;
        }
        let since = now_ms.saturating_sub(from) / 1000;
        (since >= HOOK_SILENT_AFTER_SEC).then_some(since)
    }

    /// The beat's `agentProcs`: agent host processes per host as of the last scan.
    pub fn agent_procs(&self) -> BTreeMap<String, u64> {
        let mut m = BTreeMap::new();
        for h in self.procs.values() {
            *m.entry(h.to_string()).or_insert(0) += 1;
        }
        m
    }

    /// The beat's `hookSilent`, sorted by host: per host, the longest-silent process.
    pub fn hook_silent(&self, now_ms: u64) -> Vec<crate::beat::HookSilent> {
        let mut by_host: BTreeMap<String, u64> = BTreeMap::new();
        for (k, h) in &self.procs {
            if let Some(s) = self.silent_since(k, h, now_ms) {
                let e = by_host.entry(h.to_string()).or_insert(0);
                *e = (*e).max(s);
            }
        }
        by_host.into_iter().map(|(host, since_sec)| crate::beat::HookSilent { host, since_sec }).collect()
    }

    /// Every agent-host process of the last scan (for a device-scope console quarantine).
    pub fn agent_processes(&self) -> Vec<(ProcKey, &'static str)> {
        let mut v: Vec<_> = self.procs.iter().map(|(k, h)| (*k, *h)).collect();
        v.sort();
        v
    }
}

/// A ProcessSource over one snapshot of the table (the observer scans it under the helper lock without
/// calling the OS while locked).
pub struct SnapshotSource(pub Vec<ProcInfo>);

impl ProcessSource for SnapshotSource {
    fn list(&self) -> std::io::Result<Vec<ProcInfo>> {
        Ok(self.0.clone())
    }
    fn get(&self, pid: u32) -> std::io::Result<Option<ProcInfo>> {
        Ok(self.0.iter().find(|p| p.pid == pid).cloned())
    }
}

#[cfg(any(test, feature = "test-injection"))]
pub mod fake {
    use super::*;
    use std::sync::Mutex;

    /// A process table the tests edit.
    #[derive(Default)]
    pub struct FakeProcs {
        pub table: Mutex<Vec<ProcInfo>>,
    }

    impl FakeProcs {
        pub fn new(t: Vec<ProcInfo>) -> Self {
            FakeProcs { table: Mutex::new(t) }
        }
        pub fn set(&self, t: Vec<ProcInfo>) {
            *self.table.lock().unwrap() = t;
        }
    }

    impl ProcessSource for FakeProcs {
        fn list(&self) -> std::io::Result<Vec<ProcInfo>> {
            Ok(self.table.lock().unwrap().clone())
        }
        fn get(&self, pid: u32) -> std::io::Result<Option<ProcInfo>> {
            Ok(self.table.lock().unwrap().iter().find(|p| p.pid == pid).cloned())
        }
    }

    pub fn proc(pid: u32, ppid: u32, uid: u32, start_ms: u64, image: &str, script: Option<&str>) -> ProcInfo {
        ProcInfo { pid, ppid, uid, start_ms, image: image.into(), script: script.map(str::to_string) }
    }
}

#[cfg(test)]
mod tests {
    use super::fake::*;
    use super::*;

    #[test]
    fn hosts_match_by_image_or_interpreter_plus_script() {
        let m = |image: &str, script: Option<&str>| match_host_with(&proc(1, 0, 0, 0, image, script), false).map(|h| h.host);
        assert_eq!(m("/usr/local/bin/claude", None), Some("claude-code"));
        assert_eq!(m("/opt/node/bin/node", Some("/usr/lib/node_modules/@anthropic-ai/claude-code/cli.js")), Some("claude-code"));
        assert_eq!(m("/home/u/.bun/bin/bun", Some("/x/@anthropic-ai/claude-code/cli.js")), Some("claude-code"));
        assert_eq!(m("C:\\nodejs\\node.exe", Some("C:\\npm\\node_modules\\@openai\\codex\\bin\\codex.js")), Some("codex"));
        assert_eq!(m("/usr/bin/cursor-agent", None), Some("cursor"));
        assert_eq!(m("/usr/bin/node", Some("/srv/app.js")), None, "plain node is not an agent");
        assert_eq!(m("/usr/bin/python3", Some("/x/@anthropic-ai/claude-code/cli.js")), None, "script alone is not enough");
        assert_eq!(m("/usr/bin/bun", Some("/x/@openai/codex/bin/codex.js")), None, "codex is node-only in the table");
        assert_eq!(m("/usr/bin/Claude", None), None, "case-sensitive where the OS is");
        assert_eq!(match_host_with(&proc(1, 0, 0, 0, "/Applications/X/Claude", None), true).map(|h| h.host), Some("claude-code"));
        assert_eq!(match_host_with(&proc(1, 0, 0, 0, "C:\\x\\CODEX.EXE", None), true).map(|h| h.host), Some("codex"));
    }

    #[test]
    fn ancestry_requires_parents_to_start_first() {
        let t = FakeProcs::new(vec![
            proc(100, 1, 501, 1_000, "/usr/local/bin/claude", None),
            proc(200, 100, 501, 2_000, "/bin/zsh", None),
            proc(300, 200, 501, 3_000, "/usr/bin/node", Some("/hook.mjs")),
            proc(400, 900, 501, 3_000, "/bin/sh", None),
            proc(900, 1, 501, 9_000, "/usr/local/bin/claude", None),
        ]);
        assert_eq!(agent_ancestor(&t, 300, 32).unwrap().map(|(p, h)| (p.pid, h.host)), Some((100, "claude-code")));
        assert!(agent_ancestor(&t, 400, 32).unwrap().is_none(), "a parent younger than its child is a reused pid");
        assert!(agent_ancestor(&t, 300, 1).unwrap().is_none(), "depth bound");
        assert!(agent_ancestor(&t, 12345, 32).unwrap().is_none());
    }

    #[test]
    fn hook_silent_after_120s_without_calls_and_once_per_process() {
        let t = FakeProcs::new(vec![proc(100, 1, 501, 0, "/usr/local/bin/claude", None), proc(101, 1, 501, 0, "/usr/bin/codex", None)]);
        let mut o = Observer::new(1_000_000);
        assert!(o.scan(&t, 1_000_000 + 119_000).unwrap().is_empty(), "119 s is not yet silent");
        o.on_call("codex", "s1", None, 1_000_000 + 60_000);
        let ev = o.scan(&t, 1_000_000 + 121_000).unwrap();
        assert_eq!(ev, vec![SilentEvent { host: "claude-code".into(), proc: ProcKey { pid: 100, start_ms: 0 }, since_sec: 121 }]);
        assert_eq!(ev[0].alert(0)["kind"], "hookSilent");
        assert!(o.scan(&t, 1_000_000 + 300_000).unwrap().is_empty(), "alerted once per process");
        assert_eq!(o.hook_silent(1_000_000 + 300_000), vec![crate::beat::HookSilent { host: "claude-code".into(), since_sec: 300 }]);
        assert_eq!(o.agent_procs().into_iter().collect::<Vec<_>>(), vec![("claude-code".to_string(), 1), ("codex".to_string(), 1)]);
        o.on_call("claude-code", "s2", None, 1_000_000 + 301_000);
        assert!(o.hook_silent(1_000_000 + 302_000).is_empty(), "a call clears it");
    }

    #[test]
    fn a_restarted_process_is_a_new_process() {
        let t = FakeProcs::new(vec![proc(100, 1, 501, 0, "/usr/local/bin/claude", None)]);
        let mut o = Observer::new(0);
        assert_eq!(o.scan(&t, 200_000).unwrap().len(), 1);
        t.set(vec![proc(100, 1, 501, 150_000, "/usr/local/bin/claude", None)]);
        assert!(o.scan(&t, 200_000).unwrap().is_empty(), "the new process has run only 50 s");
        assert_eq!(o.scan(&t, 271_000).unwrap().len(), 1, "and is reported on its own");
    }

    #[test]
    fn sessions_map_to_the_derived_agent_and_are_bounded() {
        let mut o = Observer::new(0);
        let a = ProcKey { pid: 100, start_ms: 5 };
        o.on_call("claude-code", "s1", Some(a), 10);
        assert_eq!(o.session("s1").map(|t| t.agent), Some(a));
        for i in 0..MAX_SESSIONS + 10 {
            o.on_call("claude-code", &format!("x{i}"), Some(a), 100 + i as u64);
        }
        assert!(o.sessions.len() <= MAX_SESSIONS);
        assert!(o.session("s1").is_none(), "the oldest is evicted first");
    }
}
