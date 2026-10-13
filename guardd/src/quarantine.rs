//! Quarantine (contract §8): the decision, the target rule and the persisted state are core; the
//! per-OS mechanics (suspend, resume, network block) implement `QuarantineBackend` in
//! crate::platform::<os> and are owned by the platform agents.
//!
//! Order (§8.4): verify the target, persist the Active entry, suspend, reply `network: "pending"`, block
//! the network, persist its result, queue the signed alert. Release (§8.5): persist Released first, then
//! unblock, then resume. Restart: Active entries are re-applied, Released ones never re-suspended.

use crate::alerts::AlertQueue;
use crate::ipc::{NetBlockState, QuarantineReq, QuarantineResp};
use crate::observe::{agent_ancestor, ProcInfo, ProcessSource};
use crate::state::{load_json, save_json};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};

/// Ancestor walk depth limit (§8.3).
pub const MAX_ANCESTOR_DEPTH: usize = 32;
/// Descendant enumeration passes, so children forked during the walk are caught (§8.3).
pub const MAX_TREE_PASSES: usize = 3;
/// After the ack, the requesting hook process has this long to exit before it is suspended too.
pub const PEER_GRACE_MS: u64 = 2000;
/// Per peer uid: more quarantine requests than this per minute are refused with `busy` (§3.6).
pub const MAX_REQUESTS_PER_MIN: u32 = 10;
/// Latency targets (contract §8.4).
pub const HOOK_TRIGGERED_BUDGET_MS: u64 = 50;
pub const CONSOLE_TRIGGERED_BUDGET_MS: u64 = 2000;

/// The caller as the kernel reports it, never as the message claims.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Peer {
    pub pid: u32,
    pub uid: u32,
    /// Windows: caller token is SYSTEM or an elevated Administrators member. Unix: uid == 0.
    pub admin: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub agent: ProcInfo,
    pub host: &'static str,
    /// The tree to suspend, top-down (agent first), excluding the requesting peer.
    pub tree: Vec<ProcInfo>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// No agent-host ancestor of the peer, the named pid is outside that agent's tree, it does not
    /// exist, or the request's host disagrees with the derived one.
    NotAgentAncestor,
    /// Target uid differs from the peer's.
    UidMismatch,
    /// pid <= 1, the helper itself, or a uid 0 process for a non-root peer.
    Protected,
    RateLimited,
}

impl Refusal {
    pub fn as_str(&self) -> &'static str {
        match self {
            Refusal::NotAgentAncestor => "not_agent_ancestor",
            Refusal::UidMismatch => "uid_mismatch",
            Refusal::Protected => "protected",
            Refusal::RateLimited => "rate_limited",
        }
    }
}

/// Every descendant of `root` (top-down, root first), following only links where the parent started
/// no later than the child; repeated up to MAX_TREE_PASSES times until no new process appears.
pub fn descendants(src: &dyn ProcessSource, root: &ProcInfo, exclude_pid: Option<u32>) -> std::io::Result<Vec<ProcInfo>> {
    let mut tree = vec![root.clone()];
    let mut seen: HashSet<u32> = HashSet::from([root.pid]);
    for _ in 0..MAX_TREE_PASSES {
        let list = src.list()?;
        let mut by_parent: HashMap<u32, Vec<&ProcInfo>> = HashMap::new();
        for p in &list {
            by_parent.entry(p.ppid).or_default().push(p);
        }
        let before = tree.len();
        let mut queue: VecDeque<ProcInfo> = tree.iter().cloned().collect();
        while let Some(parent) = queue.pop_front() {
            for c in by_parent.get(&parent.pid).into_iter().flatten() {
                if c.pid == parent.pid || c.start_ms < parent.start_ms || seen.contains(&c.pid) {
                    continue;
                }
                seen.insert(c.pid);
                tree.push((*c).clone());
                queue.push_back((*c).clone());
            }
        }
        if tree.len() == before {
            break;
        }
    }
    if let Some(x) = exclude_pid {
        tree.retain(|p| p.pid != x || p.pid == root.pid);
    }
    Ok(tree)
}

/// The rule of contract §8.3 plus decision §13.1 (peer ancestry). Pure over `src`.
pub fn resolve_target(peer: Peer, req: &QuarantineReq, src: &dyn ProcessSource, self_pid: u32) -> Result<Target, Refusal> {
    let io = |_e: std::io::Error| Refusal::NotAgentAncestor;
    let (agent, host) = agent_ancestor(src, peer.pid, MAX_ANCESTOR_DEPTH).map_err(io)?.ok_or(Refusal::NotAgentAncestor)?;
    let named = src.get(req.agent_pid).map_err(io)?.ok_or(Refusal::NotAgentAncestor)?;
    let mut cur = named;
    let mut inside = false;
    for _ in 0..=MAX_ANCESTOR_DEPTH {
        if cur.pid == agent.pid && cur.start_ms == agent.start_ms {
            inside = true;
            break;
        }
        if cur.ppid == 0 || cur.ppid == cur.pid {
            break;
        }
        let Some(parent) = src.get(cur.ppid).map_err(io)? else { break };
        if parent.start_ms > cur.start_ms {
            break;
        }
        cur = parent;
    }
    if !inside || req.host != host.host {
        return Err(Refusal::NotAgentAncestor);
    }
    if agent.pid <= 1 || agent.pid == self_pid || (agent.uid == 0 && peer.uid != 0) {
        return Err(Refusal::Protected);
    }
    if agent.uid != peer.uid {
        return Err(Refusal::UidMismatch);
    }
    let tree = descendants(src, &agent, Some(peer.pid)).map_err(io)?;
    if tree.iter().any(|p| p.pid <= 1 || p.pid == self_pid) {
        return Err(Refusal::Protected);
    }
    Ok(Target { agent, host: host.host, tree })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Origin {
    Hook,
    Console,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Active,
    Released,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PidRef {
    pub pid: u32,
    pub start_ms: u64,
}

impl From<&ProcInfo> for PidRef {
    fn from(p: &ProcInfo) -> Self {
        PidRef { pid: p.pid, start_ms: p.start_ms }
    }
}

/// One entry of state/quarantine.json (contract §8.4–§8.5).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Entry {
    /// "q-" + 16 lowercase hex, from a persisted counter.
    pub id: String,
    pub origin: Origin,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub cmd_id: Option<String>,
    pub host: String,
    pub session_hash: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub threat_id: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub rule_id: Option<String>,
    pub reason_code: String,
    pub agent: PidRef,
    pub pids: Vec<PidRef>,
    pub status: Status,
    pub network: NetBlockState,
    /// "unavailable" when the OS facility is absent or not approved (decision §13.1: macOS content
    /// filter not installed); the processes stay suspended either way.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub network_block: Option<String>,
    /// The step that failed: "suspend" | "network" | "unblock" | "resume".
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub failed_step: Option<String>,
    pub started_at_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub suspended_at_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub released_at_ms: Option<u64>,
    /// "console:<cmdId>" | "local-admin:<uid>"
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub released_by: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct QuarantineFile {
    pub next_id: u64,
    pub entries: Vec<Entry>,
    /// The last console cmdSeq applied (§8.5): lower ones are ignored, across restarts.
    #[serde(default)]
    pub last_cmd_seq: u64,
}

#[derive(Debug)]
pub enum BackendError {
    Unsupported,
    Os(String),
}

/// Per-OS mechanics. Implementations: platform::macos (SIGSTOP tree + Network Extension content
/// filter), platform::linux (cgroup v2 freeze when the cgroup holds only the tree, else SIGSTOP;
/// nftables `socket cgroupv2` match), platform::windows (NtSuspendProcess per process or job object;
/// WFP filter by app id). Each call is idempotent.
pub trait QuarantineBackend {
    /// Stop every process in `tree`, top-down; return once each is confirmed stopped.
    fn suspend(&self, tree: &[ProcInfo]) -> Result<(), BackendError>;
    /// Continue every still-living process whose start time matches.
    fn resume(&self, pids: &[PidRef]) -> Result<(), BackendError>;
    /// Block all network traffic of `entry`'s processes (and their containment profile -> deny-all).
    /// `Ok(Unsupported)` or `Err(Unsupported)` = the facility is unavailable on this device.
    fn net_block(&self, entry: &Entry) -> Result<NetBlockState, BackendError>;
    fn net_unblock(&self, entry: &Entry) -> Result<(), BackendError>;
}

/// The name the brief uses for the platform interface.
pub use self::QuarantineBackend as Quarantiner;

#[derive(Debug)]
pub enum QuarantineError {
    Refused(Refusal),
    /// Suspension failed; the entry stays Active so a restart re-applies it.
    Failed(String),
    Io(std::io::Error),
}

impl QuarantineError {
    pub fn code(&self) -> crate::ipc::ErrorCode {
        use crate::ipc::ErrorCode;
        match self {
            QuarantineError::Refused(Refusal::RateLimited) => ErrorCode::Busy,
            QuarantineError::Refused(_) => ErrorCode::TargetNotAgentAncestor,
            QuarantineError::Failed(_) => ErrorCode::QuarantineFailed,
            QuarantineError::Io(_) => ErrorCode::Internal,
        }
    }
}

#[derive(Debug)]
pub enum ReleaseError {
    UnknownQuarantine,
    Io(std::io::Error),
}

/// What happens after the reply to the hook: the network block and the alert, then the peer's grace.
#[derive(Debug, Clone, PartialEq)]
pub struct FollowUp {
    pub quarantine_id: String,
    pub peer: Option<PidRef>,
}

/// The persisted quarantine state plus the per-uid rate limiter.
pub struct Quarantines {
    path: PathBuf,
    pub file: QuarantineFile,
    rate: HashMap<u32, VecDeque<u64>>,
}

impl Quarantines {
    pub fn open(path: &Path) -> std::io::Result<Quarantines> {
        Ok(Quarantines { path: path.to_path_buf(), file: load_json(path)?.unwrap_or_default(), rate: HashMap::new() })
    }

    pub fn save(&self) -> std::io::Result<()> {
        save_json(&self.path, &self.file)
    }

    pub fn active_count(&self) -> u32 {
        self.file.entries.iter().filter(|e| e.status == Status::Active).count() as u32
    }

    pub fn get(&self, id: &str) -> Option<&Entry> {
        self.file.entries.iter().find(|e| e.id == id)
    }

    fn get_mut(&mut self, id: &str) -> Option<&mut Entry> {
        self.file.entries.iter_mut().find(|e| e.id == id)
    }

    fn next_id(&mut self) -> String {
        self.file.next_id += 1;
        format!("q-{:016x}", self.file.next_id)
    }

    /// 10 per minute per peer uid; true when this request is allowed.
    pub fn rate_ok(&mut self, uid: u32, now_ms: u64) -> bool {
        let q = self.rate.entry(uid).or_default();
        while q.front().is_some_and(|t| now_ms.saturating_sub(*t) >= 60_000) {
            q.pop_front();
        }
        if q.len() as u32 >= MAX_REQUESTS_PER_MIN {
            return false;
        }
        q.push_back(now_ms);
        true
    }
}

fn obj(v: Value) -> Map<String, Value> {
    v.as_object().cloned().unwrap_or_default()
}

/// The signed quarantine alert (§8.4 step 6), content-free; shape of golden.json alertBatch alert 2.
pub fn quarantine_alert(e: &Entry, now_ms: u64) -> Map<String, Value> {
    let mut a = obj(json!({
        "kind": "quarantine",
        "quarantineId": e.id,
        "origin": e.origin,
        "host": e.host,
        "reasonCode": e.reason_code,
        "sessionHash": e.session_hash,
        "suspendedPids": e.pids.len() as u64,
        "network": e.network,
        "ts": crate::clock::iso_ms(now_ms as i64),
    }));
    if let Some(t) = e.threat_id {
        a.insert("threatId".into(), json!(t));
    }
    if let Some(r) = &e.rule_id {
        a.insert("ruleId".into(), json!(r));
    }
    if let Some(c) = &e.cmd_id {
        a.insert("cmdId".into(), json!(c));
    }
    if let Some(n) = &e.network_block {
        a.insert("networkBlock".into(), json!(n));
    }
    if let Some(f) = &e.failed_step {
        a.insert("failedStep".into(), json!(f));
    }
    a
}

/// The signed Medium "Quarantine target refused" alert (§8.3).
pub fn refusal_alert(peer: Peer, req: &QuarantineReq, why: &Refusal, now_ms: u64) -> Map<String, Value> {
    obj(json!({
        "kind": "quarantineRefused",
        "severity": "medium",
        "host": req.host,
        "reasonCode": req.reason_code,
        "sessionHash": req.session_hash,
        "refusal": why.as_str(),
        "peerUid": peer.uid,
        "ts": crate::clock::iso_ms(now_ms as i64),
    }))
}

fn valid_request(req: &QuarantineReq) -> bool {
    req.threat_id.is_some() != req.rule_id.is_some() && !req.reason_code.is_empty() && req.reason_code.len() <= 64 && !req.host.is_empty()
}

/// Hook-triggered quarantine up to the reply (§8.4 steps 1–4). The caller replies, then runs
/// `finish` with the returned FollowUp (steps 5–6) and, after PEER_GRACE_MS, `suspend_peer`.
#[allow(clippy::too_many_arguments)]
pub fn quarantine_from_hook(
    q: &mut Quarantines,
    alerts: &mut AlertQueue,
    backend: &dyn QuarantineBackend,
    src: &dyn ProcessSource,
    peer: Peer,
    req: &QuarantineReq,
    self_pid: u32,
    now: &dyn Fn() -> u64,
) -> Result<(QuarantineResp, FollowUp), QuarantineError> {
    if !q.rate_ok(peer.uid, now()) {
        return Err(QuarantineError::Refused(Refusal::RateLimited));
    }
    let target = match resolve_target(peer, req, src, self_pid) {
        Ok(t) => t,
        Err(r) => {
            alerts.enqueue(vec![refusal_alert(peer, req, &r, now())], Some(peer.uid)).map_err(QuarantineError::Io)?;
            return Err(QuarantineError::Refused(r));
        }
    };
    let peer_ref = src.get(peer.pid).ok().flatten().map(|p| PidRef::from(&p));
    let id = q.next_id();
    let entry = Entry {
        id: id.clone(),
        origin: Origin::Hook,
        cmd_id: None,
        host: target.host.to_string(),
        session_hash: req.session_hash.clone(),
        threat_id: req.threat_id,
        rule_id: req.rule_id.clone(),
        reason_code: req.reason_code.clone(),
        agent: PidRef::from(&target.agent),
        pids: target.tree.iter().map(PidRef::from).collect(),
        status: Status::Active,
        network: NetBlockState::Pending,
        network_block: None,
        failed_step: None,
        started_at_ms: now(),
        suspended_at_ms: None,
        released_at_ms: None,
        released_by: None,
    };
    let n = entry.pids.len() as u32;
    q.file.entries.push(entry);
    q.save().map_err(QuarantineError::Io)?;
    if let Err(e) = backend.suspend(&target.tree) {
        let msg = match e {
            BackendError::Unsupported => "suspend unsupported".to_string(),
            BackendError::Os(m) => m,
        };
        let e = q.get_mut(&id).expect("just pushed");
        e.failed_step = Some("suspend".into());
        let alert = quarantine_alert(e, now());
        q.save().map_err(QuarantineError::Io)?;
        alerts.enqueue(vec![alert], None).map_err(QuarantineError::Io)?;
        return Err(QuarantineError::Failed(msg));
    }
    // Recorded in memory now and persisted by `finish` (step 6): the reply is not held for a second
    // fsync. The Active entry itself was persisted before acting.
    let at = now();
    q.get_mut(&id).expect("just pushed").suspended_at_ms = Some(at);
    Ok((QuarantineResp { quarantine_id: id.clone(), suspended_pids: n, suspended_at_ms: at, network: NetBlockState::Pending }, FollowUp { quarantine_id: id, peer: peer_ref }))
}

/// Request validation the IPC layer applies before `quarantine_from_hook` (`bad_request` otherwise).
pub fn request_ok(req: &QuarantineReq) -> bool {
    valid_request(req)
}

/// §8.4 steps 5–6: block the network, persist the result, queue the signed alert.
pub fn finish(q: &mut Quarantines, alerts: &mut AlertQueue, backend: &dyn QuarantineBackend, id: &str, now_ms: u64) -> std::io::Result<NetBlockState> {
    let Some(entry) = q.get(id).cloned() else { return Ok(NetBlockState::Failed) };
    let (state, block, failed) = match backend.net_block(&entry) {
        Ok(NetBlockState::Unsupported) | Err(BackendError::Unsupported) => (NetBlockState::Unsupported, Some("unavailable"), None),
        Ok(s) => (s, None, None),
        Err(BackendError::Os(_)) => (NetBlockState::Failed, None, Some("network")),
    };
    let e = q.get_mut(id).expect("present");
    e.network = state;
    e.network_block = block.map(str::to_string);
    if failed.is_some() {
        e.failed_step = failed.map(str::to_string);
    }
    let alert = quarantine_alert(e, now_ms);
    q.save()?;
    alerts.enqueue(vec![alert], None)?;
    Ok(state)
}

/// After the grace period: suspend the requesting hook process too if it is still alive (the same
/// process, by start time), and record it in the entry. Returns whether it was suspended.
pub fn suspend_peer(q: &mut Quarantines, backend: &dyn QuarantineBackend, src: &dyn ProcessSource, id: &str, peer: &PidRef) -> std::io::Result<bool> {
    if q.get(id).map(|e| e.status) != Some(Status::Active) {
        return Ok(false);
    }
    if peer.pid <= 1 || peer.pid == std::process::id() {
        return Ok(false);
    }
    let Some(p) = src.get(peer.pid)?.filter(|p| p.start_ms == peer.start_ms) else { return Ok(false) };
    if let Some(e) = q.get_mut(id) {
        if !e.pids.contains(peer) {
            e.pids.push(peer.clone());
        }
    }
    q.save()?;
    Ok(backend.suspend(std::slice::from_ref(&p)).is_ok())
}

/// A verified console command's quarantine (§8.3: scope session = the mapped tree; scope device = every
/// agent tree). `agents` are the resolved agent processes; empty = nothing to do (ack "ignored").
#[allow(clippy::too_many_arguments)]
pub fn quarantine_from_console(
    q: &mut Quarantines,
    alerts: &mut AlertQueue,
    backend: &dyn QuarantineBackend,
    src: &dyn ProcessSource,
    agents: &[(ProcInfo, &'static str)],
    cmd_id: &str,
    session_hash: &str,
    reason: &str,
    self_pid: u32,
    now: &dyn Fn() -> u64,
) -> std::io::Result<Option<Entry>> {
    let mut tree: Vec<ProcInfo> = Vec::new();
    for (a, _) in agents {
        if a.pid <= 1 || a.pid == self_pid || a.uid == 0 {
            continue;
        }
        for p in descendants(src, a, None)? {
            if p.pid > 1 && p.pid != self_pid && !tree.iter().any(|x| x.pid == p.pid) {
                tree.push(p);
            }
        }
    }
    let Some((first, host)) = agents.iter().find(|(a, _)| tree.iter().any(|p| p.pid == a.pid)) else { return Ok(None) };
    let id = q.next_id();
    q.file.entries.push(Entry {
        id: id.clone(),
        origin: Origin::Console,
        cmd_id: Some(cmd_id.to_string()),
        host: host.to_string(),
        session_hash: session_hash.to_string(),
        threat_id: None,
        rule_id: None,
        reason_code: reason.to_string(),
        agent: PidRef::from(first),
        pids: tree.iter().map(PidRef::from).collect(),
        status: Status::Active,
        network: NetBlockState::Pending,
        network_block: None,
        failed_step: None,
        started_at_ms: now(),
        suspended_at_ms: None,
        released_at_ms: None,
        released_by: None,
    });
    q.save()?;
    match backend.suspend(&tree) {
        Ok(()) => q.get_mut(&id).expect("pushed").suspended_at_ms = Some(now()),
        Err(_) => q.get_mut(&id).expect("pushed").failed_step = Some("suspend".into()),
    }
    q.save()?;
    if q.get(&id).is_some_and(|e| e.failed_step.is_none()) {
        finish(q, alerts, backend, &id, now())?;
    } else {
        let alert = quarantine_alert(q.get(&id).expect("pushed"), now());
        alerts.enqueue(vec![alert], None)?;
    }
    Ok(q.get(&id).cloned())
}

/// Release (admin IPC or verified console command): persist Released first, then unblock, then
/// resume. `"*"` releases every active entry. Returns how many were released.
pub fn release(q: &mut Quarantines, backend: &dyn QuarantineBackend, quarantine_id: &str, released_by: &str, now_ms: u64) -> Result<u32, ReleaseError> {
    let ids: Vec<String> = q
        .file
        .entries
        .iter()
        .filter(|e| e.status == Status::Active && (quarantine_id == "*" || e.id == quarantine_id))
        .map(|e| e.id.clone())
        .collect();
    if ids.is_empty() && quarantine_id != "*" && q.get(quarantine_id).is_none() {
        return Err(ReleaseError::UnknownQuarantine);
    }
    for id in &ids {
        let e = q.get_mut(id).expect("listed");
        e.status = Status::Released;
        e.released_at_ms = Some(now_ms);
        e.released_by = Some(released_by.to_string());
    }
    q.save().map_err(ReleaseError::Io)?;
    for id in &ids {
        undo(q, backend, id);
    }
    q.save().map_err(ReleaseError::Io)?;
    Ok(ids.len() as u32)
}

fn undo(q: &mut Quarantines, backend: &dyn QuarantineBackend, id: &str) {
    let entry = q.get(id).cloned().expect("present");
    let unblocked = backend.net_unblock(&entry).is_ok();
    let resumed = backend.resume(&entry.pids).is_ok();
    let e = q.get_mut(id).expect("present");
    if unblocked {
        e.network = NetBlockState::Removed;
    }
    e.failed_step = match (unblocked, resumed) {
        (true, true) => None,
        (false, _) => Some("unblock".into()),
        (true, false) => Some("resume".into()),
    };
}

/// At helper start: re-apply Active entries (re-suspend pids whose start time still matches,
/// re-apply the block); Released entries are never re-suspended, and a release whose unblock or
/// resume failed is retried.
pub fn reconcile_on_start(q: &mut Quarantines, backend: &dyn QuarantineBackend, src: &dyn ProcessSource) -> std::io::Result<()> {
    let ids: Vec<(String, Status)> = q.file.entries.iter().map(|e| (e.id.clone(), e.status)).collect();
    for (id, status) in ids {
        match status {
            Status::Active => {
                let entry = q.get(&id).cloned().expect("present");
                let mut alive = Vec::new();
                for r in &entry.pids {
                    if let Some(p) = src.get(r.pid)?.filter(|p| p.start_ms == r.start_ms) {
                        alive.push(p);
                    }
                }
                let suspended = alive.is_empty() || backend.suspend(&alive).is_ok();
                let state = match backend.net_block(&entry) {
                    Ok(NetBlockState::Unsupported) | Err(BackendError::Unsupported) => NetBlockState::Unsupported,
                    Ok(s) => s,
                    Err(BackendError::Os(_)) => NetBlockState::Failed,
                };
                let e = q.get_mut(&id).expect("present");
                e.network = state;
                e.network_block = (state == NetBlockState::Unsupported).then(|| "unavailable".to_string());
                e.failed_step = if !suspended {
                    Some("suspend".into())
                } else if state == NetBlockState::Failed {
                    Some("network".into())
                } else {
                    None
                };
            }
            Status::Released => {
                if q.get(&id).is_some_and(|e| e.failed_step.is_some()) {
                    undo(q, backend, &id);
                }
            }
        }
    }
    q.save()
}

#[cfg(any(test, feature = "test-injection"))]
pub mod recording {
    //! A QuarantineBackend that records every call, and what quarantine.json held at that moment, so
    //! tests can check "persist before act".
    use super::*;
    use std::sync::Mutex;

    #[derive(Debug, Clone, PartialEq)]
    pub enum Call {
        Suspend { pids: Vec<u32>, persisted_active: bool },
        Resume { pids: Vec<u32>, persisted_released: bool },
        NetBlock { id: String, persisted_active: bool },
        NetUnblock { id: String, persisted_released: bool },
    }

    pub struct Recording {
        pub calls: Mutex<Vec<Call>>,
        pub state_file: PathBuf,
        pub fail_suspend: Mutex<bool>,
        pub net: Mutex<Result<NetBlockState, String>>,
    }

    impl Recording {
        pub fn new(state_file: &Path) -> Self {
            Recording { calls: Mutex::new(vec![]), state_file: state_file.to_path_buf(), fail_suspend: Mutex::new(false), net: Mutex::new(Ok(NetBlockState::Applied)) }
        }
        pub fn calls(&self) -> Vec<Call> {
            self.calls.lock().unwrap().clone()
        }
        fn file(&self) -> QuarantineFile {
            load_json(&self.state_file).ok().flatten().unwrap_or_default()
        }
        fn persisted(&self, pids: &[u32], status: Status) -> bool {
            self.file().entries.iter().any(|e| e.status == status && pids.iter().all(|p| e.pids.iter().any(|r| r.pid == *p)))
        }
    }

    impl QuarantineBackend for Recording {
        fn suspend(&self, tree: &[ProcInfo]) -> Result<(), BackendError> {
            let pids: Vec<u32> = tree.iter().map(|p| p.pid).collect();
            let persisted_active = self.persisted(&pids, Status::Active);
            self.calls.lock().unwrap().push(Call::Suspend { pids, persisted_active });
            if *self.fail_suspend.lock().unwrap() {
                return Err(BackendError::Os("EPERM".into()));
            }
            Ok(())
        }
        fn resume(&self, refs: &[PidRef]) -> Result<(), BackendError> {
            let pids: Vec<u32> = refs.iter().map(|p| p.pid).collect();
            let persisted_released = self.persisted(&pids, Status::Released);
            self.calls.lock().unwrap().push(Call::Resume { pids, persisted_released });
            Ok(())
        }
        fn net_block(&self, entry: &Entry) -> Result<NetBlockState, BackendError> {
            let persisted_active = self.file().entries.iter().any(|e| e.id == entry.id && e.status == Status::Active);
            self.calls.lock().unwrap().push(Call::NetBlock { id: entry.id.clone(), persisted_active });
            match &*self.net.lock().unwrap() {
                Ok(s) => Ok(*s),
                Err(m) if m == "unsupported" => Err(BackendError::Unsupported),
                Err(m) => Err(BackendError::Os(m.clone())),
            }
        }
        fn net_unblock(&self, entry: &Entry) -> Result<(), BackendError> {
            let persisted_released = self.file().entries.iter().any(|e| e.id == entry.id && e.status == Status::Released);
            self.calls.lock().unwrap().push(Call::NetUnblock { id: entry.id.clone(), persisted_released });
            Ok(())
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::recording::*;
    use super::*;
    use crate::observe::fake::{proc, FakeProcs};

    const SELF: u32 = 77;

    fn table() -> FakeProcs {
        FakeProcs::new(vec![
            proc(1, 0, 0, 0, "/sbin/launchd", None),
            proc(100, 1, 501, 1_000, "/usr/local/bin/claude", None),
            proc(110, 100, 501, 1_100, "/bin/zsh", None),
            proc(120, 110, 501, 1_200, "/usr/bin/node", Some("/opt/moorai/cli/moorai-hook.mjs")),
            proc(130, 110, 501, 1_300, "/usr/bin/python3", Some("tool.py")),
            proc(200, 1, 501, 2_000, "/usr/local/bin/claude", None),
            proc(210, 200, 501, 2_100, "/usr/bin/node", Some("/opt/moorai/cli/moorai-hook.mjs")),
            proc(300, 1, 502, 3_000, "/usr/local/bin/claude", None),
            proc(400, 1, 501, 4_000, "/usr/bin/vim", None),
            proc(410, 400, 501, 4_100, "/usr/bin/node", Some("/x.mjs")),
            proc(500, 1, 0, 5_000, "/usr/local/bin/claude", None),
            proc(510, 500, 501, 5_100, "/usr/bin/node", Some("/opt/moorai/cli/moorai-hook.mjs")),
        ])
    }

    fn req(agent_pid: u32) -> QuarantineReq {
        QuarantineReq {
            agent_pid,
            pgid: None,
            sid: None,
            win_session_id: None,
            host: "claude-code".into(),
            threat_id: Some(21),
            rule_id: None,
            reason_code: "policy-quarantine".into(),
            session_hash: "a1b2c3d4e5f60718".into(),
            decided_at_ms: 0,
        }
    }

    fn hook_peer() -> Peer {
        Peer { pid: 120, uid: 501, admin: false }
    }

    #[test]
    fn the_target_is_the_peers_agent_tree_without_the_peer() {
        let t = resolve_target(hook_peer(), &req(100), &table(), SELF).unwrap();
        assert_eq!(t.host, "claude-code");
        assert_eq!(t.tree.iter().map(|p| p.pid).collect::<Vec<_>>(), vec![100, 110, 130], "top-down, peer 120 excluded");
        assert_eq!(resolve_target(hook_peer(), &req(130), &table(), SELF).unwrap().agent.pid, 100, "a descendant names the same tree");
    }

    #[test]
    fn target_rule_refusals() {
        let t = table();
        assert_eq!(resolve_target(hook_peer(), &req(200), &t, SELF), Err(Refusal::NotAgentAncestor), "another session's agent (peer ancestry)");
        assert_eq!(resolve_target(hook_peer(), &req(400), &t, SELF), Err(Refusal::NotAgentAncestor), "a non-agent process");
        assert_eq!(resolve_target(hook_peer(), &req(9999), &t, SELF), Err(Refusal::NotAgentAncestor), "no such pid");
        assert_eq!(resolve_target(Peer { pid: 410, uid: 501, admin: false }, &req(400), &t, SELF), Err(Refusal::NotAgentAncestor), "a peer with no agent ancestor");
        let mut wrong_host = req(100);
        wrong_host.host = "codex".into();
        assert_eq!(resolve_target(hook_peer(), &wrong_host, &t, SELF), Err(Refusal::NotAgentAncestor), "host disagrees");
        assert_eq!(resolve_target(Peer { pid: 120, uid: 502, admin: false }, &req(100), &t, SELF), Err(Refusal::UidMismatch), "another user's agent");
        assert_eq!(resolve_target(Peer { pid: 510, uid: 501, admin: false }, &req(500), &t, SELF), Err(Refusal::Protected), "a root agent for a user peer");
        assert_eq!(resolve_target(hook_peer(), &req(100), &t, 100), Err(Refusal::Protected), "the helper itself");
    }

    #[test]
    fn a_reused_pid_cannot_be_spliced_into_the_chain() {
        let t = table();
        // 130's parent 110 is replaced by a process that started after 130.
        let mut v = t.list().unwrap();
        v.retain(|p| p.pid != 110);
        v.push(proc(110, 100, 501, 9_999, "/bin/zsh", None));
        t.set(v);
        assert_eq!(resolve_target(hook_peer(), &req(100), &t, SELF), Err(Refusal::NotAgentAncestor));
    }

    fn setup(tag: &str) -> (PathBuf, Quarantines, AlertQueue) {
        let d = crate::state::test_root(&format!("q-{tag}"));
        std::fs::create_dir_all(d.join("alerts")).unwrap();
        let q = Quarantines::open(&d.join("quarantine.json")).unwrap();
        let a = AlertQueue::open(&d.join("alerts"), &d.join("chain.json"), "acme").unwrap();
        (d, q, a)
    }

    #[test]
    fn hook_quarantine_persists_before_it_acts_and_alerts_after_the_block() {
        let (d, mut q, mut a) = setup("order");
        let rec = Recording::new(&d.join("quarantine.json"));
        let src = table();
        let (resp, fu) = quarantine_from_hook(&mut q, &mut a, &rec, &src, hook_peer(), &req(100), SELF, &|| 1_000).unwrap();
        assert_eq!((resp.suspended_pids, resp.network, resp.quarantine_id.as_str()), (3, NetBlockState::Pending, "q-0000000000000001"));
        assert_eq!(rec.calls(), vec![Call::Suspend { pids: vec![100, 110, 130], persisted_active: true }]);
        assert!(a.is_empty(), "the alert waits for the network step");
        assert_eq!(finish(&mut q, &mut a, &rec, &fu.quarantine_id, 2_000).unwrap(), NetBlockState::Applied);
        assert_eq!(rec.calls()[1], Call::NetBlock { id: resp.quarantine_id.clone(), persisted_active: true });
        let reloaded = Quarantines::open(&d.join("quarantine.json")).unwrap();
        assert_eq!(reloaded.get(&resp.quarantine_id).unwrap().network, NetBlockState::Applied, "block result persisted");
        let b = a.next_batch("acme", "dev").unwrap().unwrap();
        assert_eq!(b.alerts[0]["kind"], "quarantine");
        assert_eq!(b.alerts[0]["threatId"], 21);
        assert_eq!(b.alerts[0]["suspendedPids"], 3);
        assert_eq!(b.alerts[0]["network"], "applied");
        // Grace: the hook process is suspended afterwards if still alive.
        assert!(suspend_peer(&mut q, &rec, &src, &fu.quarantine_id, fu.peer.as_ref().unwrap()).unwrap());
        assert_eq!(rec.calls()[2], Call::Suspend { pids: vec![120], persisted_active: true });
    }

    #[test]
    fn a_refused_target_raises_a_signed_alert_and_acts_on_nothing() {
        let (d, mut q, mut a) = setup("refuse");
        let rec = Recording::new(&d.join("quarantine.json"));
        let r = quarantine_from_hook(&mut q, &mut a, &rec, &table(), hook_peer(), &req(400), SELF, &|| 1_000);
        let err = r.unwrap_err();
        assert_eq!(err.code(), crate::ipc::ErrorCode::TargetNotAgentAncestor);
        assert!(rec.calls().is_empty());
        assert!(q.file.entries.is_empty());
        let b = a.next_batch("acme", "dev").unwrap().unwrap();
        assert_eq!((b.alerts[0]["kind"].as_str(), b.alerts[0]["refusal"].as_str(), b.alerts[0]["severity"].as_str()), (Some("quarantineRefused"), Some("not_agent_ancestor"), Some("medium")));
        assert_eq!(b.alerts[0]["peerUid"], 501);
    }

    #[test]
    fn rate_limit_is_ten_per_minute_per_uid() {
        let (d, mut q, mut a) = setup("rate");
        let rec = Recording::new(&d.join("quarantine.json"));
        for i in 0..10 {
            assert!(quarantine_from_hook(&mut q, &mut a, &rec, &table(), hook_peer(), &req(100), SELF, &|| 1_000 + i).is_ok());
        }
        let e = quarantine_from_hook(&mut q, &mut a, &rec, &table(), hook_peer(), &req(100), SELF, &|| 2_000).unwrap_err();
        assert_eq!(e.code(), crate::ipc::ErrorCode::Busy);
        assert!(quarantine_from_hook(&mut q, &mut a, &rec, &table(), hook_peer(), &req(100), SELF, &|| 62_000).is_ok());
    }

    #[test]
    fn a_failed_suspend_is_quarantine_failed_and_stays_active_for_restart() {
        let (d, mut q, mut a) = setup("fail");
        let rec = Recording::new(&d.join("quarantine.json"));
        *rec.fail_suspend.lock().unwrap() = true;
        let e = quarantine_from_hook(&mut q, &mut a, &rec, &table(), hook_peer(), &req(100), SELF, &|| 1_000).unwrap_err();
        assert_eq!(e.code(), crate::ipc::ErrorCode::QuarantineFailed);
        assert_eq!(q.file.entries[0].status, Status::Active);
        assert_eq!(q.file.entries[0].failed_step.as_deref(), Some("suspend"));
        let b = a.next_batch("acme", "dev").unwrap().unwrap();
        assert_eq!(b.alerts[0]["failedStep"], "suspend");
    }

    #[test]
    fn network_unavailable_or_failed_keeps_the_processes_suspended() {
        let (d, mut q, mut a) = setup("net");
        let rec = Recording::new(&d.join("quarantine.json"));
        *rec.net.lock().unwrap() = Err("unsupported".into());
        let (r1, _) = quarantine_from_hook(&mut q, &mut a, &rec, &table(), hook_peer(), &req(100), SELF, &|| 1_000).unwrap();
        assert_eq!(finish(&mut q, &mut a, &rec, &r1.quarantine_id, 1_001).unwrap(), NetBlockState::Unsupported);
        let e = q.get(&r1.quarantine_id).unwrap();
        assert_eq!((e.status, e.network_block.as_deref()), (Status::Active, Some("unavailable")));
        *rec.net.lock().unwrap() = Err("nft failed".into());
        let (r2, _) = quarantine_from_hook(&mut q, &mut a, &rec, &table(), hook_peer(), &req(100), SELF, &|| 1_002).unwrap();
        assert_eq!(finish(&mut q, &mut a, &rec, &r2.quarantine_id, 1_003).unwrap(), NetBlockState::Failed);
        assert_eq!(q.get(&r2.quarantine_id).unwrap().failed_step.as_deref(), Some("network"));
        let b = a.next_batch("acme", "dev").unwrap().unwrap();
        assert_eq!(b.alerts[0]["networkBlock"], "unavailable");
        assert_eq!((b.alerts[1]["network"].as_str(), b.alerts[1]["failedStep"].as_str()), (Some("failed"), Some("network")));
        assert!(!rec.calls().iter().any(|c| matches!(c, Call::Resume { .. })), "nothing is resumed on a network failure");
    }

    #[test]
    fn release_persists_first_then_unblocks_then_resumes_and_survives_restart() {
        let (d, mut q, mut a) = setup("release");
        let rec = Recording::new(&d.join("quarantine.json"));
        let src = table();
        let (r, _) = quarantine_from_hook(&mut q, &mut a, &rec, &src, hook_peer(), &req(100), SELF, &|| 1_000).unwrap();
        finish(&mut q, &mut a, &rec, &r.quarantine_id, 1_001).unwrap();
        assert!(matches!(release(&mut q, &rec, "q-ffffffffffffffff", "local-admin:0", 2_000), Err(ReleaseError::UnknownQuarantine)));
        assert_eq!(release(&mut q, &rec, &r.quarantine_id, "local-admin:0", 2_000).unwrap(), 1);
        let calls = rec.calls();
        assert_eq!(calls[calls.len() - 2], Call::NetUnblock { id: r.quarantine_id.clone(), persisted_released: true });
        assert_eq!(calls[calls.len() - 1], Call::Resume { pids: vec![100, 110, 130], persisted_released: true });
        let n = rec.calls().len();
        let mut q2 = Quarantines::open(&d.join("quarantine.json")).unwrap();
        reconcile_on_start(&mut q2, &rec, &src).unwrap();
        assert_eq!(rec.calls().len(), n, "a released entry is never re-suspended after a restart");
        assert_eq!(q2.get(&r.quarantine_id).unwrap().released_by.as_deref(), Some("local-admin:0"));
        assert_eq!(release(&mut q2, &rec, "*", "console:c-1", 3_000).unwrap(), 0);
    }

    #[test]
    fn restart_reapplies_active_entries_to_the_same_processes_only() {
        let (d, mut q, mut a) = setup("restart");
        let rec = Recording::new(&d.join("quarantine.json"));
        let src = table();
        quarantine_from_hook(&mut q, &mut a, &rec, &src, hook_peer(), &req(100), SELF, &|| 1_000).unwrap();
        // 130 exited and its pid was reused by a new process; 110 is gone.
        let mut v = src.list().unwrap();
        v.retain(|p| p.pid != 130 && p.pid != 110);
        v.push(proc(130, 1, 501, 50_000, "/usr/bin/other", None));
        src.set(v);
        let rec2 = Recording::new(&d.join("quarantine.json"));
        let mut q2 = Quarantines::open(&d.join("quarantine.json")).unwrap();
        reconcile_on_start(&mut q2, &rec2, &src).unwrap();
        assert_eq!(rec2.calls()[0], Call::Suspend { pids: vec![100], persisted_active: true });
        assert!(matches!(rec2.calls()[1], Call::NetBlock { .. }));
    }

    #[test]
    fn console_quarantine_of_a_device_takes_every_agent_tree() {
        let (d, mut q, mut a) = setup("console");
        let rec = Recording::new(&d.join("quarantine.json"));
        let src = table();
        let agents: Vec<(ProcInfo, &'static str)> = [100u32, 200, 500].iter().map(|p| (src.get(*p).unwrap().unwrap(), "claude-code")).collect();
        let e = quarantine_from_console(&mut q, &mut a, &rec, &src, &agents, "c-7", "", "admin", SELF, &|| 5).unwrap().unwrap();
        let pids: Vec<u32> = e.pids.iter().map(|p| p.pid).collect();
        assert_eq!(pids, vec![100, 110, 120, 130, 200, 210], "root-owned agent 500 is never a console target");
        assert_eq!(e.cmd_id.as_deref(), Some("c-7"));
        assert!(matches!(rec.calls()[0], Call::Suspend { persisted_active: true, .. }));
        assert!(quarantine_from_console(&mut q, &mut a, &rec, &src, &[], "c-8", "", "admin", SELF, &|| 6).unwrap().is_none());
    }
}
