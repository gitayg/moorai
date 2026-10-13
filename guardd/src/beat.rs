//! The signed heartbeat (contract §6). Every BEAT_INTERVAL_SEC the helper POSTs this body, serialised
//! as canonical JSON, to /api/devices/beat with the device-signature headers of contract §6.2.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const BEAT_INTERVAL_SEC: u64 = 300;
pub const BEAT_PATH: &str = "/api/devices/beat";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HookSilent {
    pub host: String,
    /// Seconds the host's agent process has been running with zero hook `call`s (>= 120 to appear).
    pub since_sec: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Versions {
    pub helper: String,
    /// Last hook version seen over IPC (from hello.clientVersion); omitted before any hook connects.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub hook: Option<String>,
    /// Desktop app version when installed; omitted on CLI-only devices.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub app: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Beat {
    /// Body schema version, 1.
    pub v: u32,
    pub tenant: String,
    pub device_id: String,
    /// Hostname as the hook reports `device` today (the console pseudonymises it on ingest).
    pub device: String,
    /// "darwin" | "linux" | "win32"
    pub platform: String,
    pub key_id: String,
    /// macOS kern.bootsessionuuid; Linux /proc/sys/kernel/random/boot_id; Windows boot-time-derived GUID (§6.4).
    pub boot_id: String,
    /// Seconds awake since boot, EXCLUDING sleep (macOS CLOCK_UPTIME_RAW, Linux CLOCK_MONOTONIC,
    /// Windows QueryUnbiasedInterruptTime). The sweep's "stopped vs asleep" rule depends on this.
    pub awake_sec: u64,
    /// Seconds since boot INCLUDING sleep (macOS kern.boottime, Linux CLOCK_BOOTTIME, Windows GetTickCount64).
    pub uptime_sec: u64,
    /// Strictly increasing per key, persisted; never reused across helper restarts.
    pub beat_seq: u64,
    /// The helper's alert-chain seq and head (phase 3 anchors these; phase 2 reports them).
    pub chain_seq: u64,
    pub chain_head: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub policy_iat: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub policy_fetched_at: Option<String>,
    pub policy_source: crate::ipc::PolicySource,
    /// Hook `call`s per host since the previous beat (hosts with an agent process or a call appear).
    pub hook_calls: BTreeMap<String, u64>,
    /// Agent host processes seen per host at beat time.
    pub agent_procs: BTreeMap<String, u64>,
    /// Sorted by host.
    pub hook_silent: Vec<HookSilent>,
    pub quarantines_active: u32,
    pub versions: Versions,
    /// The offset the helper applies to its clock for ts (server - local, ms), learned per §6.5.
    pub clock_offset_ms: i64,
    pub helper_started_at: String,
}

impl Beat {
    /// The exact body bytes that are sent and whose sha256 goes into the signing input.
    pub fn body_bytes(&self) -> Result<Vec<u8>, crate::canonical::CanonError> {
        let v = serde_json::to_value(self).expect("Beat serialises");
        Ok(crate::canonical::canonical_json(&v)?.into_bytes())
    }
}

/// `state/beat.json` (§4.2).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct BeatState {
    pub beat_seq: u64,
    pub clock_offset_ms: i64,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub last_beat_at: Option<String>,
}

/// `state/counters.json`: hook `call`s per host since the last ACCEPTED beat. A beat that fails keeps
/// its counts for the next one.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Counters {
    pub hook_calls: BTreeMap<String, u64>,
}

impl Counters {
    pub fn add(&mut self, host: &str) {
        *self.hook_calls.entry(host.to_string()).or_insert(0) += 1;
    }

    /// Subtract a snapshot that the console accepted.
    pub fn subtract(&mut self, sent: &BTreeMap<String, u64>) {
        for (h, n) in sent {
            if let Some(c) = self.hook_calls.get_mut(h) {
                *c = c.saturating_sub(*n);
            }
        }
        self.hook_calls.retain(|_, c| *c > 0);
    }
}

/// Assemble the next beat from helper state. Persists the incremented beatSeq BEFORE returning, so a
/// seq is never reused, even when the send fails or the helper restarts mid-send.
pub fn build_beat(state: &mut crate::state::HelperState, sys: &dyn crate::platform::SystemInfo, now_ms: u64) -> std::io::Result<Beat> {
    let binding = state.binding.clone().ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "no binding"))?;
    let mut next = state.beat.clone();
    next.beat_seq += 1;
    crate::state::save_json(&state.paths.state_file(crate::state::files::BEAT), &next)?;
    state.beat = next;
    let held = state.policy.held.clone();
    let answer = crate::policy::answer(held.as_ref(), None, now_ms);
    let mut hook_calls = state.counters.hook_calls.clone();
    let agent_procs = state.observer.agent_procs();
    for h in agent_procs.keys() {
        hook_calls.entry(h.clone()).or_insert(0);
    }
    Ok(Beat {
        v: 1,
        tenant: binding.tenant.clone(),
        device_id: state.device_id.clone(),
        device: state.device.clone(),
        platform: crate::console::platform_name().into(),
        key_id: state.key.key_id(),
        boot_id: sys.boot_id()?,
        awake_sec: sys.awake_sec()?,
        uptime_sec: sys.uptime_sec()?,
        beat_seq: state.beat.beat_seq,
        chain_seq: state.alerts.chain.seq,
        chain_head: state.alerts.chain.head.clone(),
        policy_iat: answer.iat,
        policy_fetched_at: answer.fetched_at,
        policy_source: answer.source,
        hook_calls,
        agent_procs,
        hook_silent: state.observer.hook_silent(now_ms),
        quarantines_active: state.quarantines.active_count(),
        versions: Versions { helper: crate::HELPER_VERSION.into(), hook: state.hook_version.clone(), app: state.app_version.clone() },
        clock_offset_ms: state.beat.clock_offset_ms,
        helper_started_at: crate::clock::iso_ms(state.started_at_ms as i64),
    })
}

/// The outcome of one beat for the beat loop.
#[derive(Debug, Clone, PartialEq)]
pub enum BeatOutcome {
    Sent(u64),
    NoBinding,
    Reregister,
    Failed(String),
}

/// Build, sign and send one beat against shared state; the lock is not held during the request. A
/// `401 clock_skew` adopts the offset and rebuilds the beat with a NEW beatSeq (the old one was
/// persisted and is never reused) before the single retry.
pub fn beat_once(shared: &crate::helper::Shared) -> BeatOutcome {
    use crate::console::{classify, sign_request, ConsoleError, REQUEST_TIMEOUT_MS};
    let mut attempt = 0;
    loop {
        let (req, origin, sent_calls) = {
            let mut s = shared.lock();
            let Some(binding) = s.binding.clone() else { return BeatOutcome::NoBinding };
            let now = shared.now();
            let beat = match build_beat(&mut s, shared.deps.sys.as_ref(), now) {
                Ok(b) => b,
                Err(e) => return BeatOutcome::Failed(e.to_string()),
            };
            let body = match beat.body_bytes() {
                Ok(b) => b,
                Err(e) => return BeatOutcome::Failed(e.to_string()),
            };
            let req = sign_request(&s.key, &binding, &s.device_id, "POST", BEAT_PATH, body, s.beat.clock_offset_ms, now);
            (req, binding.origin, beat.hook_calls)
        };
        let r = shared.deps.console.send(&origin, req, REQUEST_TIMEOUT_MS).and_then(classify);
        let mut s = shared.lock();
        match r {
            Ok(_) => {
                s.counters.subtract(&sent_calls);
                s.beat.last_beat_at = Some(crate::clock::iso_ms(shared.now() as i64));
                let (b, c) = (s.beat.clone(), s.counters.clone());
                let _ = crate::state::save_json(&s.paths.state_file(crate::state::files::BEAT), &b);
                let _ = crate::state::save_json(&s.paths.state_file(crate::state::files::COUNTERS), &c);
                return BeatOutcome::Sent(b.beat_seq);
            }
            Err(ConsoleError::ClockSkew { server_time }) if attempt == 0 => {
                match crate::console::offset_from_server_time(&server_time, shared.now()) {
                    Some(off) => {
                        s.beat.clock_offset_ms = off;
                        let b = s.beat.clone();
                        let _ = crate::state::save_json(&s.paths.state_file(crate::state::files::BEAT), &b);
                    }
                    None => return BeatOutcome::Failed("unreadable serverTime".into()),
                }
                attempt += 1;
            }
            Err(ConsoleError::Status(401, code)) if code == "unknown_key" => {
                s.needs_register = true;
                return BeatOutcome::Reregister;
            }
            Err(e) => return BeatOutcome::Failed(format!("{e:?}")),
        }
    }
}
