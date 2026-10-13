//! Console -> helper command channel (contract §9): a device-signed HTTPS long-poll, chosen over a
//! WebSocket because the lockfile has an HTTP client (reqwest) and no WebSocket client.

use crate::signing::CommandFields;
use serde::{Deserialize, Serialize};

/// The console holds a poll open for at most this long, then answers 204.
pub const POLL_WAIT_SEC: u64 = 25;
/// Client read timeout = wait + this margin.
pub const POLL_MARGIN_SEC: u64 = 10;
/// Reconnect after an error: delay = random(0, min(CAP, BASE * 2^attempt)) (full jitter); a 200 or
/// 204 resets attempt to 0 and the next poll starts immediately.
pub const BACKOFF_BASE_MS: u64 = 1_000;
pub const BACKOFF_CAP_MS: u64 = 60_000;
/// A command whose iat is older than this is acked "stale" and not applied.
pub const COMMAND_MAX_AGE_SEC: u64 = 86_400;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Command {
    #[serde(flatten)]
    pub fields: CommandFields,
    /// "policy-quarantine" | "admin" | ... content-free.
    pub reason: String,
    /// base64 ed25519 by the tenant policy key over signing::command_input(fields).
    pub sig: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CommandsResp {
    pub v: u32,
    /// Ascending cmdSeq, all > the poll's `after`.
    pub commands: Vec<Command>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CommandAck {
    pub v: u32,
    pub tenant: String,
    pub device_id: String,
    pub cmd_id: String,
    pub cmd_seq: u64,
    /// "applied" | "failed" | "ignored" | "stale" | "bad-signature"
    pub result: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub quarantine_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub suspended_pids: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub suspended_at_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub network: Option<crate::ipc::NetBlockState>,
}

/// Poll path for `after` (the persisted lastCmdSeq).
pub fn poll_path(after: u64) -> String {
    format!("{}?after={after}&wait={POLL_WAIT_SEC}", crate::console::COMMANDS_PATH)
}

/// Full-jitter backoff; `rand01` in [0,1).
pub fn backoff_ms(attempt: u32, rand01: f64) -> u64 {
    let ceiling = BACKOFF_CAP_MS.min(BACKOFF_BASE_MS.saturating_mul(1u64 << attempt.min(16)));
    (ceiling as f64 * rand01) as u64
}

/// `state/commands.json` (§4.2): the last cmdSeq handled and the recent command ids.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct CommandsState {
    pub last_cmd_seq: u64,
    pub recent: Vec<String>,
}

pub const RECENT_CMDS: usize = 64;
/// A `kill` command stays visible to the IPC `kill` op this long after it arrived.
pub const KILL_TTL_MS: u64 = 10 * 60 * 1000;

impl CommandsState {
    pub fn record(&mut self, cmd_id: &str, cmd_seq: u64) {
        self.last_cmd_seq = self.last_cmd_seq.max(cmd_seq);
        self.recent.retain(|c| c != cmd_id);
        self.recent.push(cmd_id.to_string());
        if self.recent.len() > RECENT_CMDS {
            let n = self.recent.len() - RECENT_CMDS;
            self.recent.drain(..n);
        }
    }
}

/// A console `kill` the IPC `kill` op reports (replaces the kill-session sentinel, §3.4).
#[derive(Debug, Clone, PartialEq)]
pub struct KillEntry {
    pub cmd_id: String,
    pub issued_at: String,
    pub scope: String,
    pub session_hash: String,
    pub received_ms: u64,
}

/// Answer an IPC `kill`: a device-scope kill, or a session-scope kill for this session hash.
pub fn kill_answer(kills: &[KillEntry], session_hash: Option<&str>, now_ms: u64) -> crate::ipc::KillResp {
    let hit = kills.iter().rev().filter(|k| now_ms.saturating_sub(k.received_ms) < KILL_TTL_MS).find(|k| k.scope == "device" || (k.scope == "session" && session_hash == Some(k.session_hash.as_str())));
    match hit {
        Some(k) => crate::ipc::KillResp { kill: true, cmd_id: Some(k.cmd_id.clone()), issued_at: Some(k.issued_at.clone()), scope: Some(k.scope.clone()) },
        None => crate::ipc::KillResp { kill: false, cmd_id: None, issued_at: None, scope: None },
    }
}

/// Verify a command against the policy trust keys and the persisted lastCmdSeq (contract §9.3).
/// Errors: "malformed", "bad-signature" (incl. no trust key on this device), "mismatch" (signed for
/// another tenant/device), "replay" (cmdSeq not above the last), "stale" (iat older than 24 h).
pub fn verify_command(cmd: &Command, policy_keys: &[String], tenant: &str, device_id: &str, last_cmd_seq: u64, now_ms: u64) -> Result<(), &'static str> {
    let f = &cmd.fields;
    let shape = matches!(f.action.as_str(), "quarantine" | "release" | "kill")
        && matches!(f.scope.as_str(), "device" | "session")
        && (f.scope != "session" || !f.session_hash.is_empty())
        && (f.action != "release" || !f.quarantine_id.is_empty())
        && !f.cmd_id.is_empty()
        && f.cmd_seq > 0;
    if !shape {
        return Err("malformed");
    }
    let input = crate::signing::command_input(f);
    if policy_keys.is_empty() || !policy_keys.iter().any(|k| crate::keys::verify_b64(k, input.as_bytes(), &cmd.sig).is_ok()) {
        return Err("bad-signature");
    }
    if f.tenant != tenant || f.device_id != device_id {
        return Err("mismatch");
    }
    if f.cmd_seq <= last_cmd_seq {
        return Err("replay");
    }
    match crate::clock::parse_iso_ms(&f.iat) {
        None => Err("malformed"),
        Some(t) if (now_ms as i64).saturating_sub(t) > (COMMAND_MAX_AGE_SEC * 1000) as i64 => Err("stale"),
        Some(_) => Ok(()),
    }
}

/// The ack `result` for a verification error, and whether lastCmdSeq advances past it. A forged
/// command never advances it (a huge forged cmdSeq must not block the real ones).
pub fn ack_for(err: &str) -> (&'static str, bool) {
    match err {
        "stale" => ("stale", true),
        "bad-signature" => ("bad-signature", false),
        _ => ("ignored", false),
    }
}

/// One poll: GET commands?after=<lastCmdSeq>&wait=25 (device-signed), apply each verified command in
/// order through `crate::helper::apply_command`, and ack each. Returns the number of commands seen.
pub fn poll_once(shared: &crate::helper::Shared) -> Result<usize, crate::console::ConsoleError> {
    use crate::console::{send_signed, ConsoleError, COMMANDS_ACK_PATH};
    let (key, binding, device_id, after, mut offset) = {
        let s = shared.lock();
        let b = s.binding.clone().ok_or_else(|| ConsoleError::BadResponse("no binding".into()))?;
        (s.key.clone(), b, s.device_id.clone(), s.last_cmd_seq(), s.beat.clock_offset_ms)
    };
    let now = || shared.now();
    let path = poll_path(after);
    let r = send_signed(shared.deps.console.as_ref(), &key, &binding, &device_id, "GET", &path, vec![], &[], &mut offset, (POLL_WAIT_SEC + POLL_MARGIN_SEC) * 1000, &now);
    shared.lock().beat.clock_offset_ms = offset;
    let resp = match r {
        Err(ConsoleError::Status(401, code)) if code == "unknown_key" => {
            shared.lock().needs_register = true;
            return Err(ConsoleError::Status(401, code));
        }
        r => r?,
    };
    if resp.status == 204 || resp.body.is_empty() {
        return Ok(0);
    }
    let list: CommandsResp = serde_json::from_slice(&resp.body).map_err(|e| ConsoleError::BadResponse(format!("commands: {e}")))?;
    let n = list.commands.len();
    for cmd in list.commands {
        let ack = crate::helper::apply_command(shared, &cmd);
        let body = crate::canonical::canonical_json(&serde_json::to_value(&ack).expect("ack serialises")).map_err(|e| ConsoleError::BadResponse(e.to_string()))?.into_bytes();
        let mut off = shared.lock().beat.clock_offset_ms;
        let r = send_signed(shared.deps.console.as_ref(), &key, &binding, &device_id, "POST", COMMANDS_ACK_PATH, body, &[], &mut off, crate::console::REQUEST_TIMEOUT_MS, &now);
        shared.lock().beat.clock_offset_ms = off;
        if let Err(e) = r {
            eprintln!("moorai-guardd: command ack failed: {e:?}");
        }
    }
    Ok(n)
}

/// The poll loop: runs on its own thread until shutdown. Re-polls at once after a 200/204; after an
/// error backs off with full jitter from 1 s, capped at 60 s.
pub fn run(shared: std::sync::Arc<crate::helper::Shared>) {
    let mut attempt = 0u32;
    while !shared.stopping() {
        if shared.lock().binding.is_none() {
            shared.sleep_ms(5_000);
            continue;
        }
        match poll_once(&shared) {
            Ok(_) => attempt = 0,
            Err(_) => {
                shared.sleep_ms(backoff_ms(attempt, crate::clock::rand01()));
                attempt = attempt.saturating_add(1);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_is_capped_full_jitter() {
        assert_eq!(backoff_ms(0, 0.0), 0);
        assert_eq!(backoff_ms(0, 0.5), 500);
        assert_eq!(backoff_ms(3, 0.5), 4_000);
        assert_eq!(backoff_ms(30, 0.999_999), 59_999);
    }

    use crate::signing::CommandFields;

    fn console_key() -> crate::keys::DeviceKey {
        crate::keys::DeviceKey::from_seed(&[3u8; 32]).unwrap()
    }

    fn cmd(seq: u64, action: &str, iat: &str) -> Command {
        let fields = CommandFields {
            tenant: "acme".into(),
            device_id: "dev".into(),
            cmd_id: format!("c-{seq}"),
            cmd_seq: seq,
            action: action.into(),
            scope: "device".into(),
            session_hash: "".into(),
            quarantine_id: if action == "release" { "q-0000000000000001".into() } else { "".into() },
            iat: iat.into(),
        };
        let sig = console_key().sign_b64(crate::signing::command_input(&fields).as_bytes());
        Command { fields, reason: "admin".into(), sig }
    }

    const NOW: u64 = 1_791_797_460_000; // 2026-10-12T09:31:00.000Z

    #[test]
    fn commands_verify_against_the_policy_keys_seq_and_age() {
        let keys = vec![console_key().public_spki_b64()];
        let c = cmd(7, "quarantine", "2026-10-12T09:31:00.000Z");
        assert_eq!(verify_command(&c, &keys, "acme", "dev", 6, NOW), Ok(()));
        assert_eq!(verify_command(&c, &keys, "acme", "dev", 7, NOW), Err("replay"));
        assert_eq!(verify_command(&c, &[], "acme", "dev", 0, NOW), Err("bad-signature"), "an unpinned helper verifies no command");
        assert_eq!(verify_command(&c, &[crate::keys::DeviceKey::from_seed(&[4u8; 32]).unwrap().public_spki_b64()], "acme", "dev", 0, NOW), Err("bad-signature"));
        assert_eq!(verify_command(&c, &keys, "acme", "other", 0, NOW), Err("mismatch"));
        let mut forged = c.clone();
        forged.fields.cmd_seq = 9_000_000;
        assert_eq!(verify_command(&forged, &keys, "acme", "dev", 0, NOW), Err("bad-signature"), "cmdSeq is inside the signature");
        let old = cmd(8, "kill", "2026-10-11T09:30:00.000Z");
        assert_eq!(verify_command(&old, &keys, "acme", "dev", 0, NOW), Err("stale"));
        let mut bad = cmd(9, "reboot", "2026-10-12T09:31:00.000Z");
        bad.fields.action = "reboot".into();
        assert_eq!(verify_command(&bad, &keys, "acme", "dev", 0, NOW), Err("malformed"));
        assert_eq!(ack_for("stale"), ("stale", true));
        assert_eq!(ack_for("bad-signature"), ("bad-signature", false));
        assert_eq!(ack_for("replay"), ("ignored", false));
    }

    #[test]
    fn the_golden_command_verifies() {
        let g: serde_json::Value = serde_json::from_slice(include_bytes!("../../test/fixtures/guardd/golden.json")).unwrap();
        let fields: CommandFields = serde_json::from_value(g["command"]["fields"].clone()).unwrap();
        let c = Command { fields, reason: "policy-quarantine".into(), sig: g["command"]["signatureB64"].as_str().unwrap().into() };
        let keys = vec![g["keys"]["consolePublicKeySpkiB64"].as_str().unwrap().to_string()];
        assert_eq!(verify_command(&c, &keys, "acme", "2af4dce3059ab31302f67f3e53b9226d", 6, NOW), Ok(()));
    }

    #[test]
    fn kill_answers_device_scope_or_the_matching_session() {
        let k = |scope: &str, sh: &str, at: u64| KillEntry { cmd_id: "c-1".into(), issued_at: "t".into(), scope: scope.into(), session_hash: sh.into(), received_ms: at };
        assert!(!kill_answer(&[], Some("s"), 0).kill);
        assert!(kill_answer(&[k("session", "s1", 0)], Some("s1"), 1).kill);
        assert!(!kill_answer(&[k("session", "s1", 0)], Some("s2"), 1).kill);
        assert!(!kill_answer(&[k("session", "s1", 0)], None, 1).kill);
        let r = kill_answer(&[k("device", "", 0)], None, 1);
        assert_eq!((r.kill, r.scope.as_deref()), (true, Some("device")));
        assert!(!kill_answer(&[k("device", "", 0)], None, KILL_TTL_MS).kill, "expires");
    }

    #[test]
    fn recent_ids_are_bounded_and_seq_only_advances() {
        let mut c = CommandsState::default();
        for i in 0..100 {
            c.record(&format!("c-{i}"), i);
        }
        c.record("c-old", 3);
        assert_eq!(c.last_cmd_seq, 99);
        assert_eq!(c.recent.len(), RECENT_CMDS);
    }

    #[test]
    fn poll_path_shape() {
        assert_eq!(poll_path(6), "/api/devices/commands?after=6&wait=25");
    }
}
