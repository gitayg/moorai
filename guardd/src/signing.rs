//! Signed-byte forms shared with the hook client and the console (contract §6, §7, §9.4). Each is a
//! pipe-joined UTF-8 string with a literal domain prefix, the same shape as `moorai-policy|v1|...`
//! (policy-sign.js), so a signature for one purpose can never verify as another.

use crate::canonical::sha256_hex;

pub const DEVREQ_PREFIX: &str = "moorai-devreq|v1";
pub const HELLO_PREFIX: &str = "moorai-guardd-hello|v1";
pub const ROTATE_PREFIX: &str = "moorai-rotate|v1";
pub const CMD_PREFIX: &str = "moorai-cmd|v1";

/// The fields of one device-signed HTTP request (contract §6.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DevReq<'a> {
    /// "GET" or "POST", upper case.
    pub method: &'a str,
    /// Path plus the raw query string exactly as sent, e.g. "/api/devices/commands?after=6&wait=25".
    pub path: &'a str,
    pub tenant: &'a str,
    pub device_id: &'a str,
    pub key_id: &'a str,
    /// ISO 8601 UTC with milliseconds, "YYYY-MM-DDTHH:MM:SS.sssZ" (what `toISOString` emits).
    pub ts: &'a str,
    /// 32 lowercase hex characters.
    pub nonce: &'a str,
    /// The exact body bytes sent; empty for GET.
    pub body: &'a [u8],
}

pub fn devreq_signing_input(r: &DevReq<'_>) -> String {
    format!(
        "{DEVREQ_PREFIX}|{}|{}|{}|{}|{}|{}|{}|{}",
        r.method,
        r.path,
        r.tenant,
        r.device_id,
        r.key_id,
        r.ts,
        r.nonce,
        sha256_hex(r.body)
    )
}

/// What the helper signs in its `hello` reply so the hook can tell it from a squatter (contract §3.6).
pub fn hello_proof_input(client_nonce: &str, key_id: &str, helper_version: &str) -> String {
    format!("{HELLO_PREFIX}|{client_nonce}|{key_id}|{helper_version}")
}

/// Signed by the OLD device key during a planned rotation (contract §5.3).
pub fn rotate_input(tenant: &str, device_id: &str, old_key_id: &str, new_key_id: &str) -> String {
    format!("{ROTATE_PREFIX}|{tenant}|{device_id}|{old_key_id}|{new_key_id}")
}

/// A console command (contract §9.4), signed with the tenant's POLICY key and verified by the helper
/// against the same anchor/pin that verifies policy. Absent optional fields are the empty string.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CommandFields {
    pub tenant: String,
    pub device_id: String,
    pub cmd_id: String,
    pub cmd_seq: u64,
    /// "quarantine" | "release" | "kill"
    pub action: String,
    /// "device" | "session"
    pub scope: String,
    pub session_hash: String,
    pub quarantine_id: String,
    pub iat: String,
}

pub fn command_input(c: &CommandFields) -> String {
    format!(
        "{CMD_PREFIX}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
        c.tenant, c.device_id, c.cmd_id, c.cmd_seq, c.action, c.scope, c.session_hash, c.quarantine_id, c.iat
    )
}
