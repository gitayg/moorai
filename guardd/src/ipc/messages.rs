//! IPC message types (contract §3.4). Every frame is `{v, id, op, ...fields}`; field names are
//! camelCase; an absent optional field is OMITTED, never `null`. Unknown fields are ignored by the
//! receiver (forward compatibility within a protocol major); an unknown `op` is `unknown_op`.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RequestFrame {
    pub v: u32,
    pub id: u32,
    #[serde(flatten)]
    pub body: Request,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResponseFrame {
    pub v: u32,
    /// The request's id; 0 when the request could not be parsed far enough to read one.
    pub id: u32,
    #[serde(flatten)]
    pub body: Response,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "lowercase")]
pub enum Request {
    Hello(HelloReq),
    Policy(PolicyReq),
    Submit(SubmitReq),
    Call(CallReq),
    Kill(KillReq),
    Quarantine(QuarantineReq),
    /// Administrator peers only (contract §3.6, §8.6). The hook never sends it.
    Release(ReleaseReq),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "lowercase")]
pub enum Response {
    Hello(HelloResp),
    Policy(PolicyResp),
    Submit(SubmitResp),
    Call(CallResp),
    Kill(KillResp),
    Quarantine(QuarantineResp),
    Release(ReleaseResp),
    Error(ErrorResp),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HelloReq {
    /// Protocol majors the client speaks, ascending.
    pub proto: Vec<u32>,
    /// "moorai-hook" | "moorai-host" | "moorai-guardctl"
    pub client: String,
    pub client_version: String,
    /// Agent host kind ("claude-code", "codex", "cursor", "gemini", "copilot"); omitted by non-hook clients.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub host: Option<String>,
    /// 32 lowercase hex; the helper signs it back in `proof`.
    pub nonce: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HelloResp {
    pub proto: u32,
    pub helper_version: String,
    pub tenant: String,
    pub device_id: String,
    pub key_id: String,
    /// Ops this helper serves, sorted.
    pub caps: Vec<String>,
    /// base64 ed25519 signature by the device key over signing::hello_proof_input(nonce, keyId, helperVersion).
    pub proof: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyReq {
    /// The `policySig.iat` the client already holds; the reply omits `policy` when it is still current.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub if_iat: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicySource {
    /// Fetched and verified within policyMaxAge.
    Fresh,
    /// Helper cache, verified, older than policyMaxAge (console unreachable).
    Cache,
    /// Last known good, verified.
    Lkg,
    /// No verified policy held; the client falls back to the posture ratchet.
    None,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyResp {
    pub source: PolicySource,
    /// The signed policy exactly as the console served it (the hook re-verifies the signature).
    /// Omitted when source is "none" or the client's `ifIat` is current.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub policy: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub iat: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub fetched_at: Option<String>,
    /// now - iat, whole seconds.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub age_sec: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubmitReq {
    /// 1..=MAX_SUBMIT_ALERTS content-free alert objects in the hook's existing alert shape. Opaque to
    /// the helper except `seq`/`chainHead`, which the helper overwrites with its own root-held chain.
    pub alerts: Vec<Map<String, Value>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubmitAck {
    pub seq: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubmitResp {
    /// One per submitted alert, same order. Sent only after the queue entry is durable (fsync).
    pub acks: Vec<SubmitAck>,
    pub chain_head: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CallReq {
    /// Hook event name ("PreToolUse", "PostToolUse", "UserPromptSubmit", "Stop", ...).
    pub event: String,
    pub host: String,
    /// 16 lowercase hex, the hook's existing session hash.
    pub session_hash: String,
    /// The agent host pid the hook believes it serves (a hint for observation only).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub agent_pid: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CallResp {}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KillReq {
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub session_hash: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KillResp {
    pub kill: bool,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub cmd_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub issued_at: Option<String>,
    /// "session" | "device"
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub scope: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QuarantineReq {
    /// Hint only: the helper derives the target itself and refuses on disagreement (contract §8.3).
    pub agent_pid: u32,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub pgid: Option<u32>,
    /// Unix session id (getsid).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub sid: Option<u32>,
    /// Windows logon session id (ProcessIdToSessionId).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub win_session_id: Option<u32>,
    pub host: String,
    /// Exactly one of threatId / ruleId.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub threat_id: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub rule_id: Option<String>,
    /// Content-free reason code, e.g. "policy-quarantine".
    pub reason_code: String,
    pub session_hash: String,
    /// Epoch ms when the hook decided (the start of the 50 ms latency budget, contract §8.7).
    pub decided_at_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetBlockState {
    Pending,
    Applied,
    Unsupported,
    Failed,
    Removed,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QuarantineResp {
    pub quarantine_id: String,
    pub suspended_pids: u32,
    /// Epoch ms when the last process in the tree was confirmed stopped.
    pub suspended_at_ms: u64,
    pub network: NetBlockState,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReleaseReq {
    /// A quarantine id, or "*" for every active quarantine on the device.
    pub quarantine_id: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReleaseResp {
    pub released: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ErrorResp {
    pub code: ErrorCode,
    /// Human-readable, content-free.
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub req_op: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    BadFrame,
    FrameTooLarge,
    UnsupportedVersion,
    UnknownOp,
    BadRequest,
    Forbidden,
    NotReady,
    Busy,
    TargetNotAgentAncestor,
    QuarantineFailed,
    UnknownQuarantine,
    Internal,
}

pub const OPS: [&str; 7] = ["hello", "policy", "submit", "call", "kill", "quarantine", "release"];
