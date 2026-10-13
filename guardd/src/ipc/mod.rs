//! Hook <-> helper IPC (contract §3). Transport is per OS (crate::transport, crate::platform);
//! framing and messages here are OS-neutral and pinned by test/fixtures/guardd/golden.json.

pub mod frame;
pub mod messages;
pub mod server;

pub use messages::*;

/// Protocol major version carried in every frame's `v`.
pub const PROTO_VERSION: u32 = 1;
/// Largest frame payload in bytes (the signed policy text is the biggest message).
pub const MAX_FRAME: usize = 1024 * 1024;
/// Largest number of alerts in one `submit`.
pub const MAX_SUBMIT_ALERTS: usize = 64;

/// Client-side budgets in milliseconds (contract §3.5). CONNECT covers connect + endpoint ownership
/// check + `hello` round trip.
pub const CONNECT_BUDGET_MS: u64 = 50;
pub const OP_TIMEOUT_POLICY_MS: u64 = 50;
pub const OP_TIMEOUT_SUBMIT_MS: u64 = 250;
pub const OP_TIMEOUT_CALL_MS: u64 = 20;
pub const OP_TIMEOUT_KILL_MS: u64 = 50;
pub const OP_TIMEOUT_QUARANTINE_MS: u64 = 100;
pub const OP_TIMEOUT_RELEASE_MS: u64 = 2000;
/// Helper side: a connection with no complete frame for this long is closed.
pub const SERVER_IDLE_MS: u64 = 5000;
/// Helper side: a frame whose bytes trickle in slower than this is dropped.
pub const SERVER_FRAME_DEADLINE_MS: u64 = 1000;
/// Helper side: concurrent connections beyond this are refused with `busy`.
pub const SERVER_MAX_CONNECTIONS: usize = 64;
