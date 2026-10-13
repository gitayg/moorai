//! moorai-guardd: the privileged helper of the trust-anchor design, phase 2
//! (docs/proposals/trust-anchors.md §4; wire contract docs/proposals/guardd-contract.md).
//!
//! Wire-format items (canonical, keys, signing, ipc::frame, ipc::messages, beat/alerts/push bodies)
//! are pinned by test/fixtures/guardd/golden.json. The core behaviour (IPC server, state, device key,
//! registration, policy, alert queue, beat, push channel, observation, quarantine decisions) is
//! implemented here; the per-OS mechanics are behind the traits of crate::platform, crate::observe
//! (ProcessSource) and crate::quarantine (QuarantineBackend), owned by the platform agents.

pub mod alerts;
pub mod beat;
pub mod canonical;
pub mod clock;
pub mod config;
pub mod console;
pub mod helper;
pub mod ipc;
pub mod keys;
pub mod observe;
pub mod platform;
pub mod policy;
pub mod push;
pub mod quarantine;
pub mod signing;
pub mod state;
pub mod transport;

pub const HELPER_VERSION: &str = env!("CARGO_PKG_VERSION");
