//! Policy fetch and verification in the helper (contract §3.4 `policy`, §4). Port of the hook's
//! verifier (cli/hook-core.mjs verifyPolicySignature / policyTrust / armPolicyPin / applyKeyRevocation /
//! isPolicyRollback / policyMaxAgeMs): ed25519 over `moorai-policy|v1|<tenant>|<iat>|<digest>`, keys from
//! the root anchor or the helper's own pin (TOFU from /api/policy/pubkey on first contact), high-water
//! mark on iat, cache and last-known-good, console back-off. All of it is root-held on a T2 device, and
//! the helper is the only process that fetches; the hook re-verifies what it is handed.

use crate::canonical::{js_canonical_json, js_number, sha256_hex};
use crate::clock::{iso_ms, parse_iso_ms};
use crate::console::{ConsoleError, ConsoleTransport, HttpRequest};
use crate::ipc::{PolicyResp, PolicySource};
use crate::state::{files, load_json, save_json};
use base64::engine::general_purpose::{STANDARD as B64, STANDARD_NO_PAD as B64NP};
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::path::{Path, PathBuf};

/// Fetch cadence: every 60 s while any hook call arrived in the last 10 min, else every 10 min.
pub const FETCH_ACTIVE_SEC: u64 = 60;
pub const FETCH_IDLE_SEC: u64 = 600;
pub const ACTIVE_WINDOW_SEC: u64 = 600;
/// Default max age before `source` turns from fresh to cache (signed `policyMaxAgeMinutes` overrides).
pub const DEFAULT_MAX_AGE_MIN: u64 = 15;
pub const POLICY_PATH: &str = "/api/policy";
pub const PUBKEY_PATH: &str = "/api/policy/pubkey";
/// Console back-off after a fetch with no HTTP response (cli/console-backoff.mjs constants).
pub const BACKOFF_BASE_MS: u64 = 60_000;
pub const BACKOFF_CAP_MS: u64 = 300_000;
pub const FETCH_TIMEOUT_MS: u64 = 10_000;
/// An IPC `policy` request is answered from the held policy when it was fetched for the request's actor
/// within this window (the hook's own cache window, cli/hook-core.mjs loadVerifiedPolicy); otherwise the
/// helper fetches on demand, bounded by ON_DEMAND_FETCH_MS, and answers with what it then holds.
pub const ON_DEMAND_FRESH_MS: u64 = 60_000;
pub const ON_DEMAND_FETCH_MS: u64 = 1_000;
/// At most this many OS users each bind one actor, and at most this many actor policies are held (least
/// recently used out).
pub const MAX_ACTORS: usize = 16;
/// At most this many actors are ever tied to a uid in one helper lifetime (`actor_uid`); past it a new
/// actor is refused (`none`, the hook's direct path), never bound by forgetting an old tie.
pub const MAX_ACTOR_UIDS: usize = 4096;

/// The hook's keyed actor as /api/policy names it (cli/hook-core.mjs loadVerifiedPolicy): `h2:` + 16..64
/// lowercase hex. Anything else is never put on the wire.
pub fn valid_actor(a: &str) -> bool {
    let Some(hex) = a.strip_prefix("h2:") else { return false };
    (16..=64).contains(&hex.len()) && hex.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Domain-separation label of the hook's keyed hash (cli/content-hash.mjs KEY_LABEL).
pub const ACTOR_KEY_LABEL: &str = "moorai/content-hash/v2";

/// The keyed actor of `user`@`host` under `install_token`, byte for byte as the hook computes it
/// (cli/content-hash.mjs actorHash = hashWithKey(deriveKey(installToken), `${user}@${host}`)):
/// key = HMAC-SHA-256(installToken, ACTOR_KEY_LABEL); actor = "h2:" + the first 16 lowercase hex of
/// HMAC-SHA-256(key, user + "@" + host). No normalisation of either part. None when the token, the login
/// name or the hostname is empty (the hook's NO_KEY is never a valid actor), so nothing actor-scoped is
/// served for that peer. Vectors: guardd/tests/fixtures/actor-vectors.json.
pub fn derive_actor(install_token: Option<&str>, user: &str, host: &str) -> Option<String> {
    use ring::hmac;
    let token = install_token.filter(|t| !t.is_empty())?;
    if user.is_empty() || host.is_empty() {
        return None;
    }
    let key = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, token.as_bytes()), ACTOR_KEY_LABEL.as_bytes());
    let tag = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key.as_ref()), format!("{user}@{host}").as_bytes());
    Some(format!("h2:{}", tag.as_ref()[..8].iter().map(|b| format!("{b:02x}")).collect::<String>()))
}

#[derive(Debug, Clone, PartialEq)]
pub struct HeldPolicy {
    /// Exact bytes served by GET /api/policy.
    pub text: String,
    pub iat: String,
    pub fetched_at: String,
    pub source: PolicySource,
    /// policyMaxAgeMs of this policy (signed `policyMaxAgeMinutes`, 1..10080, else 15 min).
    pub max_age_ms: u64,
    /// The actor the fetch that produced it named (None: no actor).
    pub actor: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyStatus {
    Ok,
    /// No trust key at all (never anchored, never pinned): trusted, as the hook's no-brick rule.
    Unanchored,
    Unsigned,
    Malformed,
    Untrusted,
    Mismatch,
    Rollback,
}

impl VerifyStatus {
    pub fn trusted(&self) -> bool {
        matches!(self, VerifyStatus::Ok | VerifyStatus::Unanchored)
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            VerifyStatus::Ok => "ok",
            VerifyStatus::Unanchored => "unanchored",
            VerifyStatus::Unsigned => "unsigned",
            VerifyStatus::Malformed => "malformed",
            VerifyStatus::Untrusted => "untrusted",
            VerifyStatus::Mismatch => "mismatch",
            VerifyStatus::Rollback => "rollback",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Verdict {
    pub status: VerifyStatus,
    /// SPKI base64 of the key that verified (hook-core publicKeyId form).
    pub key: Option<String>,
    pub iat: Option<String>,
    pub max_age_ms: u64,
    pub policy: Option<Map<String, Value>>,
}

fn verdict(status: VerifyStatus) -> Verdict {
    Verdict { status, key: None, iat: None, max_age_ms: DEFAULT_MAX_AGE_MIN * 60_000, policy: None }
}

/// JavaScript `String(x)` for the scalar forms a policySig field can take; None for objects/arrays.
fn js_string(v: Option<&Value>) -> Option<String> {
    match v {
        None | Some(Value::Null) => Some(String::new()),
        Some(Value::String(s)) => Some(s.clone()),
        Some(Value::Number(n)) => Some(js_number(n.as_f64().unwrap_or(f64::NAN))),
        Some(Value::Bool(b)) => Some(b.to_string()),
        _ => None,
    }
}

/// policyMaxAgeMs (hook-core): the signed `policyMaxAgeMinutes` when 1..=10080, else 15 minutes.
pub fn max_age_ms(policy: &Map<String, Value>) -> u64 {
    let m = match policy.get("policyMaxAgeMinutes") {
        Some(Value::Number(n)) => n.as_f64(),
        Some(Value::String(s)) => s.trim().parse::<f64>().ok(),
        _ => None,
    };
    match m {
        Some(m) if m.is_finite() && (1.0..=10080.0).contains(&m) => (m * 60_000.0).round() as u64,
        _ => DEFAULT_MAX_AGE_MIN * 60_000,
    }
}

/// isPolicyRollback: strictly older than the mark, and both sides parseable.
pub fn is_rollback(iat: &str, mark: Option<&str>) -> bool {
    match (parse_iso_ms(iat), mark.and_then(parse_iso_ms)) {
        (Some(a), Some(b)) => a < b,
        _ => false,
    }
}

/// maxIat: the later of two marks; an unparseable side loses.
pub fn max_iat(a: Option<&str>, b: Option<&str>) -> Option<String> {
    match (a.and_then(|x| parse_iso_ms(x).map(|t| (t, x))), b.and_then(|x| parse_iso_ms(x).map(|t| (t, x)))) {
        (Some((ta, xa)), Some((tb, xb))) => Some(if tb > ta { xb } else { xa }.to_string()),
        (Some((_, x)), None) | (None, Some((_, x))) => Some(x.to_string()),
        (None, None) => None,
    }
}

fn decode_sig(s: &str) -> Option<Vec<u8>> {
    B64.decode(s).or_else(|_| B64NP.decode(s.trim_end_matches('='))).ok()
}

/// The full verifier: hook-core verifyPolicySignature plus the high-water-mark refusal of
/// loadVerifiedPolicy's verify(). `keys` are SPKI base64.
pub fn verify_detailed(text: &str, keys: &[String], tenant: &str, hwm: Option<&str>) -> Verdict {
    let parsed: Value = match serde_json::from_str(text) {
        Ok(v) => v,
        Err(_) => return verdict(VerifyStatus::Malformed),
    };
    let Value::Object(policy) = parsed else { return verdict(VerifyStatus::Malformed) };
    let max_age = max_age_ms(&policy);
    let sig_env = policy.get("policySig").and_then(Value::as_object);
    let iat = sig_env.and_then(|s| s.get("iat")).and_then(Value::as_str).map(str::to_string);
    if keys.is_empty() {
        return Verdict { status: VerifyStatus::Unanchored, key: None, iat, max_age_ms: max_age, policy: Some(policy) };
    }
    let Some(s) = sig_env else { return verdict(VerifyStatus::Unsigned) };
    let Some(sig) = s.get("sig").and_then(Value::as_str).filter(|x| !x.is_empty()) else {
        return verdict(VerifyStatus::Unsigned);
    };
    let v_ok = match s.get("v") {
        Some(Value::Number(n)) => n.as_f64() == Some(1.0),
        Some(Value::String(x)) => x.trim().parse::<f64>().ok() == Some(1.0),
        _ => false,
    };
    let iat_str = match s.get("iat") {
        Some(Value::String(x)) if !x.is_empty() => Some(x.clone()),
        Some(Value::Number(n)) if n.as_f64() != Some(0.0) => Some(js_number(n.as_f64().unwrap_or(f64::NAN))),
        _ => None,
    };
    let (Some(iat_s), true, Some("ed25519")) = (iat_str, v_ok, s.get("alg").and_then(Value::as_str)) else {
        return verdict(VerifyStatus::Malformed);
    };
    let Some(sig_tenant) = js_string(s.get("tenant")) else { return verdict(VerifyStatus::Malformed) };
    let mut body = policy.clone();
    body.remove("policySig");
    let digest = sha256_hex(js_canonical_json(&Value::Object(body)).as_bytes());
    let msg = format!("moorai-policy|v1|{sig_tenant}|{iat_s}|{digest}");
    let Some(sig_bytes) = decode_sig(sig) else { return verdict(VerifyStatus::Malformed) };
    let sig_b64 = B64.encode(&sig_bytes);
    let Some(hit) = keys.iter().find(|k| crate::keys::verify_b64(k, msg.as_bytes(), &sig_b64).is_ok()) else {
        return verdict(VerifyStatus::Untrusted);
    };
    if sig_tenant != tenant {
        return verdict(VerifyStatus::Mismatch);
    }
    if is_rollback(&iat_s, hwm) {
        return verdict(VerifyStatus::Rollback);
    }
    Verdict { status: VerifyStatus::Ok, key: Some(hit.clone()), iat: Some(iat_s), max_age_ms: max_age, policy: Some(policy) }
}

/// Verify a served policy against `keys` (SPKI base64) for `tenant`, refusing an iat below `hwm`.
pub fn verify(text: &str, keys: &[String], tenant: &str, hwm: Option<&str>) -> VerifyStatus {
    verify_detailed(text, keys, tenant, hwm).status
}

/// parseTrustedKeys: PEM blocks and/or one base64 SPKI DER per line, `#` comments; entries that are not
/// an ed25519 SPKI are skipped. Returns the canonical SPKI base64 of each.
pub fn parse_trusted_keys(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut rest = text.to_string();
    const BEGIN: &str = "-----BEGIN PUBLIC KEY-----";
    const END: &str = "-----END PUBLIC KEY-----";
    while let Some(b) = rest.find(BEGIN) {
        let Some(e) = rest[b..].find(END) else { break };
        let body: String = rest[b + BEGIN.len()..b + e].chars().filter(|c| !c.is_whitespace()).collect();
        if let Ok(raw) = crate::keys::raw_from_spki_b64(&body) {
            out.push(crate::keys::spki_b64_of_raw(&raw));
        }
        rest.replace_range(b..b + e + END.len(), "");
    }
    for line in rest.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        if let Ok(raw) = crate::keys::raw_from_spki_b64(t) {
            out.push(crate::keys::spki_b64_of_raw(&raw));
        }
    }
    let mut seen = std::collections::BTreeSet::new();
    out.retain(|k| seen.insert(k.clone()));
    out
}

/// parsePublishedKeys: GET /api/policy/pubkey body -> keys for THIS tenant (`keys[]`, `publicKey`, `pem`).
pub fn parse_published_keys(text: &str, tenant: &str) -> Vec<String> {
    let Ok(Value::Object(j)) = serde_json::from_str::<Value>(text) else { return vec![] };
    if !tenant.is_empty() {
        if let Some(t) = j.get("tenant").filter(|t| !t.is_null()) {
            if js_string(Some(t)).as_deref() != Some(tenant) {
                return vec![];
            }
        }
    }
    let mut parts = Vec::new();
    fn push(v: &Value, parts: &mut Vec<String>) {
        match v {
            Value::String(s) => parts.push(s.clone()),
            Value::Object(o) => {
                for k in ["pem", "publicKey"] {
                    if let Some(x) = o.get(k) {
                        push(x, parts);
                    }
                }
            }
            _ => {}
        }
    }
    if let Some(Value::Array(a)) = j.get("keys") {
        a.iter().for_each(|x| push(x, &mut parts));
    }
    for k in ["publicKey", "pem"] {
        if let Some(x) = j.get(k) {
            push(x, &mut parts);
        }
    }
    parse_trusted_keys(&parts.join("\n"))
}

/// `nextKeys`: the signed key-rotation list inside the policy body (covered by the digest). Not in
/// hook-core yet; see the contract deviation note.
pub fn parse_next_keys(policy: &Map<String, Value>) -> Vec<String> {
    match policy.get("nextKeys") {
        Some(Value::Array(a)) => parse_trusted_keys(&a.iter().filter_map(Value::as_str).collect::<Vec<_>>().join("\n")),
        _ => vec![],
    }
}

/// parseRevokedKeys: the signed body's `revokedKeys`, trimmed and de-duplicated.
pub fn parse_revoked_keys(policy: &Map<String, Value>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    if let Some(Value::Array(a)) = policy.get("revokedKeys") {
        for k in a.iter().filter_map(Value::as_str).map(str::trim).filter(|k| !k.is_empty()) {
            if !out.iter().any(|x| x == k) {
                out.push(k.to_string());
            }
        }
    }
    out
}

/// applyKeyRevocation: prune revoked ids unless the policy revokes its own verifier ("self") or the
/// pin would end up empty ("empty"); a refused revocation prunes nothing.
pub fn apply_key_revocation(keys: &[String], revoked: &[String], verified_by: Option<&str>) -> (Vec<String>, Option<&'static str>) {
    if !keys.iter().any(|k| revoked.contains(k)) {
        return (keys.to_vec(), None);
    }
    match verified_by {
        None => return (keys.to_vec(), Some("self")),
        Some(v) if revoked.iter().any(|r| r == v) => return (keys.to_vec(), Some("self")),
        _ => {}
    }
    let kept: Vec<String> = keys.iter().filter(|k| !revoked.contains(k)).cloned().collect();
    if kept.is_empty() {
        return (keys.to_vec(), Some("empty"));
    }
    (kept, None)
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Stored {
    pub text: String,
    #[serde(default)]
    pub iat: String,
    pub fetched_at: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub actor: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Pin {
    pub v: u32,
    pub tenant: String,
    pub keys: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Hwm {
    pub v: u32,
    pub tenant: String,
    pub iat: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Backoff {
    pub failed_at_ms: u64,
    pub failures: u32,
}

impl Backoff {
    /// backoffDelay: 60 s * 2^(n-1), capped at 300 s.
    pub fn window_ms(&self) -> u64 {
        if self.failures == 0 {
            return 0;
        }
        BACKOFF_CAP_MS.min(BACKOFF_BASE_MS.saturating_mul(1u64 << (self.failures - 1).min(20)))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustMode {
    Anchored,
    Pinned,
    Unpinned,
}

/// Everything policy-related the helper holds, persisted in the state dir.
pub struct PolicyStore {
    state_dir: PathBuf,
    admin_anchor: Vec<String>,
    admin_hwm: Option<String>,
    pub cache: Option<Stored>,
    pub lkg: Option<Stored>,
    pub pin: Option<Pin>,
    pub hwm: Option<Hwm>,
    pub backoff: Backoff,
    pub last_call_ms: u64,
    pub held: Option<HeldPolicy>,
    /// Policies fetched for a hook's actor (they carry that actor's approvals and receipts), keyed by
    /// actor, in memory only. `held` (and the cache and last-known-good on disk) is only ever the
    /// actor-less policy of the background fetch, so an actor's approvals reach no one else.
    pub by_actor: std::collections::BTreeMap<String, HeldPolicy>,
    /// Which OS user (IPC peer uid, a kernel fact) holds which actor: one actor per uid, and an actor held
    /// by one uid is refused to every other uid. In memory; a helper restart clears it. Only an actor the
    /// helper derived for that uid (derive_actor) is ever bound, so the binding cannot be raced.
    pub uid_actor: std::collections::BTreeMap<u32, (String, u64)>,
    /// The first uid each actor was bound to, kept for the helper's lifetime (never evicted with
    /// `uid_actor`). Two uids with one login name derive one actor; without this, evicting the first uid's
    /// binding would let the second bind the actor and be served the first's approvals and receipts.
    pub actor_uid: std::collections::BTreeMap<String, u32>,
    /// Fetch tickets, per actor ("" = the actor-less fetch): an answer that arrives after a later-started
    /// fetch for the same actor was applied is dropped, so fetches never apply out of order.
    fetch_seq: u64,
    applied: std::collections::BTreeMap<String, u64>,
}

/// A content-free tamper finding from a fetch: (source, status) as hook-core's `rejected` pairs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rejected {
    pub source: &'static str,
    pub status: String,
}

pub struct FetchResult {
    /// Whether any HTTP response arrived (clears the back-off).
    pub reached: bool,
    /// The policy body of a 2xx answer.
    pub policy: Option<String>,
    /// The /api/policy/pubkey body of a 2xx answer.
    pub published: Option<String>,
    /// The actor the policy request named.
    pub actor: Option<String>,
}

fn load_or_none<T: serde::de::DeserializeOwned>(p: &Path) -> Option<T> {
    match load_json(p) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("moorai-guardd: ignoring unusable {}: {e}", p.display());
            None
        }
    }
}

impl PolicyStore {
    /// Load the state files and the admin anchor / admin HWM (read through the ownership checks).
    pub fn open(paths: &crate::state::Paths, tenant: Option<&str>) -> PolicyStore {
        let owner = paths.admin_owner();
        let admin_anchor = crate::config::read_owned_under(&paths.policy_pub, &paths.trust_root, owner)
            .map(|b| parse_trusted_keys(&String::from_utf8_lossy(&b)))
            .unwrap_or_default();
        let admin_hwm = crate::config::read_owned_under(&paths.policy_hwm_admin, &paths.trust_root, owner)
            .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
            .and_then(|j| {
                let ok_v = j.get("v").and_then(Value::as_f64) == Some(1.0);
                let ok_t = tenant.map_or(true, |t| j.get("tenant").and_then(Value::as_str) == Some(t));
                let iat = j.get("iat").and_then(Value::as_str)?.to_string();
                (ok_v && ok_t && parse_iso_ms(&iat).is_some()).then_some(iat)
            });
        let d = &paths.state_dir;
        let cache: Option<Stored> = load_or_none(&d.join(files::POLICY_CACHE));
        let mut s = PolicyStore {
            state_dir: d.clone(),
            admin_anchor,
            admin_hwm,
            cache,
            lkg: load_or_none(&d.join(files::POLICY_LKG)),
            pin: load_or_none(&d.join(files::POLICY_PIN)),
            hwm: load_or_none(&d.join(files::POLICY_HWM)),
            backoff: load_or_none(&d.join(files::BACKOFF)).unwrap_or_default(),
            last_call_ms: 0,
            held: None,
            by_actor: Default::default(),
            uid_actor: Default::default(),
            actor_uid: Default::default(),
            fetch_seq: 0,
            applied: Default::default(),
        };
        if let Some(t) = tenant {
            s.select_held(t, crate::clock::now_ms());
        }
        s
    }

    /// The binding's tenant changed (an administrator action): the pin and mark of the old tenant can
    /// verify nothing for the new one, so they are dropped together with the cached policies.
    pub fn reset_for_tenant_change(&mut self) -> std::io::Result<()> {
        for f in [files::POLICY_CACHE, files::POLICY_LKG, files::POLICY_PIN, files::POLICY_HWM] {
            match std::fs::remove_file(self.state_dir.join(f)) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e),
                _ => {}
            }
        }
        self.cache = None;
        self.lkg = None;
        self.pin = None;
        self.hwm = None;
        self.held = None;
        Ok(())
    }

    /// policyTrust: the admin anchor decides when present, else this helper's own pin (a pin for
    /// another tenant verifies nothing: `None` keys = refuse everything), else unpinned.
    pub fn trust(&self, tenant: &str) -> (TrustMode, Option<Vec<String>>) {
        if !self.admin_anchor.is_empty() {
            return (TrustMode::Anchored, Some(self.admin_anchor.clone()));
        }
        match &self.pin {
            None => (TrustMode::Unpinned, Some(vec![])),
            Some(p) if p.tenant != tenant => (TrustMode::Pinned, None),
            Some(p) => {
                let keys = parse_trusted_keys(&p.keys.join("\n"));
                (TrustMode::Pinned, if keys.is_empty() { None } else { Some(keys) })
            }
        }
    }

    /// The keys console commands verify against (§9.3): the same anchor or pin as policy. An
    /// unpinned helper verifies no command.
    pub fn command_keys(&self, tenant: &str) -> Vec<String> {
        self.trust(tenant).1.unwrap_or_default()
    }

    /// The effective rollback mark: the helper's own, or the admin one, whichever is later.
    pub fn mark(&self, tenant: &str) -> Option<String> {
        let own = self.hwm.as_ref().filter(|h| h.tenant == tenant).map(|h| h.iat.as_str());
        max_iat(own, self.admin_hwm.as_deref())
    }

    fn check(&self, text: &str, tenant: &str) -> Verdict {
        match self.trust(tenant).1 {
            None => verdict(VerifyStatus::Untrusted),
            Some(keys) => verify_detailed(text, &keys, tenant, self.mark(tenant).as_deref()),
        }
    }

    /// Re-verify the cache, then the LKG, under the current trust and mark; set `held`.
    pub fn select_held(&mut self, tenant: &str, now_ms: u64) {
        let pick = |s: &Stored, source: PolicySource| -> Option<HeldPolicy> {
            let v = self.check(&s.text, tenant);
            v.status.trusted().then(|| HeldPolicy {
                text: s.text.clone(),
                iat: v.iat.clone().unwrap_or_default(),
                fetched_at: s.fetched_at.clone(),
                source,
                max_age_ms: v.max_age_ms,
                actor: s.actor.clone(),
            })
        };
        // A stored copy that names an actor (written by an earlier build) is never the actor-less policy.
        let held = self.cache.as_ref().filter(|c| c.actor.is_none()).and_then(|c| pick(c, PolicySource::Fresh)).or_else(|| self.lkg.as_ref().filter(|l| l.actor.is_none()).and_then(|l| pick(l, PolicySource::Lkg)));
        self.held = held.map(|mut h| {
            if h.source == PolicySource::Fresh && !is_fresh(&h, now_ms) {
                h.source = PolicySource::Cache;
            }
            h
        });
    }

    /// Whether a hook `call` arrived inside the active window.
    pub fn active(&self, now_ms: u64) -> bool {
        self.last_call_ms > 0 && now_ms.saturating_sub(self.last_call_ms) < ACTIVE_WINDOW_SEC * 1000
    }

    /// Delay before the next fetch: the cadence, stretched by the console back-off.
    pub fn next_fetch_delay_ms(&self, now_ms: u64) -> u64 {
        let cadence = if self.active(now_ms) { FETCH_ACTIVE_SEC } else { FETCH_IDLE_SEC } * 1000;
        let elapsed = now_ms.saturating_sub(self.backoff.failed_at_ms);
        let remaining = if self.backoff.failures > 0 && self.backoff.failed_at_ms <= now_ms { self.backoff.window_ms().saturating_sub(elapsed) } else { 0 };
        cadence.max(remaining)
    }

    /// Whether an IPC `policy` request naming `actor` should fetch before it is answered: the held policy
    /// is missing, was fetched for another actor, or is older than ON_DEMAND_FRESH_MS. Never while the
    /// console back-off is open (the console did not answer recently) or before the first trusted key is
    /// pinned (the background loop does the trust-on-first-use fetch).
    /// Bind `actor` to the peer `uid` (one actor per uid; the uid's previous actor and its policy are
    /// dropped). false = another uid was the first to bind this actor in this helper's lifetime (even if
    /// its binding has since been evicted), or MAX_ACTOR_UIDS actors are already tied: the request is
    /// answered `none` and fetches nothing. The caller binds only the actor it derived for `uid`
    /// (helper::peer_actor), never a claimed one.
    pub fn bind_actor(&mut self, uid: u32, actor: &str, now_ms: u64) -> bool {
        match self.actor_uid.get(actor) {
            Some(&first) if first != uid => return false,
            Some(_) => {}
            None if self.actor_uid.len() >= MAX_ACTOR_UIDS => return false,
            None => {
                self.actor_uid.insert(actor.to_string(), uid);
            }
        }
        if let Some((old, _)) = self.uid_actor.insert(uid, (actor.to_string(), now_ms)) {
            if old != actor {
                self.by_actor.remove(&old);
            }
        }
        while self.uid_actor.len() > MAX_ACTORS {
            let Some((&lru, _)) = self.uid_actor.iter().min_by_key(|(_, (_, t))| *t) else { break };
            if let Some((a, _)) = self.uid_actor.remove(&lru) {
                self.by_actor.remove(&a);
            }
        }
        true
    }

    fn actor_bound(&self, actor: &str) -> bool {
        self.uid_actor.values().any(|(a, _)| a == actor)
    }

    /// The answer to an IPC `policy` request: an actor's own held policy, or `none` when there is none
    /// for that actor (the hook then takes its direct path); without an actor, the actor-less policy.
    pub fn answer_for(&self, actor: Option<&str>, if_iat: Option<&str>, now_ms: u64) -> PolicyResp {
        match actor {
            Some(a) => answer(self.by_actor.get(a), if_iat, now_ms),
            None => answer(self.held.as_ref(), if_iat, now_ms),
        }
    }

    pub fn needs_on_demand(&self, tenant: &str, actor: Option<&str>, now_ms: u64) -> bool {
        if self.trust(tenant).0 == TrustMode::Unpinned {
            return false;
        }
        if self.backoff.failures > 0 && now_ms.saturating_sub(self.backoff.failed_at_ms) < self.backoff.window_ms() {
            return false;
        }
        let held = match actor {
            Some(a) => self.by_actor.get(a),
            None => self.held.as_ref(),
        };
        match held {
            None => true,
            Some(h) => {
                let age = parse_iso_ms(&h.fetched_at).map(|t| (now_ms as i64).saturating_sub(t)).unwrap_or(i64::MAX);
                age < 0 || age >= ON_DEMAND_FRESH_MS as i64
            }
        }
    }

    /// The requests of one fetch cycle: the policy (naming `actor` when given), plus the published key
    /// unless anchored or pinned. The caller signs the policy request with the device key (fetch_cycle_with).
    pub fn plan(&self, binding: &crate::config::Binding) -> Vec<HttpRequest> {
        self.plan_for(binding, None)
    }

    pub fn plan_for(&self, binding: &crate::config::Binding, actor: Option<&str>) -> Vec<HttpRequest> {
        let token = binding.secret.install_token.clone().unwrap_or_default();
        let get = |p: String| HttpRequest { method: "GET", path_and_query: p, headers: vec![(crate::console::H_INSTALL_TOKEN, token.clone())], body: vec![] };
        let actor = actor.filter(|a| valid_actor(a)).map(|a| format!("&actor={}", encode_uri_component(a))).unwrap_or_default();
        let mut out = vec![get(format!("{POLICY_PATH}?tenant={}{actor}", encode_uri_component(&binding.tenant)))];
        // The unsigned /api/policy/pubkey is read ONLY on first contact (trust on first use). Once
        // pinned, keys change only through a signed `nextKeys` list (see `arm_pin`).
        if self.trust(&binding.tenant).0 == TrustMode::Unpinned {
            out.push(get(PUBKEY_PATH.to_string()));
        }
        out
    }

    /// Apply one fetch's result (hook-core loadVerifiedPolicy's network leg plus armPolicyPin).
    pub fn apply(&mut self, tenant: &str, r: FetchResult, now_ms: u64) -> std::io::Result<Vec<Rejected>> {
        let mut rejected = Vec::new();
        if r.reached {
            if self.backoff.failures > 0 {
                self.backoff = Backoff::default();
                let _ = std::fs::remove_file(self.state_dir.join(files::BACKOFF));
            }
        } else {
            self.backoff = Backoff { failed_at_ms: now_ms, failures: (self.backoff.failures + 1).min(32) };
            save_json(&self.state_dir.join(files::BACKOFF), &self.backoff)?;
        }
        if let Some(raw) = r.policy.filter(|t| !t.trim().is_empty()) {
            let (mode, _) = self.trust(tenant);
            let v = self.check(&raw, tenant);
            if v.status.trusted() && r.actor.is_some() {
                // An actor's policy: it still maintains the pin and the mark (a real signature), but it is
                // held only for that actor, in memory, never as the cache or last-known-good, and only while
                // some uid still holds the actor.
                let policy = v.policy.clone().unwrap_or_default();
                self.arm_pin(tenant, mode, &v, &raw, &policy, None, &mut rejected)?;
                let a = r.actor.clone().unwrap_or_default();
                if self.actor_bound(&a) {
                    let h = HeldPolicy { text: raw.clone(), iat: v.iat.clone().unwrap_or_default(), fetched_at: iso_ms(now_ms as i64), source: PolicySource::Fresh, max_age_ms: v.max_age_ms, actor: Some(a.clone()) };
                    self.by_actor.insert(a, h);
                    while self.by_actor.len() > MAX_ACTORS {
                        let Some(oldest) = self.by_actor.iter().min_by_key(|(_, h)| parse_iso_ms(&h.fetched_at).unwrap_or(0)).map(|(k, _)| k.clone()) else { break };
                        self.by_actor.remove(&oldest);
                    }
                }
            } else if v.status.trusted() {
                let policy = v.policy.clone().unwrap_or_default();
                let stored = Stored { text: raw.clone(), iat: v.iat.clone().unwrap_or_default(), fetched_at: iso_ms(now_ms as i64), actor: None };
                save_json(&self.state_dir.join(files::POLICY_CACHE), &stored)?;
                self.cache = Some(stored.clone());
                let armed = self.arm_pin(tenant, mode, &v, &raw, &policy, r.published.as_deref(), &mut rejected)?;
                if v.status == VerifyStatus::Ok || armed {
                    save_json(&self.state_dir.join(files::POLICY_LKG), &stored)?;
                    self.lkg = Some(stored);
                }
            } else if v.status != VerifyStatus::Malformed {
                rejected.push(Rejected { source: "server", status: v.status.as_str().to_string() });
            }
        }
        self.select_held(tenant, now_ms);
        Ok(rejected)
    }

    fn arm_pin(&mut self, tenant: &str, mode: TrustMode, v: &Verdict, raw: &str, policy: &Map<String, Value>, published_raw: Option<&str>, rejected: &mut Vec<Rejected>) -> std::io::Result<bool> {
        let mark_before = self.mark(tenant);
        let mut verified_by = v.key.clone();
        let mut learn: Vec<String> = match mode {
            TrustMode::Anchored => v.key.iter().cloned().collect(),
            // Deviation from hook-core armPolicyPin (which also learns the unsigned published keys
            // here): a pinned helper learns new keys ONLY from `nextKeys` inside a policy that verified
            // under an already-pinned key, and only when its iat is strictly above the mark, so neither
            // a console impersonator nor a replayed policy can rotate the pin.
            TrustMode::Pinned => {
                let next = parse_next_keys(policy);
                let newer = match (v.iat.as_deref().and_then(parse_iso_ms), mark_before.as_deref().and_then(parse_iso_ms)) {
                    (Some(a), Some(b)) => a > b,
                    (Some(_), None) => true,
                    _ => false,
                };
                if !next.is_empty() && !newer {
                    rejected.push(Rejected { source: "nextKeys", status: "not-newer".into() });
                }
                v.key.iter().cloned().chain(if newer { next } else { vec![] }).collect()
            }
            TrustMode::Unpinned if published_raw.is_some() => {
                let published = published_raw.map(|p| parse_published_keys(p, tenant)).unwrap_or_default();
                let t = verify_detailed(raw, &published, tenant, None);
                if t.status == VerifyStatus::Ok {
                    verified_by = t.key.clone();
                    t.key.into_iter().collect()
                } else {
                    vec![]
                }
            }
            TrustMode::Unpinned => vec![],
        };
        learn.retain(|k| !k.is_empty());
        let armed = !learn.is_empty();
        let mut keys: Vec<String> = self.pin.as_ref().filter(|p| p.tenant == tenant).map(|p| p.keys.clone()).unwrap_or_default();
        for k in learn {
            if !keys.contains(&k) {
                keys.push(k);
            }
        }
        let (keys, refused) = apply_key_revocation(&keys, &parse_revoked_keys(policy), verified_by.as_deref());
        if let Some(r) = refused {
            rejected.push(Rejected { source: "revocation", status: r.to_string() });
        }
        if !keys.is_empty() && self.pin.as_ref().map(|p| (&p.tenant, &p.keys)) != Some((&tenant.to_string(), &keys)) {
            let pin = Pin { v: 1, tenant: tenant.to_string(), keys };
            save_json(&self.state_dir.join(files::POLICY_PIN), &pin)?;
            self.pin = Some(pin);
        }
        if armed || v.status == VerifyStatus::Ok {
            let own = self.hwm.as_ref().filter(|h| h.tenant == tenant).map(|h| h.iat.clone());
            if let Some(m) = max_iat(own.as_deref(), v.iat.as_deref()) {
                if own.as_deref() != Some(m.as_str()) {
                    let h = Hwm { v: 1, tenant: tenant.to_string(), iat: m };
                    save_json(&self.state_dir.join(files::POLICY_HWM), &h)?;
                    self.hwm = Some(h);
                }
            }
        }
        Ok(armed)
    }
}

fn is_fresh(h: &HeldPolicy, now_ms: u64) -> bool {
    let at = parse_iso_ms(&h.iat).or_else(|| parse_iso_ms(&h.fetched_at));
    match at {
        Some(t) => (now_ms as i64).saturating_sub(t).max(0) < h.max_age_ms as i64,
        None => false,
    }
}

/// encodeURIComponent.
pub fn encode_uri_component(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// One fetch cycle over `transport` (network outside any lock is the caller's concern: this takes
/// the planned requests and returns the result to `PolicyStore::apply`).
pub fn fetch(transport: &dyn ConsoleTransport, origin: &str, reqs: Vec<HttpRequest>, timeout_ms: u64) -> FetchResult {
    let mut r = FetchResult { reached: false, policy: None, published: None, actor: None };
    for (i, req) in reqs.into_iter().enumerate() {
        match transport.send(origin, req, timeout_ms) {
            Ok(resp) => {
                r.reached = true;
                if (200..300).contains(&resp.status) {
                    let body = String::from_utf8_lossy(&resp.body).into_owned();
                    if i == 0 {
                        r.policy = Some(body);
                    } else {
                        r.published = Some(body);
                    }
                }
            }
            Err(ConsoleError::Status(..)) | Err(ConsoleError::ClockSkew { .. }) | Err(ConsoleError::BadResponse(_)) => r.reached = true,
            Err(ConsoleError::Network(_)) => {}
        }
    }
    r
}

/// One fetch cycle against shared state: plan under the lock, fetch without it, apply under it.
pub fn fetch_cycle(state: &std::sync::Mutex<crate::state::HelperState>, transport: &dyn ConsoleTransport) -> Result<Vec<Rejected>, ConsoleError> {
    fetch_cycle_with(state, transport, &crate::clock::now_ms, FETCH_TIMEOUT_MS, None)
}

/// fetch_cycle with the clock and the per-request timeout given (the IPC on-demand fetch passes
/// ON_DEMAND_FETCH_MS). Once the device key is registered, the policy request is device-signed (contract
/// §6.2: `moorai-devreq|v1|GET|<path and query as sent>|…`, X-Device-Id / -Key / -Ts / -Nonce / -Sig beside
/// X-Install-Token), the per-device credential the console needs to put approval receipts in the signed
/// policy (RAISEME-server server/approval-receipts.js receiptAuthFor). The console serves the policy
/// either way; a signature it cannot verify only withholds receipts. The policy content is still verified
/// here and again by the hook against the policy key: the device key adds no trust to policy content.
/// `actor`: None for the background (actor-less) fetch; Some for an IPC on-demand fetch, whose answer is
/// held for that actor only (PolicyStore::by_actor).
pub fn fetch_cycle_with(state: &std::sync::Mutex<crate::state::HelperState>, transport: &dyn ConsoleTransport, now: &dyn Fn() -> u64, timeout_ms: u64, actor: Option<String>) -> Result<Vec<Rejected>, ConsoleError> {
    let (binding, reqs, seq) = {
        let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
        let Some(b) = s.binding.clone() else { return Err(ConsoleError::BadResponse("no binding".into())) };
        let mut reqs = s.policy.plan_for(&b, actor.as_deref());
        if actor.is_some() {
            reqs.truncate(1);
        }
        if s.registration.is_some() {
            if let Some(first) = reqs.first_mut() {
                *first = crate::console::sign_request(&s.key, &b, &s.device_id, "GET", &first.path_and_query, vec![], s.beat.clock_offset_ms, now());
            }
        }
        s.policy.fetch_seq += 1;
        (b, reqs, s.policy.fetch_seq)
    };
    let mut r = fetch(transport, &binding.origin, reqs, timeout_ms);
    r.actor = actor;
    let key = r.actor.clone().unwrap_or_default();
    let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
    if s.policy.applied.get(&key).is_some_and(|&last| seq < last) {
        return Ok(vec![]);
    }
    s.policy.applied.insert(key, seq);
    s.policy.apply(&binding.tenant, r, now()).map_err(|e| ConsoleError::Network(e.to_string()))
}

/// Answer an IPC `policy` request.
pub fn answer(held: Option<&HeldPolicy>, if_iat: Option<&str>, now_ms: u64) -> PolicyResp {
    let Some(h) = held else {
        return PolicyResp { source: PolicySource::None, policy: None, iat: None, fetched_at: None, age_sec: None };
    };
    let source = match h.source {
        PolicySource::Fresh | PolicySource::Cache => {
            if is_fresh(h, now_ms) {
                PolicySource::Fresh
            } else {
                PolicySource::Cache
            }
        }
        s => s,
    };
    let current = if_iat.is_some() && !h.iat.is_empty() && if_iat == Some(h.iat.as_str());
    let age_sec = parse_iso_ms(&h.iat).map(|t| ((now_ms as i64 - t).max(0) / 1000) as u64);
    PolicyResp {
        source,
        policy: (!current).then(|| h.text.clone()),
        iat: (!h.iat.is_empty()).then(|| h.iat.clone()),
        fetched_at: (!h.fetched_at.is_empty()).then(|| h.fetched_at.clone()),
        age_sec,
    }
}

#[cfg(all(test, unix))]
pub mod tests {
    use super::*;
    use crate::keys::DeviceKey;
    use serde_json::json;
    use std::os::unix::fs::PermissionsExt;

    /// Sign `body` as the console does (policy-sign.js): policySig over policyCanonical(digest).
    pub fn sign_policy(body: Value, key: &DeviceKey, tenant: &str, iat: &str) -> String {
        let Value::Object(mut m) = body else { panic!("object") };
        m.remove("policySig");
        let digest = sha256_hex(js_canonical_json(&Value::Object(m.clone())).as_bytes());
        let sig = key.sign_b64(format!("moorai-policy|v1|{tenant}|{iat}|{digest}").as_bytes());
        m.insert("policySig".into(), json!({"v":1,"alg":"ed25519","tenant":tenant,"iat":iat,"sig":sig}));
        serde_json::to_string(&Value::Object(m)).unwrap()
    }

    fn k(n: u8) -> DeviceKey {
        DeviceKey::from_seed(&[n; 32]).unwrap()
    }

    const VECTORS: &str = include_str!("../tests/fixtures/policy-vectors.json");

    #[test]
    fn a_policy_signed_by_the_js_toolchain_verifies_here() {
        let v: Value = serde_json::from_str(VECTORS).unwrap();
        let keys = vec![v["publicKey"].as_str().unwrap().to_string()];
        let text = v["policyText"].as_str().unwrap();
        assert_eq!(v["jsStatus"], "ok");
        let d = verify_detailed(text, &keys, "acme", None);
        assert_eq!(d.status, VerifyStatus::Ok, "floats, 1e+21, U+2028 and astral keys digest as JS does");
        assert_eq!(d.max_age_ms, 30 * 60_000);
        let Value::Object(mut m) = serde_json::from_str::<Value>(text).unwrap() else { panic!() };
        m.remove("policySig");
        assert_eq!(sha256_hex(js_canonical_json(&Value::Object(m)).as_bytes()), v["digest"].as_str().unwrap());
        assert_eq!(v["otherTenantJsStatus"], "mismatch");
        assert_eq!(verify(v["otherTenantText"].as_str().unwrap(), &keys, "acme", None), VerifyStatus::Mismatch);
    }

    #[test]
    fn derive_actor_matches_the_hooks_vectors() {
        // Generated by cli/content-hash.mjs (guardd/tests/fixtures/gen-actor-vectors.mjs); the Node side is
        // checked against the same file by test/guardd-actor-parity.test.mjs.
        let fx: Value = serde_json::from_str(include_str!("../tests/fixtures/actor-vectors.json")).unwrap();
        assert_eq!(fx["keyLabel"], ACTOR_KEY_LABEL);
        let vs = fx["vectors"].as_array().unwrap();
        assert!(vs.len() >= 4);
        for v in vs {
            let (t, u, h, want) = (v["installToken"].as_str().unwrap(), v["user"].as_str().unwrap(), v["host"].as_str().unwrap(), v["actor"].as_str().unwrap());
            assert_eq!(derive_actor(Some(t), u, h).as_deref(), Some(want), "{u}@{h}");
            assert!(valid_actor(want));
        }
    }

    #[test]
    fn derive_actor_refuses_what_it_cannot_derive() {
        assert_eq!(derive_actor(None, "alice", "host"), None, "no install token");
        assert_eq!(derive_actor(Some(""), "alice", "host"), None, "empty install token (the hook's NO_KEY)");
        assert_eq!(derive_actor(Some("tok-acme"), "", "host"), None, "no login name");
        assert_eq!(derive_actor(Some("tok-acme"), "alice", ""), None, "no hostname");
    }

    #[test]
    fn verifier_statuses_match_hook_core() {
        let key = k(3);
        let keys = vec![key.public_spki_b64()];
        let good = sign_policy(json!({"a": 1}), &key, "acme", "2026-10-12T09:00:00.000Z");
        assert_eq!(verify(&good, &keys, "acme", None), VerifyStatus::Ok);
        assert_eq!(verify(&good, &[], "acme", None), VerifyStatus::Unanchored);
        assert_eq!(verify("not json", &keys, "acme", None), VerifyStatus::Malformed);
        assert_eq!(verify("[1]", &keys, "acme", None), VerifyStatus::Malformed);
        assert_eq!(verify(r#"{"a":1}"#, &keys, "acme", None), VerifyStatus::Unsigned);
        assert_eq!(verify(&good.replace("\"a\":1", "\"a\":2"), &keys, "acme", None), VerifyStatus::Untrusted, "body edited");
        assert_eq!(verify(&good, &[k(4).public_spki_b64()], "acme", None), VerifyStatus::Untrusted);
        assert_eq!(verify(&good.replace("\"alg\":\"ed25519\"", "\"alg\":\"rsa\""), &keys, "acme", None), VerifyStatus::Malformed);
        assert_eq!(verify(&good, &keys, "other", None), VerifyStatus::Mismatch);
        assert_eq!(verify(&good, &keys, "acme", Some("2026-10-12T10:00:00.000Z")), VerifyStatus::Rollback);
        assert_eq!(verify(&good, &keys, "acme", Some("2026-10-12T09:00:00.000Z")), VerifyStatus::Ok, "equal iat is not a rollback");
        assert_eq!(verify(&good, &keys, "acme", Some("garbage")), VerifyStatus::Ok, "an unreadable mark compares nothing");
    }

    #[test]
    fn revocation_refuses_self_and_empty() {
        let ks = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(apply_key_revocation(&ks(&["a", "b"]), &ks(&["a"]), Some("b")), (ks(&["b"]), None));
        assert_eq!(apply_key_revocation(&ks(&["a", "b"]), &ks(&["a"]), Some("a")), (ks(&["a", "b"]), Some("self")));
        assert_eq!(apply_key_revocation(&ks(&["a"]), &ks(&["a"]), Some("b")), (ks(&["a"]), Some("empty")));
        assert_eq!(apply_key_revocation(&ks(&["a"]), &ks(&["z"]), None), (ks(&["a"]), None));
    }

    #[test]
    fn trusted_keys_parse_pem_and_lines() {
        let a = k(1).public_spki_b64();
        let b = k(2).public_spki_b64();
        let text = format!("# anchor\n-----BEGIN PUBLIC KEY-----\n{}\n{}\n-----END PUBLIC KEY-----\n{b}\njunk\n{b}\n", &a[..30], &a[30..]);
        assert_eq!(parse_trusted_keys(&text), vec![a.clone(), b.clone()]);
        assert_eq!(parse_published_keys(&format!(r#"{{"tenant":"acme","keys":[{{"publicKey":"{a}"}}],"pem":"{b}"}}"#), "acme"), vec![a.clone(), b]);
        assert!(parse_published_keys(&format!(r#"{{"tenant":"evil","publicKey":"{a}"}}"#), "acme").is_empty());
    }

    fn tree(tag: &str) -> crate::state::Paths {
        let root = crate::state::test_root(&format!("pol-{tag}"));
        std::fs::create_dir_all(root.join("etc")).unwrap();
        for d in [root.clone(), root.join("etc")] {
            std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let p = crate::state::Paths::under(&root);
        crate::state::prepare_dirs(&p).unwrap();
        p
    }

    fn fetched(policy: Option<String>, published: Option<String>) -> FetchResult {
        FetchResult { reached: true, policy, published, actor: None }
    }

    const T0: u64 = 1_791_795_600_000; // 2026-10-12T09:00:00.000Z

    #[test]
    fn an_actor_stays_with_its_first_uid_even_after_lru_eviction() {
        // Two uids with one login name derive the same actor (user@host). The first uid keeps it for the
        // helper's lifetime: the second is refused before AND after the first uid's binding is evicted.
        let p = tree("actor-tombstone");
        let mut s = PolicyStore::open(&p, Some("acme"));
        let x = "h2:00000000000000000000000000000001";
        assert!(s.bind_actor(501, x, T0));
        assert!(!s.bind_actor(502, x, T0 + 1), "held by uid 501");
        for i in 0..=MAX_ACTORS as u32 {
            assert!(s.bind_actor(1000 + i, &format!("h2:{:032x}", 0x1000 + i), T0 + 10 + u64::from(i)));
        }
        assert!(!s.uid_actor.contains_key(&501), "uid 501's binding was evicted as least recently used");
        assert!(!s.bind_actor(502, x, T0 + 100), "evicting uid 501 never frees its actor for another uid");
        assert!(!s.uid_actor.values().any(|(a, _)| a == x));
        assert!(s.bind_actor(501, x, T0 + 200), "the first uid can bind it again");
    }

    #[test]
    fn past_max_actor_uids_a_new_actor_is_refused_not_bound_by_forgetting() {
        let p = tree("actor-tombstone-cap");
        let mut s = PolicyStore::open(&p, Some("acme"));
        assert!(s.bind_actor(7, "h2:00000000000000000000000000000007", T0));
        for i in 1..MAX_ACTOR_UIDS as u32 {
            s.actor_uid.insert(format!("h2:{:032x}", 0x10_0000 + i), 5000 + i);
        }
        assert_eq!(s.actor_uid.len(), MAX_ACTOR_UIDS);
        assert!(!s.bind_actor(8, "h2:00000000000000000000000000000008", T0 + 1), "full: refused");
        assert!(s.bind_actor(7, "h2:00000000000000000000000000000007", T0 + 2), "a tied actor still binds to its uid");
        assert_eq!(s.actor_uid.len(), MAX_ACTOR_UIDS);
    }

    #[test]
    fn first_contact_pins_the_published_key_then_refuses_other_keys() {
        let p = tree("tofu");
        let mut s = PolicyStore::open(&p, Some("acme"));
        assert_eq!(s.trust("acme").0, TrustMode::Unpinned);
        let key = k(3);
        let published = format!(r#"{{"tenant":"acme","publicKey":"{}"}}"#, key.public_spki_b64());
        let pol = sign_policy(json!({"a":1}), &key, "acme", "2026-10-12T09:00:00.000Z");
        s.apply("acme", fetched(Some(pol.clone()), Some(published)), T0).unwrap();
        assert_eq!(s.trust("acme"), (TrustMode::Pinned, Some(vec![key.public_spki_b64()])));
        assert_eq!(s.held.as_ref().unwrap().source, PolicySource::Fresh);
        assert!(s.lkg.is_some(), "a real signature makes it last-known-good");
        let forged = sign_policy(json!({"a":0}), &k(9), "acme", "2026-10-12T09:05:00.000Z");
        let rej = s.apply("acme", fetched(Some(forged), None), T0 + 300_000).unwrap();
        assert_eq!(rej, vec![Rejected { source: "server", status: "untrusted".into() }]);
        assert_eq!(s.held.as_ref().unwrap().text, pol, "the forged body never replaces the verified one");
        let reopened = PolicyStore::open(&p, Some("acme"));
        assert_eq!(reopened.trust("acme").0, TrustMode::Pinned, "the pin is persisted root-side");
    }

    #[test]
    fn an_unsigned_console_keeps_working_unanchored_without_lkg_or_mark() {
        let p = tree("unsigned");
        let mut s = PolicyStore::open(&p, Some("acme"));
        s.apply("acme", fetched(Some(r#"{"a":1}"#.into()), None), T0).unwrap();
        assert_eq!(s.held.as_ref().map(|h| h.source), Some(PolicySource::Fresh), "fetchedAt is the age when there is no iat");
        assert!(s.lkg.is_none() && s.hwm.is_none() && s.pin.is_none());
    }

    #[test]
    fn the_admin_anchor_decides_and_a_rollback_is_refused() {
        let p = tree("anchor");
        let key = k(3);
        std::fs::write(&p.policy_pub, format!("{}\n", key.public_spki_b64())).unwrap();
        std::fs::set_permissions(&p.policy_pub, std::fs::Permissions::from_mode(0o644)).unwrap();
        let mut s = PolicyStore::open(&p, Some("acme"));
        assert_eq!(s.trust("acme").0, TrustMode::Anchored);
        assert_eq!(s.plan(&crate::config::Binding { origin: "https://c".into(), tenant: "a b".into(), secret: crate::config::Secret { install_token: Some("t".into()), enroll_secret: None } }).iter().map(|r| r.path_and_query.clone()).collect::<Vec<_>>(), vec!["/api/policy?tenant=a%20b"], "anchored: no pubkey fetch");
        let newer = sign_policy(json!({"v":"new"}), &key, "acme", "2026-10-12T09:10:00.000Z");
        s.apply("acme", fetched(Some(newer.clone()), None), T0 + 600_000).unwrap();
        assert_eq!(s.mark("acme").as_deref(), Some("2026-10-12T09:10:00.000Z"));
        let older = sign_policy(json!({"v":"old"}), &key, "acme", "2026-10-12T09:00:00.000Z");
        let rej = s.apply("acme", fetched(Some(older), None), T0 + 700_000).unwrap();
        assert_eq!(rej, vec![Rejected { source: "server", status: "rollback".into() }]);
        assert_eq!(s.held.as_ref().unwrap().text, newer);
    }

    #[test]
    fn an_admin_hwm_above_everything_leaves_only_newer_policies() {
        let p = tree("adminhwm");
        let key = k(3);
        std::fs::write(&p.policy_pub, key.public_spki_b64()).unwrap();
        std::fs::write(&p.policy_hwm_admin, r#"{"v":1,"tenant":"acme","iat":"2026-10-12T12:00:00.000Z"}"#).unwrap();
        for f in [&p.policy_pub, &p.policy_hwm_admin] {
            std::fs::set_permissions(f, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        let mut s = PolicyStore::open(&p, Some("acme"));
        let rej = s.apply("acme", fetched(Some(sign_policy(json!({}), &key, "acme", "2026-10-12T09:00:00.000Z")), None), T0).unwrap();
        assert_eq!(rej[0].status, "rollback");
        assert!(s.held.is_none());
    }

    #[test]
    fn a_user_writable_anchor_is_ignored() {
        let p = tree("useranchor");
        std::fs::write(&p.policy_pub, k(9).public_spki_b64()).unwrap();
        std::fs::set_permissions(&p.policy_pub, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert_eq!(PolicyStore::open(&p, Some("acme")).trust("acme").0, TrustMode::Unpinned);
    }

    #[test]
    fn freshness_cache_and_lkg_sources() {
        let p = tree("fresh");
        let key = k(3);
        std::fs::write(&p.policy_pub, key.public_spki_b64()).unwrap();
        std::fs::set_permissions(&p.policy_pub, std::fs::Permissions::from_mode(0o644)).unwrap();
        let mut s = PolicyStore::open(&p, Some("acme"));
        let pol = sign_policy(json!({"policyMaxAgeMinutes": 15}), &key, "acme", "2026-10-12T09:00:00.000Z");
        s.apply("acme", fetched(Some(pol.clone()), None), T0).unwrap();
        let h = s.held.clone().unwrap();
        let a = answer(Some(&h), None, T0 + 60_000);
        assert_eq!((a.source, a.age_sec, a.policy.as_deref()), (PolicySource::Fresh, Some(60), Some(pol.as_str())));
        assert_eq!(answer(Some(&h), None, T0 + 15 * 60_000).source, PolicySource::Cache, "older than policyMaxAgeMinutes");
        let cur = answer(Some(&h), Some("2026-10-12T09:00:00.000Z"), T0);
        assert!(cur.policy.is_none() && cur.iat.is_some(), "ifIat current: no policy body");
        assert_eq!(answer(None, None, T0).source, PolicySource::None);
        // The cache file is lost (or no longer verifies): the LKG is served as lkg.
        std::fs::remove_file(p.state_file(files::POLICY_CACHE)).unwrap();
        let mut s2 = PolicyStore::open(&p, Some("acme"));
        s2.select_held("acme", T0);
        assert_eq!(s2.held.as_ref().map(|h| h.source), Some(PolicySource::Lkg));
    }

    #[test]
    fn back_off_after_no_response_and_cleared_by_any_answer() {
        let p = tree("backoff");
        let mut s = PolicyStore::open(&p, Some("acme"));
        assert_eq!(s.next_fetch_delay_ms(T0), FETCH_IDLE_SEC * 1000);
        s.last_call_ms = T0;
        assert_eq!(s.next_fetch_delay_ms(T0 + 1000), FETCH_ACTIVE_SEC * 1000, "a recent call: every 60 s");
        for _ in 0..3 {
            s.apply("acme", FetchResult { reached: false, policy: None, published: None, actor: None }, T0).unwrap();
        }
        assert_eq!(s.backoff.failures, 3);
        assert_eq!(s.next_fetch_delay_ms(T0 + 1000), 240_000 - 1000, "60 s * 2^2 window");
        assert_eq!(PolicyStore::open(&p, Some("acme")).backoff.failures, 3, "persisted");
        s.apply("acme", fetched(None, None), T0 + 2000).unwrap();
        assert_eq!(s.backoff, Backoff::default());
        assert!(!p.state_file(files::BACKOFF).exists());
    }

    #[test]
    fn a_tenant_change_drops_the_old_pin() {
        let p = tree("tenant");
        let key = k(3);
        let mut s = PolicyStore::open(&p, Some("acme"));
        let published = format!(r#"{{"publicKey":"{}"}}"#, key.public_spki_b64());
        s.apply("acme", fetched(Some(sign_policy(json!({}), &key, "acme", "2026-10-12T09:00:00.000Z")), Some(published)), T0).unwrap();
        assert_eq!(s.trust("other").1, None, "a pin for another tenant verifies nothing");
        s.reset_for_tenant_change().unwrap();
        assert_eq!(s.trust("other").0, TrustMode::Unpinned);
    }

    fn pinned_store(tag: &str, k1: &DeviceKey) -> (crate::state::Paths, PolicyStore) {
        let p = tree(tag);
        let mut s = PolicyStore::open(&p, Some("acme"));
        let pub1 = format!(r#"{{"publicKey":"{}"}}"#, k1.public_spki_b64());
        s.apply("acme", fetched(Some(sign_policy(json!({}), k1, "acme", "2026-10-12T09:00:00.000Z")), Some(pub1)), T0).unwrap();
        assert_eq!(s.trust("acme"), (TrustMode::Pinned, Some(vec![k1.public_spki_b64()])));
        (p, s)
    }

    #[test]
    fn a_pinned_device_never_learns_a_key_from_the_unsigned_pubkey_endpoint() {
        let (k1, evil) = (k(1), k(66));
        let (_p, mut s) = pinned_store("nopub", &k1);
        let b = crate::config::Binding { origin: "https://c".into(), tenant: "acme".into(), secret: crate::config::Secret { install_token: Some("t".into()), enroll_secret: None } };
        assert_eq!(s.plan(&b).len(), 1, "a pinned helper does not fetch /api/policy/pubkey");
        // A MITM replays the current genuinely signed policy (same iat passes the strict rollback rule)
        // and publishes its own key alongside it.
        let replay = sign_policy(json!({}), &k1, "acme", "2026-10-12T09:00:00.000Z");
        let evil_pub = format!(r#"{{"keys":["{}","{}"]}}"#, k1.public_spki_b64(), evil.public_spki_b64());
        s.apply("acme", fetched(Some(replay), Some(evil_pub)), T0 + 60_000).unwrap();
        assert_eq!(s.pin.as_ref().unwrap().keys, vec![k1.public_spki_b64()], "the published key is not learned");
        let forged = sign_policy(json!({"threatPolicy":{}}), &evil, "acme", "2026-10-12T09:05:00.000Z");
        let rej = s.apply("acme", fetched(Some(forged), None), T0 + 120_000).unwrap();
        assert_eq!(rej, vec![Rejected { source: "server", status: "untrusted".into() }]);
    }

    #[test]
    fn rotation_is_accepted_only_through_signed_next_keys_newer_than_the_mark() {
        let (k1, k2) = (k(1), k(2));
        let (_p, mut s) = pinned_store("nextkeys", &k1);
        let rot = sign_policy(json!({"nextKeys":[k2.public_spki_b64()]}), &k1, "acme", "2026-10-12T09:01:00.000Z");
        s.apply("acme", fetched(Some(rot), None), T0 + 60_000).unwrap();
        assert_eq!(s.pin.as_ref().unwrap().keys, vec![k1.public_spki_b64(), k2.public_spki_b64()], "signed nextKeys under the pinned key");
        let by_k2 = sign_policy(json!({"a":2}), &k2, "acme", "2026-10-12T09:02:00.000Z");
        assert!(s.apply("acme", fetched(Some(by_k2.clone()), None), T0 + 120_000).unwrap().is_empty());
        assert_eq!(s.held.as_ref().unwrap().text, by_k2);
        let revoke = sign_policy(json!({"revokedKeys":[k1.public_spki_b64()]}), &k2, "acme", "2026-10-12T09:03:00.000Z");
        s.apply("acme", fetched(Some(revoke), None), T0 + 180_000).unwrap();
        assert_eq!(s.pin.as_ref().unwrap().keys, vec![k2.public_spki_b64()]);
        let self_revoke = sign_policy(json!({"revokedKeys":[k2.public_spki_b64()]}), &k2, "acme", "2026-10-12T09:04:00.000Z");
        let rej = s.apply("acme", fetched(Some(self_revoke), None), T0 + 240_000).unwrap();
        assert_eq!(rej, vec![Rejected { source: "revocation", status: "self".into() }]);
        assert_eq!(s.pin.as_ref().unwrap().keys, vec![k2.public_spki_b64()]);
    }

    #[test]
    fn a_replayed_next_keys_policy_at_or_below_the_mark_teaches_nothing() {
        let (k1, k3) = (k(1), k(3));
        let (_p, mut s) = pinned_store("replaynext", &k1);
        // Signed by the pinned key, but with iat equal to the mark: verifies (not a rollback), yet
        // must not rotate the pin.
        let stale = sign_policy(json!({"nextKeys":[k3.public_spki_b64()]}), &k1, "acme", "2026-10-12T09:00:00.000Z");
        let rej = s.apply("acme", fetched(Some(stale), None), T0 + 60_000).unwrap();
        assert_eq!(rej, vec![Rejected { source: "nextKeys", status: "not-newer".into() }]);
        assert_eq!(s.pin.as_ref().unwrap().keys, vec![k1.public_spki_b64()]);
        let older = sign_policy(json!({"nextKeys":[k3.public_spki_b64()]}), &k1, "acme", "2026-10-12T08:00:00.000Z");
        s.apply("acme", fetched(Some(older), None), T0 + 120_000).unwrap();
        assert_eq!(s.pin.as_ref().unwrap().keys, vec![k1.public_spki_b64()], "an older one is a rollback and refused outright");
    }
}
