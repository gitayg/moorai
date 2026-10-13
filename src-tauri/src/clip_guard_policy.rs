// Where the clipboard guard's settings come from. No environment variable, no ~/.moorai setting and no
// webview value can turn it on, change its mode or approve an app. In order:
//
//   admin        an administrator's clipboardGuard: the macOS managed preference ClipboardGuard (a dict in
//                the run.glick.moorai profile) or "clipboardGuard" in the root/admin-owned machine file
//                (/etc/moorai/config.json, <ProgramData>\MoorAI\config.json), read only through the
//                ownership checks admin_config.rs already applies. When present it decides.
//   live policy  /api/policy, fetched by the host itself from the console the binding names
//                (console_http::target, credentialed: an administrator's console first), adopted only when
//                its ed25519 envelope (policySig) verifies. The keys, in order: the root-owned policy.pub
//                (anchored); else the hook's TOFU pin for this tenant (pinned); else none (unanchored).
//                Unanchored is the WEAK case: there is no key to check, so only the presence of an envelope
//                is required (the hook's actionTrailMode rule), and the trust rests on the TLS fetch from the
//                bound console. The envelope format is cli/hook-core.mjs's (policyCanonical / policyDigest /
//                canonicalJson), reimplemented here and checked against a Node-signed fixture.
//   in memory    the policy that verified earlier in THIS process. A refused pin or a refused live policy
//                keeps it. On an anchored device it must verify under the anchor too (it may have been taken
//                under the pin, or on the envelope alone, before policy.pub was installed).
//   saved copy   <MoorAI Host>/clipboard-guard-policy.json, written when a live policy verifies. A
//                convenience for the next launch only, and taken only when it verifies under a key that is
//                still trusted (the anchor, or a valid pin for this tenant), never on an envelope check.
//
// Rollback (clip_guard_hwm.rs, the hook's isPolicyRollback): a live policy whose signed iat is older than
// the hard mark is refused. The hard mark is only what user-writable state cannot raise: the root-owned
// policy-hwm.json, the guard's in-process mark and the in-memory policy's iat (only while that policy is
// still in force, so a refusal by them always leaves it enforcing), and the signed iat of a saved copy that
// verifies under a trusted key (a refusal by it leaves that copy enforcing). A saved copy is refused only
// by the root-owned mark. The hook's pin iat is user-writable: advisory only (an alert, never a refusal),
// and one more than MARK_SKEW_MS in the future is ignored and reported.
//
// User-writable state never turns the guard off. A pin that does not parse, or names another tenant, is
// ignored and reported (content-free tamper alert); while it is there nothing new is taken without an
// anchor, and the in-memory policy stays in force. A live policy that fails verification is refused the
// same way. Off happens only when a verified policy says off, or nothing has verified (at launch, with a
// refused pin and no anchor, nothing on disk is trustworthy, so the guard stays off and alerts).
// Not a hard guarantee: the saved copy is in the user's scope, so an agent running as the user can delete
// or replace it (a replacement must still verify under a trusted key). The root-owned helper (phase 2 of
// the trust-anchor design) is the real fix; the root-owned policy.pub and administrator settings are hard
// today.
use base64::Engine as _;
use serde_json::Value;
use sha2::{Digest, Sha256};
pub use crate::clip_guard_hwm::Mark;

const SPKI_ED25519_PREFIX: [u8; 12] = [0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];

// One base64 SPKI DER key per line, or PEM blocks; # comments. Anything else is skipped.
pub fn parse_keys(text: &str) -> Vec<[u8; 32]> {
    let mut out = vec![];
    let mut b64 = String::new();
    let mut in_pem = false;
    let push = |s: &str, out: &mut Vec<[u8; 32]>| {
        if let Ok(der) = base64::engine::general_purpose::STANDARD.decode(s.trim()) {
            if der.len() == 44 && der[..12] == SPKI_ED25519_PREFIX {
                let mut k = [0u8; 32];
                k.copy_from_slice(&der[12..]);
                if !out.contains(&k) { out.push(k); }
            }
        }
    };
    for line in text.lines().map(str::trim) {
        if line == "-----BEGIN PUBLIC KEY-----" { in_pem = true; b64.clear(); continue; }
        if line == "-----END PUBLIC KEY-----" { in_pem = false; push(&b64, &mut out); continue; }
        if in_pem { b64.push_str(line); continue; }
        if line.is_empty() || line.starts_with('#') { continue; }
        push(line, &mut out);
    }
    out
}

// The hook's pin copies (None = file absent) for this tenant → its keys, or why the pin is refused.
// Refused never means "never pinned": the caller keeps the last verified policy and reports it.
pub fn pin_keys(pins: &[Option<String>], tenant: &str) -> Result<Vec<[u8; 32]>, &'static str> {
    let mut keys = vec![];
    for text in pins.iter().flatten() {
        if text.trim().is_empty() { continue; }
        let Ok(p) = serde_json::from_str::<Value>(text) else { return Err("pin-unreadable") };
        let pin_tenant = p.get("tenant").and_then(|t| t.as_str()).unwrap_or("");
        let list = p.get("keys").and_then(|k| k.as_array()).map(|a| a.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join("\n")).unwrap_or_default();
        if p.get("v").and_then(|v| v.as_u64()) != Some(1) || pin_tenant.is_empty() { return Err("pin-unreadable"); }
        if pin_tenant != tenant { return Err("pin-other-tenant"); }
        let k = parse_keys(&list);
        if k.is_empty() { return Err("pin-unreadable"); }
        for x in k { if !keys.contains(&x) { keys.push(x); } }
    }
    Ok(keys)
}

// cli/hook-core.mjs canonicalJson: keys sorted by UTF-16 code unit, JSON.stringify for scalars.
pub fn canonical_json(v: &Value) -> String {
    match v {
        Value::Null => "null".into(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => js_number(n),
        Value::String(s) => serde_json::to_string(s).unwrap_or_default(),
        Value::Array(a) => format!("[{}]", a.iter().map(canonical_json).collect::<Vec<_>>().join(",")),
        Value::Object(o) => {
            let mut keys: Vec<&String> = o.keys().collect();
            keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
            format!("{{{}}}", keys.iter().map(|k| format!("{}:{}", serde_json::to_string(k).unwrap_or_default(), canonical_json(&o[k.as_str()]))).collect::<Vec<_>>().join(","))
        }
    }
}

// Number.prototype.toString for the values a policy carries.
fn js_number(n: &serde_json::Number) -> String {
    if n.is_i64() || n.is_u64() { return n.to_string(); }
    let f = n.as_f64().unwrap_or(0.0);
    if f == 0.0 { return "0".into(); }
    let a = f.abs();
    if (1e-6..1e21).contains(&a) { return format!("{f}"); }
    let e = format!("{f:e}");
    match e.split_once('e') { Some((m, x)) if !x.starts_with('-') => format!("{m}e+{x}"), _ => e }
}

pub fn policy_digest(policy: &Value) -> String {
    let mut body = policy.clone();
    if let Some(o) = body.as_object_mut() { o.remove("policySig"); }
    Sha256::digest(canonical_json(&body).as_bytes()).iter().map(|b| format!("{b:02x}")).collect()
}

fn scalar_text(v: Option<&Value>) -> String {
    match v { None | Some(Value::Null) => String::new(), Some(Value::String(s)) => s.clone(), Some(other) => canonical_json(other) }
}

// → Ok(()) when the envelope verifies under one of `keys` for `tenant`, else the hook's status word.
pub fn verify(policy: &Value, keys: &[[u8; 32]], tenant: &str) -> Result<(), &'static str> {
    let s = policy.get("policySig").filter(|s| s.is_object()).ok_or("unsigned")?;
    let sig = s.get("sig").and_then(|x| x.as_str()).filter(|x| !x.is_empty()).ok_or("unsigned")?;
    let v_ok = match s.get("v") { Some(Value::Number(n)) => n.as_f64() == Some(1.0), Some(Value::String(t)) => t.trim() == "1", _ => false };
    if !v_ok || s.get("alg").and_then(|a| a.as_str()) != Some("ed25519") || scalar_text(s.get("iat")).is_empty() { return Err("malformed"); }
    let signed_tenant = scalar_text(s.get("tenant"));
    let msg = format!("moorai-policy|v1|{signed_tenant}|{}|{}", scalar_text(s.get("iat")), policy_digest(policy));
    let sig = base64::engine::general_purpose::STANDARD.decode(sig).map_err(|_| "malformed")?;
    let ok = keys.iter().any(|k| ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, k).verify(msg.as_bytes(), &sig).is_ok());
    if !ok { return Err("untrusted"); }
    if signed_tenant != tenant { return Err("mismatch"); }
    Ok(())
}

fn has_envelope(policy: &Value) -> bool {
    policy.get("policySig").and_then(|s| s.get("sig")).and_then(|s| s.as_str()).is_some_and(|s| !s.is_empty())
}

pub struct Decided {
    pub policy: crate::clip_guard::ClipPolicy,
    // For the status line: where the settings came from, and why a policy was not taken.
    pub status: String,
    // The policy that verified in this call (live, or the saved copy under a trusted key): the caller keeps
    // it in memory as "verified in this process".
    pub verified: Option<Value>,
    // True when `verified` is a live policy, which is then saved for the next launch.
    pub save: bool,
    // Content-free reasons for a tamper alert (pin-other-tenant, pin-unreadable, policy-untrusted, ...).
    pub tamper: Vec<String>,
    // The guard's in-process iat high-water mark after this call, kept in memory by the caller. Moved only
    // by a policy verified under a real key (anchor or pin), never by an envelope check or the pin's iat.
    pub mark: Option<Mark>,
}

// The marks decide() does not read from its other inputs: the guard's in-process mark, the root-owned
// policy-hwm.json text, and the time a user-scope mark is judged against (None: the system clock).
#[derive(Default)]
pub struct Marks<'a> {
    pub own: Option<&'a Mark>,
    pub root: Option<&'a str>,
    pub now_ms: Option<u64>,
}

// How far in the future a user-scope mark may be (console and device clocks differ) before it is ignored.
pub const MARK_SKEW_MS: i64 = 10 * 60 * 1000;

fn iat_of(policy: &Value) -> String { scalar_text(policy.get("policySig").and_then(|s| s.get("iat"))) }

// The decision, from what each source said:
//   admin    an administrator's clipboardGuard object (root/admin-owned source)
//   live     the policy fetched now (None: no answer)
//   anchor   the root-owned policy.pub text; pins: the hook's pin copies
//   memory   the policy that verified earlier in THIS process (never one re-read from disk). On an
//            anchored device it must verify under the anchor too: it may have been taken under the pin or
//            on the envelope alone before policy.pub was installed.
//   stored   the saved last-verified copy from disk. User-writable: taken only when it verifies under a key
//            that is still trusted (the anchor, or a valid pin for this tenant), never on an envelope check.
// A live policy or saved copy whose iat is older than the high-water mark is a rollback and is refused.
#[cfg(test)]
pub fn decide(admin: Option<&Value>, live: Option<&Value>, anchor: Option<&str>, pins: &[Option<String>], tenant: &str, memory: Option<&Value>, stored: Option<&Value>) -> Decided {
    decide_with(admin, live, anchor, pins, tenant, memory, stored, &Marks::default())
}

#[allow(clippy::too_many_arguments)]
pub fn decide_with(admin: Option<&Value>, live: Option<&Value>, anchor: Option<&str>, pins: &[Option<String>], tenant: &str, memory: Option<&Value>, stored: Option<&Value>, marks: &Marks) -> Decided {
    use crate::clip_guard::ClipPolicy;
    use crate::clip_guard_hwm::{iat_order, is_rollback, max_iat};
    let mut tamper: Vec<String> = vec![];
    let anchor_keys = anchor.map(parse_keys).unwrap_or_default();
    let pin = pin_keys(pins, tenant);
    if let Err(e) = pin { tamper.push(e.into()); }
    let (keys, trust) = if !anchor_keys.is_empty() {
        (anchor_keys, "anchored")
    } else {
        match &pin {
            Ok(k) if !k.is_empty() => (k.clone(), "pinned"),
            Ok(_) => (vec![], "unanchored"),
            Err(_) => (vec![], "pin-refused"),
        }
    };
    if let Some(a) = admin.filter(|a| a.is_object()) {
        return Decided { policy: ClipPolicy::from_policy(&serde_json::json!({ "clipboardGuard": a })), status: "admin".into(), verified: None, save: false, tamper, mark: None };
    }
    // An anchored device takes nothing the anchor did not sign, the in-memory policy included.
    let memory = match memory {
        Some(m) if trust == "anchored" => match verify(m, &keys, tenant) {
            Ok(()) => Some(m),
            Err(e) => { tamper.push(format!("memory-policy-{e}")); None }
        },
        m => m,
    };
    // Hard mark: only what user-writable state cannot raise (see the header).
    let root = marks.root.and_then(|t| crate::clip_guard_hwm::parse_root_hwm(t, tenant));
    let stored_ok = stored.filter(|st| !keys.is_empty() && verify(st, &keys, tenant).is_ok() && !is_rollback(&iat_of(st), root.as_deref()));
    let mut mark = root.clone();
    if let Some(st) = stored_ok { mark = max_iat(mark.as_deref(), Some(&iat_of(st))); }
    if let Some(m) = memory {
        mark = max_iat(mark.as_deref(), marks.own.filter(|m| m.tenant == tenant).map(|m| m.iat.as_str()));
        if !keys.is_empty() && verify(m, &keys, tenant).is_ok() { mark = max_iat(mark.as_deref(), Some(&iat_of(m))); }
    }
    // Advisory: the hook's pin iat (user scope). Never refuses; a future one is ignored and reported.
    let now = marks.now_ms.map(|n| n as i64).unwrap_or_else(|| std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0));
    let mut note = String::new();
    let advisory = if pin.is_ok() { crate::clip_guard_hwm::pin_mark(pins, tenant) } else { None }.filter(|m| {
        let future = iat_order(m).is_some_and(|t| t > now + MARK_SKEW_MS);
        if future { tamper.push("hwm-future".into()); note = " (a future pin mark was ignored)".into(); }
        !future
    });
    let behind = |p: &Value, what: &str, tamper: &mut Vec<String>| if is_rollback(&iat_of(p), advisory.as_deref()) { tamper.push(format!("{what}-behind-pin-mark")); };
    let real_key = trust == "anchored" || trust == "pinned";
    let moved = |p: &Value| if real_key { max_iat(mark.as_deref(), Some(&iat_of(p))) } else { mark.clone() };
    let as_mark = |m: Option<String>| m.map(|iat| Mark { tenant: tenant.to_string(), iat });
    let mut refused = None;
    if let Some(p) = live {
        let r = match trust {
            "anchored" | "pinned" => verify(p, &keys, tenant).map_err(|e| format!("policy-{e}")),
            // The weak case: no key on the device, so only the envelope's presence can be required.
            "unanchored" if has_envelope(p) => Ok(()),
            "unanchored" => Err("policy-unsigned".into()),
            // A refused pin may have been planted to drop the device to the weak case: take nothing new.
            _ => Err("pin-refused".into()),
        };
        let r = r.and_then(|()| if is_rollback(&iat_of(p), mark.as_deref()) { Err("policy-rollback".to_string()) } else { Ok(()) });
        match r {
            Ok(()) => {
                let status = if trust == "unanchored" { "unanchored (envelope only)".to_string() } else { trust.to_string() };
                behind(p, "policy", &mut tamper);
                return Decided { policy: ClipPolicy::from_policy(p), status: format!("{status}{note}"), verified: Some(p.clone()), save: true, tamper, mark: as_mark(moved(p)) };
            }
            Err(e) => {
                if e != "pin-refused" { tamper.push(e.clone()); }
                refused = Some(e);
            }
        }
    }
    let why = refused.map(|e| format!(" (live policy not taken: {e})")).unwrap_or_default() + &note;
    if let Some(m) = memory {
        return Decided { policy: ClipPolicy::from_policy(m), status: format!("verified earlier in this run{why}"), verified: Some(m.clone()), save: false, tamper, mark: as_mark(mark) };
    }
    if let Some(st) = stored {
        if keys.is_empty() {
            // No trusted key (unanchored, or the pin refused): a disk copy proves nothing, so it is not used.
            if trust == "pin-refused" { tamper.push("stored-policy-unverifiable".into()); }
        } else {
            match verify(st, &keys, tenant) {
                Ok(()) if stored_ok.is_none() => tamper.push("stored-policy-rollback".into()),
                Ok(()) => {
                    behind(st, "stored-policy", &mut tamper);
                    return Decided { policy: ClipPolicy::from_policy(st), status: format!("saved copy, verified ({trust}){why}"), verified: Some(st.clone()), save: false, tamper, mark: as_mark(moved(st)) };
                }
                Err(e) => tamper.push(format!("stored-policy-{e}")),
            }
        }
    }
    Decided { policy: ClipPolicy::default(), status: format!("no verified policy{why}"), verified: None, save: false, tamper, mark: as_mark(mark) }
}

// ---- I/O ----

pub const STATE_FILE: &str = "clipboard-guard-policy.json";

// The saved copy carries no free-standing mark: its own signed iat is the only mark it gives (decide).
pub fn save_last(dir: &str, policy: &Value) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    crate::private_file::write_private(format!("{dir}/{STATE_FILE}"), &serde_json::json!({ "v": 1, "policy": policy }).to_string())
}

pub fn load_last(dir: &str) -> Option<Value> {
    let v: Value = serde_json::from_str(&std::fs::read_to_string(format!("{dir}/{STATE_FILE}")).ok()?).ok()?;
    v.get("policy").filter(|p| p.is_object()).cloned()
}

// A root/admin-owned file beside the machine config: policy.pub (the anchor), policy-hwm.json (the mark).
fn machine_file(name: &str) -> Option<String> {
    let machine = crate::admin_config::machine_config_path();
    let dir = std::path::Path::new(&machine).parent()?;
    crate::admin_config::read_admin_owned(&dir.join(name).to_string_lossy())
}

// The hook's two pin copies, built from the home directory only (never XDG_CONFIG_HOME or APPDATA).
fn pin_texts() -> Vec<Option<String>> {
    let home = crate::platform::home_dir();
    let latch = if cfg!(windows) { format!("{home}/AppData/Roaming/MoorAI") } else { format!("{home}/.config/moorai") };
    [format!("{home}/.moorai/policy-pin.json"), format!("{latch}/policy-pin.json")]
        .iter().map(|p| std::fs::read_to_string(p).ok()).collect()
}

// An administrator's clipboardGuard: the managed preference (macOS) first, then the machine file.
fn admin_setting() -> Option<Value> {
    #[cfg(target_os = "macos")]
    {
        let root = std::path::Path::new(crate::admin_config::MANAGED_ROOT);
        for path in crate::admin_config::managed_paths(crate::admin_config::os_username().as_deref()) {
            let Some(bytes) = crate::admin_config::read_owned_under(&path, root, 0) else { continue };
            if let Some(v) = plist_json(&bytes, "ClipboardGuard").filter(|v| v.is_object()) { return Some(v); }
        }
    }
    let text = crate::admin_config::read_admin_owned(&crate::admin_config::machine_config_path())?;
    serde_json::from_str::<Value>(&text).ok()?.get("clipboardGuard").filter(|v| v.is_object()).cloned()
}

// One key of a plist as JSON: /usr/bin/plutil reads the bytes from stdin, never a path.
#[cfg(target_os = "macos")]
fn plist_json(plist: &[u8], key: &str) -> Option<Value> {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let mut child = Command::new("/usr/bin/plutil").args(["-extract", key, "json", "-o", "-", "-"])
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().ok()?;
    let wrote = child.stdin.take().map(|mut i| i.write_all(plist).is_ok()).unwrap_or(false);
    let out = child.wait_with_output().ok()?;
    if !wrote || !out.status.success() { return None; }
    serde_json::from_slice(&out.stdout).ok()
}

// Everything decide() needs, read now. `fetch` false skips the network (the first decision at launch).
pub fn gather_and_decide(fetch: bool, memory: Option<&Value>, stored: Option<&Value>, own_mark: Option<&Mark>) -> Decided {
    let admin = crate::admin_config::admin();
    let cfg = crate::admin_config::effective_config(crate::read_config(), &admin);
    let tenant = cfg.get("tenant").and_then(|t| t.as_str()).unwrap_or("").to_string();
    let mut live_err = None;
    let live = if fetch {
        let mut q = url::form_urlencoded::Serializer::new(String::new());
        q.append_pair("tenant", &tenant).append_pair("user", &crate::platform::username()).append_pair("device", &crate::platform::hostname());
        let req = crate::console_http::ConsoleRequest { method: "GET".into(), path: format!("/api/policy?{}", q.finish()), body: None, credentialed: true, base: None, client_id: None };
        crate::console_http::target(&req, &crate::console_binding::host_dir(), &cfg, &admin)
            .and_then(|(url, token)| crate::console_binding::real_fetch(url.as_str(), token.as_deref().unwrap_or("")))
            .map_err(|e| live_err = Some(e)).ok()
    } else { None };
    let root_hwm = machine_file("policy-hwm.json");
    let marks = Marks { own: own_mark, root: root_hwm.as_deref(), now_ms: None };
    let mut d = decide_with(admin_setting().as_ref(), live.as_ref(), machine_file("policy.pub").as_deref(), &pin_texts(), &tenant, memory, stored, &marks);
    if let Some(e) = live_err { d.status = format!("{} (console: {e})", d.status); }
    d
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clip_guard::Mode;
    use serde_json::json;

    fn fixture() -> Value { serde_json::from_str(include_str!("../../test/fixtures/clipboard-guard-policy.json")).unwrap() }

    fn pk() -> String { fixture()["publicKey"].as_str().unwrap().to_string() }
    fn pin(tenant: &str) -> Option<String> { Some(json!({ "v": 1, "tenant": tenant, "keys": [pk()] }).to_string()) }
    fn signed_clear() -> Value { fixture()["policy"].clone() }
    // The fixture's body with the mode set to `mode` and a signature that is not the console's.
    fn forged(mode: &str, sig: Option<&str>) -> Value {
        let mut p = signed_clear();
        p["clipboardGuard"]["mode"] = json!(mode);
        match sig {
            Some(s) => p["policySig"]["sig"] = json!(s),
            None => { p.as_object_mut().unwrap().remove("policySig"); }
        }
        p
    }

    #[test]
    fn a_node_signed_policy_verifies_and_a_tampered_one_does_not() {
        let fx = fixture();
        let keys = parse_keys(&pk());
        assert_eq!(keys.len(), 1);
        let pol = &fx["policy"];
        assert_eq!(policy_digest(pol), fx["digest"].as_str().unwrap(), "canonical JSON matches Node");
        assert_eq!(verify(pol, &keys, "acme"), Ok(()));
        assert_eq!(verify(pol, &keys, "other"), Err("mismatch"));
        let mut t = pol.clone();
        t["clipboardGuard"]["approvedApps"] = json!(["com.openai.chat"]);
        assert_eq!(verify(&t, &keys, "acme"), Err("untrusted"));
        assert_eq!(verify(&forged("off", None), &keys, "acme"), Err("unsigned"));
        assert_eq!(verify(pol, &parse_keys(fx["otherPublicKey"].as_str().unwrap()), "acme"), Err("untrusted"));
        assert_eq!(parse_keys(fx["publicKeyPem"].as_str().unwrap()), keys);
    }

    #[test]
    fn canonical_json_matches_javascript_for_awkward_values() {
        for case in fixture()["canonical"].as_array().unwrap() {
            let v: Value = serde_json::from_str(case["json"].as_str().unwrap()).unwrap();
            assert_eq!(canonical_json(&v), case["canonical"].as_str().unwrap(), "{}", case["json"]);
        }
    }

    #[test]
    fn a_verified_live_policy_is_adopted_with_the_strongest_key_available() {
        let live = signed_clear();
        let d = decide(None, Some(&live), Some(&pk()), &[], "acme", None, None);
        assert_eq!((d.policy.mode, d.status.as_str(), d.save), (Mode::Clear, "anchored", true));
        let d = decide(None, Some(&live), None, &[pin("acme"), None], "acme", None, None);
        assert_eq!((d.policy.mode, d.status.as_str()), (Mode::Clear, "pinned"));
        let d = decide(None, Some(&live), None, &[None, None], "acme", None, None);
        assert_eq!((d.policy.mode, d.status.as_str()), (Mode::Clear, "unanchored (envelope only)"));
        assert!(d.tamper.is_empty());
    }

    #[test]
    fn a_planted_other_tenant_pin_keeps_the_last_verified_mode_and_alerts() {
        let memory = signed_clear();
        for planted in [pin("evil"), Some("{garbage".into()), Some(json!({ "v": 1, "tenant": "acme", "keys": ["junk"] }).to_string())] {
            // with no answer from the console, and with a live policy (even a genuine one) in the same call
            for live in [None, Some(signed_clear()), Some(forged("off", Some("AAAA")))] {
                let d = decide(None, live.as_ref(), None, &[planted.clone(), None], "acme", Some(&memory), None);
                assert_eq!(d.policy.mode, Mode::Clear, "{planted:?} {live:?}: {}", d.status);
                assert!(d.status.starts_with("verified earlier in this run"), "{}", d.status);
                assert!(!d.save, "nothing new is taken on a refused pin");
                assert!(d.tamper.iter().any(|t| t.starts_with("pin-")), "{:?}", d.tamper);
            }
        }
        assert_eq!(decide(None, None, None, &[pin("evil")], "acme", Some(&memory), None).tamper, vec!["pin-other-tenant"]);
    }

    #[test]
    fn a_forged_stored_policy_with_a_refused_pin_leaves_the_in_memory_mode() {
        let memory = signed_clear();
        let forged_off = forged("off", Some("AAAA"));
        let d = decide(None, None, None, &[pin("evil")], "acme", Some(&memory), Some(&forged_off));
        assert_eq!(d.policy.mode, Mode::Clear, "{}", d.status);
        assert!(d.tamper.contains(&"pin-other-tenant".to_string()), "{:?}", d.tamper);
    }

    #[test]
    fn at_startup_a_refused_pin_and_a_forged_stored_policy_stay_off_and_alert() {
        let mut forged_alert = forged("alert", Some("AAAA"));
        forged_alert["clipboardGuard"]["approvedApps"] = json!(["com.openai.chat"]);
        for stored in [forged_alert.clone(), forged("clear", None)] {
            let d = decide(None, None, None, &[pin("evil")], "acme", None, Some(&stored));
            assert_eq!(d.policy.mode, Mode::Off, "{}", d.status);
            assert!(d.policy.approved.is_empty(), "the forged approved apps are not taken");
            assert!(d.verified.is_none());
            assert!(d.tamper.contains(&"pin-other-tenant".to_string()) && d.tamper.contains(&"stored-policy-unverifiable".to_string()), "{:?}", d.tamper);
        }
        // with no key at all (unanchored), a disk copy is not taken on its envelope either
        let d = decide(None, None, None, &[], "acme", None, Some(&forged("clear", Some("AAAA"))));
        assert_eq!(d.policy.mode, Mode::Off);
    }

    #[test]
    fn a_stored_policy_signed_by_the_anchor_is_accepted() {
        let stored = signed_clear();
        // even with a planted pin: the anchor decides
        for pins in [vec![], vec![pin("evil")]] {
            let d = decide(None, None, Some(&pk()), &pins, "acme", None, Some(&stored));
            assert_eq!((d.policy.mode, d.status.as_str()), (Mode::Clear, "saved copy, verified (anchored)"));
            assert!(d.verified.is_some() && !d.save);
        }
        // a stored copy the anchor did not sign is refused and reported
        let d = decide(None, None, Some(&pk()), &[], "acme", None, Some(&forged("off", Some("AAAA"))));
        assert_eq!(d.policy.mode, Mode::Off);
        assert_eq!(d.tamper, vec!["stored-policy-untrusted"]);
    }

    #[test]
    fn a_garbage_or_missing_signature_cannot_change_the_mode() {
        let memory = signed_clear();
        let garbage = ["AAAA", "!!not base64!!", "c2lnbmF0dXJl"];
        for (anchor, pins) in [(Some(pk()), vec![]), (None, vec![pin("acme")])] {
            for live in garbage.iter().map(|g| forged("off", Some(g))).chain([forged("off", None)]) {
                let d = decide(None, Some(&live), anchor.as_deref(), &pins, "acme", Some(&memory), None);
                assert_eq!(d.policy.mode, Mode::Clear, "{}", d.status);
                assert!(!d.save);
                assert!(d.tamper.iter().any(|t| t.starts_with("policy-")), "{:?}", d.tamper);
            }
        }
        // unanchored (no key at all): an envelope is required, so an unsigned body cannot change the mode
        let d = decide(None, Some(&forged("off", None)), None, &[], "acme", Some(&memory), None);
        assert_eq!((d.policy.mode, d.tamper.clone()), (Mode::Clear, vec!["policy-unsigned".to_string()]));
    }

    #[test]
    fn the_last_verified_policy_survives_a_restart() {
        let n = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let dir = std::env::temp_dir().join(format!("moorai-clipstate-{}-{n}", std::process::id())).to_string_lossy().into_owned();
        let first = decide(None, Some(&signed_clear()), None, &[pin("acme")], "acme", None, None);
        assert!(first.save);
        save_last(&dir, first.verified.as_ref().unwrap()).unwrap();
        // a new process: nothing in memory, no answer from the console yet, the pin still valid
        let d = decide(None, None, None, &[pin("acme")], "acme", None, load_last(&dir).as_ref());
        assert_eq!((d.policy.mode, d.status.as_str()), (Mode::Clear, "saved copy, verified (pinned)"));
        // a saved copy edited in place no longer verifies and is not used
        let mut edited = load_last(&dir).unwrap();
        edited["clipboardGuard"]["mode"] = json!("off");
        edited["clipboardGuard"]["approvedApps"] = json!(["com.openai.chat"]);
        save_last(&dir, &edited).unwrap();
        let d = decide(None, None, None, &[pin("acme")], "acme", None, load_last(&dir).as_ref());
        assert_eq!((d.policy.mode, d.status.as_str()), (Mode::Off, "no verified policy"));
    }

    #[test]
    fn never_verified_stays_off() {
        for live in [None, Some(forged("clear", None)), Some(forged("clear", Some("AAAA")))] {
            let d = decide(None, live.as_ref(), Some(&pk()), &[], "acme", None, None);
            assert_eq!(d.policy.mode, Mode::Off, "{}", d.status);
            assert!(d.status.starts_with("no verified policy"), "{}", d.status);
        }
        assert_eq!(decide(None, None, None, &[pin("evil")], "acme", None, None).policy.mode, Mode::Off);
    }

    // A key generated for the test (the fixture's private key is not in the repo), as parse_keys text.
    fn keypair() -> (ring::signature::Ed25519KeyPair, String) {
        let pkcs8 = ring::signature::Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap();
        let kp = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let mut der = SPKI_ED25519_PREFIX.to_vec();
        der.extend_from_slice(ring::signature::KeyPair::public_key(&kp).as_ref());
        (kp, base64::engine::general_purpose::STANDARD.encode(der))
    }
    // A policy signed the console's way (cli/hook-core.mjs policyCanonical) with iat `iat`.
    fn sign(kp: &ring::signature::Ed25519KeyPair, tenant: &str, iat: &str, guard: Value) -> Value {
        let mut p = json!({ "clipboardGuard": guard });
        let msg = format!("moorai-policy|v1|{tenant}|{iat}|{}", policy_digest(&p));
        let sig = base64::engine::general_purpose::STANDARD.encode(kp.sign(msg.as_bytes()).as_ref());
        p["policySig"] = json!({ "v": 1, "alg": "ed25519", "tenant": tenant, "iat": iat, "sig": sig });
        p
    }
    fn pin_of(key: &str, tenant: &str, iat: &str) -> Option<String> { Some(json!({ "v": 1, "tenant": tenant, "keys": [key], "iat": iat }).to_string()) }
    const T1: &str = "2026-10-01T00:00:00.000Z";
    const T2: &str = "2026-10-02T00:00:00.000Z";

    #[test]
    fn an_anchored_device_keeps_no_policy_the_anchor_did_not_sign() {
        let (kp, key) = keypair();
        // taken earlier in this run on the envelope alone (no anchor, no pin), or under the user-writable pin
        let envelope_only = forged("clear", Some("AAAA"));
        let pin_signed = sign(&kp, "acme", T1, json!({ "mode": "clear" }));
        assert_eq!(decide(None, None, None, &[pin_of(&key, "acme", ""), None], "acme", None, None).status, "no verified policy");
        for memory in [envelope_only, pin_signed] {
            // policy.pub is now in place: the in-memory copy must verify under it like everything else
            let d = decide(None, None, Some(&pk()), &[pin_of(&key, "acme", "")], "acme", Some(&memory), None);
            assert_eq!(d.policy.mode, Mode::Off, "{}", d.status);
            assert!(d.verified.is_none(), "{}", d.status);
            assert!(d.tamper.iter().any(|t| t.starts_with("memory-policy-")), "{:?}", d.tamper);
            // and the anchor-signed saved copy is what takes over
            let d = decide(None, None, Some(&pk()), &[], "acme", Some(&memory), Some(&signed_clear()));
            assert_eq!((d.policy.mode, d.status.as_str()), (Mode::Clear, "saved copy, verified (anchored)"));
        }
        // an anchor-signed in-memory policy is kept as before
        let d = decide(None, Some(&forged("off", Some("AAAA"))), Some(&pk()), &[], "acme", Some(&signed_clear()), None);
        assert_eq!(d.policy.mode, Mode::Clear, "{}", d.status);
        assert!(d.status.starts_with("verified earlier in this run"), "{}", d.status);
    }

    #[test]
    fn an_older_validly_signed_live_policy_is_a_rollback() {
        let (kp, key) = keypair();
        let newer = sign(&kp, "acme", T2, json!({ "mode": "clear" }));
        let older = sign(&kp, "acme", T1, json!({ "mode": "off" }));
        for (anchor, pins) in [(Some(key.clone()), vec![]), (None, vec![pin_of(&key, "acme", ""), None])] {
            let d = decide(None, Some(&older), anchor.as_deref(), &pins, "acme", Some(&newer), None);
            assert_eq!(d.policy.mode, Mode::Clear, "{}", d.status);
            assert!(!d.save, "a rollback is not saved");
            assert!(d.tamper.contains(&"policy-rollback".to_string()), "{:?}", d.tamper);
            // the same policy again (equal iat) is not a rollback
            let again = sign(&kp, "acme", T2, json!({ "mode": "alert" }));
            let d = decide(None, Some(&again), anchor.as_deref(), &pins, "acme", Some(&newer), None);
            assert_eq!((d.policy.mode, d.save), (Mode::Alert, true), "{}", d.status);
        }
    }

    #[test]
    fn an_older_saved_copy_is_refused_by_the_root_mark_and_flagged_by_the_pin_mark() {
        let (kp, key) = keypair();
        // an old, validly signed copy that approved more apps, put back in place of the saved one
        let older = sign(&kp, "acme", T1, json!({ "mode": "clear", "approvedApps": ["com.openai.chat"] }));
        let root = json!({ "v": 1, "tenant": "acme", "iat": T2 }).to_string();
        let d = decide_with(None, None, None, &[pin_of(&key, "acme", ""), None], "acme", None, Some(&older), &Marks { root: Some(&root), ..Default::default() });
        assert_eq!(d.policy.mode, Mode::Off, "{}", d.status);
        assert!(d.policy.approved.is_empty() && d.verified.is_none());
        assert!(d.tamper.contains(&"stored-policy-rollback".to_string()), "{:?}", d.tamper);
        // the hook's pin iat is user-writable: it is reported, it does not refuse
        let d = decide(None, None, None, &[pin_of(&key, "acme", T2), None], "acme", None, Some(&older));
        assert_eq!(d.policy.mode, Mode::Clear, "{}", d.status);
        assert!(d.tamper.contains(&"stored-policy-behind-pin-mark".to_string()), "{:?}", d.tamper);
        // a copy at the mark is taken without a report
        let current = sign(&kp, "acme", T2, json!({ "mode": "clear" }));
        let d = decide(None, None, None, &[pin_of(&key, "acme", T2)], "acme", None, Some(&current));
        assert_eq!((d.policy.mode, d.status.as_str(), d.tamper.len()), (Mode::Clear, "saved copy, verified (pinned)", 0));
    }

    #[test]
    fn the_hard_marks_refuse_older_policies_and_leave_a_verified_one_enforcing() {
        let (kp, key) = keypair();
        let older = sign(&kp, "acme", T1, json!({ "mode": "off" }));
        let kept = sign(&kp, "acme", T1, json!({ "mode": "coach" }));
        let root = json!({ "v": 1, "tenant": "acme", "iat": T2 }).to_string();
        let own = Mark { tenant: "acme".into(), iat: T2.into() };
        let other = Mark { tenant: "evil".into(), iat: T2.into() };
        let pins = [pin_of(&key, "acme", ""), None];
        // the root-owned mark refuses a live policy and a saved copy
        let marks = Marks { root: Some(&root), ..Default::default() };
        let d = decide_with(None, Some(&older), None, &pins, "acme", None, None, &marks);
        assert!(!d.save && d.tamper.contains(&"policy-rollback".to_string()), "{:?}", d.tamper);
        let d = decide_with(None, None, None, &pins, "acme", None, Some(&older), &marks);
        assert!(d.verified.is_none() && d.tamper.contains(&"stored-policy-rollback".to_string()), "{:?}", d.tamper);
        // the in-process mark refuses only while the in-memory policy is in force, which then stays
        let marks = Marks { own: Some(&own), ..Default::default() };
        let d = decide_with(None, Some(&older), None, &pins, "acme", Some(&kept), None, &marks);
        assert_eq!((d.policy.mode, d.save), (Mode::Coach, false), "{}", d.status);
        assert!(d.tamper.contains(&"policy-rollback".to_string()), "{:?}", d.tamper);
        let d = decide_with(None, Some(&older), None, &pins, "acme", None, None, &marks);
        assert!(d.save, "no in-memory policy, no refusal by the in-process mark: {}", d.status);
        // another tenant's mark is not this tenant's
        let d = decide_with(None, Some(&older), None, &pins, "acme", Some(&kept), None, &Marks { own: Some(&other), ..Default::default() });
        assert!(d.save, "{}", d.status);
        // a verified policy moves the mark; the envelope-only case never sets one
        let d = decide(None, Some(&sign(&kp, "acme", T2, json!({ "mode": "clear" }))), None, &pins, "acme", None, None);
        assert_eq!(d.mark, Some(own.clone()));
        let d = decide(None, Some(&sign(&kp, "acme", T2, json!({ "mode": "clear" }))), None, &[], "acme", None, None);
        assert_eq!((d.status.as_str(), d.mark), ("unanchored (envelope only)", None));
    }

    #[test]
    fn after_a_restart_the_saved_copys_signed_iat_refuses_an_older_live_policy() {
        let (kp, key) = keypair();
        let n = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let dir = std::env::temp_dir().join(format!("moorai-cliphwm-{}-{n}", std::process::id())).to_string_lossy().into_owned();
        let pins = [pin_of(&key, "acme", "")];
        let d = decide(None, Some(&sign(&kp, "acme", T2, json!({ "mode": "clear" }))), None, &pins, "acme", None, None);
        save_last(&dir, d.verified.as_ref().unwrap()).unwrap();
        // after a restart the console replays an older policy: the verified saved copy (iat T2) refuses it and enforces
        let d = decide(None, Some(&sign(&kp, "acme", T1, json!({ "mode": "off" }))), None, &pins, "acme", None, load_last(&dir).as_ref());
        assert_eq!((d.policy.mode, d.status.as_str()), (Mode::Clear, "saved copy, verified (pinned) (live policy not taken: policy-rollback)"));
    }

    #[test]
    fn a_far_future_user_scope_mark_cannot_switch_the_guard_off() {
        let (kp, key) = keypair();
        let far = "2099-01-01T00:00:00.000Z";
        let genuine = sign(&kp, "acme", T2, json!({ "mode": "clear" }));
        let d = decide(None, Some(&genuine), None, &[pin_of(&key, "acme", far)], "acme", None, None);
        assert_eq!((d.policy.mode, d.save), (Mode::Clear, true), "pin mark: {} {:?}", d.status, d.tamper);
        assert_eq!(d.status, "pinned (a future pin mark was ignored)");
        assert!(d.tamper.contains(&"hwm-future".to_string()), "{:?}", d.tamper);
        let d = decide(None, None, None, &[pin_of(&key, "acme", far)], "acme", None, Some(&genuine));
        assert_eq!(d.policy.mode, Mode::Clear, "pin mark at launch: {} {:?}", d.status, d.tamper);
        assert_eq!(d.mark.map(|m| m.iat).as_deref(), Some(T2), "the guard's own mark is not raised by it");
        // a free-standing mark written beside the saved copy is not read at all
        let n = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let dir = std::env::temp_dir().join(format!("moorai-clipfut-{}-{n}", std::process::id())).to_string_lossy().into_owned();
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(format!("{dir}/{STATE_FILE}"), json!({ "v": 1, "policy": genuine, "hwm": { "tenant": "acme", "iat": far } }).to_string()).unwrap();
        let d = decide(None, Some(&genuine), None, &[pin_of(&key, "acme", "")], "acme", None, load_last(&dir).as_ref());
        assert_eq!((d.policy.mode, d.save, d.tamper.len()), (Mode::Clear, true, 0), "{}", d.status);
        // the clamp: within MARK_SKEW_MS of now a pin mark is a mark (reported), beyond it is ignored
        let now = crate::clip_guard_hwm::iat_order(T2).unwrap() as u64;
        let older = sign(&kp, "acme", T1, json!({ "mode": "clear" }));
        for (pin_iat, report) in [("2026-10-02T00:05:00.000Z", "policy-behind-pin-mark"), ("2026-10-02T01:00:00.000Z", "hwm-future")] {
            let d = decide_with(None, Some(&older), None, &[pin_of(&key, "acme", pin_iat)], "acme", None, None, &Marks { now_ms: Some(now), ..Default::default() });
            assert!(d.save && d.tamper == vec![report.to_string()], "{pin_iat}: {:?}", d.tamper);
        }
    }

    #[test]
    fn an_administrator_setting_decides() {
        let admin = json!({ "mode": "coach", "approvedApps": ["com.openai.chat"] });
        let d = decide(Some(&admin), Some(&signed_clear()), Some(&pk()), &[], "acme", None, None);
        assert_eq!((d.policy.mode, d.status.as_str()), (Mode::Coach, "admin"));
        assert!(d.policy.approved.contains("com.openai.chat"));
        assert!(d.verified.is_none() && !d.save);
    }
}
