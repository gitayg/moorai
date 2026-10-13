//! Helper -> console HTTP (contract §5–§7, §9). The HTTP client behind `ConsoleTransport` is reqwest
//! (blocking, rustls, redirects disabled so the install token can never follow a redirect to another
//! origin) at the version already in src-tauri/Cargo.lock. Tests use in-process fakes.

use crate::clock::{iso_ms, parse_iso_ms};
use crate::config::Binding;
use crate::keys::{new_nonce_hex, DeviceKey};
use crate::signing::{devreq_signing_input, rotate_input, DevReq};
use serde::{Deserialize, Serialize};

pub const REGISTER_PATH: &str = "/api/devices/register";
pub const COMMANDS_PATH: &str = "/api/devices/commands";
pub const COMMANDS_ACK_PATH: &str = "/api/devices/commands/ack";

/// Headers carried by every device-signed request (contract §6.2).
pub const H_INSTALL_TOKEN: &str = "X-Install-Token";
pub const H_ENROLL_SECRET: &str = "X-Enroll-Secret";
pub const H_DEVICE_ID: &str = "X-Device-Id";
pub const H_DEVICE_KEY: &str = "X-Device-Key";
pub const H_DEVICE_TS: &str = "X-Device-Ts";
pub const H_DEVICE_NONCE: &str = "X-Device-Nonce";
pub const H_DEVICE_SIG: &str = "X-Device-Sig";

/// The learned clock offset is bounded to ±24 h (§6.5).
pub const MAX_CLOCK_OFFSET_MS: i64 = 86_400_000;
/// Timeout for a non-poll console request.
pub const REQUEST_TIMEOUT_MS: u64 = 15_000;

#[derive(Debug, Clone, PartialEq)]
pub enum ConsoleError {
    Network(String),
    /// Non-2xx with the console's `error` code (or "" when the body has none).
    Status(u16, String),
    /// 401 {error:"clock_skew", serverTime}: adopt the offset and retry once (contract §6.5).
    ClockSkew { server_time: String },
    BadResponse(String),
}

#[derive(Debug, Clone, PartialEq)]
pub struct HttpRequest {
    pub method: &'static str,
    pub path_and_query: String,
    pub headers: Vec<(&'static str, String)>,
    pub body: Vec<u8>,
}

impl HttpRequest {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct HttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

pub trait ConsoleTransport: Send + Sync {
    /// `origin` is the admin binding's normalised origin (never a user-scope value).
    fn send(&self, origin: &str, req: HttpRequest, timeout_ms: u64) -> Result<HttpResponse, ConsoleError>;
}

/// reqwest blocking client: rustls with the platform verifier (reqwest defaults), no redirects.
pub struct ReqwestTransport {
    client: reqwest::blocking::Client,
}

impl ReqwestTransport {
    pub fn new() -> Result<Self, ConsoleError> {
        let client = reqwest::blocking::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("moorai-guardd/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| ConsoleError::Network(e.to_string()))?;
        Ok(ReqwestTransport { client })
    }
}

impl ConsoleTransport for ReqwestTransport {
    fn send(&self, origin: &str, req: HttpRequest, timeout_ms: u64) -> Result<HttpResponse, ConsoleError> {
        let url = format!("{origin}{}", req.path_and_query);
        let method = reqwest::Method::from_bytes(req.method.as_bytes()).map_err(|e| ConsoleError::Network(e.to_string()))?;
        let mut b = self.client.request(method, url).timeout(std::time::Duration::from_millis(timeout_ms));
        for (k, v) in &req.headers {
            b = b.header(*k, v);
        }
        if req.method == "POST" {
            b = b.header("Content-Type", "application/json").body(req.body);
        }
        let resp = b.send().map_err(|e| ConsoleError::Network(e.without_url().to_string()))?;
        let status = resp.status().as_u16();
        let body = resp.bytes().map_err(|e| ConsoleError::Network(e.without_url().to_string()))?.to_vec();
        Ok(HttpResponse { status, body })
    }
}

/// Build the device-signed request for `body` (contract §6.2): computes ts (with the learned clock
/// offset), a fresh nonce, the signing input and X-Device-* headers, plus X-Install-Token.
pub fn sign_request(
    key: &DeviceKey,
    binding: &Binding,
    device_id: &str,
    method: &'static str,
    path_and_query: &str,
    body: Vec<u8>,
    clock_offset_ms: i64,
    now_ms: u64,
) -> HttpRequest {
    let ts = iso_ms(now_ms as i64 + clock_offset_ms);
    let nonce = new_nonce_hex();
    let key_id = key.key_id();
    let input = devreq_signing_input(&DevReq {
        method,
        path: path_and_query,
        tenant: &binding.tenant,
        device_id,
        key_id: &key_id,
        ts: &ts,
        nonce: &nonce,
        body: &body,
    });
    let sig = key.sign_b64(input.as_bytes());
    HttpRequest {
        method,
        path_and_query: path_and_query.to_string(),
        headers: vec![
            (H_INSTALL_TOKEN, binding.secret.install_token.clone().unwrap_or_default()),
            (H_DEVICE_ID, device_id.to_string()),
            (H_DEVICE_KEY, key_id),
            (H_DEVICE_TS, ts),
            (H_DEVICE_NONCE, nonce),
            (H_DEVICE_SIG, sig),
        ],
        body,
    }
}

fn error_code(body: &[u8]) -> (String, Option<String>) {
    let v: serde_json::Value = serde_json::from_slice(body).unwrap_or(serde_json::Value::Null);
    (
        v.get("error").and_then(|e| e.as_str()).unwrap_or("").to_string(),
        v.get("serverTime").and_then(|e| e.as_str()).map(str::to_string),
    )
}

/// Classify a response: 2xx is Ok; 401 clock_skew carries serverTime; else Status(code, error).
pub fn classify(resp: HttpResponse) -> Result<HttpResponse, ConsoleError> {
    if (200..300).contains(&resp.status) {
        return Ok(resp);
    }
    let (code, server_time) = error_code(&resp.body);
    match (resp.status, code.as_str(), server_time) {
        (401, "clock_skew", Some(t)) => Err(ConsoleError::ClockSkew { server_time: t }),
        (s, _, _) => Err(ConsoleError::Status(s, code)),
    }
}

/// §6.5: offset = serverTime − local, bounded to ±24 h. None when serverTime does not parse.
pub fn offset_from_server_time(server_time: &str, local_ms: u64) -> Option<i64> {
    let t = parse_iso_ms(server_time)?;
    Some((t - local_ms as i64).clamp(-MAX_CLOCK_OFFSET_MS, MAX_CLOCK_OFFSET_MS))
}

/// Send a device-signed request; on `401 clock_skew` adopt the server's offset, re-sign with a fresh
/// nonce and retry exactly once (§6.5). `clock_offset_ms` is updated in place when adopted.
#[allow(clippy::too_many_arguments)]
pub fn send_signed(
    transport: &dyn ConsoleTransport,
    key: &DeviceKey,
    binding: &Binding,
    device_id: &str,
    method: &'static str,
    path_and_query: &str,
    body: Vec<u8>,
    extra_headers: &[(&'static str, String)],
    clock_offset_ms: &mut i64,
    timeout_ms: u64,
    now: &dyn Fn() -> u64,
) -> Result<HttpResponse, ConsoleError> {
    let build = |off: i64| {
        let mut r = sign_request(key, binding, device_id, method, path_and_query, body.clone(), off, now());
        r.headers.extend(extra_headers.iter().cloned());
        r
    };
    match transport.send(&binding.origin, build(*clock_offset_ms), timeout_ms).and_then(classify) {
        Err(ConsoleError::ClockSkew { server_time }) => {
            let off = offset_from_server_time(&server_time, now()).ok_or_else(|| ConsoleError::BadResponse("unreadable serverTime".into()))?;
            *clock_offset_ms = off;
            transport.send(&binding.origin, build(off), timeout_ms).and_then(classify)
        }
        r => r,
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterBody {
    pub v: u32,
    pub tenant: String,
    pub device_id: String,
    pub device: String,
    pub platform: String,
    pub arch: String,
    pub helper_version: String,
    /// base64 SPKI DER of the NEW key; the request is signed with that key (proof of possession).
    pub public_key: String,
    pub key_id: String,
    /// Planned rotation only: the previous key id and its signature over signing::rotate_input.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub prev_key_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub prev_key_sig: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterResp {
    pub ok: bool,
    pub device_id: String,
    pub key_id: String,
    /// "registered" | "unchanged" | "rotated" | "reenrolled" | "changed" (§5.2)
    pub status: String,
    /// Whether the device's current key is bound by an enrolment secret (§5.2).
    pub bound: bool,
    pub server_time: String,
    pub beat_interval_sec: u64,
}

/// The persisted outcome of the last successful registration (§4.2 `registration.json`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Registration {
    pub key_id: String,
    pub device_id: String,
    pub registered_at: String,
    pub status: String,
    pub origin: String,
    #[serde(default)]
    pub tenant: String,
    #[serde(default)]
    pub bound: bool,
}

pub const REGISTER_STATUSES: [&str; 5] = ["registered", "unchanged", "rotated", "reenrolled", "changed"];

pub fn platform_name() -> &'static str {
    if cfg!(target_os = "macos") {
        "darwin"
    } else if cfg!(windows) {
        "win32"
    } else {
        "linux"
    }
}

pub fn arch_name() -> &'static str {
    match std::env::consts::ARCH {
        "aarch64" => "arm64",
        "x86_64" => "x64",
        "x86" => "ia32",
        a => a,
    }
}

pub struct RegisterInput<'a> {
    /// The key being registered (signs the request: proof of possession).
    pub key: &'a DeviceKey,
    /// Planned rotation: the current (old) key, which signs the rotate statement.
    pub prev: Option<&'a DeviceKey>,
    pub binding: &'a Binding,
    pub device_id: &'a str,
    pub device: &'a str,
}

/// POST /api/devices/register (§5.2). The enrolment secret, when the binding holds one, rides in
/// `X-Enroll-Secret`; a `401 bad_enroll_secret` is returned as an error and NEVER retried without the
/// secret (no downgrade to an unbound registration).
pub fn register(transport: &dyn ConsoleTransport, input: &RegisterInput<'_>, clock_offset_ms: &mut i64, now: &dyn Fn() -> u64) -> Result<RegisterResp, ConsoleError> {
    let key_id = input.key.key_id();
    let (prev_key_id, prev_key_sig) = match input.prev {
        Some(old) => {
            let old_id = old.key_id();
            let sig = old.sign_b64(rotate_input(&input.binding.tenant, input.device_id, &old_id, &key_id).as_bytes());
            (Some(old_id), Some(sig))
        }
        None => (None, None),
    };
    let body = RegisterBody {
        v: 1,
        tenant: input.binding.tenant.clone(),
        device_id: input.device_id.to_string(),
        device: input.device.to_string(),
        platform: platform_name().into(),
        arch: arch_name().into(),
        helper_version: crate::HELPER_VERSION.into(),
        public_key: input.key.public_spki_b64(),
        key_id: key_id.clone(),
        prev_key_id,
        prev_key_sig,
    };
    let bytes = crate::canonical::canonical_json(&serde_json::to_value(&body).expect("RegisterBody serialises"))
        .map_err(|e| ConsoleError::BadResponse(e.to_string()))?
        .into_bytes();
    let extra: Vec<(&'static str, String)> = input.binding.secret.enroll_secret.iter().map(|s| (H_ENROLL_SECRET, s.clone())).collect();
    let resp = send_signed(transport, input.key, input.binding, input.device_id, "POST", REGISTER_PATH, bytes, &extra, clock_offset_ms, REQUEST_TIMEOUT_MS, now)?;
    let r: RegisterResp = serde_json::from_slice(&resp.body).map_err(|e| ConsoleError::BadResponse(format!("register response: {e}")))?;
    if !r.ok || r.key_id != key_id || r.device_id != input.device_id || !REGISTER_STATUSES.contains(&r.status.as_str()) {
        return Err(ConsoleError::BadResponse("register response does not match the request".into()));
    }
    Ok(r)
}

#[cfg(any(test, feature = "test-injection"))]
pub mod fake {
    //! A scripted in-process console for unit and integration tests.
    use super::*;
    use std::sync::Mutex;

    pub type Handler = Box<dyn Fn(&HttpRequest) -> Result<HttpResponse, ConsoleError> + Send + Sync>;

    pub struct FakeConsole {
        pub seen: Mutex<Vec<HttpRequest>>,
        pub handler: Handler,
    }

    impl FakeConsole {
        pub fn new(handler: Handler) -> Self {
            FakeConsole { seen: Mutex::new(vec![]), handler }
        }
        pub fn requests(&self) -> Vec<HttpRequest> {
            self.seen.lock().unwrap().clone()
        }
    }

    impl ConsoleTransport for FakeConsole {
        fn send(&self, _origin: &str, req: HttpRequest, _t: u64) -> Result<HttpResponse, ConsoleError> {
            let r = (self.handler)(&req);
            self.seen.lock().unwrap().push(req);
            r
        }
    }

    pub fn json(status: u16, v: serde_json::Value) -> Result<HttpResponse, ConsoleError> {
        Ok(HttpResponse { status, body: serde_json::to_vec(&v).unwrap() })
    }
}

#[cfg(test)]
mod tests {
    use super::fake::*;
    use super::*;
    use crate::config::Secret;
    use serde_json::json;
    use std::sync::atomic::{AtomicU32, Ordering};

    fn binding(enroll: Option<&str>) -> Binding {
        Binding {
            origin: "https://console.example".into(),
            tenant: "acme".into(),
            secret: Secret { install_token: Some("tok".into()), enroll_secret: enroll.map(str::to_string) },
        }
    }

    fn verify_signed(req: &HttpRequest, key: &DeviceKey, tenant: &str) {
        let input = devreq_signing_input(&DevReq {
            method: req.method,
            path: &req.path_and_query,
            tenant,
            device_id: req.header(H_DEVICE_ID).unwrap(),
            key_id: req.header(H_DEVICE_KEY).unwrap(),
            ts: req.header(H_DEVICE_TS).unwrap(),
            nonce: req.header(H_DEVICE_NONCE).unwrap(),
            body: &req.body,
        });
        crate::keys::verify_b64(&key.public_spki_b64(), input.as_bytes(), req.header(H_DEVICE_SIG).unwrap()).expect("device signature verifies");
    }

    #[test]
    fn signed_requests_carry_the_contract_headers_and_verify() {
        let key = DeviceKey::from_seed(&[7u8; 32]).unwrap();
        let r = sign_request(&key, &binding(None), "d".repeat(32).as_str(), "POST", "/api/devices/beat", b"{}".to_vec(), 1500, 1_000_000);
        assert_eq!(r.header(H_DEVICE_TS), Some(iso_ms(1_001_500).as_str()), "ts = local clock + offset");
        assert_eq!(r.header(H_INSTALL_TOKEN), Some("tok"));
        assert_eq!(r.header(H_DEVICE_KEY), Some(key.key_id().as_str()));
        assert_eq!(r.header(H_DEVICE_NONCE).unwrap().len(), 32);
        verify_signed(&r, &key, "acme");
        let r2 = sign_request(&key, &binding(None), "d", "POST", "/x", vec![], 0, 0);
        assert_ne!(r.header(H_DEVICE_NONCE), r2.header(H_DEVICE_NONCE), "fresh nonce per request");
    }

    #[test]
    fn clock_skew_adopts_the_offset_and_retries_once_with_a_fresh_nonce() {
        let calls = AtomicU32::new(0);
        let fc = FakeConsole::new(Box::new(move |_r| {
            if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                json(401, json!({"error":"clock_skew","serverTime": iso_ms(10_000_000)}))
            } else {
                json(201, json!({"ok": true}))
            }
        }));
        let key = DeviceKey::from_seed(&[7u8; 32]).unwrap();
        let mut off = 0i64;
        let now = || 4_000_000u64;
        let r = send_signed(&fc, &key, &binding(None), "d", "POST", "/api/devices/beat", b"{}".to_vec(), &[], &mut off, 1000, &now);
        assert!(r.is_ok());
        assert_eq!(off, 6_000_000);
        let reqs = fc.requests();
        assert_eq!(reqs.len(), 2);
        assert_ne!(reqs[0].header(H_DEVICE_NONCE), reqs[1].header(H_DEVICE_NONCE));
        assert_eq!(reqs[1].header(H_DEVICE_TS), Some(iso_ms(10_000_000).as_str()));
    }

    #[test]
    fn a_second_clock_skew_is_not_retried_and_the_offset_is_bounded() {
        let fc = FakeConsole::new(Box::new(|_r| json(401, json!({"error":"clock_skew","serverTime":"2099-01-01T00:00:00.000Z"}))));
        let key = DeviceKey::from_seed(&[7u8; 32]).unwrap();
        let mut off = 0i64;
        let r = send_signed(&fc, &key, &binding(None), "d", "GET", "/x", vec![], &[], &mut off, 1000, &|| 0);
        assert!(matches!(r, Err(ConsoleError::ClockSkew { .. })));
        assert_eq!(fc.requests().len(), 2);
        assert_eq!(off, MAX_CLOCK_OFFSET_MS);
    }

    fn reg_ok(status: &'static str, bound: bool) -> Handler {
        Box::new(move |r: &HttpRequest| {
            let b: serde_json::Value = serde_json::from_slice(&r.body).unwrap();
            json(201, json!({"ok":true,"deviceId":b["deviceId"],"keyId":b["keyId"],"status":status,"bound":bound,"serverTime":"2026-10-12T00:00:00.000Z","beatIntervalSec":300}))
        })
    }

    #[test]
    fn registration_is_signed_by_the_new_key_and_carries_the_enrol_secret() {
        let fc = FakeConsole::new(reg_ok("registered", true));
        let key = DeviceKey::from_seed(&[9u8; 32]).unwrap();
        let b = binding(Some("mes_0123"));
        let input = RegisterInput { key: &key, prev: None, binding: &b, device_id: "2af4dce3059ab31302f67f3e53b9226d", device: "host1" };
        let r = register(&fc, &input, &mut 0, &|| 1_791_797_399_120).unwrap();
        assert_eq!((r.status.as_str(), r.bound), ("registered", true));
        let req = &fc.requests()[0];
        assert_eq!(req.path_and_query, REGISTER_PATH);
        assert_eq!(req.header(H_ENROLL_SECRET), Some("mes_0123"));
        assert_eq!(req.header(H_INSTALL_TOKEN), Some("tok"));
        verify_signed(req, &key, "acme");
        let body: serde_json::Value = crate::canonical::parse_canonical(&req.body).expect("canonical body");
        assert_eq!(body["publicKey"], key.public_spki_b64());
        assert!(body.get("prevKeyId").is_none());
    }

    #[test]
    fn rotation_carries_the_old_keys_statement() {
        let fc = FakeConsole::new(reg_ok("rotated", true));
        let old = DeviceKey::from_seed(&[1u8; 32]).unwrap();
        let new = DeviceKey::from_seed(&[2u8; 32]).unwrap();
        let b = binding(None);
        let input = RegisterInput { key: &new, prev: Some(&old), binding: &b, device_id: "dev", device: "h" };
        register(&fc, &input, &mut 0, &|| 0).unwrap();
        let req = &fc.requests()[0];
        let body: serde_json::Value = serde_json::from_slice(&req.body).unwrap();
        assert_eq!(body["prevKeyId"], old.key_id());
        let stmt = rotate_input("acme", "dev", &old.key_id(), &new.key_id());
        crate::keys::verify_b64(&old.public_spki_b64(), stmt.as_bytes(), body["prevKeySig"].as_str().unwrap()).unwrap();
        assert!(req.header(H_ENROLL_SECRET).is_none());
        verify_signed(req, &new, "acme");
    }

    #[test]
    fn a_bad_enrol_secret_is_an_error_and_is_not_retried_unbound() {
        let fc = FakeConsole::new(Box::new(|_r| json(401, json!({"error":"bad_enroll_secret"}))));
        let key = DeviceKey::from_seed(&[9u8; 32]).unwrap();
        let b = binding(Some("mes_bad"));
        let input = RegisterInput { key: &key, prev: None, binding: &b, device_id: "dev", device: "h" };
        assert_eq!(register(&fc, &input, &mut 0, &|| 0), Err(ConsoleError::Status(401, "bad_enroll_secret".into())));
        assert_eq!(fc.requests().len(), 1, "one attempt, never a second without the secret");
    }

    #[test]
    fn a_mismatched_register_response_is_refused() {
        let fc = FakeConsole::new(Box::new(|_r| json(201, json!({"ok":true,"deviceId":"other","keyId":"x","status":"registered","bound":false,"serverTime":"","beatIntervalSec":300}))));
        let key = DeviceKey::from_seed(&[9u8; 32]).unwrap();
        let b = binding(None);
        let input = RegisterInput { key: &key, prev: None, binding: &b, device_id: "dev", device: "h" };
        assert!(matches!(register(&fc, &input, &mut 0, &|| 0), Err(ConsoleError::BadResponse(_))));
    }
}
