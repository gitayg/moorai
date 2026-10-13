// The clipboard guard's loop and its connections: the signed policy (clip_guard_policy.rs), the OS
// providers (clip_guard_mac.rs / clip_guard_win.rs), the scanner (the webview's detection engine, the
// same detectors the app runs on prompts and on OCR text), the console, the notification and the status
// line. The decisions are clip_guard.rs.
//
// The scanner round trip: the host emits "clipguard-scan" { id, text } to the app window, src/clipguard.js
// runs the secret and PII detectors over it and answers with clipguard_result { id, findings } (detector
// ids, threat ids, risk levels). The text stays in this process and the webview; it is not logged, stored
// or sent. No answer within 2 s counts as "scanner unavailable" and nothing is done.
#![cfg_attr(not(any(target_os = "macos", windows)), allow(dead_code, unused_imports))]
use crate::clip_guard::{ClipPolicy, Finding, Guard, Mode, Providers};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;
use tauri::{Emitter, Manager};

const POLICY_REFRESH: Duration = Duration::from_secs(300);
const POLICY_RETRY: Duration = Duration::from_secs(60);
const SCAN_TIMEOUT: Duration = Duration::from_secs(2);
#[cfg(target_os = "macos")]
const POLL: Duration = Duration::from_millis(500);
#[cfg(any(target_os = "macos", windows))]
const OFF_POLL: Duration = Duration::from_secs(2);

#[derive(Default)]
struct Shared {
    policy: Mutex<(ClipPolicy, String)>,
    status: Mutex<Value>,
    pending: Mutex<HashMap<u64, mpsc::Sender<Option<Vec<Finding>>>>>,
    next: AtomicU64,
}

fn shared() -> &'static Shared {
    static S: OnceLock<Shared> = OnceLock::new();
    S.get_or_init(|| Shared { policy: Mutex::new((ClipPolicy::default(), "no verified policy".into())), ..Default::default() })
}

pub fn supported() -> bool { cfg!(any(target_os = "macos", windows)) }

fn refresh_status(app: &tauri::AppHandle, last: Option<Value>) {
    let (pol, trust) = shared().policy.lock().unwrap().clone();
    let mut st = shared().status.lock().unwrap();
    let prev_last = st.get("lastAction").cloned().unwrap_or(Value::Null);
    #[cfg(target_os = "macos")]
    let access = Value::from(crate::clip_guard_mac::access_behavior());
    #[cfg(not(target_os = "macos"))]
    let access = Value::Null;
    *st = json!({
        "supported": supported(),
        "platform": std::env::consts::OS,
        "mode": if supported() { pol.mode.as_str() } else { "off" },
        "policyMode": pol.mode.as_str(),
        "policy": trust,
        "approvedApps": pol.approved.len(),
        "extraAiApps": pol.extra_ai.len(),
        "pasteboardAccess": access,
        "lastAction": last.unwrap_or(prev_last),
    });
    let _ = app.emit("clipguard-status", st.clone());
}

// No content: on/off, mode, why, counts, and the last action (what, which app, when).
#[tauri::command]
pub fn clipguard_status() -> Value {
    let st = shared().status.lock().unwrap().clone();
    if st.is_null() { json!({ "supported": supported(), "platform": std::env::consts::OS, "mode": "off", "policy": "no verified policy" }) } else { st }
}

#[derive(Deserialize)]
pub struct FindingIn {
    #[serde(rename = "detectorId")]
    detector_id: String,
    #[serde(rename = "threatId", default)]
    threat_id: u64,
    #[serde(rename = "riskLevel", default)]
    risk_level: String,
}

// The webview's answer to a scan request. `findings` is null when its engine could not scan.
#[tauri::command]
pub fn clipguard_result(id: u64, findings: Option<Vec<FindingIn>>) {
    let tx = shared().pending.lock().unwrap().remove(&id);
    if let Some(tx) = tx {
        let _ = tx.send(findings.map(|v| v.into_iter().take(64).map(|f| Finding { detector: f.detector_id, threat_id: f.threat_id, risk: f.risk_level }).collect()));
    }
}

struct WebviewScanner { app: tauri::AppHandle }
impl crate::clip_guard::Scanner for WebviewScanner {
    fn scan(&self, text: &str) -> Option<Vec<Finding>> {
        let id = shared().next.fetch_add(1, Ordering::Relaxed) + 1;
        let (tx, rx) = mpsc::channel();
        shared().pending.lock().unwrap().insert(id, tx);
        if self.app.emit_to("main", "clipguard-scan", json!({ "id": id, "text": text })).is_err() {
            shared().pending.lock().unwrap().remove(&id);
            return None;
        }
        let r = rx.recv_timeout(SCAN_TIMEOUT).ok().flatten();
        shared().pending.lock().unwrap().remove(&id);
        r
    }
}

struct SystemClock;
impl crate::clip_guard::Clock for SystemClock {
    fn now_ms(&self) -> u64 { std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0) }
}

struct HostSink { app: tauri::AppHandle }
impl crate::clip_guard::Sink for HostSink {
    fn alert(&self, alert: Value) { post_alert(&self.app, alert, true); }

    fn notify(&self, title: &str, body: &str) {
        #[cfg(target_os = "macos")]
        crate::clip_guard_mac::notify(title, body);
        #[cfg(windows)]
        crate::clip_guard_win::notify(title, body);
        let _ = self.app.emit("clipguard-notice", json!({ "title": title, "body": body }));
    }
}

// Stamp the identity every alert carries, append to the local audit file, post to the bound console.
fn post_alert(app: &tauri::AppHandle, mut alert: Value, record_last: bool) {
    let admin = crate::admin_config::admin();
    let cfg = crate::admin_config::effective_config(crate::read_config(), &admin);
    let (user, device) = (crate::platform::username(), crate::platform::hostname());
    let key = crate::content_hash::tenant_key();
    if let Some(o) = alert.as_object_mut() {
        o.insert("user".into(), user.clone().into());
        o.insert("device".into(), device.clone().into());
        o.insert("platform".into(), std::env::consts::OS.into());
        o.insert("tenant".into(), cfg.get("tenant").and_then(|t| t.as_str()).unwrap_or("unprovisioned").into());
        o.insert("actor".into(), crate::content_hash::hash_with_key(key.as_ref(), &format!("{user}@{device}")).into());
        o.insert("appVersion".into(), env!("CARGO_PKG_VERSION").into());
    }
    if record_last {
        let g = &alert["clipboardGuard"];
        refresh_status(app, Some(json!({ "action": g["action"], "app": g["app"], "ts": alert["ts"] })));
    }
    // The on-device audit sink (lib.rs native_log's file), content-free like the alert itself.
    if let Ok(dir) = app.path().app_data_dir() {
        use std::io::Write;
        let _ = std::fs::create_dir_all(&dir);
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(dir.join("audit.jsonl")) { let _ = writeln!(f, "{}", json!({ "alert": alert })); }
    }
    std::thread::spawn(move || {
        let req = crate::console_http::ConsoleRequest { method: "POST".into(), path: "/api/alerts".into(), body: None, credentialed: true, base: None, client_id: None };
        match crate::console_http::target(&req, &crate::console_binding::host_dir(), &cfg, &admin) {
            Ok((url, token)) => {
                if let Err(e) = tauri::async_runtime::block_on(crate::console_http::send("POST", url, Some(alert), token, None, crate::console_http::TIMEOUT)) {
                    eprintln!("[moorai] clipboard guard: alert not delivered: {e}");
                }
            }
            Err(e) => eprintln!("[moorai] clipboard guard: alert not sent: {e}"),
        }
    });
}

fn hash(text: &str) -> String { crate::content_hash::hash_with_key(crate::content_hash::tenant_key().as_ref(), text) }

// A content-free tamper alert, once per reason per run: a refused pin or a refused live policy.
fn tamper_alert(app: &tauri::AppHandle, reason: &str, kept: &str) {
static SENT: OnceLock<Mutex<std::collections::HashSet<String>>> = OnceLock::new();
if !SENT.get_or_init(Default::default).lock().unwrap().insert(reason.to_string()) { return; }
let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0);
post_alert(app, json!({
    "threatId": 0,
    "category": "Clipboard guard: policy refused, last verified policy kept",
    "riskLevel": "High",
    "stage": "clipboard",
    "tool": "clipboard-guard",
    "reasonCode": "CLIPBOARD_GUARD_POLICY_REFUSED",
    "ts": crate::clip_guard::iso8601(now),
    "contentHash": format!("clipguard:{reason}"),
    "clipboardGuard": { "refused": reason, "kept": kept },
}), false);
}

fn policy_thread(app: tauri::AppHandle) {
    std::thread::spawn(move || {
        let dir = crate::console_binding::host_dir();
        // `memory`: the policy that verified in this process. `stored`: the saved copy, a convenience for
        // the next launch that decide() takes only under a key that is still trusted.
        let stored = crate::clip_guard_policy::load_last(&dir);
        let mut memory: Option<Value> = None;
        let mut fetch = false;
        loop {
            let d = crate::clip_guard_policy::gather_and_decide(fetch, memory.as_ref(), stored.as_ref());
            if d.save {
                if let Some(p) = &d.verified {
                    if let Err(e) = crate::clip_guard_policy::save_last(&dir, p) { eprintln!("[moorai] clipboard guard: last verified policy not saved: {e}"); }
                }
            }
            if d.verified.is_some() { memory = d.verified.clone(); }
            for t in &d.tamper { tamper_alert(&app, t, d.policy.mode.as_str()); }
            let answered = !d.status.contains("(console: ");
            *shared().policy.lock().unwrap() = (d.policy, d.status);
            refresh_status(&app, None);
            if fetch { std::thread::sleep(if answered { POLICY_REFRESH } else { POLICY_RETRY }); }
            fetch = true;
        }
    });
}

// One step: pick up a changed policy, then let the guard look. Returns the current mode.
fn step(guard: &mut Guard, apps: &mut (ClipPolicy, crate::clip_guard_apps::AppList), p: &Providers) -> Mode {
    let pol = shared().policy.lock().unwrap().0.clone();
    if pol != apps.0 {
        apps.1 = crate::clip_guard_apps::AppList::builtin(pol.extra_ai.clone());
        apps.0 = pol.clone();
        guard.set_policy(pol);
    }
    guard.tick(p, &apps.1);
    guard.policy.mode
}

pub fn start(app: tauri::AppHandle) {
    refresh_status(&app, None);
    // Fetched on every platform, so a Linux status line can say the policy asks for what it cannot do.
    policy_thread(app.clone());
    if !supported() { return; }
    std::thread::spawn(move || {
        let scanner = WebviewScanner { app: app.clone() };
        let sink = HostSink { app: app.clone() };
        let mut guard = Guard::new(ClipPolicy::default());
        let mut apps = (ClipPolicy::default(), crate::clip_guard_apps::AppList::builtin(Default::default()));
        #[cfg(target_os = "macos")]
        {
            let (clip, front) = (crate::clip_guard_mac::MacClipboard, crate::clip_guard_mac::MacFrontmost);
            let p = Providers { clip: &clip, front: &front, clock: &SystemClock, scanner: &scanner, sink: &sink, hash: &hash };
            loop {
                let mode = objc2::rc::autoreleasepool(|_| step(&mut guard, &mut apps, &p));
                std::thread::sleep(if mode == Mode::Off { OFF_POLL } else { POLL });
            }
        }
        #[cfg(windows)]
        {
            let mut last_off_check = std::time::Instant::now() - OFF_POLL;
            let r = crate::clip_guard_win::run(|hwnd| {
                // Off: the 500 ms timer still fires, but the guard is consulted only every 2 s and then
                // touches nothing (clip_guard.rs returns before reading the clipboard).
                if guard.policy.mode == Mode::Off && last_off_check.elapsed() < OFF_POLL && shared().policy.lock().unwrap().0.mode == Mode::Off { return; }
                last_off_check = std::time::Instant::now();
                let clip = crate::clip_guard_win::WinClipboard { hwnd };
                let front = crate::clip_guard_win::WinFrontmost;
                let p = Providers { clip: &clip, front: &front, clock: &SystemClock, scanner: &scanner, sink: &sink, hash: &hash };
                step(&mut guard, &mut apps, &p);
            });
            if let Err(e) = r { eprintln!("[moorai] clipboard guard: listener not started: {e}"); }
        }
    });
}
