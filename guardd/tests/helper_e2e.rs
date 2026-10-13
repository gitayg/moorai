//! End-to-end tests of the helper core over a real Unix socket and an injected state tree
//! (`Paths::under`, feature `test-injection`), with fake platform facilities (process table, quarantine
//! backend, system info) and a scripted in-process console. Run:
//!   cargo test --features test-injection --test helper_e2e
#![cfg(all(unix, feature = "test-injection"))]

use moorai_guardd::canonical::{js_canonical_json, parse_canonical, sha256_hex};
use moorai_guardd::console::fake::FakeConsole;
use moorai_guardd::console::{ConsoleError, HttpRequest, HttpResponse};
use moorai_guardd::helper::{deliver_once, observe_once, register_once, rotate_key, Deps, Helper, IpcHandler, Shared};
use moorai_guardd::ipc::frame::{encode_value, Decoder};
use moorai_guardd::keys::{verify_b64, DeviceKey};
use moorai_guardd::observe::fake::{proc, FakeProcs};
use moorai_guardd::observe::ProcInfo;
use moorai_guardd::platform::SystemInfo;
use moorai_guardd::quarantine::recording::{Call, Recording};
use moorai_guardd::signing::{command_input, devreq_signing_input, hello_proof_input, CommandFields, DevReq};
use moorai_guardd::state::Paths;
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const T0: u64 = 1_791_795_600_000; // 2026-10-12T09:00:00.000Z
const AGENT: u32 = 3_999_001;
const CHILD: u32 = 3_999_002;
const OTHER_AGENT: u32 = 3_999_100;
const NOT_AGENT: u32 = 3_999_200;

struct Sys;
impl SystemInfo for Sys {
    fn boot_id(&self) -> std::io::Result<String> {
        Ok("8d1c1e0f-0000-4000-8000-000000000001".into())
    }
    fn awake_sec(&self) -> std::io::Result<u64> {
        Ok(3600)
    }
    fn uptime_sec(&self) -> std::io::Result<u64> {
        Ok(7200)
    }
    fn machine_id(&self) -> std::io::Result<String> {
        Ok("test-machine-0001".into())
    }
    fn hostname(&self) -> String {
        "test-host".into()
    }
}

/// What the fake console serves; tests edit it between steps.
#[derive(Default)]
struct Script {
    policy: Option<String>,
    published: Option<String>,
    commands: Vec<Value>,
    register_status: Option<(&'static str, bool)>,
    alerts_status: Option<(u16, &'static str)>,
}

fn console_key() -> DeviceKey {
    DeviceKey::from_seed(&[0x5a; 32]).unwrap()
}

fn sign_policy(body: Value, key: &DeviceKey, tenant: &str, iat: &str) -> String {
    let Value::Object(mut m) = body else { panic!() };
    let digest = sha256_hex(js_canonical_json(&Value::Object(m.clone())).as_bytes());
    let sig = key.sign_b64(format!("moorai-policy|v1|{tenant}|{iat}|{digest}").as_bytes());
    m.insert("policySig".into(), json!({"v":1,"alg":"ed25519","tenant":tenant,"iat":iat,"sig":sig}));
    serde_json::to_string(&Value::Object(m)).unwrap()
}

fn signed_command(seq: u64, action: &str, scope: &str, session: &str, qid: &str, device_id: &str) -> Value {
    let f = CommandFields {
        tenant: "acme".into(),
        device_id: device_id.into(),
        cmd_id: format!("c-{seq:032}"),
        cmd_seq: seq,
        action: action.into(),
        scope: scope.into(),
        session_hash: session.into(),
        quarantine_id: qid.into(),
        iat: "2026-10-12T09:00:30.000Z".into(),
    };
    let sig = console_key().sign_b64(command_input(&f).as_bytes());
    let mut v = serde_json::to_value(&f).unwrap();
    v["reason"] = json!("admin");
    v["sig"] = json!(sig);
    v
}

struct World {
    root: PathBuf,
    paths: Paths,
    shared: Arc<Shared>,
    console: Arc<FakeConsole>,
    script: Arc<Mutex<Script>>,
    procs: Arc<FakeProcs>,
    backend: Arc<Recording>,
    clock: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
}

impl Drop for World {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

fn reply(status: u16, v: Value) -> Result<HttpResponse, ConsoleError> {
    Ok(HttpResponse { status, body: serde_json::to_vec(&v).unwrap() })
}

fn handler(script: Arc<Mutex<Script>>) -> moorai_guardd::console::fake::Handler {
    Box::new(move |r: &HttpRequest| {
        let s = script.lock().unwrap();
        let path = r.path_and_query.split('?').next().unwrap_or("");
        match path {
            "/api/devices/register" => {
                let b: Value = serde_json::from_slice(&r.body).unwrap();
                let (status, bound) = s.register_status.unwrap_or(("registered", r.header("X-Enroll-Secret").is_some()));
                reply(201, json!({"ok":true,"deviceId":b["deviceId"],"keyId":b["keyId"],"status":status,"bound":bound,"serverTime":"2026-10-12T09:00:00.000Z","beatIntervalSec":300}))
            }
            "/api/devices/beat" => reply(201, json!({"ok":true})),
            "/api/devices/alerts" => match s.alerts_status {
                Some((code, err)) => reply(code, json!({"error": err})),
                None => reply(201, json!({"ok":true})),
            },
            "/api/devices/commands" => {
                if s.commands.is_empty() {
                    Ok(HttpResponse { status: 204, body: vec![] })
                } else {
                    reply(200, json!({"v":1,"commands": s.commands}))
                }
            }
            "/api/devices/commands/ack" => reply(200, json!({"ok":true})),
            "/api/policy" => match &s.policy {
                Some(p) => Ok(HttpResponse { status: 200, body: p.clone().into_bytes() }),
                None => reply(404, json!({})),
            },
            "/api/policy/pubkey" => match &s.published {
                Some(p) => Ok(HttpResponse { status: 200, body: p.clone().into_bytes() }),
                None => reply(404, json!({})),
            },
            _ => reply(404, json!({})),
        }
    })
}

fn world(tag: &str) -> World {
    let base = moorai_guardd::state::test_root(&format!("e2e-{tag}"));
    std::fs::create_dir_all(base.join("etc")).unwrap();
    for d in [base.clone(), base.join("etc")] {
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let paths = Paths::under(&base);
    std::fs::write(&paths.machine_config, r#"{"serverUrl":"http://127.0.0.1:9","tenant":"acme","helper":"required"}"#).unwrap();
    std::fs::set_permissions(&paths.machine_config, std::fs::Permissions::from_mode(0o644)).unwrap();
    std::fs::write(&paths.secret, r#"{"installToken":"tok-acme","enrollSecret":"mes_0123456789abcdef0123456789abcdef"}"#).unwrap();
    std::fs::set_permissions(&paths.secret, std::fs::Permissions::from_mode(0o600)).unwrap();
    open_world(base, paths)
}

fn table() -> Vec<ProcInfo> {
    let me = std::process::id();
    vec![
        proc(1, 0, 0, 0, "/sbin/launchd", None),
        proc(AGENT, 1, uid(), 1_000, "/usr/local/bin/claude", None),
        proc(me, AGENT, uid(), 2_000, "/usr/bin/node", Some("/opt/moorai/cli/moorai-hook.mjs")),
        proc(CHILD, AGENT, uid(), 3_000, "/bin/zsh", None),
        proc(OTHER_AGENT, 1, uid(), 1_500, "/usr/local/bin/claude", None),
        proc(NOT_AGENT, 1, uid(), 1_600, "/usr/bin/vim", None),
    ]
}

fn uid() -> u32 {
    moorai_guardd::state::current_uid()
}

fn open_world(root: PathBuf, paths: Paths) -> World {
    let script = Arc::new(Mutex::new(Script::default()));
    let console = Arc::new(FakeConsole::new(handler(script.clone())));
    let procs = Arc::new(FakeProcs::new(table()));
    let backend = Arc::new(Recording::new(&paths.state_file("quarantine.json")));
    let clock = Arc::new(AtomicU64::new(T0));
    let c2 = clock.clone();
    let deps = Deps { procs: procs.clone(), backend: backend.clone(), sys: Arc::new(Sys), console: console.clone(), clock: Arc::new(move || c2.load(Ordering::SeqCst)) };
    let shared = Helper::new(paths.clone()).unwrap().open_shared(deps).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let listener = moorai_guardd::transport::bind(&paths).unwrap();
    let h: Arc<dyn moorai_guardd::ipc::server::Handler> = Arc::new(IpcHandler { shared: shared.clone() });
    let st = stop.clone();
    std::thread::spawn(move || moorai_guardd::ipc::server::serve(listener.as_ref(), h, &st).unwrap());
    World { root, paths, shared, console, script, procs, backend, clock, stop }
}

struct Client {
    s: UnixStream,
    d: Decoder,
    id: u32,
}

impl Client {
    fn connect(w: &World) -> Client {
        let s = UnixStream::connect(&w.paths.endpoint).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        Client { s, d: Decoder::new(), id: 0 }
    }
    fn send(&mut self, mut v: Value) -> Value {
        self.id += 1;
        v["v"] = json!(1);
        v["id"] = json!(self.id);
        self.s.write_all(&encode_value(&v).unwrap()).unwrap();
        self.read()
    }
    fn read(&mut self) -> Value {
        let mut buf = [0u8; 65536];
        loop {
            if let Some(v) = self.d.next_value().unwrap() {
                return v;
            }
            let n = self.s.read(&mut buf).unwrap();
            assert!(n > 0, "connection closed");
            self.d.push(&buf[..n]);
        }
    }
    fn hello(&mut self) -> Value {
        self.send(json!({"op":"hello","proto":[1],"client":"moorai-hook","clientVersion":"1.13.6","host":"claude-code","nonce":"00112233445566778899aabbccddeeff"}))
    }
}

/// Server latency against the client budget (§3.5). Printed, and asserted with 2x slack so a loaded
/// test runner does not flake: the budget itself is gated by the CI latency job on a real install
/// (§11.4), not by unit tests sharing a CPU with the rest of the suite.
fn within_budget(op: &str, dt: Duration, budget_ms: u64) {
    eprintln!("latency {op}: {dt:?} (budget {budget_ms} ms)");
    assert!(dt < Duration::from_millis(budget_ms * 2), "{op} took {dt:?}, over 2x its {budget_ms} ms budget");
}

fn device_pub(w: &World) -> String {
    std::fs::read_to_string(w.paths.device_pub()).unwrap().trim().to_string()
}

fn verify_devreq(req: &HttpRequest, spki: &str) {
    let input = devreq_signing_input(&DevReq {
        method: req.method,
        path: &req.path_and_query,
        tenant: "acme",
        device_id: req.header("X-Device-Id").unwrap(),
        key_id: req.header("X-Device-Key").unwrap(),
        ts: req.header("X-Device-Ts").unwrap(),
        nonce: req.header("X-Device-Nonce").unwrap(),
        body: &req.body,
    });
    verify_b64(spki, input.as_bytes(), req.header("X-Device-Sig").unwrap()).expect("device signature verifies against device.pub");
    assert_eq!(req.header("X-Install-Token"), Some("tok-acme"));
    if req.method == "POST" {
        let body = parse_canonical(&req.body).expect("canonical body");
        assert_eq!((body["tenant"].as_str(), body["deviceId"].as_str()), (Some("acme"), req.header("X-Device-Id")));
    }
}

fn requests_to(w: &World, path: &str) -> Vec<HttpRequest> {
    w.console.requests().into_iter().filter(|r| r.path_and_query.split('?').next() == Some(path)).collect()
}

fn pin_console_key(w: &World) {
    let ck = console_key();
    let mut s = w.script.lock().unwrap();
    s.policy = Some(sign_policy(json!({"threatPolicy":{"21":"quarantine"},"policyMaxAgeMinutes":15}), &ck, "acme", "2026-10-12T09:00:00.000Z"));
    s.published = Some(format!(r#"{{"tenant":"acme","publicKey":"{}"}}"#, ck.public_spki_b64()));
    drop(s);
    moorai_guardd::policy::fetch_cycle(w.shared.state_mutex(), w.console.as_ref()).unwrap();
}

#[test]
fn hello_proves_the_device_key_and_reports_the_binding() {
    let w = world("hello");
    let mut c = Client::connect(&w);
    let t = Instant::now();
    let h = c.hello();
    let dt = t.elapsed();
    assert_eq!(h["op"], "hello");
    assert_eq!((h["tenant"].as_str(), h["proto"].as_u64()), (Some("acme"), Some(1)));
    let spki = device_pub(&w);
    let key_id = moorai_guardd::keys::key_id_of_raw(&moorai_guardd::keys::raw_from_spki_b64(&spki).unwrap());
    assert_eq!(h["keyId"], key_id.as_str(), "keyId is device.pub's");
    let input = hello_proof_input("00112233445566778899aabbccddeeff", &key_id, h["helperVersion"].as_str().unwrap());
    verify_b64(&spki, input.as_bytes(), h["proof"].as_str().unwrap()).expect("proof verifies against device.pub");
    assert_eq!(h["caps"], json!(["call", "hello", "kill", "policy", "quarantine", "release", "submit"]));
    assert_eq!(h["deviceId"], moorai_guardd::keys::device_id_of_machine_id("test-machine-0001").as_str());
    within_budget("hello", dt, moorai_guardd::ipc::CONNECT_BUDGET_MS);
    assert_eq!(std::fs::metadata(&w.paths.endpoint).unwrap().permissions().mode() & 0o777, 0o666);
    let bad = c.send(json!({"op":"hello","proto":[2],"client":"moorai-hook","clientVersion":"x","nonce":"00112233445566778899aabbccddeeff"}));
    assert_eq!(bad["code"], "unsupported_version");
}

#[test]
fn without_a_binding_hello_is_not_ready() {
    let base = moorai_guardd::state::test_root("e2e-nobind");
    std::fs::create_dir_all(&base).unwrap();
    std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o755)).unwrap();
    let w = open_world(base.clone(), Paths::under(&base));
    let mut c = Client::connect(&w);
    assert_eq!(c.hello()["code"], "not_ready");
}

#[test]
fn ops_other_than_hello_first_are_refused_and_release_is_admin_only() {
    let w = world("auth");
    let mut c = Client::connect(&w);
    assert_eq!(c.send(json!({"op":"kill"}))["code"], "bad_request");
    let mut c = Client::connect(&w);
    c.hello();
    let r = c.send(json!({"op":"release","quarantineId":"*"}));
    assert_eq!((r["code"].as_str(), r["reqOp"].as_str()), (Some("forbidden"), Some("release")), "uid {} is not an admin peer", uid());
}

#[test]
fn registration_is_bound_by_the_enrol_secret_which_is_then_removed() {
    let w = world("register");
    let r = register_once(&w.shared).unwrap().unwrap();
    assert_eq!((r.status.as_str(), r.bound), ("registered", true));
    let req = &requests_to(&w, "/api/devices/register")[0];
    assert_eq!(req.header("X-Enroll-Secret"), Some("mes_0123456789abcdef0123456789abcdef"));
    verify_devreq(req, &device_pub(&w));
    let secret: Value = serde_json::from_slice(&std::fs::read(&w.paths.secret).unwrap()).unwrap();
    assert!(secret.get("enrollSecret").is_none() && secret["installToken"] == "tok-acme");
    assert_eq!(std::fs::metadata(&w.paths.secret).unwrap().permissions().mode() & 0o777, 0o600);
    let reg: Value = serde_json::from_slice(&std::fs::read(w.paths.state_file("registration.json")).unwrap()).unwrap();
    assert_eq!((reg["status"].as_str(), reg["bound"].as_bool()), (Some("registered"), Some(true)));
    assert!(register_once(&w.shared).unwrap().is_none(), "nothing to do once registered");
    assert_eq!(requests_to(&w, "/api/devices/register").len(), 1);
}

#[test]
fn a_planned_rotation_is_signed_by_the_old_key_and_swaps_device_key_and_pub() {
    let w = world("rotate");
    register_once(&w.shared).unwrap();
    let old_pub = device_pub(&w);
    w.script.lock().unwrap().register_status = Some(("rotated", true));
    let r = rotate_key(&w.shared).unwrap().unwrap();
    assert_eq!(r.status, "rotated");
    let req = requests_to(&w, "/api/devices/register").pop().unwrap();
    let body: Value = serde_json::from_slice(&req.body).unwrap();
    let new_pub = device_pub(&w);
    assert_ne!(old_pub, new_pub);
    assert_eq!(body["publicKey"], new_pub.as_str());
    verify_devreq(&req, &new_pub);
    let stmt = moorai_guardd::signing::rotate_input("acme", body["deviceId"].as_str().unwrap(), body["prevKeyId"].as_str().unwrap(), body["keyId"].as_str().unwrap());
    verify_b64(&old_pub, stmt.as_bytes(), body["prevKeySig"].as_str().unwrap()).unwrap();
    assert!(!w.paths.state_file("device.key.next").exists());
    let mut c = Client::connect(&w);
    assert_eq!(c.hello()["keyId"], body["keyId"], "hello proves the new key");
}

#[test]
fn policy_is_fetched_verified_pinned_and_served() {
    let w = world("policy");
    let mut c = Client::connect(&w);
    c.hello();
    assert_eq!(c.send(json!({"op":"policy"}))["source"], "none");
    pin_console_key(&w);
    let p = c.send(json!({"op":"policy"}));
    assert_eq!(p["source"], "fresh");
    assert_eq!(p["policy"].as_str(), w.script.lock().unwrap().policy.as_deref(), "the console's exact bytes");
    let same = c.send(json!({"op":"policy","ifIat":"2026-10-12T09:00:00.000Z"}));
    assert!(same.get("policy").is_none());
    w.clock.store(T0 + 20 * 60_000, Ordering::SeqCst);
    assert_eq!(c.send(json!({"op":"policy"}))["source"], "cache");
    let fetches = requests_to(&w, "/api/policy");
    assert_eq!(fetches[0].path_and_query, "/api/policy?tenant=acme");
    assert_eq!(fetches[0].header("X-Install-Token"), Some("tok-acme"));
}

#[test]
fn submitted_alerts_are_durable_across_a_restart_then_delivered_signed() {
    let root;
    let paths;
    let acks;
    {
        let w = world("submit");
        register_once(&w.shared).unwrap();
        let mut c = Client::connect(&w);
        c.hello();
        let t = Instant::now();
        let r = c.send(json!({"op":"submit","alerts":[{"threatId":21,"severity":"high","seq":5,"peerUid":0},{"threatId":22}]}));
        within_budget("submit", t.elapsed(), moorai_guardd::ipc::OP_TIMEOUT_SUBMIT_MS);
        acks = r["acks"].clone();
        assert_eq!(acks, json!([{"seq":1},{"seq":2}]));
        assert_eq!(r["chainHead"].as_str().unwrap().len(), 64);
        assert_eq!(c.send(json!({"op":"submit","alerts":[]}))["code"], "bad_request");
        root = w.root.clone();
        paths = w.paths.clone();
    }
    // A new helper over the same state: the acked alerts are still queued.
    let _ = std::fs::remove_file(&paths.endpoint);
    let w = open_world(root, paths);
    assert_eq!(w.shared.lock().alerts.len(), 2);
    match deliver_once(&w.shared) {
        moorai_guardd::alerts::Delivery::Delivered { alerts, .. } => assert_eq!(alerts, 2),
        d => panic!("{d:?}"),
    }
    let req = &requests_to(&w, "/api/devices/alerts")[0];
    verify_devreq(req, &device_pub(&w));
    let body: Value = serde_json::from_slice(&req.body).unwrap();
    assert_eq!((body["firstSeq"].as_u64(), body["lastSeq"].as_u64()), (Some(1), Some(2)));
    assert_eq!(body["alerts"][0]["peerUid"], uid(), "peerUid is the kernel's, not the message's");
    assert_eq!(body["alerts"][0]["seq"], 1);
    assert!(w.shared.lock().alerts.is_empty());
    assert_eq!(deliver_once(&w.shared), moorai_guardd::alerts::Delivery::Empty);
}

#[test]
fn a_failed_delivery_is_retried_with_the_same_batch_id_and_409_duplicate_counts_as_delivered() {
    let w = world("retry");
    register_once(&w.shared).unwrap();
    w.shared.lock().alerts.enqueue(vec![json!({"a":1}).as_object().unwrap().clone()], Some(1)).unwrap();
    w.script.lock().unwrap().alerts_status = Some((500, "boom"));
    assert!(matches!(deliver_once(&w.shared), moorai_guardd::alerts::Delivery::Retry(_)));
    w.script.lock().unwrap().alerts_status = Some((409, "duplicate"));
    assert!(matches!(deliver_once(&w.shared), moorai_guardd::alerts::Delivery::Delivered { .. }));
    let sent = requests_to(&w, "/api/devices/alerts");
    let ids: Vec<Value> = sent.iter().map(|r| serde_json::from_slice::<Value>(&r.body).unwrap()["batchId"].clone()).collect();
    assert_eq!(ids[0], ids[1]);
    assert_ne!(sent[0].header("X-Device-Nonce"), sent[1].header("X-Device-Nonce"));
}

#[test]
fn calls_are_counted_into_a_signed_beat_whose_seq_is_never_reused() {
    let w = world("beat");
    register_once(&w.shared).unwrap();
    let mut c = Client::connect(&w);
    c.hello();
    let t = Instant::now();
    let r = c.send(json!({"op":"call","event":"PreToolUse","host":"claude-code","sessionHash":"a1b2c3d4e5f60718","agentPid":1}));
    within_budget("call", t.elapsed(), moorai_guardd::ipc::OP_TIMEOUT_CALL_MS);
    assert_eq!(r["op"], "call");
    c.send(json!({"op":"call","event":"Stop","host":"claude-code","sessionHash":"a1b2c3d4e5f60718"}));
    assert_eq!(c.send(json!({"op":"call","event":"x","host":"claude-code","sessionHash":"nothex"}))["code"], "bad_request");
    observe_once(&w.shared).unwrap();
    assert_eq!(moorai_guardd::beat::beat_once(&w.shared), moorai_guardd::beat::BeatOutcome::Sent(1));
    let req = requests_to(&w, "/api/devices/beat").pop().unwrap();
    verify_devreq(&req, &device_pub(&w));
    let b: Value = serde_json::from_slice(&req.body).unwrap();
    assert_eq!(b["hookCalls"], json!({"claude-code": 2}));
    assert_eq!(b["agentProcs"], json!({"claude-code": 2}));
    assert_eq!((b["bootId"].as_str(), b["awakeSec"].as_u64(), b["uptimeSec"].as_u64()), (Some("8d1c1e0f-0000-4000-8000-000000000001"), Some(3600), Some(7200)));
    assert_eq!(b["versions"]["hook"], "1.13.6");
    assert_eq!(b["policySource"], "none");
    assert_eq!(moorai_guardd::beat::beat_once(&w.shared), moorai_guardd::beat::BeatOutcome::Sent(2));
    let b2: Value = serde_json::from_slice(&requests_to(&w, "/api/devices/beat").pop().unwrap().body).unwrap();
    assert_eq!(b2["hookCalls"], json!({"claude-code": 0}), "counts reset after an accepted beat");
    let persisted: Value = serde_json::from_slice(&std::fs::read(w.paths.state_file("beat.json")).unwrap()).unwrap();
    assert_eq!(persisted["beatSeq"], 2);
}

#[test]
fn an_agent_without_calls_for_120s_is_hook_silent_with_one_signed_alert() {
    let w = world("silent");
    w.clock.store(T0 + 121_000, Ordering::SeqCst);
    assert_eq!(observe_once(&w.shared).unwrap(), 2, "both claude processes");
    assert_eq!(observe_once(&w.shared).unwrap(), 0, "once per process");
    let s = w.shared.lock();
    assert_eq!(s.observer.hook_silent(T0 + 121_000), vec![moorai_guardd::beat::HookSilent { host: "claude-code".into(), since_sec: 121 }]);
    assert_eq!(s.alerts.len(), 2);
}

#[test]
fn quarantine_over_ipc_targets_the_callers_agent_tree_in_contract_order() {
    let w = world("quarantine");
    let mut c = Client::connect(&w);
    c.hello();
    let req = json!({"op":"quarantine","agentPid":AGENT,"host":"claude-code","threatId":21,"reasonCode":"policy-quarantine","sessionHash":"a1b2c3d4e5f60718","decidedAtMs":T0});
    let t = Instant::now();
    let r = c.send(req.clone());
    within_budget("quarantine", t.elapsed(), moorai_guardd::ipc::OP_TIMEOUT_QUARANTINE_MS);
    assert_eq!((r["op"].as_str(), r["network"].as_str(), r["suspendedPids"].as_u64()), (Some("quarantine"), Some("pending"), Some(2)));
    // The follow-up runs after the reply: network block, then the signed alert.
    let deadline = Instant::now() + Duration::from_secs(2);
    while w.backend.calls().len() < 2 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    let calls = w.backend.calls();
    assert_eq!(calls[0], Call::Suspend { pids: vec![AGENT, CHILD], persisted_active: true }, "persisted before acting; the hook process itself is left running");
    assert!(matches!(&calls[1], Call::NetBlock { persisted_active: true, .. }));
    let deadline = Instant::now() + Duration::from_secs(2);
    while w.shared.lock().alerts.is_empty() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    let batch = w.shared.lock().alerts.next_batch("acme", "d").unwrap().unwrap();
    assert_eq!((batch.alerts[0]["kind"].as_str(), batch.alerts[0]["network"].as_str()), (Some("quarantine"), Some("applied")));
    // After the grace period the requesting process would be suspended too (unit-tested in
    // quarantine.rs); here the "hook" is the helper's own test process, which is never suspended.
    std::thread::sleep(Duration::from_millis(moorai_guardd::quarantine::PEER_GRACE_MS + 300));
    assert_eq!(w.backend.calls().len(), 2, "the helper never suspends itself");
}

#[test]
fn quarantine_naming_another_tree_is_refused_with_a_signed_alert() {
    let w = world("refused");
    let mut c = Client::connect(&w);
    c.hello();
    for pid in [OTHER_AGENT, NOT_AGENT, 1] {
        let r = c.send(json!({"op":"quarantine","agentPid":pid,"host":"claude-code","threatId":21,"reasonCode":"policy-quarantine","sessionHash":"a1b2c3d4e5f60718","decidedAtMs":T0}));
        assert_eq!(r["code"], "target_not_agent_ancestor", "pid {pid}");
    }
    assert!(w.backend.calls().is_empty());
    let mut s = w.shared.lock();
    assert_eq!(s.alerts.len(), 3);
    let b = s.alerts.next_batch("acme", "d").unwrap().unwrap();
    assert!(b.alerts.iter().all(|a| a["kind"] == "quarantineRefused" && a["peerUid"] == uid()));
    drop(s);
    let bad = c.send(json!({"op":"quarantine","agentPid":AGENT,"host":"claude-code","threatId":21,"ruleId":"r1","reasonCode":"x","sessionHash":"a1b2c3d4e5f60718","decidedAtMs":T0}));
    assert_eq!(bad["code"], "bad_request", "exactly one of threatId / ruleId");
}

#[test]
fn console_commands_are_verified_applied_acked_and_never_replayed() {
    let w = world("push");
    register_once(&w.shared).unwrap();
    pin_console_key(&w);
    let device_id = w.shared.lock().device_id.clone();
    // A call maps the session to this process's agent tree.
    let mut c = Client::connect(&w);
    c.hello();
    c.send(json!({"op":"call","event":"PreToolUse","host":"claude-code","sessionHash":"a1b2c3d4e5f60718"}));
    let forged = {
        let mut v = signed_command(9, "kill", "device", "", "", &device_id);
        v["sig"] = json!(DeviceKey::from_seed(&[1; 32]).unwrap().sign_b64(b"x"));
        v
    };
    w.script.lock().unwrap().commands = vec![
        signed_command(5, "kill", "session", "a1b2c3d4e5f60718", "", &device_id),
        forged,
        signed_command(6, "quarantine", "session", "a1b2c3d4e5f60718", "", &device_id),
    ];
    assert_eq!(moorai_guardd::push::poll_once(&w.shared).unwrap(), 3);
    let polls = requests_to(&w, "/api/devices/commands");
    assert_eq!(polls[0].path_and_query, "/api/devices/commands?after=0&wait=25");
    verify_devreq(&polls[0], &device_pub(&w));
    let acks: Vec<Value> = requests_to(&w, "/api/devices/commands/ack").iter().map(|r| {
        verify_devreq(r, &device_pub(&w));
        serde_json::from_slice(&r.body).unwrap()
    }).collect();
    assert_eq!(acks.iter().map(|a| a["result"].as_str().unwrap()).collect::<Vec<_>>(), vec!["applied", "bad-signature", "applied"]);
    assert_eq!(acks[2]["suspendedPids"], 2, "the agent and its child; the helper's own pid (this test process) is never a target");
    let k = c.send(json!({"op":"kill","sessionHash":"a1b2c3d4e5f60718"}));
    assert_eq!((k["kill"].as_bool(), k["scope"].as_str()), (Some(true), Some("session")));
    assert_eq!(c.send(json!({"op":"kill","sessionHash":"ffffffffffffffff"}))["kill"], false);
    let qid = acks[2]["quarantineId"].as_str().unwrap().to_string();
    assert_eq!(w.shared.lock().last_cmd_seq(), 6, "the forged seq 9 did not advance it");
    // The same commands again (a replay): nothing is re-applied.
    let n = w.backend.calls().len();
    moorai_guardd::push::poll_once(&w.shared).unwrap();
    assert_eq!(w.backend.calls().len(), n);
    let polls = requests_to(&w, "/api/devices/commands");
    assert_eq!(polls.last().unwrap().path_and_query, "/api/devices/commands?after=6&wait=25");
    // Release by console command.
    w.script.lock().unwrap().commands = vec![signed_command(7, "release", "device", "", &qid, &device_id)];
    moorai_guardd::push::poll_once(&w.shared).unwrap();
    assert!(matches!(w.backend.calls().last().unwrap(), Call::Resume { persisted_released: true, .. }));
    let q: Value = serde_json::from_slice(&std::fs::read(w.paths.state_file("quarantine.json")).unwrap()).unwrap();
    assert_eq!((q["entries"][0]["status"].as_str(), q["lastCmdSeq"].as_u64()), (Some("released"), Some(7)));
    assert_eq!(q["entries"][0]["releasedBy"], format!("console:c-{:032}", 7));
}

#[test]
fn the_full_helper_threads_register_beat_and_poll_on_their_own() {
    let w = world("threads");
    let deps = Deps {
        procs: w.procs.clone(),
        backend: w.backend.clone(),
        sys: Arc::new(Sys),
        console: w.console.clone(),
        clock: Arc::new(moorai_guardd::clock::now_ms),
    };
    // A second helper instance over a fresh tree with the background threads running.
    let base = w.root.join("threads2");
    std::fs::create_dir_all(base.join("etc")).unwrap();
    for d in [base.clone(), base.join("etc")] {
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let p = Paths::under(&base);
    std::fs::copy(&w.paths.machine_config, &p.machine_config).unwrap();
    std::fs::write(&p.secret, r#"{"installToken":"tok-acme"}"#).unwrap();
    std::fs::set_permissions(&p.secret, std::fs::Permissions::from_mode(0o600)).unwrap();
    let shared = Helper::new(p).unwrap().start(deps).unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    let seen = |path: &str| requests_to(&w, path).iter().any(|r| r.header("X-Device-Key") == Some(shared.lock().key.key_id().as_str()));
    while !(seen("/api/devices/register") && seen("/api/devices/beat") && seen("/api/devices/commands")) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    shared.stop();
    assert!(seen("/api/devices/register"), "registered");
    assert!(seen("/api/devices/beat"), "the start-up beat");
    assert!(seen("/api/devices/commands"), "the long-poll");
}
