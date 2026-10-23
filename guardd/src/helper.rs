//! The helper process: wires state, the IPC server loop and the background threads (policy fetch,
//! alert delivery, beat, observation, registration, command poll).

use crate::console::{ConsoleError, ConsoleTransport};
use crate::ipc::server::{error_frame, AfterReply, ConnCtx, Handler};
use crate::ipc::{
    CallResp, ErrorCode, HelloResp, ReleaseResp, Request, RequestFrame, Response, ResponseFrame, MAX_SUBMIT_ALERTS, OPS, PROTO_VERSION,
};
use crate::observe::ProcessSource;
use crate::platform::SystemInfo;
use crate::quarantine::{Peer, QuarantineBackend};
use crate::state::{files, save_json, HelperState, Paths};
use crate::transport::PeerCred;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

#[derive(Debug)]
pub enum StartError {
    /// Injected (non-system) paths while running as root/SYSTEM (contract §10.2).
    InjectedPathsWhilePrivileged,
    /// The system paths need root/SYSTEM; an unprivileged process refuses to run (§1, §10.2).
    Unprivileged,
    Io(std::io::Error),
    Config(crate::config::ConfigError),
    Key(crate::keys::KeyError),
}

/// The OS facilities and the console client the helper runs on. Production: `platform::Platform` and
/// `ReqwestTransport`; tests: fakes.
#[derive(Clone)]
pub struct Deps {
    pub procs: Arc<dyn ProcessSource + Send + Sync>,
    pub backend: Arc<dyn QuarantineBackend + Send + Sync>,
    pub sys: Arc<dyn SystemInfo + Send + Sync>,
    pub console: Arc<dyn ConsoleTransport>,
    pub clock: Arc<dyn Fn() -> u64 + Send + Sync>,
}

/// State shared by the IPC handlers and the background threads.
pub struct Shared {
    state: Mutex<HelperState>,
    pub deps: Deps,
    stop: AtomicBool,
    wake: (Mutex<()>, std::sync::Condvar),
}

impl Shared {
    pub fn new(state: HelperState, deps: Deps) -> Arc<Shared> {
        Arc::new(Shared { state: Mutex::new(state), deps, stop: AtomicBool::new(false), wake: (Mutex::new(()), std::sync::Condvar::new()) })
    }

    pub fn lock(&self) -> MutexGuard<'_, HelperState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn now(&self) -> u64 {
        (self.deps.clock)()
    }

    pub fn stopping(&self) -> bool {
        self.stop.load(Ordering::SeqCst)
    }

    pub fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
        self.wake.1.notify_all();
    }

    /// Sleep up to `ms`, returning early on shutdown or `poke`.
    pub fn sleep_ms(&self, ms: u64) {
        let g = self.wake.0.lock().unwrap_or_else(|e| e.into_inner());
        if !self.stopping() {
            let _ = self.wake.1.wait_timeout(g, std::time::Duration::from_millis(ms));
        }
    }

    /// Wake sleeping loops (new alerts to deliver, a registration to do).
    pub fn poke(&self) {
        self.wake.1.notify_all();
    }

    /// The state mutex itself (policy::fetch_cycle takes it to lock around its network leg).
    pub fn state_mutex(&self) -> &Mutex<HelperState> {
        &self.state
    }

    pub fn stop_flag(&self) -> &AtomicBool {
        &self.stop
    }
}

pub struct Helper {
    pub paths: Paths,
}

impl Helper {
    /// The only constructor. A privileged process accepts nothing but `Paths::system()`, so a
    /// root-installed binary cannot be pointed at attacker-chosen state even if a future change
    /// added a way to pass paths in.
    pub fn new(paths: Paths) -> Result<Helper, StartError> {
        if !paths.system && running_privileged() {
            return Err(StartError::InjectedPathsWhilePrivileged);
        }
        Ok(Helper { paths })
    }

    /// Production run: refuses the system paths unless privileged, then wires the platform layer and
    /// the reqwest console client.
    pub fn run(self) -> Result<(), StartError> {
        if self.paths.system && !running_privileged() {
            return Err(StartError::Unprivileged);
        }
        let console: Arc<dyn ConsoleTransport> = Arc::new(crate::console::ReqwestTransport::new().map_err(|e| StartError::Io(std::io::Error::other(format!("{e:?}"))))?);
        let platform = Arc::new(crate::platform::Platform::new());
        let deps = Deps { procs: platform.clone(), backend: platform.clone(), sys: platform, console, clock: Arc::new(crate::clock::now_ms) };
        self.run_with(deps)
    }

    /// Open state, re-apply quarantines, bind the endpoint, start the threads, serve until SIGTERM /
    /// SIGINT, then send the shutdown beat.
    pub fn run_with(self, deps: Deps) -> Result<(), StartError> {
        let shared = self.start(deps)?;
        let listener = crate::transport::bind(&self.paths).map_err(StartError::Io)?;
        install_signal_handlers();
        let s2 = shared.clone();
        std::thread::spawn(move || {
            while !s2.stopping() {
                if SIGNALLED.load(Ordering::SeqCst) {
                    s2.stop();
                }
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
        });
        let handler: Arc<dyn Handler> = Arc::new(IpcHandler { shared: shared.clone() });
        let r = crate::ipc::server::serve(listener.as_ref(), handler, shared.stop_flag());
        crate::beat::beat_once(&shared);
        #[cfg(unix)]
        let _ = std::fs::remove_file(&self.paths.endpoint);
        r.map_err(StartError::Io)
    }

    /// Everything but the accept loop: open state, reconcile quarantines, start the background
    /// threads. Returns the shared state (tests drive the handler and loops directly).
    pub fn start(&self, deps: Deps) -> Result<Arc<Shared>, StartError> {
        let shared = self.open_shared(deps)?;
        spawn_loops(&shared);
        Ok(shared)
    }

    /// Open state and reconcile quarantines, without starting any thread (tests drive each loop's
    /// single step: register_once, policy::fetch_cycle, deliver_once, beat::beat_once,
    /// push::poll_once, observe_once).
    pub fn open_shared(&self, deps: Deps) -> Result<Arc<Shared>, StartError> {
        let now = (deps.clock)();
        let mut state = HelperState::open(self.paths.clone(), deps.sys.as_ref(), now).map_err(|e| match e {
            crate::state::OpenError::Io(e) => StartError::Io(e),
            crate::state::OpenError::Key(k) => StartError::Key(k),
        })?;
        if let Some(e) = &state.binding_error {
            eprintln!("moorai-guardd: no console binding yet ({e}); serving hello as not_ready");
        }
        {
            let st = &mut state;
            crate::quarantine::reconcile_on_start(&mut st.quarantines, deps.backend.as_ref(), deps.procs.as_ref()).map_err(StartError::Io)?;
        }
        Ok(Shared::new(state, deps))
    }
}

fn spawn_loops(shared: &Arc<Shared>) {
    let s = shared.clone();
    std::thread::spawn(move || register_loop(&s));
    let s = shared.clone();
    std::thread::spawn(move || policy_loop(&s));
    let s = shared.clone();
    std::thread::spawn(move || alerts_loop(&s));
    let s = shared.clone();
    std::thread::spawn(move || beat_loop(&s));
    let s = shared.clone();
    std::thread::spawn(move || observe_loop(&s));
    let s = shared.clone();
    std::thread::spawn(move || crate::push::run(s));
}

/// Register when needed (§5.2): no registration, a new key, a changed binding, a staged rotation, or
/// the console answered `unknown_key`. A `401 bad_enroll_secret` is logged and retried later with the
/// same secret, never without it.
pub fn register_once(shared: &Shared) -> Result<Option<crate::console::RegisterResp>, ConsoleError> {
    let (binding, current, pending, device_id, device, mut off) = {
        let s = shared.lock();
        if !s.needs_register {
            return Ok(None);
        }
        let Some(b) = s.binding.clone() else { return Ok(None) };
        let pending = crate::keys::pending_rotation(&s.paths.state_dir).ok().flatten();
        (b, s.key.clone(), pending, s.device_id.clone(), s.device.clone(), s.beat.clock_offset_ms)
    };
    let now = || shared.now();
    let input = match &pending {
        Some(new) => crate::console::RegisterInput { key: new, prev: Some(&current), binding: &binding, device_id: &device_id, device: &device },
        None => crate::console::RegisterInput { key: &current, prev: None, binding: &binding, device_id: &device_id, device: &device },
    };
    let r = crate::console::register(shared.deps.console.as_ref(), &input, &mut off, &now);
    let mut s = shared.lock();
    s.beat.clock_offset_ms = off;
    let resp = r?;
    if pending.is_some() {
        crate::keys::commit_rotation(&s.paths.state_dir).map_err(|e| ConsoleError::BadResponse(format!("{e:?}")))?;
        let key = crate::keys::DeviceKey::load_or_create(&s.paths.state_dir).map_err(|e| ConsoleError::BadResponse(format!("{e:?}")))?;
        let _ = crate::keys::write_device_pub(&s.paths.run_dir, &key);
        s.key = Arc::new(key);
    }
    let reg = crate::console::Registration {
        key_id: resp.key_id.clone(),
        device_id: resp.device_id.clone(),
        registered_at: crate::clock::iso_ms(shared.now() as i64),
        status: resp.status.clone(),
        origin: binding.origin.clone(),
        tenant: binding.tenant.clone(),
        bound: resp.bound,
    };
    save_json(&s.paths.state_file(files::REGISTRATION), &reg).map_err(|e| ConsoleError::BadResponse(e.to_string()))?;
    s.registration = Some(reg);
    s.needs_register = false;
    if resp.bound && binding.secret.enroll_secret.is_some() {
        match crate::config::remove_enroll_secret(&s.paths) {
            Ok(()) => {
                if let Some(b) = s.binding.as_mut() {
                    b.secret.enroll_secret = None;
                }
            }
            Err(e) => eprintln!("moorai-guardd: could not remove the used enrolment secret: {e}"),
        }
    }
    if resp.status == "changed" {
        eprintln!("moorai-guardd: the console recorded this registration as a key change (unbound)");
    }
    Ok(Some(resp))
}

/// Planned rotation (§5.2 `rotated`): stage a new key and register it with the old key's statement.
pub fn rotate_key(shared: &Shared) -> Result<Option<crate::console::RegisterResp>, ConsoleError> {
    {
        let mut s = shared.lock();
        crate::keys::stage_rotation(&s.paths.state_dir).map_err(|e| ConsoleError::BadResponse(format!("{e:?}")))?;
        s.needs_register = true;
    }
    register_once(shared)
}

fn register_loop(shared: &Shared) {
    let mut attempt = 0u32;
    while !shared.stopping() {
        match register_once(shared) {
            Ok(_) => {
                attempt = 0;
                shared.sleep_ms(30_000);
            }
            Err(e) => {
                eprintln!("moorai-guardd: registration failed: {e:?}");
                shared.sleep_ms(crate::clock::full_jitter_ms(5_000, 300_000, attempt, crate::clock::rand01()).max(1_000));
                attempt = attempt.saturating_add(1);
            }
        }
    }
}

/// One policy fetch (background cadence or IPC on demand); content-free tamper findings are queued.
pub fn policy_fetch_once(shared: &Shared, timeout_ms: u64, actor: Option<String>) {
    let now = || shared.now();
    match crate::policy::fetch_cycle_with(&shared.state, shared.deps.console.as_ref(), &now, timeout_ms, actor) {
        Ok(rejected) => {
            let alerts: Vec<_> = rejected
                .iter()
                .map(|r| serde_json::json!({"kind":"policyRejected","source":r.source,"status":r.status,"ts":crate::clock::iso_ms(shared.now() as i64)}).as_object().cloned().unwrap_or_default())
                .collect();
            if !alerts.is_empty() {
                let _ = shared.lock().alerts.enqueue(alerts, None);
                shared.poke();
            }
        }
        Err(e) => eprintln!("moorai-guardd: policy fetch: {e:?}"),
    }
}

fn policy_loop(shared: &Shared) {
    while !shared.stopping() {
        if shared.lock().binding.is_some() {
            policy_fetch_once(shared, crate::policy::FETCH_TIMEOUT_MS, None);
        }
        let delay = shared.lock().policy.next_fetch_delay_ms(shared.now());
        shared.sleep_ms(delay);
    }
}

/// Deliver one batch (§7.1): sign, POST, and ack / retry / drop per the console's answer.
pub fn deliver_once(shared: &Shared) -> crate::alerts::Delivery {
    use crate::alerts::Delivery;
    let (key, binding, device_id, batch, mut off) = {
        let mut s = shared.lock();
        let Some(b) = s.binding.clone() else { return Delivery::Retry("no binding".into()) };
        if s.needs_register {
            return Delivery::Reregister;
        }
        let device_id = s.device_id.clone();
        let batch = match s.alerts.next_batch(&b.tenant, &device_id) {
            Ok(Some(x)) => x,
            Ok(None) => return Delivery::Empty,
            Err(e) => return Delivery::Retry(e.to_string()),
        };
        (s.key.clone(), b, device_id, batch, s.beat.clock_offset_ms)
    };
    let body = match batch.body_bytes() {
        Ok(b) => b,
        Err(e) => return Delivery::Retry(e.to_string()),
    };
    let now = || shared.now();
    let r = crate::console::send_signed(shared.deps.console.as_ref(), &key, &binding, &device_id, "POST", crate::alerts::ALERTS_PATH, body, &[], &mut off, crate::console::REQUEST_TIMEOUT_MS, &now);
    let mut s = shared.lock();
    s.beat.clock_offset_ms = off;
    match crate::alerts::classify_delivery(&r) {
        "ack" => match s.alerts.ack_batch(&batch.batch_id) {
            Ok(()) => Delivery::Delivered { batch_id: batch.batch_id, alerts: batch.alerts.len() },
            Err(e) => Delivery::Retry(e.to_string()),
        },
        "drop" => {
            let _ = s.alerts.drop_batch_as_overflow(&batch.batch_id);
            Delivery::Retry("413".into())
        }
        "reregister" => {
            s.needs_register = true;
            shared.poke();
            Delivery::Reregister
        }
        _ => Delivery::Retry(format!("{:?}", r.err())),
    }
}

fn alerts_loop(shared: &Shared) {
    use crate::alerts::{Delivery, RETRY_BASE_MS, RETRY_CAP_MS};
    let mut attempt = 0u32;
    while !shared.stopping() {
        match deliver_once(shared) {
            Delivery::Delivered { .. } => attempt = 0,
            Delivery::Empty => {
                attempt = 0;
                shared.sleep_ms(5_000);
            }
            Delivery::Retry(_) | Delivery::Reregister => {
                shared.sleep_ms(crate::clock::full_jitter_ms(RETRY_BASE_MS, RETRY_CAP_MS, attempt, crate::clock::rand01()).max(500));
                attempt = attempt.saturating_add(1);
            }
        }
    }
}

fn beat_loop(shared: &Shared) {
    while !shared.stopping() {
        match crate::beat::beat_once(shared) {
            crate::beat::BeatOutcome::Reregister => shared.poke(),
            crate::beat::BeatOutcome::Failed(e) => eprintln!("moorai-guardd: beat failed: {e}"),
            _ => {}
        }
        shared.sleep_ms(crate::beat::BEAT_INTERVAL_SEC * 1000);
    }
}

/// One observation pass (§8.2): scan without the lock held for the process listing, then record the
/// silent processes and queue one signed alert per newly silent process.
pub fn observe_once(shared: &Shared) -> std::io::Result<usize> {
    let now = shared.now();
    let list = shared.deps.procs.list()?;
    let snapshot = crate::observe::SnapshotSource(list);
    let mut s = shared.lock();
    let events = s.observer.scan(&snapshot, now)?;
    // Hook-call counters are kept in memory on the `call` path (20 ms budget) and persisted here,
    // every scan, so a restart loses at most one scan interval of counts.
    let counters = s.counters.clone();
    save_json(&s.paths.state_file(files::COUNTERS), &counters)?;
    if !events.is_empty() {
        let alerts = events.iter().map(|e| e.alert(now)).collect();
        s.alerts.enqueue(alerts, None)?;
        shared.poke();
    }
    Ok(events.len())
}

fn observe_loop(shared: &Shared) {
    while !shared.stopping() {
        if let Err(e) = observe_once(shared) {
            eprintln!("moorai-guardd: observation: {e}");
        }
        shared.sleep_ms(crate::observe::SCAN_INTERVAL_SEC * 1000);
    }
}

/// Apply one console command (§9.3, §8.3, §8.5) and build its ack. lastCmdSeq is persisted BEFORE the
/// command acts, so a replay after a crash is refused.
pub fn apply_command(shared: &Shared, cmd: &crate::push::Command) -> crate::push::CommandAck {
    let now = shared.now();
    let f = &cmd.fields;
    let mut s = shared.lock();
    let tenant = s.binding.as_ref().map(|b| b.tenant.clone()).unwrap_or_default();
    let keys = s.policy.command_keys(&tenant);
    let mut ack = crate::push::CommandAck {
        v: 1,
        tenant: tenant.clone(),
        device_id: s.device_id.clone(),
        cmd_id: f.cmd_id.clone(),
        cmd_seq: f.cmd_seq,
        result: String::new(),
        quarantine_id: None,
        suspended_pids: None,
        suspended_at_ms: None,
        network: None,
    };
    let last = s.last_cmd_seq();
    if let Err(e) = crate::push::verify_command(cmd, &keys, &tenant, &s.device_id, last, now) {
        let (result, advance) = crate::push::ack_for(e);
        ack.result = result.into();
        if advance {
            if let Err(e) = persist_cmd_seq(&mut s, &f.cmd_id, f.cmd_seq) {
                eprintln!("moorai-guardd: could not persist cmdSeq: {e}");
            }
        }
        return ack;
    }
    if s.commands.recent.contains(&f.cmd_id) {
        ack.result = "ignored".into();
        return ack;
    }
    if let Err(e) = persist_cmd_seq(&mut s, &f.cmd_id, f.cmd_seq) {
        eprintln!("moorai-guardd: could not persist cmdSeq: {e}");
        ack.result = "failed".into();
        return ack;
    }
    match f.action.as_str() {
        "kill" => {
            s.kills.push(crate::push::KillEntry { cmd_id: f.cmd_id.clone(), issued_at: f.iat.clone(), scope: f.scope.clone(), session_hash: f.session_hash.clone(), received_ms: now });
            ack.result = "applied".into();
        }
        "release" => {
            let st = &mut *s;
            match crate::quarantine::release(&mut st.quarantines, shared.deps.backend.as_ref(), &f.quarantine_id, &format!("console:{}", f.cmd_id), now) {
                Ok(_) => ack.result = "applied".into(),
                Err(crate::quarantine::ReleaseError::UnknownQuarantine) => ack.result = "ignored".into(),
                Err(_) => ack.result = "failed".into(),
            }
            ack.quarantine_id = Some(f.quarantine_id.clone());
        }
        "quarantine" => {
            let agents: Vec<(crate::observe::ProcInfo, &'static str)> = match f.scope.as_str() {
                "session" => s
                    .observer
                    .session(&f.session_hash)
                    .and_then(|t| shared.deps.procs.get(t.agent.pid).ok().flatten().filter(|p| p.start_ms == t.agent.start_ms).and_then(|p| crate::observe::match_host(&p).map(|h| (p, h.host))))
                    .into_iter()
                    .collect(),
                _ => shared.deps.procs.list().unwrap_or_default().into_iter().filter_map(|p| crate::observe::match_host(&p).map(|h| (p, h.host))).collect(),
            };
            let st = &mut *s;
            let clock = shared.deps.clock.clone();
            let now_fn = move || clock();
            match crate::quarantine::quarantine_from_console(&mut st.quarantines, &mut st.alerts, shared.deps.backend.as_ref(), shared.deps.procs.as_ref(), &agents, &f.cmd_id, &f.session_hash, &cmd.reason, std::process::id(), &now_fn) {
                Ok(Some(e)) => {
                    ack.result = if e.failed_step.as_deref() == Some("suspend") { "failed" } else { "applied" }.into();
                    ack.quarantine_id = Some(e.id.clone());
                    ack.suspended_pids = Some(e.pids.len() as u32);
                    ack.suspended_at_ms = e.suspended_at_ms;
                    ack.network = Some(e.network);
                    shared.poke();
                }
                Ok(None) => ack.result = "ignored".into(),
                Err(_) => ack.result = "failed".into(),
            }
        }
        _ => ack.result = "ignored".into(),
    }
    ack
}

fn persist_cmd_seq(s: &mut HelperState, cmd_id: &str, cmd_seq: u64) -> std::io::Result<()> {
    s.commands.record(cmd_id, cmd_seq);
    save_json(&s.paths.state_file(files::COMMANDS), &s.commands)?;
    if cmd_seq > s.quarantines.file.last_cmd_seq {
        s.quarantines.file.last_cmd_seq = cmd_seq;
        s.quarantines.save()?;
    }
    Ok(())
}

/// The IPC op dispatcher (§3.4), behind `authorize`.
pub struct IpcHandler {
    pub shared: Arc<Shared>,
}

fn is_hex(s: &str, n: usize) -> bool {
    s.len() == n && s.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

/// The actor of the IPC peer `uid`, derived as its hook computes it (policy::derive_actor) from the uid's
/// login name, the helper's own install token and the hostname. None when any of them is missing.
fn peer_actor(shared: &Shared, uid: u32) -> Option<String> {
    let token = shared.lock().binding.as_ref().and_then(|b| b.secret.install_token.clone())?;
    let user = shared.deps.sys.login_name(uid)?;
    crate::policy::derive_actor(Some(&token), &user, &shared.deps.sys.hostname())
}

fn short_token(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.bytes().all(|c| c.is_ascii_alphanumeric() || b"-_.".contains(&c))
}

impl Handler for IpcHandler {
    fn handle(&self, ctx: &mut ConnCtx, peer: &PeerCred, req: RequestFrame) -> (ResponseFrame, Option<AfterReply>) {
        let id = req.id;
        let op = op_name(&req.body);
        if let Err(code) = authorize(&req.body, peer) {
            return (error_frame(id, code, &format!("{op} requires an administrator peer"), Some(op)), None);
        }
        let reply = |body: Response| ResponseFrame { v: PROTO_VERSION, id, body };
        let err = |code: ErrorCode, msg: &str| error_frame(id, code, msg, Some(op));
        let shared = &self.shared;
        match req.body {
            Request::Hello(h) => {
                if !h.proto.contains(&PROTO_VERSION) {
                    return (err(ErrorCode::UnsupportedVersion, "no common protocol version"), None);
                }
                if !matches!(h.client.as_str(), "moorai-hook" | "moorai-host" | "moorai-guardctl") || !is_hex(&h.nonce, 32) || h.client_version.len() > 64 {
                    return (err(ErrorCode::BadRequest, "bad hello"), None);
                }
                let mut s = shared.lock();
                let Some(tenant) = s.binding.as_ref().map(|b| b.tenant.clone()) else {
                    return (err(ErrorCode::NotReady, "no console binding yet"), None);
                };
                match h.client.as_str() {
                    "moorai-hook" => s.hook_version = Some(h.client_version.clone()),
                    "moorai-host" => s.app_version = Some(h.client_version.clone()),
                    _ => {}
                }
                let key_id = s.key.key_id();
                let proof = s.key.sign_b64(crate::signing::hello_proof_input(&h.nonce, &key_id, crate::HELPER_VERSION).as_bytes());
                let mut caps: Vec<String> = OPS.iter().map(|o| o.to_string()).collect();
                caps.sort();
                ctx.hello_done = true;
                ctx.client = Some(h.client);
                (reply(Response::Hello(HelloResp { proto: PROTO_VERSION, helper_version: crate::HELPER_VERSION.into(), tenant, device_id: s.device_id.clone(), key_id, caps, proof })), None)
            }
            Request::Policy(p) => {
                if p.actor.as_deref().is_some_and(|a| !crate::policy::valid_actor(a)) {
                    return (err(ErrorCode::BadRequest, "actor must be h2: and 16..64 hex"), None);
                }
                // A policy request counts as hook activity (fetch cadence). The actor is never taken from the
                // message: the helper derives it from the peer (kernel uid -> login name, its own install token,
                // the hostname) exactly as that peer's hook computes it. A request naming any other actor, or
                // naming one when none can be derived, is answered `none` with no fetch (the hook then takes
                // its direct path). A request naming no actor is served the derived one, or, when none can be
                // derived, only the actor-less policy. The derived actor is bound to the uid (one actor per
                // uid). The answer is that actor's own held policy, fetched on demand when missing or older
                // than 60 s (bounded by ON_DEMAND_FETCH_MS; this connection's thread waits, no other). No
                // request changes what another uid's requests or the background fetch name or receive.
                let now = shared.now();
                let derived = peer_actor(shared, peer.uid);
                let actor = match (p.actor.as_deref(), derived) {
                    (Some(claimed), Some(d)) if claimed == d => Some(d),
                    (Some(_), _) => {
                        shared.lock().policy.last_call_ms = now;
                        return (reply(Response::Policy(crate::policy::answer(None, None, now))), None);
                    }
                    (None, d) => d,
                };
                let on_demand = {
                    let mut s = shared.lock();
                    s.policy.last_call_ms = now;
                    if let Some(a) = actor.as_deref() {
                        if !s.policy.bind_actor(peer.uid, a, now) {
                            return (reply(Response::Policy(crate::policy::answer(None, None, now))), None);
                        }
                    }
                    s.binding.as_ref().map(|b| b.tenant.clone()).is_some_and(|t| s.policy.needs_on_demand(&t, actor.as_deref(), now))
                };
                if on_demand {
                    policy_fetch_once(shared, crate::policy::ON_DEMAND_FETCH_MS, actor.clone());
                }
                let s = shared.lock();
                (reply(Response::Policy(s.policy.answer_for(actor.as_deref(), p.if_iat.as_deref(), shared.now()))), None)
            }
            Request::Submit(sub) => {
                if sub.alerts.is_empty() || sub.alerts.len() > MAX_SUBMIT_ALERTS {
                    return (err(ErrorCode::BadRequest, "1..64 alerts"), None);
                }
                let r = shared.lock().alerts.enqueue(sub.alerts, Some(peer.uid));
                match r {
                    Ok(resp) => {
                        shared.poke();
                        (reply(Response::Submit(resp)), None)
                    }
                    Err(_) => (err(ErrorCode::Internal, "queue write failed"), None),
                }
            }
            Request::Call(c) => {
                if !short_token(&c.host) || !short_token(&c.event) || !is_hex(&c.session_hash, 16) {
                    return (err(ErrorCode::BadRequest, "bad call"), None);
                }
                let agent = crate::observe::agent_ancestor(shared.deps.procs.as_ref(), peer.pid, crate::quarantine::MAX_ANCESTOR_DEPTH)
                    .ok()
                    .flatten()
                    .filter(|(p, _)| p.uid == peer.uid)
                    .map(|(p, _)| crate::observe::ProcKey::from(&p));
                let now = shared.now();
                let mut s = shared.lock();
                s.counters.add(&c.host);
                s.observer.on_call(&c.host, &c.session_hash, peer.uid, agent, now);
                s.policy.last_call_ms = now;
                (reply(Response::Call(CallResp {})), None)
            }
            Request::Kill(k) => {
                let s = shared.lock();
                (reply(Response::Kill(crate::push::kill_answer(&s.kills, k.session_hash.as_deref(), shared.now()))), None)
            }
            Request::Quarantine(q) => {
                if !crate::quarantine::request_ok(&q) || !is_hex(&q.session_hash, 16) {
                    return (err(ErrorCode::BadRequest, "bad quarantine request"), None);
                }
                let qpeer = Peer { pid: peer.pid, uid: peer.uid, admin: peer.admin };
                let clock = shared.deps.clock.clone();
                let now_fn = move || clock();
                let r = {
                    let mut s = shared.lock();
                    let st = &mut *s;
                    crate::quarantine::quarantine_from_hook(&mut st.quarantines, &mut st.alerts, shared.deps.backend.as_ref(), shared.deps.procs.as_ref(), qpeer, &q, std::process::id(), &now_fn)
                };
                shared.poke();
                match r {
                    Ok((resp, fu)) => {
                        let sh = shared.clone();
                        let after: AfterReply = Box::new(move || {
                            {
                                let mut s = sh.lock();
                                let st = &mut *s;
                                let _ = crate::quarantine::finish(&mut st.quarantines, &mut st.alerts, sh.deps.backend.as_ref(), &fu.quarantine_id, sh.now());
                            }
                            sh.poke();
                            if let Some(p) = fu.peer.clone() {
                                let sh2 = sh.clone();
                                let id = fu.quarantine_id.clone();
                                std::thread::spawn(move || {
                                    std::thread::sleep(std::time::Duration::from_millis(crate::quarantine::PEER_GRACE_MS));
                                    let mut s = sh2.lock();
                                    let _ = crate::quarantine::suspend_peer(&mut s.quarantines, sh2.deps.backend.as_ref(), sh2.deps.procs.as_ref(), &id, &p);
                                });
                            }
                        });
                        (reply(Response::Quarantine(resp)), Some(after))
                    }
                    Err(e) => (err(e.code(), "quarantine refused or failed"), None),
                }
            }
            Request::Release(r) => {
                let now = shared.now();
                let mut s = shared.lock();
                let st = &mut *s;
                match crate::quarantine::release(&mut st.quarantines, shared.deps.backend.as_ref(), &r.quarantine_id, &format!("local-admin:{}", peer.uid), now) {
                    Ok(n) => (reply(Response::Release(ReleaseResp { released: n })), None),
                    Err(crate::quarantine::ReleaseError::UnknownQuarantine) => (err(ErrorCode::UnknownQuarantine, "no such quarantine"), None),
                    Err(_) => (err(ErrorCode::Internal, "release failed"), None),
                }
            }
        }
    }
}

fn op_name(r: &Request) -> &'static str {
    match r {
        Request::Hello(_) => "hello",
        Request::Policy(_) => "policy",
        Request::Submit(_) => "submit",
        Request::Call(_) => "call",
        Request::Kill(_) => "kill",
        Request::Quarantine(_) => "quarantine",
        Request::Release(_) => "release",
    }
}

/// Which peers may send which op (contract §3.6). `release` is administrator-only; every other op is
/// open to any local peer, whose kernel identity is then used by the op itself.
pub fn authorize(req: &Request, peer: &PeerCred) -> Result<(), ErrorCode> {
    match req {
        Request::Release(_) if !peer.admin => Err(ErrorCode::Forbidden),
        _ => Ok(()),
    }
}

static SIGNALLED: AtomicBool = AtomicBool::new(false);

#[cfg(unix)]
extern "C" fn on_signal(_: libc::c_int) {
    SIGNALLED.store(true, Ordering::SeqCst);
}

#[cfg(unix)]
fn install_signal_handlers() {
    // SAFETY: the handler only stores to an atomic, which is async-signal-safe.
    unsafe {
        libc::signal(libc::SIGTERM, on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t);
        libc::signal(libc::SIGINT, on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t);
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }
}

#[cfg(windows)]
fn install_signal_handlers() {}

#[cfg(unix)]
pub fn running_privileged() -> bool {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() == 0 }
}

#[cfg(windows)]
pub fn running_privileged() -> bool {
    todo!("OpenProcessToken(GetCurrentProcess) -> TokenUser is S-1-5-18, or TokenElevation set")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::{KillReq, ReleaseReq};

    fn peer(admin: bool) -> PeerCred {
        PeerCred { pid: 4242, uid: if admin { 0 } else { 501 }, sid: None, admin }
    }

    #[test]
    fn release_is_admin_only() {
        let r = Request::Release(ReleaseReq { quarantine_id: "*".into() });
        assert_eq!(authorize(&r, &peer(false)), Err(ErrorCode::Forbidden));
        assert_eq!(authorize(&r, &peer(true)), Ok(()));
        assert_eq!(authorize(&Request::Kill(KillReq { session_hash: None }), &peer(false)), Ok(()));
    }

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
        fn login_name(&self, uid: u32) -> Option<String> {
            Some(format!("user{uid}"))
        }
    }

    const T0: u64 = 1_791_795_600_000;
    // Two users on one device: A (uid 501) runs claude 100 with its hook 120; B (uid 502) runs claude 200
    // with a process 220 under it, and 300 outside any agent.
    const A: u32 = 501;
    const B: u32 = 502;

    #[cfg(unix)]
    fn two_user_device(tag: &str) -> (Arc<Shared>, IpcHandler, std::sync::Arc<std::sync::atomic::AtomicU64>) {
        use crate::observe::fake::{proc, FakeProcs};
        use std::os::unix::fs::PermissionsExt;
        let base = crate::state::test_root(tag);
        std::fs::create_dir_all(base.join("etc")).unwrap();
        std::fs::set_permissions(base.join("etc"), std::fs::Permissions::from_mode(0o755)).unwrap();
        let paths = Paths::under(&base);
        std::fs::write(&paths.machine_config, r#"{"serverUrl":"http://127.0.0.1:9","tenant":"acme","helper":"required"}"#).unwrap();
        std::fs::set_permissions(&paths.machine_config, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::write(&paths.secret, r#"{"installToken":"tok-acme"}"#).unwrap();
        std::fs::set_permissions(&paths.secret, std::fs::Permissions::from_mode(0o600)).unwrap();
        let procs = Arc::new(FakeProcs::new(vec![
            proc(1, 0, 0, 0, "/sbin/launchd", None),
            proc(100, 1, A, 1_000, "/usr/local/bin/claude", None),
            proc(120, 100, A, 2_000, "/usr/bin/node", Some("/opt/moorai/cli/moorai-hook.mjs")),
            proc(200, 1, B, 1_000, "/usr/local/bin/claude", None),
            proc(220, 200, B, 2_000, "/usr/bin/node", Some("/tmp/x.mjs")),
            proc(300, 1, B, 2_000, "/usr/bin/python3", None),
        ]));
        let clock = Arc::new(std::sync::atomic::AtomicU64::new(T0));
        let c2 = clock.clone();
        let console = Arc::new(crate::console::fake::FakeConsole::new(Box::new(|_r: &crate::console::HttpRequest| Ok(crate::console::HttpResponse { status: 404, body: b"{}".to_vec() }))));
        let deps = Deps {
            procs,
            backend: Arc::new(crate::quarantine::recording::Recording::new(&paths.state_file("quarantine.json"))),
            sys: Arc::new(Sys),
            console,
            clock: Arc::new(move || c2.load(Ordering::SeqCst)),
        };
        let shared = Helper::new(paths).unwrap().open_shared(deps).unwrap();
        (shared.clone(), IpcHandler { shared }, clock)
    }

    fn call(h: &IpcHandler, pid: u32, uid: u32, session: &str) {
        let req = RequestFrame { v: PROTO_VERSION, id: 1, body: Request::Call(crate::ipc::CallReq { event: "PreToolUse".into(), host: "claude-code".into(), session_hash: session.into(), agent_pid: None }) };
        let mut ctx = ConnCtx { hello_done: true, client: Some("moorai-hook".into()) };
        let (resp, _) = h.handle(&mut ctx, &PeerCred { pid, uid, sid: None, admin: false }, req);
        assert!(matches!(resp.body, Response::Call(_)), "{resp:?}");
    }

    #[cfg(unix)]
    #[test]
    fn another_users_calls_do_not_vouch_for_this_users_agent() {
        let (shared, h, clock) = two_user_device("silentx");
        // B, from inside its own agent and from outside any agent, keeps calling for claude-code
        call(&h, 220, B, "bbbbbbbbbbbbbbbb");
        call(&h, 300, B, "cccccccccccccccc");
        clock.store(T0 + 121_000, Ordering::SeqCst);
        assert_eq!(observe_once(&shared).unwrap(), 1, "A's claude (100) is silent: B's calls prove nothing about it");
        assert_eq!(shared.lock().observer.hook_silent(T0 + 121_000).len(), 1);
        // A's own hook clears it
        call(&h, 120, A, "aaaaaaaaaaaaaaaa");
        assert!(shared.lock().observer.hook_silent(T0 + 122_000).is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn another_user_cannot_take_over_a_session() {
        let (shared, h, _clock) = two_user_device("sessx");
        call(&h, 120, A, "aaaaaaaaaaaaaaaa");
        call(&h, 220, B, "aaaaaaaaaaaaaaaa");
        let agent = shared.lock().observer.session("aaaaaaaaaaaaaaaa").map(|t| t.agent.pid);
        assert_eq!(agent, Some(100), "a console quarantine of A's session still targets A's agent");
        // A's own later calls keep it, and B's own sessions are B's
        call(&h, 120, A, "aaaaaaaaaaaaaaaa");
        call(&h, 220, B, "bbbbbbbbbbbbbbbb");
        assert_eq!(shared.lock().observer.session("bbbbbbbbbbbbbbbb").map(|t| t.agent.pid), Some(200));
    }

    #[cfg(unix)]
    #[test]
    fn injected_paths_refused_when_root() {
        let p = Paths::under(std::path::Path::new("/nonexistent/guardd-test"));
        let r = Helper::new(p);
        if running_privileged() {
            assert!(matches!(r, Err(StartError::InjectedPathsWhilePrivileged)));
        } else {
            assert!(r.is_ok());
        }
    }

    #[cfg(unix)]
    #[test]
    fn system_paths_refuse_to_run_unprivileged() {
        if running_privileged() {
            return;
        }
        assert!(matches!(Helper::new(Paths::system()).unwrap().run(), Err(StartError::Unprivileged)));
    }
}
