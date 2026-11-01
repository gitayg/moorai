// Clipboard guard: stop sensitive text being pasted into an AI app the organisation has not approved, and
// report it without content.
//
// This file is the decision logic only. Every input and output goes through a provider, so the tests
// drive it with fakes: the clipboard (change counter, text read, text write), the frontmost app, the
// clock, the scanner (the app's own secret/PII detectors, src/clipguard.js) and the sink (alert to the
// console, local notification). The OS bindings are clip_guard_mac.rs / clip_guard_win.rs and the loop,
// policy fetch and console posting are clip_guard_run.rs.
//
// When it reads: the change counter is read on every tick (it carries no content). The clipboard TEXT is
// read only when the frontmost app is on the AI-app list, is not approved, and either the clipboard
// changed or that app just came to the front (the "already on the clipboard" order). The text is handed
// to the scanner and dropped; only detector ids, the app id, the mode taken and a keyed hash leave.
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};

pub const RATE_WINDOW_MS: u64 = 10 * 60 * 1000;
// Threats whose alert hash is process-keyed (data/cardholder.js PROCESS_KEYED_THREATS): #90 cardholder data.
pub const PROCESS_KEYED_THREATS: [u64; 1] = [90];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode { Off, Alert, Coach, Clear }

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self { Mode::Off => "off", Mode::Alert => "alert", Mode::Coach => "coach", Mode::Clear => "clear" }
    }
}

// policy.clipboardGuard, as read from a policy whose signature has already been checked
// (clip_guard_policy.rs). Anything unrecognised reads "off".
#[derive(Debug, Clone, PartialEq)]
pub struct ClipPolicy {
    pub mode: Mode,
    pub approved: HashSet<String>,
    pub extra_ai: HashSet<String>,
    pub detectors: Option<HashSet<String>>,
}

impl Default for ClipPolicy {
    fn default() -> Self { ClipPolicy { mode: Mode::Off, approved: HashSet::new(), extra_ai: HashSet::new(), detectors: None } }
}

fn id_set(v: Option<&Value>) -> HashSet<String> {
    v.and_then(|a| a.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str()).map(|s| s.trim().to_ascii_lowercase()).filter(|s| !s.is_empty() && s.len() <= 256).collect())
        .unwrap_or_default()
}

impl ClipPolicy {
    pub fn from_policy(policy: &Value) -> ClipPolicy {
        let Some(g) = policy.get("clipboardGuard").filter(|g| g.is_object()) else { return ClipPolicy::default() };
        let mode = match g.get("mode").and_then(|m| m.as_str()) {
            Some("alert") => Mode::Alert,
            Some("coach") => Mode::Coach,
            Some("clear") => Mode::Clear,
            _ => Mode::Off,
        };
        let detectors = g.get("detectors").and_then(|d| d.as_array()).map(|_| id_set(g.get("detectors"))).filter(|s| !s.is_empty());
        ClipPolicy { mode, approved: id_set(g.get("approvedApps")), extra_ai: id_set(g.get("aiApps")), detectors }
    }

    // A detector the guard acts on: the policy's subset when it names one, else every secret and PII
    // detector (secret-*, dlp-*) except secret-file-upload, which matches upload commands, not data.
    pub fn wants(&self, detector: &str) -> bool {
        match &self.detectors {
            Some(set) => set.contains(&detector.to_ascii_lowercase()),
            None => (detector.starts_with("secret-") || detector.starts_with("dlp-")) && detector != "secret-file-upload",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Finding { pub detector: String, pub threat_id: u64, pub risk: String }

pub trait Clipboard {
    fn change_count(&self) -> i64;
    // Plain text only: None when the clipboard holds no text, or holds files or an image.
    fn read_text(&self) -> Option<String>;
    fn write_text(&self, text: &str) -> bool;
}
pub trait Frontmost { fn frontmost(&self) -> Option<String>; }
pub trait Clock { fn now_ms(&self) -> u64; }
// None: the scanner could not answer (the app's webview did not reply in time). Nothing is done then.
pub trait Scanner { fn scan(&self, text: &str) -> Option<Vec<Finding>>; }
pub trait Sink {
    fn alert(&self, alert: Value);
    fn notify(&self, title: &str, body: &str);
}

pub struct Providers<'a> {
    pub clip: &'a dyn Clipboard,
    pub front: &'a dyn Frontmost,
    pub clock: &'a dyn Clock,
    pub scanner: &'a dyn Scanner,
    pub sink: &'a dyn Sink,
    // The keyed content hash (content_hash::hash_with_key under the tenant key).
    pub hash: &'a dyn Fn(&str) -> String,
}

// The AI-app list: catalog ids (clip_guard_apps.rs) plus the policy's aiApps, lowercased.
pub trait AiApps {
    fn is_ai(&self, app: &str) -> bool;
    fn display_name(&self, app: &str) -> String;
}

#[derive(Debug, Clone, PartialEq)]
pub enum Outcome {
    Off,
    Idle,
    OwnWrite,
    NoApp,
    NotAi,
    Approved,
    NoText,
    ScannerUnavailable,
    Clean,
    Acted { action: &'static str, alerted: bool, notified: bool, trigger: &'static str },
}

// What the last scan found for one clipboard state, so switching back to an AI app with the same
// clipboard does not read it again. Holds findings and hashes, never the text.
struct Scanned { count: i64, findings: Vec<Finding>, hash: String, local: u64 }

pub struct Guard {
    pub policy: ClipPolicy,
    last_count: Option<i64>,
    last_front: Option<String>,
    own_write: Option<i64>,
    scanned: Option<Scanned>,
    sent: HashMap<(u64, String), u64>,
    local_key: std::collections::hash_map::RandomState,
}

impl Guard {
    pub fn new(policy: ClipPolicy) -> Guard {
        Guard { policy, last_count: None, last_front: None, own_write: None, scanned: None, sent: HashMap::new(), local_key: Default::default() }
    }

    // A per-process keyed digest for the rate-limit table, so different texts never share an entry even
    // when the device is unenrolled and every contentHash is the "h2:nokey" sentinel. Never sent.
    fn local_digest(&self, text: &str) -> u64 {
        use std::hash::BuildHasher;
        self.local_key.hash_one(text)
    }

    pub fn set_policy(&mut self, policy: ClipPolicy) {
        if policy != self.policy { self.scanned = None; }
        self.policy = policy;
    }

    pub fn tick(&mut self, p: &Providers, apps: &dyn AiApps) -> Outcome {
        if self.policy.mode == Mode::Off {
            self.last_count = None;
            self.last_front = None;
            return Outcome::Off;
        }
        let count = p.clip.change_count();
        let front = p.front.frontmost().map(|s| s.to_ascii_lowercase());
        let changed = self.last_count != Some(count);
        let activated = front != self.last_front;
        let first = self.last_count.is_none();
        self.last_count = Some(count);
        self.last_front = front.clone();
        if !changed && !activated { return Outcome::Idle; }
        if self.own_write == Some(count) { return Outcome::OwnWrite; }
        let Some(app) = front else { return Outcome::NoApp };
        if !apps.is_ai(&app) { return Outcome::NotAi; }
        if self.policy.approved.contains(&app) { return Outcome::Approved; }
        let trigger = if changed && !first { "clipboard-change" } else { "app-activation" };

        let (findings, hash, local) = match &self.scanned {
            Some(s) if s.count == count => (s.findings.clone(), s.hash.clone(), s.local),
            _ => {
                let Some(text) = p.clip.read_text().filter(|t| !t.trim().is_empty()) else { return Outcome::NoText };
                // Not answered (the webview is still loading): forget the counter so the next tick asks again.
                let Some(found) = p.scanner.scan(&text) else { self.last_count = None; return Outcome::ScannerUnavailable };
                // A card on the clipboard: the hash of the whole text is process-keyed (content_hash::process_hash).
                let hash = if found.iter().any(|f| PROCESS_KEYED_THREATS.contains(&f.threat_id)) { crate::content_hash::process_hash(&text) } else { (p.hash)(&text) };
                let s = Scanned { count, findings: found, hash, local: self.local_digest(&text) };
                let out = (s.findings.clone(), s.hash.clone(), s.local);
                self.scanned = Some(s);
                out
            }
        };
        let mut hits: Vec<Finding> = findings.into_iter().filter(|f| self.policy.wants(&f.detector)).collect();
        if hits.is_empty() { return Outcome::Clean; }
        hits.sort_by(|a, b| a.detector.cmp(&b.detector));
        hits.dedup_by(|a, b| a.detector == b.detector);

        let now = p.clock.now_ms();
        self.sent.retain(|_, t| now.saturating_sub(*t) < RATE_WINDOW_MS);
        let key = (local, app.clone());
        let limited = self.sent.contains_key(&key);
        let name = apps.display_name(&app);
        let mode = self.policy.mode;

        let mut action = match mode { Mode::Alert => "alerted", Mode::Coach => "coached", _ => "cleared" };
        let mut notified = false;
        if mode == Mode::Clear {
            if p.clip.write_text(&notice_text(&hits, &name)) {
                self.own_write = Some(p.clip.change_count());
                self.last_count = self.own_write;
                self.scanned = None;
            } else {
                action = "clear-failed";
            }
            // A cleared clipboard is a destructive act the user must be told about every time.
            p.sink.notify("MoorAI cleared your clipboard", &notification_body(&hits, &name, true));
            notified = true;
        } else if mode == Mode::Coach && !limited {
            p.sink.notify("MoorAI: sensitive text on your clipboard", &notification_body(&hits, &name, false));
            notified = true;
        }
        let alerted = !limited;
        if alerted {
            p.sink.alert(build_alert(&hits, &app, mode, action, trigger, &hash, now));
            self.sent.insert(key, now);
        }
        Outcome::Acted { action, alerted, notified, trigger }
    }
}

fn worst_risk(hits: &[Finding]) -> &str {
    let rank = |r: &str| match r { "Critical" => 4, "High" => 3, "Medium" => 2, "Low" => 1, _ => 0 };
    hits.iter().map(|f| f.risk.as_str()).max_by_key(|r| rank(r)).unwrap_or("High")
}

// The content-free alert: detector ids, app id, mode and action, trigger, keyed hash. The runner adds
// the identity fields every alert carries (user, device, tenant, actor, appVersion).
pub fn build_alert(hits: &[Finding], app: &str, mode: Mode, action: &str, trigger: &str, hash: &str, now_ms: u64) -> Value {
    let risk = worst_risk(hits);
    let threat = hits.iter().find(|f| f.risk == risk).map(|f| f.threat_id).unwrap_or(0);
    json!({
        "threatId": threat,
        "category": "Clipboard guard: sensitive text with an unapproved AI app in front",
        "riskLevel": risk,
        "stage": "clipboard",
        "tool": "clipboard-guard",
        "reasonCode": "CLIPBOARD_GUARD",
        "ts": iso8601(now_ms),
        "contentHash": hash,
        "clipboardGuard": {
            "mode": mode.as_str(),
            "action": action,
            "trigger": trigger,
            "app": app,
            "detectors": hits.iter().map(|f| f.detector.clone()).collect::<Vec<_>>(),
        }
    })
}

// What the user is told: what kind of data, which app, why, and what happened. Never the data.
pub fn kinds(hits: &[Finding]) -> String {
    let mut seen: Vec<&str> = vec![];
    for f in hits {
        let l = crate::clip_guard_apps::detector_label(&f.detector);
        if !seen.contains(&l) { seen.push(l); }
    }
    match seen.len() {
        0 => "sensitive data".into(),
        1 => seen[0].into(),
        _ => format!("{} and {}", seen[..seen.len() - 1].join(", "), seen[seen.len() - 1]),
    }
}

pub fn notification_body(hits: &[Finding], app: &str, cleared: bool) -> String {
    let k = kinds(hits);
    if cleared {
        format!("The text you copied contains {k}. {app} is not approved by your organisation for this data, so MoorAI replaced the clipboard. Your security team was notified (without the text).")
    } else {
        format!("The text you copied contains {k}. {app} is not approved by your organisation for this data. Please don't paste it there. Your security team was notified (without the text).")
    }
}

pub fn notice_text(hits: &[Finding], app: &str) -> String {
    format!("[MoorAI removed this from the clipboard: it contained {}, and {app} is not approved for it.]", kinds(hits))
}

pub fn iso8601(ms: u64) -> String {
    let secs = ms / 1000;
    let (days, rem) = (secs / 86400, secs % 86400);
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{:03}Z", rem / 3600, rem % 3600 / 60, rem % 60, ms % 1000)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};

    const SECRET: &str = "deploy key AKIAIOSFODNN7EXAMPLE for prod";
    const CHATGPT: &str = "com.openai.chat";

    struct FakeClip { count: Cell<i64>, text: RefCell<Option<String>>, reads: Cell<u32>, writable: bool }
    impl FakeClip {
        fn new(text: Option<&str>) -> FakeClip { FakeClip { count: Cell::new(1), text: RefCell::new(text.map(String::from)), reads: Cell::new(0), writable: true } }
        fn copy(&self, text: &str) { *self.text.borrow_mut() = Some(text.into()); self.count.set(self.count.get() + 1); }
    }
    impl Clipboard for FakeClip {
        fn change_count(&self) -> i64 { self.count.get() }
        fn read_text(&self) -> Option<String> { self.reads.set(self.reads.get() + 1); self.text.borrow().clone() }
        fn write_text(&self, t: &str) -> bool {
            if !self.writable { return false; }
            *self.text.borrow_mut() = Some(t.into());
            self.count.set(self.count.get() + 1);
            true
        }
    }
    struct FakeFront(RefCell<Option<String>>);
    impl FakeFront { fn set(&self, a: &str) { *self.0.borrow_mut() = Some(a.into()); } }
    impl Frontmost for FakeFront { fn frontmost(&self) -> Option<String> { self.0.borrow().clone() } }
    struct FakeClock(Cell<u64>);
    impl Clock for FakeClock { fn now_ms(&self) -> u64 { self.0.get() } }
    // Flags anything containing "AKIA" as an AWS key and "@" as an email; "inj" as an injection.
    struct FakeScanner { calls: Cell<u32>, down: bool }
    impl Scanner for FakeScanner {
        fn scan(&self, text: &str) -> Option<Vec<Finding>> {
            self.calls.set(self.calls.get() + 1);
            if self.down { return None; }
            let mut out = vec![];
            if text.contains("AKIA") { out.push(Finding { detector: "secret-aws-akia".into(), threat_id: 39, risk: "Critical".into() }); }
            if text.contains('@') { out.push(Finding { detector: "dlp-email".into(), threat_id: 15, risk: "High".into() }); }
            if text.contains("ignore previous") { out.push(Finding { detector: "inj-ignore".into(), threat_id: 3, risk: "High".into() }); }
            if text.contains("4111") { out.push(Finding { detector: "dlp-payment-card".into(), threat_id: 90, risk: "Critical".into() }); }
            Some(out)
        }
    }
    #[derive(Default)]
    struct FakeSink { alerts: RefCell<Vec<Value>>, notes: RefCell<Vec<(String, String)>> }
    impl Sink for FakeSink {
        fn alert(&self, a: Value) { self.alerts.borrow_mut().push(a); }
        fn notify(&self, t: &str, b: &str) { self.notes.borrow_mut().push((t.into(), b.into())); }
    }
    struct Apps;
    impl AiApps for Apps {
        fn is_ai(&self, app: &str) -> bool { app == CHATGPT || app == "com.anthropic.claudefordesktop" }
        fn display_name(&self, app: &str) -> String { if app == CHATGPT { "ChatGPT".into() } else { app.into() } }
    }

    struct World { clip: FakeClip, front: FakeFront, clock: FakeClock, scanner: FakeScanner, sink: FakeSink }
    impl World {
        fn new(text: Option<&str>, front: &str) -> World {
            World { clip: FakeClip::new(text), front: FakeFront(RefCell::new(Some(front.into()))), clock: FakeClock(Cell::new(1_760_000_000_000)), scanner: FakeScanner { calls: Cell::new(0), down: false }, sink: FakeSink::default() }
        }
        fn tick(&self, g: &mut Guard) -> Outcome {
            let hash = |t: &str| crate::content_hash::hash_with_key(crate::content_hash::derive_key("tok-test").as_ref(), t);
            let p = Providers { clip: &self.clip, front: &self.front, clock: &self.clock, scanner: &self.scanner, sink: &self.sink, hash: &hash };
            g.tick(&p, &Apps)
        }
    }
    fn guard(mode: &str) -> Guard { Guard::new(ClipPolicy::from_policy(&json!({ "clipboardGuard": { "mode": mode } }))) }

    #[test]
    fn off_reads_nothing_and_does_nothing() {
        let w = World::new(Some(SECRET), CHATGPT);
        let mut g = guard("off");
        assert_eq!(w.tick(&mut g), Outcome::Off);
        w.clip.copy(SECRET);
        assert_eq!(w.tick(&mut g), Outcome::Off);
        assert_eq!(w.clip.reads.get(), 0);
        assert!(w.sink.alerts.borrow().is_empty() && w.sink.notes.borrow().is_empty());
        assert_eq!(ClipPolicy::from_policy(&json!({})).mode, Mode::Off, "no clipboardGuard key is off");
        assert_eq!(ClipPolicy::from_policy(&json!({ "clipboardGuard": { "mode": "CLEAR" } })).mode, Mode::Off, "unknown values are off");
    }

    #[test]
    fn alert_mode_posts_one_content_free_alert_and_leaves_the_clipboard() {
        let w = World::new(Some("nothing here"), "com.apple.finder");
        let mut g = guard("alert");
        assert_eq!(w.tick(&mut g), Outcome::NotAi);
        w.front.set(CHATGPT);
        assert_eq!(w.tick(&mut g), Outcome::Clean);
        w.clip.copy(SECRET);
        assert_eq!(w.tick(&mut g), Outcome::Acted { action: "alerted", alerted: true, notified: false, trigger: "clipboard-change" });
        assert_eq!(w.clip.text.borrow().as_deref(), Some(SECRET), "alert mode never touches the clipboard");
        let alerts = w.sink.alerts.borrow();
        assert_eq!(alerts.len(), 1);
        let a = &alerts[0];
        assert_eq!(a["clipboardGuard"]["detectors"], json!(["secret-aws-akia"]));
        assert_eq!(a["clipboardGuard"]["app"], CHATGPT);
        assert_eq!(a["clipboardGuard"]["mode"], "alert");
        assert_eq!(a["riskLevel"], "Critical");
        assert!(a["contentHash"].as_str().unwrap().starts_with("h2:"));
        assert!(w.sink.notes.borrow().is_empty());
    }

    #[test]
    fn a_card_on_the_clipboard_is_hashed_under_the_process_key_not_the_tenant_key() {
        const CARD: &str = "card 4111 1111 1111 1111 exp 12/29";
        let w = World::new(None, CHATGPT);
        let mut g = guard("alert");
        w.tick(&mut g);
        w.clip.copy(CARD);
        assert!(matches!(w.tick(&mut g), Outcome::Acted { alerted: true, .. }));
        let h = w.sink.alerts.borrow()[0]["contentHash"].as_str().unwrap().to_string();
        let tenant = crate::content_hash::hash_with_key(crate::content_hash::derive_key("tok-test").as_ref(), CARD);
        assert!(h.starts_with("proc:") && h.len() == 21, "{h}");
        assert_ne!(h, tenant);
        assert!(!h.contains(&tenant[3..]));
        assert_eq!(h, crate::content_hash::process_hash(CARD), "stable within the process");
        assert_eq!(w.sink.alerts.borrow()[0]["threatId"], 90);
        // A card next to a secret: any #90 finding on the clipboard keeps the hash process-keyed.
        let both = format!("{CARD} {SECRET}");
        w.clip.copy(&both);
        w.tick(&mut g);
        let h2 = w.sink.alerts.borrow()[1]["contentHash"].as_str().unwrap().to_string();
        assert!(h2.starts_with("proc:"), "{h2}");
    }

    #[test]
    fn coach_mode_alerts_and_explains_without_the_text() {
        let w = World::new(None, CHATGPT);
        let mut g = guard("coach");
        w.tick(&mut g);
        w.clip.copy("mail jane.doe@example.com and AKIAIOSFODNN7EXAMPLE");
        assert_eq!(w.tick(&mut g), Outcome::Acted { action: "coached", alerted: true, notified: true, trigger: "clipboard-change" });
        let notes = w.sink.notes.borrow();
        assert_eq!(notes.len(), 1);
        assert!(notes[0].1.contains("an AWS access key") && notes[0].1.contains("an email address") && notes[0].1.contains("ChatGPT"), "{:?}", notes[0]);
        assert!(!notes[0].1.contains("AKIAIOSFODNN7EXAMPLE") && !notes[0].1.contains("jane.doe"));
        assert_eq!(w.sink.alerts.borrow()[0]["clipboardGuard"]["detectors"], json!(["dlp-email", "secret-aws-akia"]));
    }

    #[test]
    fn clear_mode_replaces_the_text_and_ignores_its_own_write() {
        let w = World::new(None, CHATGPT);
        let mut g = guard("clear");
        w.tick(&mut g);
        w.clip.copy(SECRET);
        assert_eq!(w.tick(&mut g), Outcome::Acted { action: "cleared", alerted: true, notified: true, trigger: "clipboard-change" });
        let now = w.clip.text.borrow().clone().unwrap();
        assert!(now.starts_with("[MoorAI removed this from the clipboard") && !now.contains("AKIA"), "{now}");
        assert_eq!(w.tick(&mut g), Outcome::Idle, "the notice MoorAI wrote is not scanned again");
        let reads = w.clip.reads.get();
        w.front.set("com.apple.finder");
        w.tick(&mut g);
        w.front.set(CHATGPT);
        assert_eq!(w.tick(&mut g), Outcome::OwnWrite, "nor read when the AI app comes back to the front");
        assert_eq!(w.clip.reads.get(), reads);
        assert_eq!(w.sink.alerts.borrow()[0]["clipboardGuard"]["action"], "cleared");
        assert_eq!(w.sink.notes.borrow()[0].0, "MoorAI cleared your clipboard");
    }

    #[test]
    fn a_failed_clear_is_reported_as_such() {
        let mut w = World::new(None, CHATGPT);
        w.clip.writable = false;
        let mut g = guard("clear");
        w.tick(&mut g);
        w.clip.copy(SECRET);
        assert!(matches!(w.tick(&mut g), Outcome::Acted { action: "clear-failed", .. }));
        assert_eq!(w.sink.alerts.borrow()[0]["clipboardGuard"]["action"], "clear-failed");
    }

    #[test]
    fn an_approved_ai_app_is_never_read() {
        let w = World::new(Some(SECRET), CHATGPT);
        let mut g = Guard::new(ClipPolicy::from_policy(&json!({ "clipboardGuard": { "mode": "clear", "approvedApps": ["COM.OPENAI.CHAT"] } })));
        assert_eq!(w.tick(&mut g), Outcome::Approved);
        w.clip.copy(SECRET);
        assert_eq!(w.tick(&mut g), Outcome::Approved);
        assert_eq!(w.clip.reads.get(), 0);
        assert!(w.sink.alerts.borrow().is_empty());
    }

    #[test]
    fn a_non_ai_app_is_never_read() {
        let w = World::new(Some(SECRET), "com.apple.textedit");
        let mut g = guard("clear");
        assert_eq!(w.tick(&mut g), Outcome::NotAi);
        w.clip.copy(SECRET);
        assert_eq!(w.tick(&mut g), Outcome::NotAi);
        assert_eq!(w.clip.reads.get(), 0);
        assert_eq!(w.clip.text.borrow().as_deref(), Some(SECRET));
    }

    #[test]
    fn policy_can_add_an_ai_app() {
        struct PolicyApps(HashSet<String>);
        impl AiApps for PolicyApps {
            fn is_ai(&self, app: &str) -> bool { Apps.is_ai(app) || self.0.contains(app) }
            fn display_name(&self, app: &str) -> String { app.into() }
        }
        let pol = ClipPolicy::from_policy(&json!({ "clipboardGuard": { "mode": "alert", "aiApps": ["Com.Apple.TextEdit"] } }));
        assert!(pol.extra_ai.contains("com.apple.textedit"));
        let apps = PolicyApps(pol.extra_ai.clone());
        let w = World::new(Some(SECRET), "com.apple.textedit");
        let mut g = Guard::new(pol);
        let hash = |t: &str| crate::content_hash::hash_with_key(None, t);
        let p = Providers { clip: &w.clip, front: &w.front, clock: &w.clock, scanner: &w.scanner, sink: &w.sink, hash: &hash };
        assert!(matches!(g.tick(&p, &apps), Outcome::Acted { action: "alerted", .. }));
    }

    #[test]
    fn rate_limited_to_one_alert_per_content_and_app_per_ten_minutes() {
        let w = World::new(None, CHATGPT);
        let mut g = guard("coach");
        w.tick(&mut g);
        w.clip.copy(SECRET);
        assert!(matches!(w.tick(&mut g), Outcome::Acted { alerted: true, .. }));
        // switch away and back with the same clipboard: same content and app, inside the window
        w.front.set("com.apple.finder");
        w.tick(&mut g);
        w.front.set(CHATGPT);
        assert_eq!(w.tick(&mut g), Outcome::Acted { action: "coached", alerted: false, notified: false, trigger: "app-activation" });
        // the same text copied again
        w.clip.copy(SECRET);
        assert!(matches!(w.tick(&mut g), Outcome::Acted { alerted: false, .. }));
        // another app is another key
        w.front.set("com.anthropic.claudefordesktop");
        assert!(matches!(w.tick(&mut g), Outcome::Acted { alerted: true, .. }));
        // other text is another key
        w.front.set(CHATGPT);
        w.tick(&mut g);
        w.clip.copy("AKIAIOSFODNN7EXAMPLF other");
        assert!(matches!(w.tick(&mut g), Outcome::Acted { alerted: true, .. }));
        // ten minutes on, the first pair alerts again
        w.clock.0.set(w.clock.0.get() + RATE_WINDOW_MS);
        w.clip.copy(SECRET);
        assert!(matches!(w.tick(&mut g), Outcome::Acted { alerted: true, .. }));
        assert_eq!(w.sink.alerts.borrow().len(), 4);
        assert_eq!(w.sink.notes.borrow().len(), 4, "coach notifications follow the alert rate limit");
    }

    #[test]
    fn clear_mode_still_clears_inside_the_rate_window() {
        let w = World::new(None, CHATGPT);
        let mut g = guard("clear");
        w.tick(&mut g);
        w.clip.copy(SECRET);
        assert!(matches!(w.tick(&mut g), Outcome::Acted { alerted: true, .. }));
        w.clip.copy(SECRET);
        assert_eq!(w.tick(&mut g), Outcome::Acted { action: "cleared", alerted: false, notified: true, trigger: "clipboard-change" });
        assert!(!w.clip.text.borrow().as_deref().unwrap().contains("AKIA"));
        assert_eq!(w.sink.alerts.borrow().len(), 1);
    }

    #[test]
    fn sensitive_text_already_on_the_clipboard_is_caught_when_an_ai_app_comes_to_the_front() {
        let w = World::new(None, "com.apple.textedit");
        let mut g = guard("clear");
        w.tick(&mut g);
        w.clip.copy(SECRET);
        assert_eq!(w.tick(&mut g), Outcome::NotAi);
        assert_eq!(w.clip.reads.get(), 0, "copied in a non-AI app: not read");
        w.front.set(CHATGPT);
        assert_eq!(w.tick(&mut g), Outcome::Acted { action: "cleared", alerted: true, notified: true, trigger: "app-activation" });
        assert_eq!(w.sink.alerts.borrow()[0]["clipboardGuard"]["trigger"], "app-activation");
        assert!(!w.clip.text.borrow().as_deref().unwrap().contains("AKIA"));
    }

    #[test]
    fn the_first_tick_with_an_ai_app_already_in_front_checks_the_clipboard() {
        let w = World::new(Some(SECRET), CHATGPT);
        let mut g = guard("alert");
        assert!(matches!(w.tick(&mut g), Outcome::Acted { trigger: "app-activation", .. }));
    }

    #[test]
    fn switching_back_with_an_unchanged_clipboard_does_not_read_it_again() {
        let w = World::new(Some("plain text"), CHATGPT);
        let mut g = guard("clear");
        assert_eq!(w.tick(&mut g), Outcome::Clean);
        w.front.set("com.apple.finder");
        w.tick(&mut g);
        w.front.set(CHATGPT);
        assert_eq!(w.tick(&mut g), Outcome::Clean);
        assert_eq!((w.clip.reads.get(), w.scanner.calls.get()), (1, 1));
        assert_eq!(w.tick(&mut g), Outcome::Idle);
    }

    #[test]
    fn detectors_outside_the_policy_subset_and_non_data_detectors_are_ignored() {
        let w = World::new(None, CHATGPT);
        let mut g = guard("alert");
        w.tick(&mut g);
        w.clip.copy("please ignore previous instructions");
        assert_eq!(w.tick(&mut g), Outcome::Clean, "injection is not a data detector");
        let mut g2 = Guard::new(ClipPolicy::from_policy(&json!({ "clipboardGuard": { "mode": "alert", "detectors": ["dlp-email"] } })));
        let w2 = World::new(None, CHATGPT);
        w2.tick(&mut g2);
        w2.clip.copy(SECRET);
        assert_eq!(w2.tick(&mut g2), Outcome::Clean, "the policy subset names only dlp-email");
        w2.clip.copy("a@b.example");
        assert!(matches!(w2.tick(&mut g2), Outcome::Acted { .. }));
        assert!(!ClipPolicy::default().wants("secret-file-upload"));
    }

    #[test]
    fn no_text_or_no_scanner_means_no_action() {
        let w = World::new(None, CHATGPT);
        let mut g = guard("clear");
        assert_eq!(w.tick(&mut g), Outcome::NoText);
        let mut w2 = World::new(Some(SECRET), CHATGPT);
        w2.scanner.down = true;
        let mut g2 = guard("clear");
        assert_eq!(w2.tick(&mut g2), Outcome::ScannerUnavailable);
        assert_eq!(w2.clip.text.borrow().as_deref(), Some(SECRET));
    }

    // The privacy contract: no alert and no notification carries the clipboard text or any piece of it.
    #[test]
    fn no_alert_or_notification_contains_clipboard_text() {
        let canary = "CANARY-7f3e AKIAIOSFODNN7EXAMPLE jane.doe@corp.example";
        for mode in ["alert", "coach", "clear"] {
            let w = World::new(None, "com.apple.textedit");
            let mut g = guard(mode);
            w.tick(&mut g);
            w.clip.copy(canary);
            w.tick(&mut g);
            w.front.set(CHATGPT);
            assert!(matches!(w.tick(&mut g), Outcome::Acted { .. }), "{mode}");
            let mut out: Vec<String> = w.sink.alerts.borrow().iter().map(|a| a.to_string()).collect();
            out.extend(w.sink.notes.borrow().iter().map(|(t, b)| format!("{t} {b}")));
            if mode == "clear" { out.push(w.clip.text.borrow().clone().unwrap()); }
            assert!(!out.is_empty());
            for s in &out {
                for piece in ["CANARY", "7f3e", "AKIAIOSFODNN7EXAMPLE", "AKIA", "jane.doe", "corp.example"] {
                    assert!(!s.contains(piece), "{mode}: {piece:?} leaked into {s}");
                }
            }
            let a = &w.sink.alerts.borrow()[0];
            let mut keys: Vec<&str> = a["clipboardGuard"].as_object().unwrap().keys().map(|k| k.as_str()).collect();
            keys.sort();
            assert_eq!(keys, ["action", "app", "detectors", "mode", "trigger"]);
        }
    }

    #[test]
    fn iso8601_formats_utc() {
        assert_eq!(iso8601(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(iso8601(1_760_000_000_123), "2025-10-09T08:53:20.123Z");
        assert_eq!(iso8601(951_782_400_000), "2000-02-29T00:00:00.000Z");
    }
}
