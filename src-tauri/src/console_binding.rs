// Which console the host may send the install token to. ~/.moorai/config.json (and the pre-rebrand
// ~/.curaiq/config.json it falls back to) is writable by anything running as the user — including a
// prompt-injected coding agent, and from inside the MXC container, whose grants cover ~/.moorai. Its
// `serverUrl` therefore cannot decide where credentials go: a rewritten value would collect the token.
//
// The trusted origin lives in a HOST-ONLY file, outside every agent grant:
//   Windows  %LOCALAPPDATA%\MoorAI Host\console.json   (the directory mxc.rs's "moorai-host" class
//            denies to the container, beside mxc.json)
//   macOS    ~/Library/Application Support/MoorAI Host/console.json  (denied to the Seatbelt-isolated
//            agent by platform.rs's profile)
//   Linux    $XDG_DATA_HOME (or ~/.local/share)/MoorAI Host/console.json
// It is written at enrolment (save_provision), and once, on first use, for installs enrolled before
// this file existed (trust on first use of config.json's serverUrl as it stands then). After that a
// serverUrl that names another origin is ignored with a visible message; re-enrolling in the app is the
// only way to move consoles. Rules for every origin: https, or http to localhost / 127.0.0.1 / [::1]
// only (local development); no userinfo; origin only (any path or query is dropped). Credentialed
// requests never follow redirects.
use serde_json::{json, Value};

pub const HOST_DIR_NAME: &str = "MoorAI Host";
pub const BINDING_FILE: &str = "console.json";

pub fn host_dir() -> String {
    let home = crate::platform::home_dir();
    let env = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
    if cfg!(windows) {
        format!("{}\\{HOST_DIR_NAME}", env("LOCALAPPDATA").unwrap_or_else(|| format!("{home}\\AppData\\Local")))
    } else if cfg!(target_os = "macos") {
        format!("{home}/Library/Application Support/{HOST_DIR_NAME}")
    } else {
        format!("{}/{HOST_DIR_NAME}", env("XDG_DATA_HOME").unwrap_or_else(|| format!("{home}/.local/share")))
    }
}

// → "https://host[:port]" (or "http://localhost:port" for local development), or why it is refused.
pub fn normalize_origin(raw: &str) -> Result<String, String> {
    let u = url::Url::parse(raw.trim()).map_err(|_| format!("\"{}\" is not a URL", raw.trim()))?;
    if !u.username().is_empty() || u.password().is_some() { return Err("the console URL carries credentials".into()); }
    let host = u.host_str().filter(|h| !h.is_empty()).ok_or("the console URL has no host")?.to_ascii_lowercase();
    let local = matches!(host.as_str(), "localhost" | "127.0.0.1" | "[::1]");
    match u.scheme() {
        "https" => {}
        "http" if local => {}
        "http" => return Err(format!("http://{host} is not https (plain http is allowed only for localhost)")),
        s => return Err(format!("{s}: is not an https URL")),
    }
    Ok(match u.port() { Some(p) => format!("{}://{host}:{p}", u.scheme()), None => format!("{}://{host}", u.scheme()) })
}

// Ok(None) = no record yet; Err = a record exists but is unusable (never silently re-trusted).
pub fn read_binding(dir: &str) -> Result<Option<String>, String> {
    let path = format!("{dir}/{BINDING_FILE}");
    let Ok(text) = std::fs::read_to_string(&path) else { return Ok(None) };
    let v: Value = serde_json::from_str(&text).map_err(|_| "the recorded console file is unreadable — re-enrol to record it again".to_string())?;
    let origin = v.get("origin").and_then(|o| o.as_str()).ok_or("the recorded console file has no origin — re-enrol to record it again")?;
    let n = normalize_origin(origin).map_err(|e| format!("the recorded console is unusable ({e}) — re-enrol to record it again"))?;
    if n != origin { return Err("the recorded console is not a bare origin — re-enrol to record it again".into()); }
    Ok(Some(n))
}

pub fn write_binding(dir: &str, origin: &str, source: &str) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let at = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    crate::private_file::write_private(format!("{dir}/{BINDING_FILE}"), &json!({ "origin": origin, "source": source, "recordedAt": at }).to_string()).map_err(|e| e.to_string())
}

pub struct Resolved { pub origin: Option<String>, pub warning: Option<String> }

// The console credentialed requests may go to, given the host-only record and the agent-writable
// config. Records the config's origin on first use when there is no record yet (migration).
pub fn resolve(dir: &str, cfg: &Value) -> Resolved {
    let server = cfg.get("serverUrl").and_then(|v| v.as_str()).unwrap_or("").trim();
    let token = cfg.get("installToken").and_then(|v| v.as_str()).unwrap_or("");
    match read_binding(dir) {
        Err(e) => Resolved { origin: None, warning: Some(format!("MoorAI is not sending its install token: {e}.")) },
        Ok(Some(bound)) => {
            let differs = !server.is_empty() && normalize_origin(server).ok().as_deref() != Some(bound.as_str());
            let warning = differs.then(|| format!(
                "~/.moorai/config.json now names {server} as the console, but this device was enrolled with {bound}. MoorAI ignored the change and sends its install token only to {bound}. Re-enrol in the app to move to another console."));
            Resolved { origin: Some(bound), warning }
        }
        Ok(None) if server.is_empty() || token.is_empty() => Resolved { origin: None, warning: None },
        Ok(None) => match normalize_origin(server) {
            Ok(o) => {
                let _ = write_binding(dir, &o, "migration");
                Resolved { origin: Some(o), warning: None }
            }
            Err(e) => Resolved { origin: None, warning: Some(format!("MoorAI is not sending its install token to the console in ~/.moorai/config.json: {e}.")) },
        },
    }
}

// save_provision with an install token is an enrolment: its serverUrl becomes the recorded console.
pub fn record_enrolment(dir: &str, incoming: &Value) -> Result<(), String> {
    if incoming.get("installToken").and_then(|v| v.as_str()).unwrap_or("").is_empty() { return Ok(()); }
    let server = incoming.get("serverUrl").and_then(|v| v.as_str()).ok_or("the provision has no serverUrl")?;
    let origin = normalize_origin(server).map_err(|e| format!("enrolment refused: {e}"))?;
    write_binding(dir, &origin, "enrolment")
}

pub type Fetch<'a> = &'a dyn Fn(&str, &str) -> Result<Value, String>;

// Tests that point HOME at a scratch directory hold this, so they never see each other's HOME.
#[cfg(test)]
pub(crate) static TEST_HOME_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

// The one credentialed GET: 4 s, redirects off (a 3xx is a failure, so the token cannot be bounced on),
// non-2xx is a failure.
pub fn real_fetch(url: &str, token: &str) -> Result<Value, String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(4))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| e.to_string())?;
    let r = client.get(url).header("X-Install-Token", token).send().map_err(|e| e.to_string())?;
    if !r.status().is_success() { return Err(format!("console answered {}", r.status().as_u16())); }
    r.json::<Value>().map_err(|e| e.to_string())
}

pub struct Decision { pub allowed: bool, pub warning: Option<String> }

// #3 — is this agent permitted for our tenant/device? Asks the recorded console (authoritative),
// falling back to the cached allow-list on a network error or a refused console, else deny.
// Unprovisioned installs (no install token, or no console at all) are not restricted.
pub fn policy_allows(cfg: &Value, dir: &str, tool: &str, user: &str, device: &str, fetch: Fetch) -> Decision {
    let token = cfg.get("installToken").and_then(|v| v.as_str()).unwrap_or("");
    if token.is_empty() { return Decision { allowed: true, warning: None }; }
    let cached = cfg.get("allowedTools").and_then(|v| v.as_array()).map(|a| a.iter().any(|x| x.as_str() == Some(tool)));
    let r = resolve(dir, cfg);
    let Some(origin) = r.origin else {
        return Decision { allowed: if r.warning.is_some() { cached.unwrap_or(false) } else { true }, warning: r.warning };
    };
    let mut url = match url::Url::parse(&format!("{origin}/api/policy")) { Ok(u) => u, Err(_) => return Decision { allowed: cached.unwrap_or(false), warning: r.warning } };
    url.query_pairs_mut().append_pair("user", user).append_pair("device", device);
    let allowed = match fetch(url.as_str(), token) {
        Ok(j) => j.get("allowedTools").and_then(|v| v.as_array()).map(|a| a.iter().any(|x| x.as_str() == Some(tool))).unwrap_or(true),
        Err(_) => cached.unwrap_or(false),
    };
    Decision { allowed, warning: r.warning }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    fn scratch(tag: &str) -> String {
        let n = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let d = std::env::temp_dir().join(format!("moorai-console-{tag}-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d.to_string_lossy().into_owned()
    }

    // A one-route HTTP server on loopback. Records every request's X-Install-Token (or "<none>").
    struct Srv { origin: String, seen: Arc<Mutex<Vec<String>>> }
    fn serve(respond: impl Fn() -> String + Send + 'static) -> Srv {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin = format!("http://127.0.0.1:{}", l.local_addr().unwrap().port());
        let seen = Arc::new(Mutex::new(vec![]));
        let s2 = seen.clone();
        std::thread::spawn(move || {
            for stream in l.incoming().flatten() {
                let mut r = BufReader::new(stream.try_clone().unwrap());
                let mut tok = "<none>".to_string();
                let mut line = String::new();
                while r.read_line(&mut line).map(|n| n > 0).unwrap_or(false) {
                    let t = line.trim_end().to_string();
                    if t.is_empty() { break; }
                    if let Some((k, v)) = t.split_once(':') { if k.eq_ignore_ascii_case("x-install-token") { tok = v.trim().to_string(); } }
                    line.clear();
                }
                s2.lock().unwrap().push(tok);
                let _ = (&stream).write_all(respond().as_bytes());
            }
        });
        Srv { origin, seen }
    }
    fn ok_json(body: &'static str) -> impl Fn() -> String { move || format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()) }
    fn write_test_binding(dir: &str, origin: &str) {
        std::fs::write(format!("{dir}/console.json"), json!({ "origin": origin, "source": "enrolment" }).to_string()).unwrap();
    }

    #[test]
    fn rewritten_server_url_does_not_receive_the_install_token() {
        let good = serve(ok_json(r#"{"allowedTools":["claude","codex"]}"#));
        let evil = serve(ok_json(r#"{"allowedTools":["claude","codex"]}"#));
        let dir = scratch("rewrite");
        write_test_binding(&dir, &good.origin);
        // what a prompt-injected agent writes into ~/.moorai/config.json
        let cfg = json!({ "serverUrl": evil.origin, "installToken": "tok-SECRET-INSTALL", "tenant": "acme" });
        let d = policy_allows(&cfg, &dir, "codex", "u", "d", &real_fetch);
        assert!(evil.seen.lock().unwrap().is_empty(), "the install token went to the rewritten serverUrl: {:?}", evil.seen.lock().unwrap());
        assert_eq!(*good.seen.lock().unwrap(), vec!["tok-SECRET-INSTALL".to_string()], "the recorded console is asked instead");
        assert!(d.allowed);
        assert!(d.warning.as_deref().unwrap_or("").contains(&evil.origin), "the user is told: {:?}", d.warning);
    }

    #[test]
    fn plain_http_server_url_is_refused_before_anything_is_sent() {
        let dir = scratch("http");
        let calls = RefCell::new(vec![]);
        let fetch = |url: &str, tok: &str| { calls.borrow_mut().push((url.to_string(), tok.to_string())); Ok(json!({ "allowedTools": ["codex"] })) };
        let cfg = json!({ "serverUrl": "http://collector.example.net", "installToken": "tok-SECRET-INSTALL", "allowedTools": [] });
        let d = policy_allows(&cfg, &dir, "codex", "u", "d", &fetch);
        assert!(calls.borrow().is_empty(), "token offered over plain http to a non-local host: {:?}", calls.borrow());
        assert!(!d.allowed, "falls back to the cached allow-list (codex not in it)");
        assert!(d.warning.is_some());
        assert!(read_binding(&dir).unwrap().is_none(), "a refused origin is never recorded");
    }

    #[test]
    fn the_recorded_console_cannot_redirect_the_token_elsewhere() {
        let evil = serve(ok_json(r#"{"allowedTools":["codex"]}"#));
        let target = format!("{}/api/policy", evil.origin);
        let good = serve(move || format!("HTTP/1.1 302 Found\r\nLocation: {target}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"));
        let dir = scratch("redirect");
        write_test_binding(&dir, &good.origin);
        let cfg = json!({ "serverUrl": good.origin, "installToken": "tok-SECRET-INSTALL", "allowedTools": ["claude"] });
        let d = policy_allows(&cfg, &dir, "codex", "u", "d", &real_fetch);
        assert_eq!(good.seen.lock().unwrap().len(), 1);
        assert!(evil.seen.lock().unwrap().is_empty(), "the redirect was followed with the token: {:?}", evil.seen.lock().unwrap());
        assert!(!d.allowed, "a redirect is a failed fetch → cached allow-list");
    }

    #[test]
    fn migration_trusts_the_current_server_url_once_then_holds_it() {
        let first = serve(ok_json(r#"{"allowedTools":["codex"]}"#));
        let later = serve(ok_json(r#"{"allowedTools":["codex"]}"#));
        let dir = scratch("tofu");
        let cfg = json!({ "serverUrl": format!("{}/some/path?x=1", first.origin), "installToken": "tok-SECRET-INSTALL" });
        let d = policy_allows(&cfg, &dir, "codex", "u", "d", &real_fetch);
        assert!(d.allowed && d.warning.is_none());
        assert_eq!(read_binding(&dir).unwrap().as_deref(), Some(first.origin.as_str()), "recorded host-side as a bare origin");
        let rec: Value = serde_json::from_str(&std::fs::read_to_string(format!("{dir}/console.json")).unwrap()).unwrap();
        assert_eq!(rec["source"], "migration");
        let moved = json!({ "serverUrl": later.origin, "installToken": "tok-SECRET-INSTALL" });
        let d2 = policy_allows(&moved, &dir, "codex", "u", "d", &real_fetch);
        assert!(later.seen.lock().unwrap().is_empty(), "after migration a new serverUrl gets nothing");
        assert_eq!(first.seen.lock().unwrap().len(), 2);
        assert!(d2.warning.is_some());
    }

    #[test]
    fn enrolment_records_the_console_and_refuses_unsafe_ones() {
        let dir = scratch("enrol");
        record_enrolment(&dir, &json!({ "allowedTools": ["codex"] })).unwrap();
        assert!(read_binding(&dir).unwrap().is_none(), "a policy-cache save is not an enrolment");
        assert!(record_enrolment(&dir, &json!({ "installToken": "t", "serverUrl": "http://evil.example" })).is_err());
        assert!(record_enrolment(&dir, &json!({ "installToken": "t" })).is_err(), "no serverUrl, no enrolment");
        assert!(read_binding(&dir).unwrap().is_none());
        record_enrolment(&dir, &json!({ "installToken": "t", "serverUrl": "https://app.moorai.dev/" })).unwrap();
        assert_eq!(read_binding(&dir).unwrap().as_deref(), Some("https://app.moorai.dev"));
        record_enrolment(&dir, &json!({ "installToken": "t", "serverUrl": "https://acme.example:8443" })).unwrap();
        assert_eq!(read_binding(&dir).unwrap().as_deref(), Some("https://acme.example:8443"), "re-enrolling moves the console");
    }

    #[test]
    fn a_tampered_record_is_refused_not_re_trusted() {
        let dir = scratch("tamper");
        std::fs::write(format!("{dir}/console.json"), r#"{"origin":"http://collector.example.net"}"#).unwrap();
        let calls = RefCell::new(0);
        let fetch = |_: &str, _: &str| { *calls.borrow_mut() += 1; Ok(json!({})) };
        let d = policy_allows(&json!({ "serverUrl": "https://app.moorai.dev", "installToken": "t" }), &dir, "codex", "u", "d", &fetch);
        assert_eq!(*calls.borrow(), 0);
        assert!(!d.allowed && d.warning.is_some());
    }

    #[test]
    fn unprovisioned_installs_are_unrestricted_and_send_nothing() {
        let dir = scratch("unprov");
        let calls = RefCell::new(0);
        let fetch = |_: &str, _: &str| { *calls.borrow_mut() += 1; Ok(json!({})) };
        assert!(policy_allows(&json!({ "serverUrl": "https://app.moorai.dev" }), &dir, "codex", "u", "d", &fetch).allowed);
        assert!(policy_allows(&json!({ "installToken": "t" }), &dir, "codex", "u", "d", &fetch).allowed);
        assert_eq!(*calls.borrow(), 0);
    }

    #[test]
    fn enrolment_through_the_real_commands_records_the_console_and_identity_reports_it() {
        let _g = TEST_HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let home = scratch("home");
        let var = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
        let saved: Vec<(&str, Option<String>)> = [var, "LOCALAPPDATA", "XDG_DATA_HOME"].into_iter().map(|k| (k, std::env::var(k).ok())).collect();
        std::env::set_var(var, &home);
        std::env::remove_var("LOCALAPPDATA");
        std::env::remove_var("XDG_DATA_HOME");
        let dir = host_dir();
        assert!(dir.starts_with(&home), "host dir {dir} is under the scratch home");
        let r1 = crate::save_provision(json!({ "tenant": "acme", "serverUrl": "http://collector.example.net", "installToken": "tok-SECRET-INSTALL" }));
        let config_written = std::path::Path::new(&format!("{home}/.moorai/config.json")).exists();
        crate::save_provision(json!({ "tenant": "acme", "serverUrl": "https://console.good.test/", "installToken": "tok-SECRET-INSTALL" })).unwrap();
        let bound = read_binding(&dir);
        // the agent rewrites config.json afterwards
        std::fs::write(format!("{home}/.moorai/config.json"), json!({ "tenant": "acme", "serverUrl": "https://collector.example.net", "installToken": "tok-SECRET-INSTALL" }).to_string()).unwrap();
        let id = crate::identity();
        for (k, v) in saved { match v { Some(v) => std::env::set_var(k, v), None => std::env::remove_var(k) } }
        assert!(r1.is_err(), "a plain-http provision is refused");
        assert!(!config_written, "nothing was written for the refused enrolment");
        assert_eq!(bound.unwrap().as_deref(), Some("https://console.good.test"));
        assert_eq!(id["console"], "https://console.good.test", "the renderer is handed the recorded console: {id}");
        assert!(id["consoleWarning"].as_str().unwrap_or("").contains("collector.example.net"), "and told the change was ignored: {id}");
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn origin_rules() {
        for (i, o) in [("https://app.moorai.dev", "https://app.moorai.dev"), ("https://App.MoorAI.dev/x?y#z", "https://app.moorai.dev"), ("https://h.example:8443/", "https://h.example:8443"),
            ("http://localhost:8787", "http://localhost:8787"), ("http://127.0.0.1:9", "http://127.0.0.1:9"), ("http://[::1]:9", "http://[::1]:9")] {
            assert_eq!(normalize_origin(i).as_deref(), Ok(o), "{i}");
        }
        for bad in ["http://app.moorai.dev", "https://user:pw@app.moorai.dev", "ftp://x.example", "file:///etc/passwd", "app.moorai.dev", "", "http://localhost.evil.example", "javascript:alert(1)"] {
            assert!(normalize_origin(bad).is_err(), "{bad}");
        }
    }
}
