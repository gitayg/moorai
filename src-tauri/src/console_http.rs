// The webview's console calls, made by the host. The renderer's CSP connect-src names no console, so a
// self-hosted console at any origin works without widening it: src/api.js invokes `console_fetch`,
// and this module picks the origin, attaches the install token, and refuses everything else.
//
//   credentialed   origin = the console recorded host-side at enrolment (console_binding.rs). The
//                  renderer cannot name one. The install token is read from config.json here and
//                  sent as X-Install-Token; it never crosses the IPC boundary.
//   uncredentialed origin = the base the renderer names (enrolment against a console URL the user
//                  typed, signup, the default policy). No token, no cookies.
// Both: https, or http to localhost / 127.0.0.1 / [::1] only (normalize_origin); the request URL must
// keep exactly that origin; only the routes below; redirects are never followed; 4 s timeout.
use serde::Deserialize;
use serde_json::{json, Value};
use std::time::Duration;

pub const TIMEOUT: Duration = Duration::from_secs(4);

#[derive(Deserialize, Debug, Clone)]
pub struct ConsoleRequest {
    pub method: String,
    pub path: String,
    #[serde(default)]
    pub body: Option<Value>,
    #[serde(default)]
    pub credentialed: bool,
    #[serde(default)]
    pub base: Option<String>,
    // X-Client-Id, which the console stores with alerts and prompt events. Not a credential.
    #[serde(default, rename = "clientId")]
    pub client_id: Option<String>,
}

fn client_id_header(id: Option<&str>) -> Option<String> {
    id.filter(|v| !v.is_empty() && v.len() <= 64 && v.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')).map(String::from)
}

fn route_allowed(method: &str, path: &str, credentialed: bool) -> bool {
    match (credentialed, method) {
        (true, "GET") => path == "/api/policy",
        (true, "POST") => matches!(path, "/api/alerts" | "/api/prompt-event" | "/api/device-report" | "/api/agent-posture"),
        (false, "GET") => matches!(path, "/api/policy" | "/api/signup/claim" | "/api/health")
            || (path.starts_with("/d/") && path.len() > 3 && !path[3..].contains('/')),
        (false, "POST") => path == "/api/signup",
        _ => false,
    }
}

// → the URL to call and the token to attach, or why the call is refused. Nothing is sent on Err.
pub fn target(req: &ConsoleRequest, dir: &str, cfg: &Value) -> Result<(url::Url, Option<String>), String> {
    let method = req.method.to_ascii_uppercase();
    if !req.path.starts_with('/') || req.path.starts_with("//") || req.path.contains('\\') || req.path.contains('#') || req.path.chars().any(|c| c.is_control() || c == ' ') {
        return Err(format!("refused console path {:?}", req.path));
    }
    let (origin, token) = if req.credentialed {
        let token = cfg.get("installToken").and_then(|v| v.as_str()).filter(|t| !t.is_empty()).ok_or("this device is not enrolled")?;
        let r = crate::console_binding::resolve(dir, cfg);
        let origin = r.origin.ok_or_else(|| r.warning.unwrap_or_else(|| "no console is recorded for this device".into()))?;
        (origin, Some(token.to_string()))
    } else {
        let base = req.base.as_deref().ok_or("no console named")?;
        (crate::console_binding::normalize_origin(base)?, None)
    };
    let url = url::Url::parse(&format!("{origin}{}", req.path)).map_err(|e| e.to_string())?;
    if url.origin().ascii_serialization() != origin {
        return Err(format!("refused: {} leaves the console origin {origin}", req.path));
    }
    if !route_allowed(&method, url.path(), req.credentialed) {
        return Err(format!("refused console route {method} {}", url.path()));
    }
    Ok((url, token))
}

pub async fn send(method: &str, url: url::Url, body: Option<Value>, token: Option<String>, client_id: Option<String>, timeout: Duration) -> Result<Value, String> {
    let client = reqwest::Client::builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| e.to_string())?;
    let mut rq = if method.eq_ignore_ascii_case("POST") { client.post(url) } else { client.get(url) };
    if let Some(t) = token { rq = rq.header("X-Install-Token", t); }
    if let Some(c) = client_id { rq = rq.header("X-Client-Id", c); }
    if let Some(b) = body { rq = rq.json(&b); }
    let r = rq.send().await.map_err(|e| e.to_string())?;
    let status = r.status().as_u16();
    let text = r.text().await.unwrap_or_default();
    Ok(json!({ "status": status, "body": serde_json::from_str::<Value>(&text).unwrap_or(Value::Null) }))
}

// → { status, body }. A non-2xx answer (and an unfollowed 3xx) is a status, not an error; a refused
// call or a network failure / timeout is an error.
#[tauri::command]
pub async fn console_fetch(req: ConsoleRequest) -> Result<Value, String> {
    let (url, token) = target(&req, &crate::console_binding::host_dir(), &crate::read_config())?;
    send(&req.method, url, req.body, token, client_id_header(req.client_id.as_deref()), TIMEOUT).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    fn scratch(tag: &str) -> String {
        let n = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let d = std::env::temp_dir().join(format!("moorai-chttp-{tag}-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d.to_string_lossy().into_owned()
    }
    fn rq(method: &str, path: &str, credentialed: bool, base: Option<&str>) -> ConsoleRequest {
        ConsoleRequest { method: method.into(), path: path.into(), body: None, credentialed, base: base.map(String::from), client_id: None }
    }
    fn bound(origin: &str) -> String {
        let dir = scratch("bound");
        crate::console_binding::write_binding(&dir, origin, "enrolment").unwrap();
        dir
    }

    // Loopback server: records "METHOD path token body" per request and answers with `respond`.
    struct Srv { origin: String, seen: Arc<Mutex<Vec<String>>> }
    fn serve(respond: impl Fn() -> Option<String> + Send + 'static) -> Srv {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin = format!("http://127.0.0.1:{}", l.local_addr().unwrap().port());
        let seen = Arc::new(Mutex::new(vec![]));
        let s2 = seen.clone();
        std::thread::spawn(move || {
            for stream in l.incoming().flatten() {
                let mut r = BufReader::new(stream.try_clone().unwrap());
                let mut first = String::new();
                r.read_line(&mut first).unwrap_or(0);
                let (mut tok, mut len) = ("<none>".to_string(), 0usize);
                let mut line = String::new();
                while r.read_line(&mut line).map(|n| n > 0).unwrap_or(false) {
                    let t = line.trim_end().to_string();
                    if t.is_empty() { break; }
                    if let Some((k, v)) = t.split_once(':') {
                        if k.eq_ignore_ascii_case("x-install-token") { tok = v.trim().to_string(); }
                        if k.eq_ignore_ascii_case("content-length") { len = v.trim().parse().unwrap_or(0); }
                    }
                    line.clear();
                }
                let mut body = vec![0u8; len];
                let _ = r.read_exact(&mut body);
                let req: Vec<&str> = first.split_whitespace().take(2).collect();
                s2.lock().unwrap().push(format!("{} {} {}", req.join(" "), tok, String::from_utf8_lossy(&body)));
                match respond() {
                    Some(resp) => { let _ = (&stream).write_all(resp.as_bytes()); }
                    None => { std::thread::sleep(Duration::from_secs(30)); }
                }
            }
        });
        Srv { origin, seen }
    }
    fn ok(body: &'static str) -> impl Fn() -> Option<String> { move || Some(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())) }
    fn run<F: std::future::Future>(f: F) -> F::Output { tauri::async_runtime::block_on(f) }

    #[test]
    fn https_only_plain_http_is_for_localhost() {
        let dir = scratch("https");
        for base in ["http://console.acme.example", "ftp://console.acme.example", "file:///etc/passwd", "javascript:alert(1)", "console.acme.example", "https://user:pw@console.acme.example"] {
            assert!(target(&rq("GET", "/d/tok", false, Some(base)), &dir, &json!({})).is_err(), "{base}");
        }
        for (base, want) in [("https://console.acme.example:8443/ignored?x", "https://console.acme.example:8443/d/tok"), ("http://127.0.0.1:8788", "http://127.0.0.1:8788/d/tok"), ("http://localhost:8787", "http://localhost:8787/d/tok")] {
            assert_eq!(target(&rq("GET", "/d/tok", false, Some(base)), &dir, &json!({})).unwrap().0.as_str(), want);
        }
    }

    #[test]
    fn origin_only_a_path_cannot_move_the_request_elsewhere() {
        let dir = bound("https://console.good.test");
        let cfg = json!({ "installToken": "tok-SECRET-INSTALL" });
        for path in [".evil.test/api/policy", "@evil.test/api/policy", "//evil.test/api/policy", ":443@evil.test/api/policy", "\\\\evil.test/api/policy", "/api/policy#@evil.test", "/api/../admin/api/users", "/api/admin/users", "/download/app.tar.gz", "/d/a/b"] {
            assert!(target(&rq("GET", path, true, None), &dir, &cfg).is_err(), "credentialed {path}");
            assert!(target(&rq("GET", path, false, Some("https://console.good.test")), &dir, &json!({})).is_err(), "uncredentialed {path}");
        }
        assert!(target(&rq("DELETE", "/api/policy", true, None), &dir, &cfg).is_err());
        assert!(target(&rq("POST", "/api/signup", true, None), &dir, &cfg).is_err(), "the token never rides signup");
        let (u, t) = target(&rq("GET", "/api/policy?tenant=acme&user=u", true, None), &dir, &cfg).unwrap();
        assert_eq!(u.as_str(), "https://console.good.test/api/policy?tenant=acme&user=u");
        assert_eq!(t.as_deref(), Some("tok-SECRET-INSTALL"));
    }

    #[test]
    fn credentialed_calls_go_to_the_recorded_console_only() {
        let dir = bound("https://console.good.test");
        // the agent rewrote config.json, and the renderer names a base: neither moves the token
        let cfg = json!({ "installToken": "tok-SECRET-INSTALL", "serverUrl": "https://collector.evil.test" });
        let (u, t) = target(&rq("POST", "/api/alerts", true, Some("https://collector.evil.test")), &dir, &cfg).unwrap();
        assert_eq!(u.origin().ascii_serialization(), "https://console.good.test");
        assert_eq!(t.as_deref(), Some("tok-SECRET-INSTALL"));
        assert!(target(&rq("POST", "/api/alerts", true, None), &scratch("none"), &json!({ "installToken": "t", "serverUrl": "http://collector.evil.test" })).is_err(), "no usable console, no call");
        assert!(target(&rq("POST", "/api/alerts", true, None), &dir, &json!({})).is_err(), "not enrolled, no credentialed call");
        let (_, t2) = target(&rq("GET", "/api/policy", false, Some("https://console.good.test")), &dir, &cfg).unwrap();
        assert_eq!(t2, None, "uncredentialed calls carry no token");
    }

    #[test]
    fn the_token_reaches_the_console_and_redirects_are_not_followed() {
        let evil = serve(ok(r#"{"allowedTools":["codex"]}"#));
        let target_url = format!("{}/api/policy", evil.origin);
        let good = serve(move || Some(format!("HTTP/1.1 302 Found\r\nLocation: {target_url}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")));
        let dir = bound(&good.origin);
        let cfg = json!({ "installToken": "tok-SECRET-INSTALL" });
        let (u, t) = target(&rq("GET", "/api/policy", true, None), &dir, &cfg).unwrap();
        let r = run(send("GET", u, None, t, None, TIMEOUT)).unwrap();
        assert_eq!(r["status"], 302, "{r}");
        assert_eq!(good.seen.lock().unwrap().len(), 1);
        assert!(good.seen.lock().unwrap()[0].contains("tok-SECRET-INSTALL"));
        assert!(evil.seen.lock().unwrap().is_empty(), "redirect followed: {:?}", evil.seen.lock().unwrap());

        let console = serve(ok(r#"{"ok":true}"#));
        let dir2 = bound(&console.origin);
        let (u, t) = target(&ConsoleRequest { body: Some(json!({ "outcome": "sent" })), ..rq("POST", "/api/prompt-event", true, None) }, &dir2, &cfg).unwrap();
        let r = run(send("POST", u, Some(json!({ "outcome": "sent" })), t, None, TIMEOUT)).unwrap();
        assert_eq!(r, json!({ "status": 200, "body": { "ok": true } }));
        assert_eq!(console.seen.lock().unwrap()[0], r#"POST /api/prompt-event tok-SECRET-INSTALL {"outcome":"sent"}"#);
    }

    #[test]
    fn the_client_id_header_is_a_plain_id_or_nothing() {
        assert_eq!(client_id_header(Some("c-1a2b3c")).as_deref(), Some("c-1a2b3c"));
        for bad in ["", "c-1\r\nX-Install-Token: x", "c 1", &"a".repeat(65)] { assert_eq!(client_id_header(Some(bad)), None, "{bad:?}"); }
        assert_eq!(client_id_header(None), None);
    }

    #[test]
    fn a_console_that_never_answers_times_out_at_four_seconds() {
        let hang = serve(|| None);
        let (u, _) = target(&rq("GET", "/api/health", false, Some(&hang.origin)), &scratch("t"), &json!({})).unwrap();
        let t0 = std::time::Instant::now();
        let r = run(send("GET", u, None, None, None, TIMEOUT));
        let took = t0.elapsed();
        assert!(r.is_err(), "{r:?}");
        assert!(took >= Duration::from_millis(3900) && took < Duration::from_secs(8), "took {took:?}");
    }
}
