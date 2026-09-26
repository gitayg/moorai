// AI-provider API keys AT REST — the Rust host's mirror of cli/aibom-keys.mjs, so the console's device
// inventory gets the same signal the CLI AIBOM has. Read that file for the rationale; the contract is
// identical and test/aibom-rust-parity.test.mjs pins the tables below to the JS ones:
//   * a SMALL, FIXED set of places (SHELL_RC, AI_CLI_DIRS depth <= 2 / <= 25 files per dir, top-level
//     .env of ~ and of each immediate child of DEV_ROOTS, <= 200 children per root, <= 300 dotenvs);
//   * every file skipped when > 1 MB or when its first 8 KB hold a NUL; unreadable → skipped;
//   * output per finding is exactly { provider, locationClass, location, keyHash } — location only for a
//     fixed well-known path, null for a project .env; keyHash = the keyed per-tenant HMAC
//     (content_hash.rs, byte-identical to cli/content-hash.mjs). The key and the file never leave here.
use regex::Regex;
use serde::Serialize;
use std::collections::HashSet;
use std::fs;
use std::io::Read;
use std::sync::OnceLock;

pub const MAX_FILE_BYTES: u64 = 1024 * 1024;
pub const MAX_CLI_FILES_PER_DIR: usize = 25;
pub const MAX_DEV_CHILDREN: usize = 200;
pub const MAX_DOTENV_FILES: usize = 300;

pub const SHELL_RC: &[&str] = &[".zshrc", ".zshenv", ".bashrc", ".bash_profile", ".profile", ".config/fish/config.fish"];
pub const AI_CLI_DIRS: &[(&str, &str)] = &[
    (".config/aichat", "aichat"),
    (".config/shell_gpt", "shell_gpt"),
    (".config/io.datasette.llm", "llm"),
    ("Library/Application Support/io.datasette.llm", "llm"),
    (".config/fabric", "fabric"),
    (".config/mods", "mods"),
    (".gemini", "gemini"),
];
pub const DEV_ROOTS: &[&str] = &["code", "src", "dev", "projects", "Projects", "workspace", "repos", "git", "Developer"];

// (provider, JS regex source WITHOUT the trailing END lookahead, needsAiContext). The sources are the
// JS ones character for character — test/aibom-rust-parity.test.mjs asserts `re.source === src + END`
// for every row of data/ai-key-shapes.js. Rust's regex has no lookahead, so END is applied by
// `compile` as a consumed `(?:[^A-Za-z0-9_-]|$)` after a capture group; that char can never begin the
// next key (every shape starts with a letter), so the match sequence equals JS's matchAll.
pub const AI_KEY_SHAPES: &[(&str, &str, bool)] = &[
    ("Anthropic", r"\bsk-ant-(?:api03|admin01)-[A-Za-z0-9_-]{93}AA", false),
    ("OpenAI", r"\bsk-(?:proj|svcacct|admin)-(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58})T3BlbkFJ(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58})", false),
    ("OpenAI", r"\bsk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}", false),
    ("Hugging Face", r"\bhf_[A-Za-z]{34}", false),
    ("Perplexity", r"\bpplx-[a-zA-Z0-9]{48}", false),
    ("Google", r"\bAIza[A-Za-z0-9_-]{35}", true),
];
// JS: /GEMINI|GOOGLE_(?:GENAI_|AI_)?API_KEY|GOOGLE_AI|GENAI|VERTEX|PALM/i (non-unicode /i = ASCII folding).
pub const GOOGLE_AI_NAME: &str = r"GEMINI|GOOGLE_(?:GENAI_|AI_)?API_KEY|GOOGLE_AI|GENAI|VERTEX|PALM";

struct Shapes { keys: Vec<(&'static str, Regex, bool)>, google_ai_name: Regex }

fn shapes() -> &'static Shapes {
    static S: OnceLock<Shapes> = OnceLock::new();
    S.get_or_init(|| Shapes {
        // JS \b is ASCII (\w = [A-Za-z0-9_]); Rust's default \b is Unicode, so pin it to ASCII.
        keys: AI_KEY_SHAPES.iter().map(|(p, src, ctx)| {
            let body = src.replace(r"\b", r"(?-u:\b)");
            (*p, Regex::new(&format!(r"({body})(?:[^A-Za-z0-9_-]|$)")).expect("key shape"), *ctx)
        }).collect(),
        google_ai_name: Regex::new(&format!("(?i-u:{GOOGLE_AI_NAME})")).expect("google ai name"),
    })
}

// → [(provider, value)] for one text; mirrors findAiKeys (line by line, Google gated on the same line).
pub fn find_ai_keys(text: &str, ai_context: bool) -> Vec<(&'static str, String)> {
    let s = shapes();
    let mut out = vec![];
    for line in text.split('\n') {
        for (provider, re, needs_ctx) in &s.keys {
            if *needs_ctx && !ai_context && !s.google_ai_name.is_match(line) { continue; }
            for c in re.captures_iter(line) {
                out.push((*provider, c[1].to_string()));
            }
        }
    }
    out
}

#[derive(Serialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct KeyFinding {
    pub provider: String,
    pub location_class: String,
    pub location: Option<String>,
    pub key_hash: String,
}

// Bounded, binary-safe read (readSmallText). None = skipped. metadata() follows symlinks, as statSync.
fn read_small_text(p: &str) -> Option<String> {
    let md = fs::metadata(p).ok()?;
    if !md.is_file() || md.len() > MAX_FILE_BYTES { return None; }
    let mut f = fs::File::open(p).ok()?;
    let mut buf = Vec::with_capacity(md.len() as usize);
    f.read_to_end(&mut buf).ok()?;
    let head = &buf[..buf.len().min(8192)];
    if head.contains(&0) { return None; }
    // readFileSync(p, "utf8") replaces invalid sequences with U+FFFD; so does from_utf8_lossy.
    Some(String::from_utf8_lossy(&buf).into_owned())
}

// readdirSync withFileTypes: names sorted bytewise (libuv's scandir sort), types NOT following symlinks.
fn list_dir(p: &str) -> Vec<(String, fs::FileType)> {
    let mut v: Vec<(String, fs::FileType)> = match fs::read_dir(p) {
        Ok(rd) => rd.flatten().filter_map(|e| Some((e.file_name().to_str()?.to_string(), e.file_type().ok()?))).collect(),
        Err(_) => vec![],
    };
    v.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    v
}

fn is_dotenv_name(n: &str) -> bool {
    let Some(rest) = n.strip_prefix(".env") else { return false };
    let name_ok = rest.is_empty()
        || rest.strip_prefix('.').is_some_and(|r| !r.is_empty() && r.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'));
    let lower = n.to_ascii_lowercase();
    name_ok && !["example", "sample", "template", "dist"].iter().any(|t| lower.contains(t))
}

pub fn scan_keys_at_rest(home: &str, hash: &dyn Fn(&str) -> String) -> Vec<KeyFinding> {
    let mut findings = vec![];
    let mut seen: HashSet<String> = HashSet::new();
    let mut scan = |path: &str, class: &str, location: Option<String>, ai_context: bool, findings: &mut Vec<KeyFinding>| {
        let Some(text) = read_small_text(path) else { return };
        for (provider, value) in find_ai_keys(&text, ai_context) {
            let key_hash = hash(&value);
            let k = format!("{provider}|{class}|{}|{key_hash}", location.as_deref().unwrap_or("null"));
            if !seen.insert(k) { continue; }
            findings.push(KeyFinding { provider: provider.into(), location_class: class.into(), location: location.clone(), key_hash });
        }
    };

    for rel in SHELL_RC {
        let p = format!("{home}/{rel}");
        if fs::metadata(&p).is_err() { continue; }
        scan(&p, "shell-rc", Some(format!("~/{rel}")), false, &mut findings);
    }

    // walk(dir, 1): files count toward the per-dir cap; only depth-1 subdirs are entered (depth <= 2).
    fn walk(d: &str, depth: u8, n: &mut usize, on_file: &mut dyn FnMut(&str)) {
        for (name, ft) in list_dir(d) {
            if *n >= MAX_CLI_FILES_PER_DIR { return; }
            let p = format!("{d}/{name}");
            if ft.is_file() { *n += 1; on_file(&p); }
            else if ft.is_dir() && depth < 2 { walk(&p, depth + 1, n, on_file); }
        }
    }
    for (rel, _tool) in AI_CLI_DIRS {
        let mut n = 0usize;
        walk(&format!("{home}/{rel}"), 1, &mut n, &mut |p| scan(p, "ai-cli-config", Some(format!("~/{rel}")), true, &mut findings));
    }

    let mut dotenvs = 0usize;
    let mut scan_dotenvs_in = |dir: &str, fixed_prefix: Option<&str>, dotenvs: &mut usize, findings: &mut Vec<KeyFinding>| {
        for (name, ft) in list_dir(dir) {
            if *dotenvs >= MAX_DOTENV_FILES { return; }
            if !ft.is_file() || !is_dotenv_name(&name) { continue; }
            *dotenvs += 1;
            scan(&format!("{dir}/{name}"), "dotenv", fixed_prefix.map(|p| format!("{p}{name}")), false, findings);
        }
    };
    scan_dotenvs_in(home, Some("~/"), &mut dotenvs, &mut findings);
    let mut roots: HashSet<std::path::PathBuf> = HashSet::new();
    for root in DEV_ROOTS {
        let root_dir = format!("{home}/{root}");
        let Ok(real) = fs::canonicalize(&root_dir) else { continue };
        if !roots.insert(real) { continue; }
        scan_dotenvs_in(&root_dir, None, &mut dotenvs, &mut findings);
        let mut children = 0usize;
        for (name, ft) in list_dir(&root_dir) {
            if !ft.is_dir() || name.starts_with('.') { continue; }
            children += 1;
            if children > MAX_DEV_CHILDREN || dotenvs >= MAX_DOTENV_FILES { break; }
            scan_dotenvs_in(&format!("{root_dir}/{name}"), None, &mut dotenvs, &mut findings);
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::content_hash::{derive_key, hash_with_key, NO_KEY};

    const TOKEN: &str = "test-install-token-rust-keys";
    fn fill(n: usize, seed: &str) -> String { seed.repeat(n / seed.len() + 1)[..n].to_string() }
    // Obviously fake values that still satisfy the shapes; built at runtime so no literal key is in the tree.
    fn keys() -> Vec<(&'static str, String)> {
        vec![
            ("anthropic", format!("sk-ant-api03-{}AA", fill(93, "FAKEtestKEY0"))),
            ("openai", format!("sk-proj-{}T3BlbkFJ{}", fill(74, "FAKEtestOpenAI0"), fill(74, "TESTfakeKEY9"))),
            ("googleCli", format!("AIza{}", fill(35, "FAKEtestGemini1"))),
            ("googleDotenv", format!("AIza{}", fill(35, "FAKEtestGemini2"))),
            ("hf", format!("hf_{}", fill(34, "fakehuggingfacetest"))),
            ("pplx", format!("pplx-{}", fill(48, "FAKEtestPplx0"))),
            ("maps", format!("AIza{}", fill(35, "FAKEtestMapsKey"))),
            ("big", format!("sk-ant-api03-{}AA", fill(93, "FAKEbigFILE00"))),
            ("bin", format!("sk-ant-api03-{}AA", fill(93, "FAKEbinFILE00"))),
            ("deep", format!("sk-ant-api03-{}AA", fill(93, "FAKEdeepDIR00"))),
            ("example", format!("sk-ant-api03-{}AA", fill(93, "FAKEexample00"))),
            ("symlinked", format!("sk-ant-api03-{}AA", fill(93, "FAKEsymlink00"))),
            ("unreadable", format!("sk-ant-api03-{}AA", fill(93, "FAKEunread000"))),
        ]
    }
    fn k(name: &str) -> String { keys().into_iter().find(|(n, _)| *n == name).unwrap().1 }
    const SENTINELS: &[&str] = &["SENTINEL_RC_CONTENT", "SENTINEL_ENV_CONTENT", "SENTINEL_CLI_CONTENT"];

    struct TempHome(std::path::PathBuf);
    impl Drop for TempHome { fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); } }
    // (remove_dir_all unlinks the mode-000 .bashrc fine: deleting needs write on the DIRECTORY only)
    fn seed_home() -> TempHome {
        let dir = std::env::temp_dir().join(format!("moorai-rs-keys-{}-{}", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        let w = |rel: &str, body: &[u8]| { let p = dir.join(rel); fs::create_dir_all(p.parent().unwrap()).unwrap(); fs::write(p, body).unwrap(); };
        w(".zshrc", format!("alias ll='ls -la' # SENTINEL_RC_CONTENT\nexport ANTHROPIC_API_KEY=\"{}\"\n", k("anthropic")).as_bytes());
        w(".config/fish/config.fish", format!("set -gx OPENAI_API_KEY {}\n", k("openai")).as_bytes());
        w(".config/aichat/config.yaml", format!("# SENTINEL_CLI_CONTENT\nclients:\n  - type: gemini\n    api_key: {}\n", k("googleCli")).as_bytes());
        w(".env", format!("GEMINI_API_KEY={}\r\n", k("googleDotenv")).as_bytes());
        w("code/myproj/.env", format!("HF_TOKEN={}\nPPLX_KEY='{}'\nDB_HOST=SENTINEL_ENV_CONTENT\n", k("hf"), k("pplx")).as_bytes());
        w("code/maps/.env", format!("MAPS_API_KEY={}\n", k("maps")).as_bytes());
        w("code/big/.env", format!("ANTHROPIC_API_KEY={}\n{}", k("big"), "#".repeat(1024 * 1024 + 10)).as_bytes());
        #[cfg(unix)] // mode 000 = unreadable → skipped (fail-open); Windows has no equivalent here
        {
            use std::os::unix::fs::PermissionsExt;
            w(".bashrc", format!("export ANTHROPIC_API_KEY={}\n", k("unreadable")).as_bytes());
            fs::set_permissions(dir.join(".bashrc"), fs::Permissions::from_mode(0o000)).unwrap();
        }
        let mut bin = format!("K={}\n", k("bin")).into_bytes(); bin.extend_from_slice(&[0, 1, 2, 0]);
        w("code/bin/.env", &bin);
        w("code/a/b/.env", format!("ANTHROPIC_API_KEY={}\n", k("deep")).as_bytes());
        w("code/myproj/.env.example", format!("ANTHROPIC_API_KEY={}\n", k("example")).as_bytes());
        // a symlinked DIRECTORY under an AI CLI dir is not followed (Dirent.isDirectory() is false for it)
        w("elsewhere/secrets.yaml", format!("key: {}\n", k("symlinked")).as_bytes());
        #[cfg(unix)]
        std::os::unix::fs::symlink(dir.join("elsewhere"), dir.join(".config/aichat/linked")).unwrap();
        TempHome(dir)
    }

    fn assert_no_leak(out: &str) {
        for (name, key) in keys() {
            assert!(!out.contains(&key), "raw {name} key leaked");
            let body = ["sk-ant-api03-", "sk-proj-", "AIza", "hf_", "pplx-"].iter().fold(key.clone(), |acc, p| acc.strip_prefix(p).map(str::to_string).unwrap_or(acc));
            assert!(!out.contains(&body[..8]), "{name} key prefix leaked");
            assert!(!out.contains(&key[key.len() - 10..]), "{name} key suffix leaked");
        }
        for s in SENTINELS { assert!(!out.contains(s), "file content {s} leaked"); }
    }

    #[test]
    fn shape_table_classifies_each_fake_key_and_gates_google() {
        let p = |t: &str, ctx: bool| find_ai_keys(t, ctx).into_iter().map(|(p, _)| p).collect::<Vec<_>>();
        assert_eq!(p(&format!("X={}", k("anthropic")), false), ["Anthropic"]);
        assert_eq!(p(&format!("X={}", k("openai")), false), ["OpenAI"]);
        assert_eq!(p(&format!("HF_TOKEN={}", k("hf")), false), ["Hugging Face"]);
        assert_eq!(p(&format!("P={}", k("pplx")), false), ["Perplexity"]);
        assert_eq!(p(&format!("GEMINI_API_KEY={}", k("googleDotenv")), false), ["Google"]);
        assert_eq!(p(&format!("gemini_api_key={}", k("googleDotenv")), false), ["Google"], "variable gate is case-insensitive");
        assert!(p(&format!("MAPS_API_KEY={}", k("maps")), false).is_empty(), "a bare Google API key is not an AI key");
        assert_eq!(p(&format!("api_key: {}", k("maps")), true), ["Google"]);
        assert!(p("sk-ant-api03-short", false).is_empty());
        // END / \b edges: a trailing or leading word char voids the match, a separator does not
        assert!(p(&format!("{}x", k("anthropic")), false).is_empty());
        assert!(p(&format!("a{}", k("anthropic")), false).is_empty());
        assert_eq!(p(&format!("-{0},{0}", k("anthropic")), false), ["Anthropic", "Anthropic"]);
        let o58 = format!("sk-admin-{}T3BlbkFJ{}", fill(58, "FAKEfiftyeight"), fill(58, "EIGHTYfake"));
        assert_eq!(find_ai_keys(&o58, false), vec![("OpenAI", o58.clone())]);
    }

    #[test]
    fn scan_reports_provider_class_and_keyed_hash_only() {
        let h = seed_home();
        let home = h.0.to_str().unwrap();
        let key = derive_key(TOKEN);
        let hash = |s: &str| hash_with_key(key.as_ref(), s);
        let f = scan_keys_at_rest(home, &hash);
        let json = serde_json::to_string(&f).unwrap();
        assert_no_leak(&json); // the load-bearing negative first: no key, key fragment or file content
        let has = |prov: &str, class: &str, loc: Option<&str>, name: &str| f.iter().any(|x|
            x.provider == prov && x.location_class == class && x.location.as_deref() == loc && x.key_hash == hash(&k(name)));
        assert!(has("Anthropic", "shell-rc", Some("~/.zshrc"), "anthropic"));
        assert!(has("OpenAI", "shell-rc", Some("~/.config/fish/config.fish"), "openai"));
        assert!(has("Google", "ai-cli-config", Some("~/.config/aichat"), "googleCli"));
        assert!(has("Google", "dotenv", Some("~/.env"), "googleDotenv"));
        assert!(has("Hugging Face", "dotenv", None, "hf"), "project .env — no path");
        assert!(has("Perplexity", "dotenv", None, "pplx"));
        assert_eq!(f.len(), 6, "exactly the six in-scope keys: {f:?}");
        for name in ["maps", "big", "bin", "deep", "example", "symlinked", "unreadable"] {
            assert!(!f.iter().any(|x| x.key_hash == hash(&k(name))), "{name} key must not be reported");
        }
        for x in &f { assert!(x.key_hash.starts_with("h2:") && x.key_hash.len() == 19); }
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let mut ks: Vec<_> = v[0].as_object().unwrap().keys().cloned().collect(); ks.sort();
        assert_eq!(ks, ["keyHash", "location", "locationClass", "provider"]);
        assert!(json.contains("\"location\":null"));
    }

    #[test]
    fn unenrolled_device_hashes_every_key_to_no_key() {
        let h = seed_home();
        let f = scan_keys_at_rest(h.0.to_str().unwrap(), &|s| hash_with_key(derive_key("").as_ref(), s));
        assert!(!f.is_empty());
        assert!(f.iter().all(|x| x.key_hash == NO_KEY));
        assert_no_leak(&serde_json::to_string(&f).unwrap());
    }

    #[test]
    fn missing_home_is_empty_not_a_panic() {
        assert!(scan_keys_at_rest("/nonexistent/moorai-home", &|s| s.len().to_string()).is_empty());
    }

    #[test]
    fn dotenv_names() {
        for n in [".env", ".env.local", ".env.prod-2"] { assert!(is_dotenv_name(n), "{n}"); }
        for n in [".env.example", ".env.Sample", ".env.dist", ".envrc", ".env.", ".env.a.b", "x.env"] { assert!(!is_dotenv_name(n), "{n}"); }
    }
    // End to end through the real Tauri command the renderer invokes for the device report
    // (src/api.js → invoke("device_ai_assets") → POST /api/device-report as `aiAssets`).
    #[test]
    fn device_report_carries_the_three_new_fields_and_never_the_key() {
        let h = seed_home();
        let home = h.0.to_str().unwrap().to_string();
        fs::create_dir_all(h.0.join(".moorai")).unwrap();
        fs::write(h.0.join(".moorai/config.json"), format!(r#"{{"tenant":"t","installToken":"{TOKEN}"}}"#)).unwrap();
        fs::write(h.0.join(".claude.json"), r#"{"mcpServers":{"local-http":{"type":"http","url":"http://localhost:3333/mcp?token=SECRETMCPTOKEN"}}}"#).unwrap();
        let var = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
        let prev = std::env::var(var).ok();
        std::env::set_var(var, &home);
        let report = crate::device_ai_assets();
        match prev { Some(v) => std::env::set_var(var, v), None => std::env::remove_var(var) }
        let json = serde_json::to_string(&report).unwrap();
        let keys = report["apiKeysAtRest"].as_array().expect("apiKeysAtRest array");
        assert_eq!(keys.len(), 6, "{json}");
        let want = hash_with_key(derive_key(TOKEN).as_ref(), &k("anthropic"));
        assert!(keys.iter().any(|x| x["provider"] == "Anthropic" && x["locationClass"] == "shell-rc" && x["location"] == "~/.zshrc" && x["keyHash"] == want.as_str()), "{json}");
        assert!(report["localRuntimes"].is_array(), "localRuntimes array");
        let mcp = report["localMcpListeners"].as_array().expect("localMcpListeners array");
        assert_eq!(mcp[0]["name"], "local-http");
        assert_eq!(mcp[0]["port"], 3333);
        assert!(report["providers"].is_array() && report["localModels"].is_array(), "existing fields kept");
        assert_no_leak(&json);
        assert!(!json.contains("SECRETMCPTOKEN"));
    }
    #[test]
    fn shared_fixture_cases_match_node() {
        let fx: serde_json::Value = serde_json::from_str(include_str!("../../test/fixtures/ai-key-shapes-parity.json")).unwrap();
        let key = |name: &str| {
            let spec = &fx["keys"][name];
            let mut k = format!("{}{}{}", spec[0].as_str().unwrap(), fill(spec[1].as_u64().unwrap() as usize, spec[2].as_str().unwrap()), spec[3].as_str().unwrap());
            if let Some(t) = fx["suffixes"].get(name) { k += &format!("{}{}", t[0].as_str().unwrap(), fill(t[1].as_u64().unwrap() as usize, t[2].as_str().unwrap())); }
            k
        };
        let names: Vec<String> = fx["keys"].as_object().unwrap().keys().cloned().collect();
        let cases = fx["cases"].as_array().unwrap();
        assert!(cases.len() >= 15);
        for c in cases {
            let mut text = c["text"].as_str().unwrap().to_string();
            for n in &names { text = text.replace(&format!("{{{n}}}"), &key(n)); }
            let got: Vec<(String, String)> = find_ai_keys(&text, c["ctx"].as_bool().unwrap()).into_iter().map(|(p, v)| (p.to_string(), v)).collect();
            let want: Vec<(String, String)> = c["expect"].as_array().unwrap().iter()
                .map(|e| (e[0].as_str().unwrap().to_string(), key(e[1].as_str().unwrap()))).collect();
            assert_eq!(got, want, "case {}", c["text"]);
        }
    }
}
