// Local models whose NAME says their safety training was removed: the Rust mirror of
// cli/local-model-names.mjs, so the desktop host sends the console the same content-free
// `localModelSafety` block the Node AIBOM carries. Model names are read in memory only, from the same
// places (Ollama manifests + GET 127.0.0.1:11434/api/tags, LM Studio, Jan, GPT4All, the llama.cpp cache
// and the Hugging Face hub cache), split into words the same way and matched against the same tokens.
// The record holds runtime ids, counts and booleans; a name, path, org, tag or digest never leaves here.
// A name says nothing about the weights: this neither proves nor disproves a backdoor.
//
// Parity is pinned two ways: test/aibom-rust-parity.test.mjs reads the tables below and compares them
// with the JS module, and the tests at the bottom replay test/fixtures/local-ai/model-names.json, whose
// expectations are the JS module's outputs. The bounds match too: one deadline for the whole collection,
// the same entry caps (counted per read, including the end-of-directory read), a total (not idle)
// timeout plus byte and model caps on /api/tags. The probe host is fixed; OLLAMA_HOST is not followed.
use serde::Serialize;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

pub const SAFETY_REMOVED_TOKENS: &[&str] = &["abliterated", "obliterated", "uncensored", "decensored", "unaligned", "jailbroken", "heretic"];
pub const MODEL_SOURCES: &[&str] = &["ollama", "lmstudio", "jan", "gpt4all", "llama.cpp", "huggingface"];
pub const DEADLINE_MS: i64 = 2000;
pub const MAX_ENTRIES: usize = 5000;
pub const MAX_PER_DIR: usize = 1000;
pub const HTTP_TIMEOUT_MS: i64 = 1000;
pub const HTTP_MAX_BYTES: usize = 1024 * 1024;
pub const HTTP_MAX_MODELS: usize = 1000;
pub const MAX_NAME_LENGTH: usize = 256;
pub const OLLAMA_PORT: u16 = 11434;
// Node's default --max-http-header-size; a longer response head is refused, as Node refuses it.
const MAX_HEADER_BYTES: usize = 16 * 1024;

// JS measures `name.length` in UTF-16 code units, so an emoji counts twice.
fn utf16_len(s: &str) -> usize { s.encode_utf16().count() }

// Words of a name, as JS nameWords: a break at a lower→upper change, after an acronym ("LMUncensored" →
// LM Uncensored) and at a letter↔digit change (all ASCII-only, like the JS regexes), then Unicode
// lower-casing and a split at every character that is not [a-z0-9]. Each rule looks at adjacent
// characters of the original name, so one pass gives what the four JS replace() passes give.
pub fn name_words(name: &str) -> Vec<String> {
    if name.is_empty() || utf16_len(name) > MAX_NAME_LENGTH { return vec![]; }
    let cs: Vec<char> = name.chars().collect();
    let lo = |c: char| c.is_ascii_lowercase();
    let up = |c: char| c.is_ascii_uppercase();
    let dg = |c: char| c.is_ascii_digit();
    let al = |c: char| c.is_ascii_alphabetic();
    let mut spaced = String::with_capacity(name.len() * 2);
    for (i, &c) in cs.iter().enumerate() {
        spaced.push(c);
        let Some(&n) = cs.get(i + 1) else { continue };
        let acronym = up(c) && up(n) && cs.get(i + 2).is_some_and(|&x| lo(x));
        if (lo(c) && up(n)) || acronym || (al(c) && dg(n)) || (dg(c) && al(n)) { spaced.push(' '); }
    }
    spaced.to_lowercase().split(|c: char| !(c.is_ascii_lowercase() || c.is_ascii_digit())).filter(|w| !w.is_empty()).map(str::to_string).collect()
}

pub fn safety_removed_by_name(name: &str) -> bool {
    name_words(name).iter().any(|w| SAFETY_REMOVED_TOKENS.contains(&w.as_str()))
}

// Node's path.join for this host: the directories, and so the dedupe below, are the ones the JS walks.
#[cfg(not(windows))]
pub fn join(parts: &[&str]) -> String {
    let joined = parts.iter().filter(|p| !p.is_empty()).copied().collect::<Vec<_>>().join("/");
    if joined.is_empty() { return ".".into(); }
    let abs = joined.starts_with('/');
    let tail = normalize_segments(&joined, '/', abs, |c| c == '/');
    if tail.is_empty() { return if abs { "/".into() } else if joined.ends_with('/') { "./".into() } else { ".".into() }; }
    let trail = if joined.ends_with('/') { "/" } else { "" };
    format!("{}{tail}{trail}", if abs { "/" } else { "" })
}

// path.win32.join, for the shapes these roots take: a drive ("C:\" or "C:"), a UNC share or a rooted path.
#[cfg(windows)]
pub fn join(parts: &[&str]) -> String {
    let joined = parts.iter().filter(|p| !p.is_empty()).copied().collect::<Vec<_>>().join("\\").replace('/', "\\");
    if joined.is_empty() { return ".".into(); }
    let b = joined.as_bytes();
    let (device, rest) = if b.len() >= 2 && b[1] == b':' && b[0].is_ascii_alphabetic() {
        joined.split_at(2)
    } else if joined.starts_with("\\\\") && !joined.starts_with("\\\\\\") {
        let mut it = joined[2..].splitn(3, '\\');
        let (server, share) = (it.next().unwrap_or(""), it.next().unwrap_or(""));
        if server.is_empty() || share.is_empty() { ("", joined.as_str()) } else { joined.split_at(2 + server.len() + 1 + share.len()) }
    } else { ("", joined.as_str()) };
    let abs = rest.starts_with('\\') || (device.starts_with("\\\\") && !device.is_empty());
    let tail = normalize_segments(rest, '\\', abs, |c| c == '\\');
    let trail = if !tail.is_empty() && joined.ends_with('\\') { "\\" } else { "" };
    let tail = if tail.is_empty() && !abs { ".".to_string() } else { tail };
    format!("{device}{}{tail}{trail}", if abs { "\\" } else { "" })
}

// Node's normalizeString: drop "" and ".", let ".." pop a segment, keep a leading ".." only when relative.
fn normalize_segments(p: &str, sep: char, abs: bool, is_sep: impl Fn(char) -> bool) -> String {
    let mut st: Vec<&str> = vec![];
    for seg in p.split(is_sep) {
        match seg {
            "" | "." => {}
            ".." => { if st.last().is_some_and(|l| *l != "..") { st.pop(); } else if !abs { st.push(".."); } }
            s => st.push(s),
        }
    }
    st.join(&sep.to_string())
}

// How a directory is laid out, the JS WALKS keys.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Kind { OllamaManifests, PublisherRepo, ModelFiles, FilesAndHf, HfCache }

#[cfg(test)]
impl Kind {
    pub fn as_str(self) -> &'static str {
        match self { Kind::OllamaManifests => "ollama-manifests", Kind::PublisherRepo => "publisher-repo", Kind::ModelFiles => "model-files", Kind::FilesAndHf => "files-and-hf", Kind::HfCache => "hf-cache" }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ModelDir { pub runtime: &'static str, pub kind: Kind, pub dir: String }

// The JS modelDirs, in the same order with the same dedupe. An empty env value counts as unset (JS `||`).
pub fn model_dirs(platform: &str, env: &dyn Fn(&str) -> Option<String>, home: &str) -> Vec<ModelDir> {
    let (win, mac) = (platform == "win32", platform == "darwin");
    let e = |k: &str| env(k).filter(|v| !v.is_empty());
    let local_app_data = e("LOCALAPPDATA").unwrap_or_else(|| join(&[home, "AppData", "Local"]));
    let app_data = e("APPDATA").unwrap_or_else(|| join(&[home, "AppData", "Roaming"]));
    let xdg_cache = e("XDG_CACHE_HOME").unwrap_or_else(|| join(&[home, ".cache"]));
    let mut out: Vec<ModelDir> = vec![];
    let mut add = |runtime: &'static str, kind: Kind, dir: String| {
        if !dir.is_empty() && !out.iter().any(|d| d.runtime == runtime && d.dir == dir) { out.push(ModelDir { runtime, kind, dir }); }
    };
    let linux_ollama = (!win && !mac).then(|| "/usr/share/ollama/.ollama/models".to_string());
    for m in [e("OLLAMA_MODELS"), Some(join(&[home, ".ollama", "models"])), linux_ollama].into_iter().flatten() {
        add("ollama", Kind::OllamaManifests, join(&[&m, "manifests"]));
    }
    add("lmstudio", Kind::PublisherRepo, join(&[home, ".lmstudio", "models"]));
    add("lmstudio", Kind::PublisherRepo, join(&[home, ".cache", "lm-studio", "models"]));
    let jan = if win { join(&[&app_data, "Jan", "data"]) } else if mac { join(&[home, "Library", "Application Support", "Jan", "data"]) } else { join(&[home, ".local", "share", "Jan", "data"]) };
    add("jan", Kind::PublisherRepo, join(&[&jan, "llamacpp", "models"]));
    add("jan", Kind::PublisherRepo, join(&[&jan, "mlx", "models"]));
    add("gpt4all", Kind::ModelFiles, if win { join(&[&local_app_data, "nomic.ai", "GPT4All"]) } else if mac { join(&[home, "Library", "Application Support", "nomic.ai", "GPT4All"]) } else { join(&[home, ".local", "share", "nomic.ai", "GPT4All"]) });
    add("llama.cpp", Kind::FilesAndHf, e("LLAMA_CACHE").unwrap_or_else(|| if win { join(&[&local_app_data, "llama.cpp"]) } else if mac { join(&[home, "Library", "Caches", "llama.cpp"]) } else { join(&[&xdg_cache, "llama.cpp"]) }));
    add("huggingface", Kind::HfCache, e("HF_HUB_CACHE").unwrap_or_else(|| match e("HF_HOME") { Some(h) => join(&[&h, "hub"]), None => join(&[&xdg_cache, "huggingface", "hub"]) }));
    out
}

// JS /\.(gguf|llamafile)$/i: ASCII case only, end of the name.
fn is_model_file(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.ends_with(".gguf") || n.ends_with(".llamafile")
}

// JS /^models--(.+)$/ (`.` stops at a line terminator), then "--" → "/".
fn hf_repo(entry: &str) -> Option<String> {
    let rest = entry.strip_prefix("models--")?;
    if rest.is_empty() || rest.contains(['\n', '\r', '\u{2028}', '\u{2029}']) { return None; }
    Some(rest.replace("--", "/"))
}

// The directory seam (fs.opendirSync's Dir in JS). read(): Ok(Some) an entry, Ok(None) the end, Err a
// read that failed mid-directory. `dir` is "a directory or a symlink", as the JS Dirent test.
pub struct Entry { pub name: String, pub dir: bool }
pub trait DirRead { fn read(&mut self) -> Result<Option<Entry>, ()>; }
pub trait ModelFs { fn opendir(&self, dir: &str) -> Option<Box<dyn DirRead + '_>>; }

pub struct RealFs;
struct RealDir(std::fs::ReadDir);
impl DirRead for RealDir {
    fn read(&mut self) -> Result<Option<Entry>, ()> {
        match self.0.next() {
            None => Ok(None),
            Some(Err(_)) => Err(()),
            Some(Ok(e)) => {
                let ft = e.file_type().map_err(|_| ())?;
                Ok(Some(Entry { name: e.file_name().to_string_lossy().into_owned(), dir: ft.is_dir() || ft.is_symlink() }))
            }
        }
    }
}
impl ModelFs for RealFs {
    fn opendir(&self, dir: &str) -> Option<Box<dyn DirRead + '_>> {
        std::fs::read_dir(dir).ok().map(|r| Box::new(RealDir(r)) as Box<dyn DirRead>)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Limits { pub max_entries: usize, pub max_per_dir: usize }
pub const LIMITS: Limits = Limits { max_entries: MAX_ENTRIES, max_per_dir: MAX_PER_DIR };

pub struct Opts<'a> { pub platform: &'a str, pub home: &'a str, pub env: &'a dyn Fn(&str) -> Option<String>, pub deadline_ms: i64, pub limits: Limits }

// The in-memory collection; names never leave it, summarize() reduces it to counts.
pub struct Scan<'a> {
    fs: &'a dyn ModelFs,
    now: &'a dyn Fn() -> i64,
    stop_at: i64,
    limits: Limits,
    by_runtime: HashMap<&'static str, HashMap<String, bool>>,
    pub entries: usize,
    pub truncated: bool,
    pub timed_out: bool,
}

impl<'a> Scan<'a> {
    // One directory, within every bound, in the JS order of checks: deadline, then caps, then one read.
    fn list(&mut self, dir: &str) -> Vec<Entry> {
        if self.timed_out { return vec![]; }
        if self.entries >= self.limits.max_entries { self.truncated = true; return vec![]; }
        let fs = self.fs;
        let Some(mut d) = fs.opendir(dir) else { return vec![] };
        let mut out = vec![];
        loop {
            if (self.now)() > self.stop_at { self.timed_out = true; break; }
            if self.entries >= self.limits.max_entries || out.len() >= self.limits.max_per_dir { self.truncated = true; break; }
            let Ok(e) = d.read() else { break };
            self.entries += 1;
            let Some(e) = e else { break };
            if e.name.starts_with('.') { continue; }
            out.push(e);
        }
        out
    }

    fn add(&mut self, runtime: &'static str, name: &str, matched: bool) {
        if name.is_empty() || utf16_len(name) > MAX_NAME_LENGTH { return; }
        let v = self.by_runtime.entry(runtime).or_default().entry(name.to_string()).or_insert(false);
        *v = *v || matched;
    }

    fn add_name(&mut self, runtime: &'static str, name: &str) {
        let m = safety_removed_by_name(name);
        self.add(runtime, name, m);
    }

    fn walk(&mut self, runtime: &'static str, kind: Kind, root: &str) {
        match kind {
            Kind::OllamaManifests => {
                for reg in self.list(root) {
                    if !reg.dir { continue; }
                    for ns in self.list(&join(&[root, &reg.name])) {
                        if !ns.dir { continue; }
                        for model in self.list(&join(&[root, &reg.name, &ns.name])) {
                            if !model.dir { continue; }
                            for tag in self.list(&join(&[root, &reg.name, &ns.name, &model.name])) {
                                if tag.dir { continue; }
                                let base = if reg.name == "registry.ollama.ai" {
                                    if ns.name == "library" { model.name.clone() } else { format!("{}/{}", ns.name, model.name) }
                                } else { format!("{}/{}/{}", reg.name, ns.name, model.name) };
                                self.add_name(runtime, &format!("{base}:{}", tag.name));
                            }
                        }
                    }
                }
            }
            Kind::PublisherRepo => {
                for publisher in self.list(root) {
                    if !publisher.dir { continue; }
                    for repo in self.list(&join(&[root, &publisher.name])) {
                        if !repo.dir { continue; }
                        let name = format!("{}/{}", publisher.name, repo.name);
                        let matched = safety_removed_by_name(&name)
                            || self.list(&join(&[root, &publisher.name, &repo.name])).iter().any(|f| !f.dir && safety_removed_by_name(&f.name));
                        self.add(runtime, &name, matched);
                    }
                }
            }
            Kind::ModelFiles => {
                for f in self.list(root) { if !f.dir && is_model_file(&f.name) { self.add_name(runtime, &f.name); } }
            }
            Kind::FilesAndHf => {
                for f in self.list(root) {
                    if !f.dir && is_model_file(&f.name) { self.add_name(runtime, &f.name); } else if f.dir { if let Some(r) = hf_repo(&f.name) { self.add_name(runtime, &r); } }
                }
            }
            Kind::HfCache => {
                for f in self.list(root) { if f.dir { if let Some(r) = hf_repo(&f.name) { self.add_name(runtime, &r); } } }
            }
        }
    }
}

pub fn scan_model_names<'a>(o: &Opts, fs: &'a dyn ModelFs, now: &'a dyn Fn() -> i64, deadline: i64) -> Scan<'a> {
    let mut st = Scan { fs, now, stop_at: deadline, limits: o.limits, by_runtime: HashMap::new(), entries: 0, truncated: false, timed_out: false };
    for d in model_dirs(o.platform, o.env, o.home) {
        if st.timed_out || st.entries >= st.limits.max_entries { break; }
        st.walk(d.runtime, d.kind, &d.dir);
    }
    st
}

// The content-free record: fixed keys, runtime ids from MODEL_SOURCES, counts and booleans only.
#[derive(Serialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ModelSafety { pub basis: &'static str, pub safety_removed_by_name: bool, pub count: usize, pub sources: Vec<ModelSource>, pub truncated: bool, pub timed_out: bool }

#[derive(Serialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ModelSource { pub runtime: &'static str, pub models: usize, pub safety_removed_by_name: usize }

pub fn summarize(st: &Scan) -> ModelSafety {
    let sources: Vec<ModelSource> = MODEL_SOURCES.iter().filter_map(|&runtime| {
        let m = st.by_runtime.get(runtime).filter(|m| !m.is_empty())?;
        Some(ModelSource { runtime, models: m.len(), safety_removed_by_name: m.values().filter(|v| **v).count() })
    }).collect();
    let count = sources.iter().map(|s| s.safety_removed_by_name).sum();
    ModelSafety { basis: "name", safety_removed_by_name: count > 0, count, sources, truncated: st.truncated, timed_out: st.timed_out }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Tags { pub names: Vec<String>, pub truncated: bool }

// An /api/tags body → its non-empty string `name`s (capped) or None when it is not { models: [...] }.
pub fn parse_ollama_tags(text: &str, max_models: usize) -> Option<Tags> {
    let j: serde_json::Value = serde_json::from_str(text).ok()?;
    let models = j.get("models")?.as_array()?;
    let names: Vec<String> = models.iter().filter_map(|m| m.get("name")?.as_str()).filter(|s| !s.is_empty()).map(str::to_string).collect();
    let truncated = names.len() > max_models;
    Some(Tags { names: names.into_iter().take(max_models).collect(), truncated })
}

// One HTTP/1.1 exchange over a socket whose every read gets only the time left before `deadline`.
struct Conn { s: TcpStream, buf: Vec<u8>, pos: usize, deadline: Instant }

impl Conn {
    fn left(&self) -> Option<Duration> { self.deadline.checked_duration_since(Instant::now()).filter(|d| !d.is_zero()) }
    // Some(0) at EOF; None once the deadline passes or the socket fails.
    fn fill(&mut self) -> Option<usize> {
        let mut chunk = [0u8; 16384];
        loop {
            self.s.set_read_timeout(Some(self.left()?)).ok()?;
            match self.s.read(&mut chunk) {
                Ok(n) => { self.buf.extend_from_slice(&chunk[..n]); return Some(n); }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => return None,
            }
        }
    }
    fn avail(&self) -> usize { self.buf.len() - self.pos }
    fn need(&mut self, n: usize) -> Option<()> {
        while self.avail() < n { if self.fill()? == 0 { return None; } }
        Some(())
    }
    fn line(&mut self, cap: usize) -> Option<String> {
        loop {
            if let Some(i) = self.buf[self.pos..].windows(2).position(|w| w == b"\r\n") {
                let l = String::from_utf8_lossy(&self.buf[self.pos..self.pos + i]).into_owned();
                self.pos += i + 2;
                return Some(l);
            }
            if self.avail() > cap || self.fill()? == 0 { return None; }
        }
    }
    fn chunked(&mut self, max_bytes: usize) -> Option<Vec<u8>> {
        let mut body = vec![];
        loop {
            let size_line = self.line(MAX_HEADER_BYTES)?;
            let size = usize::from_str_radix(size_line.split(';').next()?.trim(), 16).ok()?;
            if size == 0 {
                let mut trailers = 0;
                loop {
                    let t = self.line(MAX_HEADER_BYTES)?;
                    if t.is_empty() { return Some(body); }
                    trailers += t.len();
                    if trailers > MAX_HEADER_BYTES { return None; }
                }
            }
            // A chunk size comes from the listener: refuse one over the bound before any arithmetic, and
            // never let a sum wrap (a wrapped sum panics in debug and slices out of range in release).
            if size > max_bytes || body.len().checked_add(size)? > max_bytes { return None; }
            let end = self.pos.checked_add(size)?;
            let next = end.checked_add(2)?;
            self.need(size.checked_add(2)?)?;
            body.extend_from_slice(&self.buf[self.pos..end]);
            if &self.buf[end..next] != b"\r\n" { return None; }
            self.pos = next;
        }
    }
}

// GET http://127.0.0.1:<port>/api/tags → Some(tags) or None (refused, timed out, too big, not 200, not
// JSON, malformed framing). The timer is TOTAL, so a server that drips bytes cannot hold the probe
// open. Plain std::net: no proxy, no redirect, no decompression, the same request Node's http sends.
pub fn fetch_ollama_tags_loopback(port: u16, timeout_ms: i64, max_bytes: usize, max_models: usize) -> Option<Tags> {
    let deadline = Instant::now() + Duration::from_millis(timeout_ms.max(1) as u64);
    let left = deadline.checked_duration_since(Instant::now()).filter(|d| !d.is_zero())?;
    let mut s = TcpStream::connect_timeout(&SocketAddr::from(([127, 0, 0, 1], port)), left).ok()?;
    let left = deadline.checked_duration_since(Instant::now()).filter(|d| !d.is_zero())?;
    s.set_write_timeout(Some(left)).ok()?;
    s.write_all(format!("GET /api/tags HTTP/1.1\r\nAccept: application/json\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n").as_bytes()).ok()?;
    let mut c = Conn { s, buf: vec![], pos: 0, deadline };
    let status = c.line(MAX_HEADER_BYTES)?;
    let mut parts = status.splitn(3, ' ');
    if !matches!(parts.next(), Some("HTTP/1.1" | "HTTP/1.0")) || parts.next() != Some("200") { return None; }
    let (mut length, mut encoded, mut chunked, mut head) = (None::<usize>, false, false, status.len());
    loop {
        let l = c.line(MAX_HEADER_BYTES)?;
        head += l.len() + 2;
        if head > MAX_HEADER_BYTES { return None; }
        if l.is_empty() { break; }
        let (k, v) = l.split_once(':')?;
        let v = v.trim();
        if k.eq_ignore_ascii_case("content-length") {
            // Node (llhttp) refuses a repeated Content-Length, even an equal one.
            if length.is_some() { return None; }
            length = Some(v.parse().ok()?);
        } else if k.eq_ignore_ascii_case("transfer-encoding") {
            encoded = true;
            chunked = v.rsplit(',').next().is_some_and(|x| x.trim().eq_ignore_ascii_case("chunked"));
        }
    }
    if encoded && length.is_some() { return None; }
    let body = if chunked {
        c.chunked(max_bytes)?
    } else if let Some(n) = length {
        if n > max_bytes { return None; }
        c.need(n)?;
        c.buf[c.pos..c.pos + n].to_vec()
    } else {
        loop {
            if c.avail() > max_bytes { return None; }
            if c.fill()? == 0 { break; }
        }
        c.buf[c.pos..].to_vec()
    };
    parse_ollama_tags(&String::from_utf8_lossy(&body), max_models)
}

// The whole collector, as JS localModelSafety: directory walks, then /api/tags with whatever time is
// left (never more than HTTP_TIMEOUT_MS). Fail-open: a part that cannot run contributes nothing.
pub fn local_model_safety_with(o: &Opts, fs: &dyn ModelFs, now: &dyn Fn() -> i64, ollama_tags: &dyn Fn(i64) -> Option<Tags>) -> ModelSafety {
    let deadline = now() + o.deadline_ms;
    let mut st = scan_model_names(o, fs, now, deadline);
    let left = deadline - now();
    if left <= 0 {
        st.timed_out = true;
    } else if let Some(r) = ollama_tags(left.min(HTTP_TIMEOUT_MS)) {
        for n in &r.names { st.add_name("ollama", n); }
        if r.truncated { st.truncated = true; }
    }
    summarize(&st)
}

// The device report's entry point: this OS, this process's environment, the real disk and loopback.
pub fn collect(home: &str) -> ModelSafety {
    let start = Instant::now();
    let now = move || start.elapsed().as_millis() as i64;
    let env = |k: &str| std::env::var_os(k).map(|v| v.to_string_lossy().into_owned());
    let o = Opts { platform: crate::ai_runtime::platform_name(), home, env: &env, deadline_ms: DEADLINE_MS, limits: LIMITS };
    local_model_safety_with(&o, &RealFs, &now, &|t| fetch_ollama_tags_loopback(OLLAMA_PORT, t, HTTP_MAX_BYTES, HTTP_MAX_MODELS))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};
    use std::net::{TcpListener, TcpStream};

    // The JS reference's outputs; test/aibom-rust-parity.test.mjs asserts the JS module still gives them.
    const FX: &str = include_str!("../../test/fixtures/local-ai/model-names.json");
    fn fx() -> Value { serde_json::from_str(FX).unwrap() }
    fn s(v: &Value) -> &str { v.as_str().unwrap() }

    fn expand_name(v: &Value) -> String {
        if let Some(n) = v.as_str() { return n.to_string(); }
        format!("{}{}{}", s(&v["prefix"]), s(&v["repeat"]).repeat(v["times"].as_u64().unwrap() as usize), s(&v["suffix"]))
    }
    fn expand_paths(v: &Value) -> Vec<String> {
        v.as_array().unwrap().iter().flat_map(|p| match p.as_str() {
            Some(x) => vec![x.to_string()],
            None => (0..p["count"].as_u64().unwrap()).map(|i| s(&p["gen"]).replace("{i}", &i.to_string())).collect(),
        }).collect()
    }

    // The fixture's tree, insertion-ordered like the JS Map: None is a file, a "!" entry fails when read.
    #[derive(Default)]
    struct Node { kids: Vec<(String, Option<Node>)> }
    struct FakeFs { root: Node }
    impl FakeFs {
        fn new(paths: &[String]) -> Self {
            let mut root = Node::default();
            for p in paths {
                let segs: Vec<&str> = p.split('/').filter(|x| !x.is_empty()).collect();
                let mut n = &mut root;
                for (i, seg) in segs.iter().enumerate() {
                    let leaf_file = i == segs.len() - 1 && !p.ends_with('/');
                    let at = match n.kids.iter().position(|(k, _)| k == seg) {
                        Some(at) => at,
                        None => { n.kids.push((seg.to_string(), if leaf_file { None } else { Some(Node::default()) })); n.kids.len() - 1 }
                    };
                    match n.kids[at].1.as_mut() { Some(next) => n = next, None => break }
                }
            }
            FakeFs { root }
        }
    }
    struct FakeDir<'a> { kids: &'a [(String, Option<Node>)], i: usize }
    impl DirRead for FakeDir<'_> {
        fn read(&mut self) -> Result<Option<Entry>, ()> {
            let Some((k, v)) = self.kids.get(self.i) else { return Ok(None) };
            self.i += 1;
            if k == "!" { return Err(()); }
            Ok(Some(Entry { name: k.clone(), dir: v.is_some() }))
        }
    }
    impl ModelFs for FakeFs {
        fn opendir(&self, dir: &str) -> Option<Box<dyn DirRead + '_>> {
            let mut n = &self.root;
            for seg in dir.split(['/', '\\']).filter(|x| !x.is_empty()) {
                n = n.kids.iter().find(|(k, _)| k == seg)?.1.as_ref()?;
            }
            Some(Box::new(FakeDir { kids: &n.kids, i: 0 }))
        }
    }

    fn env_of(v: &Value) -> HashMap<String, String> {
        v.as_object().map(|m| m.iter().map(|(k, x)| (k.clone(), s(x).to_string())).collect()).unwrap_or_default()
    }
    fn tags_of(v: &Value) -> Option<Tags> {
        if v.is_null() { return None; }
        Some(Tags { names: v["names"].as_array().unwrap().iter().map(|x| s(x).to_string()).collect(), truncated: v["truncated"].as_bool().unwrap() })
    }
    fn tags_json(t: &Option<Tags>) -> Value { t.as_ref().map_or(Value::Null, |t| json!({ "names": t.names, "truncated": t.truncated })) }

    // One fixture tree case → (record JSON, the timeout /api/tags was given or null), as the JS replay.
    fn run_tree(c: &Value, fs: &dyn ModelFs, home: &str) -> Value {
        let env_map = env_of(&c["env"]);
        let env = |k: &str| env_map.get(k).cloned();
        let lim = &c["limits"];
        let limits = Limits {
            max_entries: lim["maxEntries"].as_u64().map_or(MAX_ENTRIES, |x| x as usize),
            max_per_dir: lim["maxPerDir"].as_u64().map_or(MAX_PER_DIR, |x| x as usize),
        };
        let (tick, deadline_ms) = match c["clock"].as_object() { Some(k) => (k["tick"].as_i64().unwrap(), k["deadlineMs"].as_i64().unwrap()), None => (0, DEADLINE_MS) };
        let t = std::cell::Cell::new(0i64);
        let now = || { t.set(t.get() + tick); t.get() };
        let o = Opts { platform: c["platform"].as_str().unwrap_or("linux"), home, env: &env, deadline_ms, limits };
        let seen = std::cell::Cell::new(None::<i64>);
        let tags = tags_of(&c["tags"]);
        let rec = local_model_safety_with(&o, fs, &now, &|ms| { seen.set(Some(ms)); tags.clone() });
        json!({ "record": rec, "tagsTimeoutMs": seen.get() })
    }

    #[test]
    fn names_split_and_match_as_the_js_reference() {
        let f = fx();
        let cases = f["names"].as_array().unwrap();
        assert!(cases.len() >= 80);
        for c in cases {
            let n = expand_name(&c["name"]);
            let want: Vec<String> = c["words"].as_array().unwrap().iter().map(|w| s(w).to_string()).collect();
            assert_eq!(name_words(&n), want, "{n:?}");
            assert_eq!(safety_removed_by_name(&n), c["match"].as_bool().unwrap(), "{n:?}");
        }
    }

    #[cfg(not(windows))]
    #[test]
    fn model_dirs_are_the_js_reference_per_os_and_env() {
        for c in fx()["dirs"].as_array().unwrap() {
            let env_map = env_of(&c["env"]);
            let got: Vec<String> = model_dirs(s(&c["platform"]), &|k| env_map.get(k).cloned(), s(&c["home"])).iter()
                .map(|d| format!("{}|{}|{}", d.runtime, d.kind.as_str(), d.dir)).collect();
            let want: Vec<String> = c["expect"].as_array().unwrap().iter().map(|x| s(x).to_string()).collect();
            assert_eq!(got, want, "{}", c["env"]);
        }
    }

    #[test]
    fn fake_trees_clock_and_bounds_give_the_js_record() {
        let f = fx();
        let cases = f["trees"].as_array().unwrap();
        assert!(cases.len() >= 15);
        for c in cases {
            let fs = FakeFs::new(&expand_paths(&c["paths"]));
            assert_eq!(run_tree(c, &fs, c["home"].as_str().unwrap_or("/home/dev")), c["expect"], "{}", c["name"]);
        }
    }

    #[test]
    fn the_full_tree_on_a_real_disk_gives_the_fake_tree_record() {
        let f = fx();
        let c = &f["trees"][0];
        let home = std::env::temp_dir().join(format!("moorai-rs-modelnames-{}", std::process::id()));
        for p in expand_paths(&c["paths"]) {
            let rel = home.join(p.strip_prefix("/home/dev/").unwrap());
            if p.ends_with('/') { std::fs::create_dir_all(&rel).unwrap(); } else { std::fs::create_dir_all(rel.parent().unwrap()).unwrap(); std::fs::write(&rel, "").unwrap(); }
        }
        let got = run_tree(c, &RealFs, home.to_str().unwrap());
        let _ = std::fs::remove_dir_all(&home);
        assert_eq!(got, c["expect"]);
    }

    #[test]
    fn api_tags_bodies_parse_as_the_js_reference() {
        for c in fx()["tags"].as_array().unwrap() {
            let max = c["maxModels"].as_u64().map_or(HTTP_MAX_MODELS, |x| x as usize);
            assert_eq!(tags_json(&parse_ollama_tags(s(&c["body"]), max)), c["expect"], "{}", c["body"]);
        }
    }

    fn body_of(b: &Value) -> Vec<u8> {
        if let Some(t) = b["text"].as_str() { return t.as_bytes().to_vec(); }
        if let Some(h) = b["hex"].as_str() { return (0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap()).collect(); }
        if let Some(n) = b["models"].as_u64() { return format!("{{\"models\":[{}]}}", (0..n).map(|i| format!("{{\"name\":\"m{i}:latest\"}}")).collect::<Vec<_>>().join(",")).into_bytes(); }
        let (head, tail) = ("{\"models\":[{\"name\":\"a-uncensored:1b\"}],\"pad\":\"", "\"}");
        format!("{head}{}{tail}", "x".repeat(b["padTo"].as_u64().unwrap() as usize - head.len() - tail.len())).into_bytes()
    }
    fn raw_of(c: &Value) -> Vec<u8> {
        let body = body_of(&c["body"]);
        let mut lines: Vec<String> = vec![s(&c["status"]).to_string()];
        lines.extend(c["headers"].as_array().unwrap().iter().map(|h| s(h).to_string()));
        let transfer = s(&c["transfer"]);
        let mut payload = body.clone();
        match transfer {
            "length" => lines.push(format!("Content-Length: {}", body.len())),
            "lowerlength" => lines.push(format!("content-length: {}", body.len())),
            "short" => lines.push(format!("Content-Length: {}", body.len() + 10)),
            "chunked" | "chunkedcut" => {
                lines.push("Transfer-Encoding: chunked".into());
                payload = vec![];
                for ch in body.chunks(c["chunk"].as_u64().unwrap_or(7) as usize) {
                    payload.extend(format!("{:x}\r\n", ch.len()).as_bytes());
                    payload.extend(ch);
                    payload.extend(b"\r\n");
                }
                if transfer == "chunked" {
                    payload.extend(format!("0\r\n{}\r\n", c["trailer"].as_str().map(|t| format!("{t}\r\n")).unwrap_or_default()).as_bytes());
                }
            }
            _ => {}
        }
        let mut out = format!("{}\r\n\r\n", lines.join("\r\n")).into_bytes();
        out.extend(payload);
        out
    }
    // accept() that gives up after 3 s, so a client that never connects fails the test instead of hanging it.
    fn accept_within(l: &TcpListener) -> Option<TcpStream> {
        l.set_nonblocking(true).unwrap();
        let t = Instant::now();
        while t.elapsed() < Duration::from_secs(3) {
            if let Ok((sock, _)) = l.accept() { sock.set_nonblocking(false).unwrap(); return Some(sock); }
            std::thread::sleep(Duration::from_millis(5));
        }
        None
    }
    // Serves `raw` once on 127.0.0.1 after reading the request head; returns (port, the request line).
    fn serve_once(raw: Vec<u8>) -> (u16, std::thread::JoinHandle<String>) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let h = std::thread::spawn(move || {
            let Some(mut sock) = accept_within(&l) else { return String::new() };
            sock.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            let mut got = vec![];
            let mut b = [0u8; 4096];
            while !got.windows(4).any(|w| w == b"\r\n\r\n") { let n = sock.read(&mut b).unwrap_or(0); if n == 0 { break; } got.extend_from_slice(&b[..n]); }
            let _ = sock.write_all(&raw);
            let _ = sock.shutdown(std::net::Shutdown::Both);
            String::from_utf8_lossy(&got).into_owned()
        });
        (port, h)
    }

    #[test]
    fn raw_http_responses_from_loopback_give_the_js_result() {
        let f = fx();
        let cases = f["http"].as_array().unwrap();
        assert!(cases.len() >= 25);
        for c in cases {
            let (port, h) = serve_once(raw_of(c));
            let got = fetch_ollama_tags_loopback(port, HTTP_TIMEOUT_MS, HTTP_MAX_BYTES, HTTP_MAX_MODELS);
            let req = h.join().unwrap();
            assert_eq!(tags_json(&got), c["expect"], "{}", c["name"]);
            assert!(req.starts_with("GET /api/tags HTTP/1.1\r\n"), "{req}");
            assert!(req.contains(&format!("\r\nHost: 127.0.0.1:{port}\r\n")), "{req}");
        }
    }

    #[test]
    fn loopback_never_answering_is_abandoned_at_the_timeout() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let h = std::thread::spawn(move || { let s = accept_within(&l); std::thread::sleep(Duration::from_millis(1500)); drop(s); });
        let t = Instant::now();
        assert_eq!(fetch_ollama_tags_loopback(port, 300, HTTP_MAX_BYTES, HTTP_MAX_MODELS), None);
        assert!(t.elapsed() < Duration::from_millis(1000), "took {:?}", t.elapsed());
        h.join().unwrap();
    }

    #[test]
    fn loopback_slow_drip_is_abandoned_at_the_timeout_total_not_idle() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let h = std::thread::spawn(move || {
            let Some(mut s) = accept_within(&l) else { return };
            let _ = s.write_all(b"HTTP/1.1 200 OK\r\n\r\n");
            for _ in 0..30 { if s.write_all(b" ").is_err() { break; } std::thread::sleep(Duration::from_millis(50)); }
        });
        let t = Instant::now();
        assert_eq!(fetch_ollama_tags_loopback(port, 300, HTTP_MAX_BYTES, HTTP_MAX_MODELS), None);
        assert!(t.elapsed() < Duration::from_millis(1000), "took {:?}", t.elapsed());
        h.join().unwrap();
    }

    // A listener on 127.0.0.1:11434 chooses the chunk size. 2^64-1 must not overflow the parser's sums,
    // as the first chunk (size + 2) or after one (body + size); None, no panic, well inside the timeout.
    #[test]
    fn loopback_chunk_size_2_pow_64_minus_1_is_none_without_a_panic() {
        for tail in ["ffffffffffffffff\r\n{\"models\":[]}\r\n0\r\n\r\n", "7\r\n{\"model\r\nffffffffffffffff\r\ns\":[]}\r\n0\r\n\r\n"] {
            let (port, h) = serve_once(format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{tail}").into_bytes());
            let t = Instant::now();
            let got = std::panic::catch_unwind(|| fetch_ollama_tags_loopback(port, HTTP_TIMEOUT_MS, HTTP_MAX_BYTES, HTTP_MAX_MODELS));
            h.join().unwrap();
            assert_eq!(got.ok(), Some(None), "{tail:?}");
            assert!(t.elapsed() < Duration::from_millis(HTTP_TIMEOUT_MS as u64), "took {:?}", t.elapsed());
        }
    }

    #[test]
    fn loopback_nothing_listening_is_none() {
        let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        assert_eq!(fetch_ollama_tags_loopback(port, 500, HTTP_MAX_BYTES, HTTP_MAX_MODELS), None);
    }

    // The JSON.parse cases serde_json does not accept the same way. All are bodies a real Ollama never
    // sends (Go escapes invalid text as U+FFFD and nests three levels); Rust then drops the API names
    // (fail-open: the disk walk still counts) where JS would keep them.
    #[test]
    fn known_json_divergences_fail_open() {
        assert_eq!(parse_ollama_tags(r#"{"models":[{"name":"\ud800x-uncensored"}]}"#, 10), None, "JSON.parse keeps a lone surrogate");
        let deep = format!(r#"{{"models":[{{"name":"a"}}],"x":{}{}}}"#, "[".repeat(200), "]".repeat(200));
        assert_eq!(parse_ollama_tags(&deep, 10), None, "JSON.parse has no 128-level nesting limit");
        assert_eq!(parse_ollama_tags(r#"{"models":[{"name":"a"}],"x":1e400}"#, 10), None, "JSON.parse reads 1e400 as Infinity");
    }

    const ALLOWED_KEYS: &[&str] = &["basis", "safetyRemovedByName", "count", "sources", "runtime", "models", "truncated", "timedOut"];
    fn assert_content_free(v: &Value, at: &str) {
        match v {
            Value::Object(m) => for (k, x) in m { assert!(ALLOWED_KEYS.contains(&k.as_str()), "{at}: key {k}"); assert_content_free(x, at); },
            Value::Array(a) => for x in a { assert_content_free(x, at); },
            Value::String(x) => assert!(x == "name" || MODEL_SOURCES.contains(&x.as_str()), "{at}: free string {x}"),
            Value::Number(_) | Value::Bool(_) => {}
            Value::Null => panic!("{at}: null"),
        }
    }

    #[test]
    fn content_free_every_fixture_record_and_this_device() {
        let f = fx();
        for c in f["trees"].as_array().unwrap() {
            let fs = FakeFs::new(&expand_paths(&c["paths"]));
            let rec = run_tree(c, &fs, c["home"].as_str().unwrap_or("/home/dev"))["record"].clone();
            assert_content_free(&rec, s(&c["name"]));
            let text = rec.to_string();
            for leak in ["huihui", "qwen", "Qwen", "abliterated", "uncensored", "Unaligned", "OBLITERATED", "secret", "acme", "/home", ".gguf", "manifests", "models--", "Q4_K_M", "registry.ollama.ai", "hf.co", ":8b", "nidumai"] {
                assert!(!text.contains(leak), "{}: {leak} leaked", c["name"]);
            }
        }
        // the real collector on this machine: bounded by the 2 s deadline, never a name or a path
        let home = crate::platform::home_dir();
        let t = Instant::now();
        let rec = serde_json::to_value(collect(&home)).unwrap();
        assert!(t.elapsed() < Duration::from_millis(3500), "took {:?}", t.elapsed());
        assert_content_free(&rec, "collect");
        assert!(home.is_empty() || !rec.to_string().contains(&home));
    }
}
