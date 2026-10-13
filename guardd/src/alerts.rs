//! The root-held alert queue and signed batch delivery (contract §3.4 `submit`, §7).
//!
//! Each acked `submit` is one file `alerts/<firstSeq, 20 digits>.json`, fsynced before the ack, holding
//! the alerts with their chain seq and the chain head after each. The chain is the record-chain.mjs link,
//! `chash = sha256(prev|seq|rhash)`, with `rhash` = record-chain's `recordRhash` of the alert (seq
//! excluded). `chain.json` holds `{seq, head, overflow, inflight}`; a batch in flight keeps its batchId
//! across retries and helper restarts.

use crate::canonical::{canonical_json, js_canonical_json, sha256_hex};
use crate::state::{load_json, save_json, write_atomic};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub const ALERTS_PATH: &str = "/api/devices/alerts";
pub const MAX_BATCH_ALERTS: usize = 64;
pub const MAX_BATCH_BYTES: usize = 256 * 1024;
/// Retry schedule after a failed delivery: exponential from 5 s, capped at 300 s, full jitter.
pub const RETRY_BASE_MS: u64 = 5_000;
pub const RETRY_CAP_MS: u64 = 300_000;
/// Queue bound on disk; past it the oldest NON-quarantine alerts are dropped and a
/// `queueOverflow` count is carried on the next batch.
pub const QUEUE_MAX_ALERTS: usize = 10_000;
/// Keys the helper owns on a queued alert; whatever the hook sent under them is replaced.
pub const HELPER_KEYS: [&str; 3] = ["seq", "chainHead", "peerUid"];

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AlertBatch {
    pub v: u32,
    pub tenant: String,
    pub device_id: String,
    /// 32 lowercase hex, random per batch; a retried batch keeps its id (the console dedupes on it).
    pub batch_id: String,
    pub first_seq: u64,
    pub last_seq: u64,
    pub chain_head: String,
    /// Contiguous by `seq`, firstSeq..=lastSeq (gaps only where the overflow rule dropped alerts).
    pub alerts: Vec<Map<String, Value>>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub queue_overflow: Option<u64>,
}

impl AlertBatch {
    pub fn body_bytes(&self) -> Result<Vec<u8>, crate::canonical::CanonError> {
        let v = serde_json::to_value(self).expect("AlertBatch serialises");
        Ok(crate::canonical::canonical_json(&v)?.into_bytes())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Queued {
    alert: Map<String, Value>,
    head: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct QueueFile {
    v: u32,
    entries: Vec<Queued>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Inflight {
    pub batch_id: String,
    pub first_seq: u64,
    pub last_seq: u64,
    pub overflow: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Chain {
    pub seq: u64,
    pub head: String,
    #[serde(default)]
    pub overflow: u64,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub inflight: Option<Inflight>,
}

/// record-chain.mjs `genesis`.
pub fn genesis(log_key: &str, tenant: &str) -> String {
    format!("g:{}", &sha256_hex(format!("moorai/chain/{log_key}/{tenant}").as_bytes())[..24])
}

/// record-chain.mjs `recordRhash` over a wire object: sha256 of JSON.stringify of the sorted
/// `[key, value]` pairs (here: `seq` excluded, the chain's own field), first 32 hex.
pub fn record_rhash(obj: &Map<String, Value>) -> String {
    let mut keys: Vec<&String> = obj.keys().filter(|k| k.as_str() != "seq" && k.as_str() != "chain").collect();
    keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
    let pairs: Vec<String> = keys
        .iter()
        .map(|k| {
            let kv = canonical_json(&Value::String((*k).clone())).expect("string");
            let vv = canonical_json(&obj[*k]).unwrap_or_else(|_| js_canonical_json(&obj[*k]));
            format!("[{kv},{vv}]")
        })
        .collect();
    sha256_hex(format!("[{}]", pairs.join(",")).as_bytes())[..32].to_string()
}

pub fn chain_hash(prev: &str, seq: u64, rhash: &str) -> String {
    sha256_hex(format!("{prev}|{seq}|{rhash}").as_bytes())
}

/// Durable FIFO under state/alerts/. `enqueue` returns only after the entries are fsynced, which is
/// what makes a `submit` ack mean "cannot be deleted by the agent any more".
pub struct AlertQueue {
    dir: PathBuf,
    chain_path: PathBuf,
    pub chain: Chain,
    files: BTreeMap<u64, QueueFile>,
}

fn file_name(first_seq: u64) -> String {
    format!("{first_seq:020}.json")
}

impl AlertQueue {
    /// Open state/alerts (`dir`) with chain.json at `chain_path`; recover after a crash: temp files are
    /// removed, an unparseable entry is set aside as `.corrupt` (never deleted), and the chain is moved
    /// forward past any entry fsynced before chain.json was updated.
    pub fn open(dir: &Path, chain_path: &Path, tenant: &str) -> std::io::Result<Self> {
        let mut chain: Chain = load_json(chain_path)?.unwrap_or_default();
        if chain.head.is_empty() {
            chain.head = genesis("guardd-alerts", tenant);
        }
        let mut files = BTreeMap::new();
        for e in std::fs::read_dir(dir)? {
            let e = e?;
            let name = e.file_name().to_string_lossy().into_owned();
            if name.starts_with('.') && name.contains(".tmp-") {
                std::fs::remove_file(e.path())?;
                continue;
            }
            let Some(stem) = name.strip_suffix(".json") else { continue };
            let Ok(first) = stem.parse::<u64>() else { continue };
            match load_json::<QueueFile>(&e.path()) {
                Ok(Some(f)) if !f.entries.is_empty() => {
                    files.insert(first, f);
                }
                Ok(_) => std::fs::remove_file(e.path())?,
                Err(err) => {
                    eprintln!("moorai-guardd: setting aside unreadable alert file {name}: {err}");
                    std::fs::rename(e.path(), dir.join(format!("{name}.corrupt")))?;
                }
            }
        }
        let last = files.values().flat_map(|f| f.entries.iter()).filter_map(|q| q.alert.get("seq").and_then(Value::as_u64).map(|s| (s, q.head.clone()))).max_by_key(|(s, _)| *s);
        if let Some((s, h)) = last {
            if s > chain.seq {
                chain.seq = s;
                chain.head = h;
                save_json(chain_path, &chain)?;
            }
        }
        Ok(AlertQueue { dir: dir.to_path_buf(), chain_path: chain_path.to_path_buf(), chain, files })
    }

    pub fn len(&self) -> usize {
        self.files.values().map(|f| f.entries.len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn write_file(&self, first: u64, f: &QueueFile) -> std::io::Result<()> {
        let bytes = serde_json::to_vec(f).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        write_atomic(&self.dir.join(file_name(first)), &bytes)
    }

    fn remove_file(&self, first: u64) -> std::io::Result<()> {
        match std::fs::remove_file(self.dir.join(file_name(first))) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        }
    }

    /// Stamp each alert with the next chain seq (and the peer's uid), persist the queue file and then
    /// chain.json, both fsynced, and return the acks. Applies the overflow rule afterwards.
    pub fn enqueue(&mut self, alerts: Vec<Map<String, Value>>, peer_uid: Option<u32>) -> std::io::Result<crate::ipc::SubmitResp> {
        if alerts.is_empty() {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "no alerts"));
        }
        let mut chain = self.chain.clone();
        let first = chain.seq + 1;
        let mut entries = Vec::with_capacity(alerts.len());
        let mut acks = Vec::with_capacity(alerts.len());
        for mut a in alerts {
            for k in HELPER_KEYS {
                a.remove(k);
            }
            if let Some(uid) = peer_uid {
                a.insert("peerUid".into(), Value::from(uid));
            }
            let seq = chain.seq + 1;
            let head = chain_hash(&chain.head, seq, &record_rhash(&a));
            a.insert("seq".into(), Value::from(seq));
            chain.seq = seq;
            chain.head = head.clone();
            acks.push(crate::ipc::SubmitAck { seq });
            entries.push(Queued { alert: a, head });
        }
        let file = QueueFile { v: 1, entries };
        self.write_file(first, &file)?;
        save_json(&self.chain_path, &chain)?;
        self.chain = chain;
        self.files.insert(first, file);
        self.enforce_bound()?;
        Ok(crate::ipc::SubmitResp { acks, chain_head: self.chain.head.clone() })
    }

    fn in_flight(&self, seq: u64) -> bool {
        self.chain.inflight.as_ref().is_some_and(|i| (i.first_seq..=i.last_seq).contains(&seq))
    }

    /// Past QUEUE_MAX_ALERTS drop the oldest alerts that are neither quarantine alerts nor part of the
    /// batch in flight; the count rides on the next batch as `queueOverflow`.
    fn enforce_bound(&mut self) -> std::io::Result<()> {
        let mut excess = self.len().saturating_sub(QUEUE_MAX_ALERTS);
        if excess == 0 {
            return Ok(());
        }
        let mut dropped = 0u64;
        let keys: Vec<u64> = self.files.keys().copied().collect();
        for first in keys {
            if excess == 0 {
                break;
            }
            let mut f = self.files[&first].clone();
            let before = f.entries.len();
            let mut kept = Vec::with_capacity(before);
            for q in f.entries.into_iter() {
                let seq = q.alert.get("seq").and_then(Value::as_u64).unwrap_or(0);
                let protected = q.alert.get("kind").and_then(Value::as_str) == Some("quarantine") || self.in_flight(seq);
                if excess > 0 && !protected {
                    excess -= 1;
                    dropped += 1;
                } else {
                    kept.push(q);
                }
            }
            f.entries = kept;
            if f.entries.len() != before {
                if f.entries.is_empty() {
                    self.remove_file(first)?;
                    self.files.remove(&first);
                } else {
                    self.write_file(first, &f)?;
                    self.files.insert(first, f);
                }
            }
        }
        if dropped > 0 {
            self.chain.overflow += dropped;
            save_json(&self.chain_path, &self.chain)?;
        }
        Ok(())
    }

    fn queued(&self) -> impl Iterator<Item = &Queued> {
        self.files.values().flat_map(|f| f.entries.iter())
    }

    /// The next batch to send (oldest first), or None when empty. A batch already in flight is rebuilt
    /// with the same batchId and contents; a new one is recorded in chain.json before it is returned.
    pub fn next_batch(&mut self, tenant: &str, device_id: &str) -> std::io::Result<Option<AlertBatch>> {
        if let Some(inf) = self.chain.inflight.clone() {
            let picked: Vec<&Queued> = self.queued().filter(|q| self.in_flight(q.alert.get("seq").and_then(Value::as_u64).unwrap_or(0))).collect();
            if !picked.is_empty() {
                return Ok(Some(self.batch_of(&picked, inf.batch_id, inf.overflow, tenant, device_id)));
            }
            self.chain.inflight = None;
            save_json(&self.chain_path, &self.chain)?;
        }
        let mut picked: Vec<&Queued> = Vec::new();
        let mut size = 512usize;
        for q in self.queued() {
            let n = canonical_json(&Value::Object(q.alert.clone())).map(|s| s.len()).unwrap_or(MAX_BATCH_BYTES) + 1;
            if picked.len() == MAX_BATCH_ALERTS || (!picked.is_empty() && size + n > MAX_BATCH_BYTES) {
                break;
            }
            size += n;
            picked.push(q);
        }
        if picked.is_empty() {
            return Ok(None);
        }
        let batch = self.batch_of(&picked, crate::clock::random_hex(16), self.chain.overflow, tenant, device_id);
        self.chain.inflight = Some(Inflight { batch_id: batch.batch_id.clone(), first_seq: batch.first_seq, last_seq: batch.last_seq, overflow: self.chain.overflow });
        save_json(&self.chain_path, &self.chain)?;
        Ok(Some(batch))
    }

    fn batch_of(&self, picked: &[&Queued], batch_id: String, overflow: u64, tenant: &str, device_id: &str) -> AlertBatch {
        let seq = |q: &Queued| q.alert.get("seq").and_then(Value::as_u64).unwrap_or(0);
        AlertBatch {
            v: 1,
            tenant: tenant.into(),
            device_id: device_id.into(),
            batch_id,
            first_seq: seq(picked[0]),
            last_seq: seq(picked[picked.len() - 1]),
            chain_head: picked[picked.len() - 1].head.clone(),
            alerts: picked.iter().map(|q| q.alert.clone()).collect(),
            queue_overflow: (overflow > 0).then_some(overflow),
        }
    }

    /// Drop a batch the console acknowledged with 201 (or 409 duplicate batchId), or one it refused
    /// as too large (413, counted into the overflow). Unknown ids are ignored.
    pub fn ack_batch(&mut self, batch_id: &str) -> std::io::Result<()> {
        self.finish_batch(batch_id, false)
    }

    pub fn drop_batch_as_overflow(&mut self, batch_id: &str) -> std::io::Result<()> {
        self.finish_batch(batch_id, true)
    }

    fn finish_batch(&mut self, batch_id: &str, count_as_overflow: bool) -> std::io::Result<()> {
        let Some(inf) = self.chain.inflight.clone().filter(|i| i.batch_id == batch_id) else { return Ok(()) };
        let mut removed = 0u64;
        let keys: Vec<u64> = self.files.keys().copied().collect();
        for first in keys {
            let mut f = self.files[&first].clone();
            let before = f.entries.len();
            f.entries.retain(|q| !(inf.first_seq..=inf.last_seq).contains(&q.alert.get("seq").and_then(Value::as_u64).unwrap_or(0)));
            removed += (before - f.entries.len()) as u64;
            if f.entries.len() == before {
                continue;
            }
            if f.entries.is_empty() {
                self.remove_file(first)?;
                self.files.remove(&first);
            } else {
                self.write_file(first, &f)?;
                self.files.insert(first, f);
            }
        }
        self.chain.inflight = None;
        self.chain.overflow = self.chain.overflow.saturating_sub(inf.overflow);
        if count_as_overflow {
            self.chain.overflow += removed;
        }
        save_json(&self.chain_path, &self.chain)
    }
}

/// What a delivery attempt did, for the delivery loop's retry schedule.
#[derive(Debug, Clone, PartialEq)]
pub enum Delivery {
    Empty,
    Delivered { batch_id: String, alerts: usize },
    Retry(String),
    /// 401 unknown_key: the console does not know this key; register again before retrying.
    Reregister,
}

/// Map a console answer for a batch to what the queue does with it (§6.3, §7.1).
pub fn classify_delivery(r: &Result<crate::console::HttpResponse, crate::console::ConsoleError>) -> &'static str {
    use crate::console::ConsoleError::*;
    match r {
        Ok(_) => "ack",
        Err(Status(409, code)) if code == "duplicate" => "ack",
        Err(Status(413, _)) => "drop",
        Err(Status(401, code)) if code == "unknown_key" => "reregister",
        _ => "retry",
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use serde_json::json;

    fn dir() -> (PathBuf, PathBuf) {
        let d = crate::state::test_root("alerts");
        std::fs::create_dir_all(d.join("alerts")).unwrap();
        (d.join("alerts"), d.join("chain.json"))
    }

    fn alert(i: u64) -> Map<String, Value> {
        json!({"threatId": i, "severity":"high", "seq": 999_999, "peerUid": 0, "chainHead": "forged"}).as_object().unwrap().clone()
    }

    #[test]
    fn enqueue_stamps_seq_and_chain_and_overwrites_hook_supplied_fields() {
        let (d, c) = dir();
        let mut q = AlertQueue::open(&d, &c, "acme").unwrap();
        let r = q.enqueue(vec![alert(1), alert(2)], Some(501)).unwrap();
        assert_eq!(r.acks.iter().map(|a| a.seq).collect::<Vec<_>>(), vec![1, 2]);
        let g = genesis("guardd-alerts", "acme");
        let mut a1 = alert(1);
        a1.remove("seq");
        a1.remove("chainHead");
        a1.insert("peerUid".into(), json!(501));
        let h1 = chain_hash(&g, 1, &record_rhash(&a1));
        let mut a2 = alert(2);
        a2.remove("seq");
        a2.remove("chainHead");
        a2.insert("peerUid".into(), json!(501));
        let h2 = chain_hash(&h1, 2, &record_rhash(&a2));
        assert_eq!(r.chain_head, h2);
        let b = q.next_batch("acme", "dev").unwrap().unwrap();
        assert_eq!(b.alerts[0]["peerUid"], json!(501));
        assert_eq!(b.alerts[1]["seq"], json!(2));
        assert!(b.alerts[0].get("chainHead").is_none());
        assert_eq!((b.first_seq, b.last_seq, b.chain_head.as_str()), (1, 2, h2.as_str()));
    }

    #[test]
    fn rhash_matches_record_chain_mjs() {
        // node -e 'const {createHash}=require("crypto");const o={b:{y:1,x:"é"},a:[1,"two"]};
        //   console.log(createHash("sha256").update(JSON.stringify(Object.keys(o).sort().map(k=>[k,o[k]]))).digest("hex").slice(0,32))'
        // with o.b given in canonical order {x,y}.
        let o = json!({"b":{"x":"\u{e9}","y":1},"a":[1,"two"]}).as_object().unwrap().clone();
        let expected = &sha256_hex("[[\"a\",[1,\"two\"]],[\"b\",{\"x\":\"\u{e9}\",\"y\":1}]]".as_bytes())[..32];
        assert_eq!(record_rhash(&o), expected);
    }

    #[test]
    fn acked_alerts_survive_a_restart_and_the_chain_continues() {
        let (d, c) = dir();
        let mut q = AlertQueue::open(&d, &c, "acme").unwrap();
        let r1 = q.enqueue(vec![alert(1)], None).unwrap();
        drop(q);
        let mut q = AlertQueue::open(&d, &c, "acme").unwrap();
        assert_eq!(q.len(), 1);
        let r2 = q.enqueue(vec![alert(2)], None).unwrap();
        assert_eq!(r2.acks[0].seq, 2);
        let mut a2 = alert(2);
        for k in HELPER_KEYS {
            a2.remove(k);
        }
        assert_eq!(r2.chain_head, chain_hash(&r1.chain_head, 2, &record_rhash(&a2)));
    }

    #[test]
    fn a_crash_between_queue_file_and_chain_does_not_reuse_seqs() {
        let (d, c) = dir();
        let mut q = AlertQueue::open(&d, &c, "acme").unwrap();
        q.enqueue(vec![alert(1), alert(2)], None).unwrap();
        // Roll chain.json back as if the process died after the queue file's fsync.
        save_json(&c, &Chain { seq: 0, head: genesis("guardd-alerts", "acme"), overflow: 0, inflight: None }).unwrap();
        std::fs::write(d.join(".x.tmp-abc"), b"partial").unwrap();
        let mut q = AlertQueue::open(&d, &c, "acme").unwrap();
        assert_eq!(q.chain.seq, 2);
        assert!(!d.join(".x.tmp-abc").exists(), "temp files are cleaned");
        assert_eq!(q.enqueue(vec![alert(3)], None).unwrap().acks[0].seq, 3);
    }

    #[test]
    fn batches_are_bounded_oldest_first_and_keep_their_id_until_acked() {
        let (d, c) = dir();
        let mut q = AlertQueue::open(&d, &c, "acme").unwrap();
        for i in 0..3 {
            q.enqueue((0..50).map(|j| alert(i * 100 + j)).collect(), None).unwrap();
        }
        let b1 = q.next_batch("acme", "dev").unwrap().unwrap();
        assert_eq!((b1.first_seq, b1.last_seq, b1.alerts.len()), (1, 64, 64));
        let again = q.next_batch("acme", "dev").unwrap().unwrap();
        assert_eq!(again, b1, "a retry resends the identical batch");
        drop(q);
        let mut q = AlertQueue::open(&d, &c, "acme").unwrap();
        assert_eq!(q.next_batch("acme", "dev").unwrap().unwrap().batch_id, b1.batch_id, "in-flight id survives a restart");
        q.ack_batch("not-this-one").unwrap();
        assert_eq!(q.len(), 150);
        q.ack_batch(&b1.batch_id).unwrap();
        assert_eq!(q.len(), 86);
        let b2 = q.next_batch("acme", "dev").unwrap().unwrap();
        assert_ne!(b2.batch_id, b1.batch_id);
        assert_eq!((b2.first_seq, b2.last_seq), (65, 128));
        q.ack_batch(&b2.batch_id).unwrap();
        let b3 = q.next_batch("acme", "dev").unwrap().unwrap();
        q.ack_batch(&b3.batch_id).unwrap();
        assert!(q.is_empty());
        assert!(q.next_batch("acme", "dev").unwrap().is_none());
        assert_eq!(std::fs::read_dir(&d).unwrap().count(), 0, "acked files are deleted");
    }

    #[test]
    fn a_batch_never_exceeds_256_kib() {
        let (d, c) = dir();
        let mut q = AlertQueue::open(&d, &c, "acme").unwrap();
        let big = "x".repeat(20_000);
        q.enqueue((0..30).map(|i| json!({"i": i, "pad": big}).as_object().unwrap().clone()).collect(), None).unwrap();
        let b = q.next_batch("acme", "dev").unwrap().unwrap();
        assert!(b.body_bytes().unwrap().len() <= MAX_BATCH_BYTES, "{}", b.body_bytes().unwrap().len());
        assert!(b.alerts.len() < 30 && !b.alerts.is_empty());
    }

    #[test]
    fn overflow_drops_oldest_non_quarantine_and_reports_the_count() {
        let (d, c) = dir();
        let mut q = AlertQueue::open(&d, &c, "acme").unwrap();
        let mut first = vec![json!({"kind":"quarantine","quarantineId":"q-1"}).as_object().unwrap().clone()];
        first.extend((0..63).map(alert));
        q.enqueue(first, None).unwrap();
        for i in 0..(QUEUE_MAX_ALERTS / 64) {
            q.enqueue((0..64).map(|j| alert((i * 64 + j) as u64)).collect(), None).unwrap();
        }
        assert_eq!(q.len(), QUEUE_MAX_ALERTS);
        let expected = (64 + (QUEUE_MAX_ALERTS / 64) * 64 - QUEUE_MAX_ALERTS) as u64;
        assert_eq!(q.chain.overflow, expected);
        let b = q.next_batch("acme", "dev").unwrap().unwrap();
        assert_eq!(b.alerts[0]["kind"], json!("quarantine"), "the quarantine alert survives");
        assert_eq!(b.alerts[1]["seq"], json!(2 + expected), "the oldest plain alerts went first");
        assert_eq!(b.queue_overflow, Some(expected));
        q.ack_batch(&b.batch_id).unwrap();
        assert_eq!(q.chain.overflow, 0, "the count is carried once");
    }

    #[test]
    fn delivery_outcomes_follow_the_contract() {
        use crate::console::{ConsoleError::*, HttpResponse};
        assert_eq!(classify_delivery(&Ok(HttpResponse { status: 201, body: vec![] })), "ack");
        assert_eq!(classify_delivery(&Err(Status(409, "duplicate".into()))), "ack");
        assert_eq!(classify_delivery(&Err(Status(409, "replay".into()))), "retry");
        assert_eq!(classify_delivery(&Err(Status(413, "".into()))), "drop");
        assert_eq!(classify_delivery(&Err(Status(401, "unknown_key".into()))), "reregister");
        assert_eq!(classify_delivery(&Err(Network("x".into()))), "retry");
    }
}
