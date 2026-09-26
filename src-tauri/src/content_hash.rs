// Rust twin of cli/content-hash.mjs (read that file for WHY the fingerprint is keyed and per-tenant).
// Same key (the enrollment installToken from ~/.moorai/config.json), same derivation
// HMAC-SHA-256(installToken, "moorai/content-hash/v2"), same output "h2:" + first 16 hex of
// HMAC-SHA-256(key, value), same NO_KEY sentinel when unenrolled — so a key-at-rest hash computed here
// is byte-identical to the Node agent's and the desktop renderer's (src/content-hash.js).
// test/fixtures/content-hash-parity.json holds vectors asserted by BOTH this file's tests and Node's.
use sha2::{Digest, Sha256};

pub const HASH_PREFIX: &str = "h2:";
pub const NO_KEY: &str = "h2:nokey";
pub const KEY_LABEL: &str = "moorai/content-hash/v2";
const HEX_LEN: usize = 16;

fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        k[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut inner = Sha256::new();
    inner.update(k.map(|b| b ^ 0x36));
    inner.update(msg);
    let mut outer = Sha256::new();
    outer.update(k.map(|b| b ^ 0x5c));
    outer.update(inner.finalize());
    outer.finalize().into()
}

pub fn derive_key(install_token: &str) -> Option<[u8; 32]> {
    if install_token.is_empty() { return None; }
    Some(hmac_sha256(install_token.as_bytes(), KEY_LABEL.as_bytes()))
}

pub fn hash_with_key(key: Option<&[u8; 32]>, s: &str) -> String {
    match key {
        None => NO_KEY.to_string(),
        Some(k) => {
            let mac = hmac_sha256(k, s.as_bytes());
            let hex: String = mac.iter().map(|b| format!("{b:02x}")).collect();
            format!("{HASH_PREFIX}{}", &hex[..HEX_LEN])
        }
    }
}

// The enrolled key, read the way `identity()` reads the token (config.json, legacy dir fallback).
pub fn tenant_key() -> Option<[u8; 32]> {
    let cfg = crate::read_config();
    derive_key(cfg.get("installToken").and_then(|t| t.as_str()).unwrap_or(""))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Vectors shared with test/content-hash-parity.test.mjs, which asserts Node produces the same.
    #[test]
    fn matches_the_node_vectors() {
        let fx: serde_json::Value = serde_json::from_str(include_str!("../../test/fixtures/content-hash-parity.json")).unwrap();
        let sets = fx["sets"].as_array().unwrap();
        assert!(sets.len() >= 2);
        for set in sets {
            let key = derive_key(set["token"].as_str().unwrap());
            let vectors = set["vectors"].as_array().unwrap();
            assert!(vectors.len() >= 4);
            for v in vectors {
                assert_eq!(hash_with_key(key.as_ref(), v["input"].as_str().unwrap()), v["hash"].as_str().unwrap(), "input {:?}", v["input"]);
            }
        }
        assert_eq!(hash_with_key(derive_key("").as_ref(), "anything"), NO_KEY);
    }
}
