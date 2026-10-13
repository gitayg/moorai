//! The per-device ed25519 key (contract §5.1). Generated at first start inside the helper's state
//! directory, never leaves it. On the wire the public key is base64 (standard, padded) SPKI DER, the
//! form `parseTrustedKeys` (cli/hook-core.mjs) and policy-sign.js already use; the key id is the
//! first 32 lowercase hex characters of sha256(raw 32-byte public key).

use crate::canonical::{hex, sha256_hex};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ring::signature::{self, Ed25519KeyPair, KeyPair};
use std::path::Path;

/// DER prefix of an ed25519 SubjectPublicKeyInfo; the raw key follows (12 + 32 = 44 bytes).
pub const SPKI_ED25519_PREFIX: [u8; 12] = [0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];
pub const KEY_ID_HEX_LEN: usize = 32;

#[derive(Debug)]
pub enum KeyError {
    BadSeed,
    BadPublicKey,
    BadSignature,
    Io(std::io::Error),
}

pub struct DeviceKey {
    pair: Ed25519KeyPair,
}

impl DeviceKey {
    /// Deterministic key from a 32-byte seed. Production seeds come from `SystemRandom`; tests use
    /// the public golden seed in test/fixtures/guardd/golden.json.
    pub fn from_seed(seed: &[u8]) -> Result<Self, KeyError> {
        let pair = Ed25519KeyPair::from_seed_unchecked(seed).map_err(|_| KeyError::BadSeed)?;
        Ok(DeviceKey { pair })
    }

    /// A fresh key from the OS CSPRNG, with its seed (the seed is what `device.key` stores).
    pub fn generate() -> Result<(Self, [u8; 32]), KeyError> {
        use ring::rand::SecureRandom;
        let mut seed = [0u8; 32];
        ring::rand::SystemRandom::new().fill(&mut seed).map_err(|_| KeyError::BadSeed)?;
        Ok((Self::from_seed(&seed)?, seed))
    }

    /// Load `device.key` (contract §4) or create it, 0600 / SYSTEM-only, on first start. A key file
    /// that exists but does not parse is NOT replaced silently: it is an error the helper reports,
    /// because replacing it changes the key id and raises "device key changed" on the console.
    pub fn load_or_create(state_dir: &Path) -> Result<Self, KeyError> {
        let path = state_dir.join(crate::state::files::DEVICE_KEY);
        match load_seed_file(&path)? {
            Some(k) => Ok(k),
            None => {
                let (k, seed) = Self::generate()?;
                crate::state::write_atomic(&path, format!("{}\n", hex(&seed)).as_bytes()).map_err(KeyError::Io)?;
                Ok(k)
            }
        }
    }
    pub fn raw_public(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(self.pair.public_key().as_ref());
        out
    }

    pub fn public_spki_b64(&self) -> String {
        spki_b64_of_raw(&self.raw_public())
    }

    pub fn key_id(&self) -> String {
        key_id_of_raw(&self.raw_public())
    }

    /// Detached signature over `msg`, base64 standard padded.
    pub fn sign_b64(&self, msg: &[u8]) -> String {
        B64.encode(self.pair.sign(msg).as_ref())
    }
}

/// Parse a seed file: 64 lowercase hex characters, one optional trailing newline. None when absent.
fn load_seed_file(path: &Path) -> Result<Option<DeviceKey>, KeyError> {
    let bytes = match crate::state::read_private(path).map_err(KeyError::Io)? {
        None => return Ok(None),
        Some(b) => b,
    };
    let text = std::str::from_utf8(&bytes).map_err(|_| KeyError::BadSeed)?;
    let text = text.strip_suffix('\n').unwrap_or(text);
    if text.len() != 64 || !text.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)) {
        return Err(KeyError::BadSeed);
    }
    let seed = crate::canonical::unhex(text).ok_or(KeyError::BadSeed)?;
    DeviceKey::from_seed(&seed).map(Some)
}

/// Planned rotation, step 1 (contract §5.2 `rotated`): the pending new key, created once and kept in
/// `device.key.next` until the console accepted it, so a crash or a failed registration retries with
/// the same key instead of minting another.
pub fn stage_rotation(state_dir: &Path) -> Result<DeviceKey, KeyError> {
    let path = state_dir.join(crate::state::files::DEVICE_KEY_NEXT);
    if let Some(k) = load_seed_file(&path)? {
        return Ok(k);
    }
    let (k, seed) = DeviceKey::generate()?;
    crate::state::write_atomic(&path, format!("{}\n", hex(&seed)).as_bytes()).map_err(KeyError::Io)?;
    Ok(k)
}

/// The pending rotation key, if one is staged.
pub fn pending_rotation(state_dir: &Path) -> Result<Option<DeviceKey>, KeyError> {
    load_seed_file(&state_dir.join(crate::state::files::DEVICE_KEY_NEXT))
}

/// Planned rotation, step 2: the console accepted the new key, so it becomes `device.key` (atomic
/// rename, then fsync of the directory).
pub fn commit_rotation(state_dir: &Path) -> Result<(), KeyError> {
    let next = state_dir.join(crate::state::files::DEVICE_KEY_NEXT);
    std::fs::rename(&next, state_dir.join(crate::state::files::DEVICE_KEY)).map_err(KeyError::Io)?;
    std::fs::File::open(state_dir).and_then(|d| crate::state::fsync(&d)).map_err(KeyError::Io)
}

/// Publish `device.pub` (contract §4.2) in the run dir, 0644: the base64 SPKI and a newline. The hook
/// reads it through readRootOwned and verifies the hello proof against it.
pub fn write_device_pub(run_dir: &Path, key: &DeviceKey) -> std::io::Result<()> {
    crate::state::write_atomic_mode(&run_dir.join(crate::state::files::DEVICE_PUB), format!("{}\n", key.public_spki_b64()).as_bytes(), 0o644)
}

pub fn spki_b64_of_raw(raw: &[u8; 32]) -> String {
    let mut der = SPKI_ED25519_PREFIX.to_vec();
    der.extend_from_slice(raw);
    B64.encode(der)
}

pub fn key_id_of_raw(raw: &[u8; 32]) -> String {
    sha256_hex(raw)[..KEY_ID_HEX_LEN].to_string()
}

/// Raw 32-byte key from base64 SPKI DER; anything but exactly the ed25519 SPKI shape is refused.
pub fn raw_from_spki_b64(spki_b64: &str) -> Result<[u8; 32], KeyError> {
    let der = B64.decode(spki_b64).map_err(|_| KeyError::BadPublicKey)?;
    if der.len() != 44 || der[..12] != SPKI_ED25519_PREFIX {
        return Err(KeyError::BadPublicKey);
    }
    let mut raw = [0u8; 32];
    raw.copy_from_slice(&der[12..]);
    Ok(raw)
}

pub fn verify_b64(spki_b64: &str, msg: &[u8], sig_b64: &str) -> Result<(), KeyError> {
    let raw = raw_from_spki_b64(spki_b64)?;
    let sig = B64.decode(sig_b64).map_err(|_| KeyError::BadSignature)?;
    signature::UnparsedPublicKey::new(&signature::ED25519, raw)
        .verify(msg, &sig)
        .map_err(|_| KeyError::BadSignature)
}

/// deviceId (contract §5.1): first 32 hex of sha256("moorai-device|v1|" + OS machine id).
pub fn device_id_of_machine_id(machine_id: &str) -> String {
    sha256_hex(format!("moorai-device|v1|{machine_id}").as_bytes())[..32].to_string()
}

/// A fresh 16-byte nonce as 32 lowercase hex (contract §6.3).
pub fn new_nonce_hex() -> String {
    use ring::rand::SecureRandom;
    let mut b = [0u8; 16];
    ring::rand::SystemRandom::new().fill(&mut b).expect("system RNG");
    hex(&b)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    fn dir(tag: &str) -> std::path::PathBuf {
        let d = crate::state::test_root(&format!("keys-{tag}"));
        std::fs::create_dir_all(&d).unwrap();
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
        d
    }

    #[test]
    fn first_start_generates_and_persists_0600_then_reloads_the_same_key() {
        let d = dir("gen");
        let k1 = DeviceKey::load_or_create(&d).unwrap();
        let f = d.join("device.key");
        assert_eq!(std::fs::metadata(&f).unwrap().mode() & 0o777, 0o600);
        let k2 = DeviceKey::load_or_create(&d).unwrap();
        assert_eq!(k1.key_id(), k2.key_id());
        let other = DeviceKey::load_or_create(&dir("gen2")).unwrap();
        assert_ne!(k1.key_id(), other.key_id(), "seeds come from the CSPRNG");
    }

    #[test]
    fn an_unparseable_key_file_is_an_error_and_is_left_in_place() {
        let d = dir("bad");
        let f = d.join("device.key");
        crate::state::write_atomic(&f, b"not hex at all").unwrap();
        assert!(matches!(DeviceKey::load_or_create(&d), Err(KeyError::BadSeed)));
        assert_eq!(std::fs::read(&f).unwrap(), b"not hex at all", "never silently replaced");
        crate::state::write_atomic(&f, "AB".repeat(32).as_bytes()).unwrap();
        assert!(matches!(DeviceKey::load_or_create(&d), Err(KeyError::BadSeed)), "upper-case hex is not the stored form");
    }

    #[test]
    fn a_key_file_readable_by_others_is_refused() {
        let d = dir("mode");
        DeviceKey::load_or_create(&d).unwrap();
        std::fs::set_permissions(d.join("device.key"), std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(DeviceKey::load_or_create(&d), Err(KeyError::Io(_))));
    }

    #[test]
    fn rotation_stages_one_key_and_commits_it() {
        let d = dir("rot");
        let old = DeviceKey::load_or_create(&d).unwrap();
        let n1 = stage_rotation(&d).unwrap();
        let n2 = stage_rotation(&d).unwrap();
        assert_eq!(n1.key_id(), n2.key_id(), "a retried rotation reuses the staged key");
        assert_ne!(n1.key_id(), old.key_id());
        assert_eq!(pending_rotation(&d).unwrap().unwrap().key_id(), n1.key_id());
        commit_rotation(&d).unwrap();
        assert_eq!(DeviceKey::load_or_create(&d).unwrap().key_id(), n1.key_id());
        assert!(pending_rotation(&d).unwrap().is_none());
    }

    #[test]
    fn device_pub_is_world_readable_spki() {
        let d = dir("pub");
        let k = DeviceKey::load_or_create(&d).unwrap();
        write_device_pub(&d, &k).unwrap();
        let f = d.join("device.pub");
        assert_eq!(std::fs::metadata(&f).unwrap().mode() & 0o777, 0o644);
        assert_eq!(std::fs::read_to_string(&f).unwrap().trim(), k.public_spki_b64());
    }
}
