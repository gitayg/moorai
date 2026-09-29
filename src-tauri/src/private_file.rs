// Owner-only file writes for ~/.moorai/config.json, which carries the install token and agent token.
// std::fs::write follows the process umask (typically 0644), leaving both readable by any local user.
// On unix the file is created 0600 and then chmod'ed 0600, so a config written by an older build
// (or by hand) is tightened on its next write too. Elsewhere this is std::fs::write: on Windows the
// file inherits the user-profile ACL, the same protection the Node side relies on for ~/.moorai.
use std::path::Path;

#[cfg(unix)]
pub fn write_private<P: AsRef<Path>>(path: P, contents: &str) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let path = path.as_ref();
    let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(path)?;
    // mode() applies only when the file is created; an existing 0644 file keeps its mode until this.
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    f.write_all(contents.as_bytes())
}

#[cfg(not(unix))]
pub fn write_private<P: AsRef<Path>>(path: P, contents: &str) -> std::io::Result<()> {
    std::fs::write(path, contents)
}

#[cfg(all(test, unix))]
mod tests {
    use super::write_private;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    fn scratch(name: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let dir = std::env::temp_dir().join(format!("moorai-private-{}-{}-{}", name, std::process::id(), nanos));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("config.json")
    }

    fn mode(p: &PathBuf) -> u32 { std::fs::metadata(p).unwrap().permissions().mode() & 0o777 }

    #[test]
    fn fresh_write_is_owner_only() {
        let p = scratch("fresh");
        write_private(&p, r#"{"installToken":"t"}"#).unwrap();
        assert_eq!(mode(&p), 0o600, "fresh config.json mode {:o}", mode(&p));
        assert_eq!(std::fs::read_to_string(&p).unwrap(), r#"{"installToken":"t"}"#);
    }

    #[test]
    fn overwrite_tightens_an_existing_0644_file() {
        let p = scratch("overwrite");
        std::fs::write(&p, "old contents that are longer than the new ones").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        write_private(&p, r#"{"agentToken":"a"}"#).unwrap();
        assert_eq!(mode(&p), 0o600, "overwritten config.json mode {:o}", mode(&p));
        assert_eq!(std::fs::read_to_string(&p).unwrap(), r#"{"agentToken":"a"}"#, "truncated, not appended");
    }
}
