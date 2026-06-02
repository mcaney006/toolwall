use blake3::Hasher;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs;
use std::path::Path;
use toolwall_core::{ServerName, ToolFingerprint, ToolName};

/// Fingerprint format version; bump if hashing changes
pub const FINGERPRINT_VERSION: u32 = 1;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ToolFingerprintRecord {
    /// Format version for schema compat checks
    pub version: u32,
    pub server: String,
    pub name: String,
    pub hash: String,
}

impl ToolFingerprintRecord {
    /// Build a current-version baseline record from a computed fingerprint.
    pub fn from_fingerprint(fp: &ToolFingerprint) -> Self {
        ToolFingerprintRecord {
            version: FINGERPRINT_VERSION,
            server: fp.server.0.clone(),
            name: fp.name.0.clone(),
            hash: fp.hash.clone(),
        }
    }
}

pub fn compute_fingerprint(
    server: &ServerName,
    name: &ToolName,
    description: Option<&str>,
    input_schema: Option<&Value>,
    command: Option<&str>,
    args: Option<&[String]>,
) -> ToolFingerprint {
    let mut h = Hasher::new();
    h.update(server.0.as_bytes());
    h.update(name.0.as_bytes());
    if let Some(d) = description {
        h.update(d.as_bytes());
    }
    if let Some(schema) = input_schema {
        // Key ordering is stable only because serde_json's `preserve_order` feature is
        // off (Value::Object is a BTreeMap). If anything in the tree enables it, hashing
        // becomes insertion-order-dependent and fingerprints will be unstable.
        match serde_json::to_vec(schema) {
            Ok(s) => {
                h.update(&s);
            }
            Err(_) => {
                // Unhashable schema: include marker so fingerprint differs from no-schema
                h.update(b"[UNHASHABLE_SCHEMA]");
            }
        }
    }
    if let Some(c) = command {
        h.update(c.as_bytes());
    }
    if let Some(a) = args {
        for arg in a {
            h.update(arg.as_bytes());
        }
    }
    let hash = h.finalize().to_hex().to_string();
    ToolFingerprint {
        server: server.clone(),
        name: name.clone(),
        hash,
    }
}

pub fn save_baseline(path: &Path, records: &[ToolFingerprintRecord]) -> Result<(), std::io::Error> {
    // Validate path safety: reject absolute paths to system directories
    if path.is_absolute() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "baseline path must not be absolute",
        ));
    }
    let s =
        serde_json::to_string_pretty(records).map_err(|e| std::io::Error::other(e.to_string()))?;
    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "baseline path has no parent",
        )
    })?;
    fs::create_dir_all(parent)?;
    fs::write(path, s)
}

pub fn load_baseline(path: &Path) -> Result<Vec<ToolFingerprintRecord>, std::io::Error> {
    // Validate path safety: reject absolute paths
    if path.is_absolute() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "baseline path must not be absolute",
        ));
    }
    let s = fs::read_to_string(path)?;
    let recs: Vec<ToolFingerprintRecord> =
        serde_json::from_str(&s).map_err(|e| std::io::Error::other(e.to_string()))?;
    // Verify all records match our format version
    for rec in &recs {
        if rec.version != FINGERPRINT_VERSION {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "baseline has version {}, expected {}",
                    rec.version, FINGERPRINT_VERSION
                ),
            ));
        }
    }
    Ok(recs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_fingerprint_stable_across_key_order() {
        // The hash must not depend on JSON key insertion order, or every harmless
        // reserialization would look like drift. Guards against `preserve_order`.
        let server = ServerName("s".into());
        let name = ToolName("t".into());
        let schema_a = json!({"a": 1, "b": {"x": true, "y": false}});
        let schema_b = json!({"b": {"y": false, "x": true}, "a": 1});
        let fp_a = compute_fingerprint(&server, &name, Some("d"), Some(&schema_a), None, None);
        let fp_b = compute_fingerprint(&server, &name, Some("d"), Some(&schema_b), None, None);
        assert_eq!(fp_a.hash, fp_b.hash);
    }

    #[test]
    fn test_fingerprint_changes_with_schema_content() {
        let server = ServerName("s".into());
        let name = ToolName("t".into());
        let fp_a = compute_fingerprint(&server, &name, None, Some(&json!({"a": 1})), None, None);
        let fp_b = compute_fingerprint(&server, &name, None, Some(&json!({"a": 2})), None, None);
        assert_ne!(fp_a.hash, fp_b.hash);
    }

    #[test]
    fn test_version_mismatch_rejected() {
        let path = Path::new(".toolwall_test_fp/baseline-wrong-version.json");
        let _ = std::fs::create_dir_all(path.parent().unwrap());
        let bad_record = ToolFingerprintRecord {
            version: 999,
            server: "test".into(),
            name: "tool".into(),
            hash: "abc123".into(),
        };
        let _ = save_baseline(path, &[bad_record]);
        // Loading should fail version check
        let result = load_baseline(path);
        assert!(result.is_err(), "expected version mismatch error");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("version") || err_msg.contains("999"),
            "error message should mention version mismatch, got: {}",
            err_msg
        );
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_dir(".toolwall_test_fp");
    }

    #[test]
    fn test_absolute_path_rejected() {
        let rec = ToolFingerprintRecord {
            version: FINGERPRINT_VERSION,
            server: "test".into(),
            name: "tool".into(),
            hash: "abc123".into(),
        };
        let absolute_path = Path::new("/etc/passwd");
        let result = save_baseline(absolute_path, &[rec]);
        assert!(result.is_err());
    }
}
