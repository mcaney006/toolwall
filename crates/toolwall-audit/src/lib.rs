use serde::Serialize;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use toolwall_redact::redact_json;

pub struct AuditWriter {
    path: Box<Path>,
}

impl AuditWriter {
    pub fn new(path: &Path) -> Self {
        AuditWriter {
            path: Box::from(path),
        }
    }

    pub fn append_event<T: Serialize>(&self, event: &T) -> Result<(), std::io::Error> {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&*self.path)?;
        let mut v = serde_json::to_value(event).map_err(|_e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "failed to serialize audit event (check for non-serializable types)",
            )
        })?;
        // SECURITY: redact before writing to prevent secret leakage
        v = redact_json(&v);
        let s = serde_json::to_string(&v).map_err(|_e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "failed to encode redacted audit event",
            )
        })?;
        file.write_all(s.as_bytes())?;
        file.write_all(b"\n")?;
        // Explicitly flush to ensure audit events aren't lost
        file.flush()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_fs::fixture::PathChild;
    use assert_fs::TempDir;
    use serde_json::json;

    #[test]
    fn test_append_redacted() {
        let td = TempDir::new().unwrap();
        let child = td.child("audit.jsonl");
        let p = child.path();
        let w = AuditWriter::new(p);
        let obj = json!({"message":"token=sk-ABCDEF"});
        w.append_event(&obj).unwrap();
        let s = std::fs::read_to_string(p).unwrap();
        assert!(s.contains("REDACTED"));
    }

    #[test]
    fn test_no_raw_secret_reaches_disk() {
        // The audit log is the one artifact that persists, so it must never contain
        // a raw secret even if one slips into an event field.
        let td = TempDir::new().unwrap();
        let child = td.child("audit.jsonl");
        let p = child.path();
        let w = AuditWriter::new(p);

        let fakes = [
            "AKIAIOSFODNN7EXAMPLE",
            "ghp_FAKE0000000000000000000000000000000000",
            "sk-proj-FAKEFAKEFAKEFAKEFAKEFAKE",
        ];
        w.append_event(&json!({
            "args": { "key": fakes[0], "token": fakes[1] },
            "findings": [fakes[2]],
        }))
        .unwrap();

        let s = std::fs::read_to_string(p).unwrap();
        for f in fakes {
            assert!(!s.contains(f), "raw secret hit the audit log: {f}");
        }
    }
}
