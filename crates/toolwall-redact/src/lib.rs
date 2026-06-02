use regex::Regex;
use serde_json::Value;
use std::sync::OnceLock;

// Compile regexes once at first use, bail at runtime rather than panic if they're invalid.
// This is defensive: these are hardcoded regexes that should never fail, but if they do
// in a newer Rust version, we want to fail gracefully rather than panic silently.
fn get_redaction_regexes() -> Result<RedactionRegexes, String> {
    static REGEXES: OnceLock<Result<RedactionRegexes, String>> = OnceLock::new();
    REGEXES.get_or_init(RedactionRegexes::compile).clone()
}

#[derive(Clone)]
struct RedactionRegexes {
    aws: Regex,
    keyvalue: Regex,
    privkey: Regex,
    sk: Regex,
    ghp: Regex,
    akia: Regex,
    xox: Regex,
    apikey: Regex,
}

impl RedactionRegexes {
    fn compile() -> Result<Self, String> {
        Ok(RedactionRegexes {
            aws: Regex::new(r"(?i)aws(_|\-)?(access|secret)?[=:\s]*[A-Za-z0-9/+=]{16,}")
                .map_err(|e| format!("invalid aws regex: {}", e))?,
            keyvalue: Regex::new(
                r"(?i)(token|secret|password|pass|key)[=:\s]*[A-Za-z0-9_\-\.=]{8,}",
            )
            .map_err(|e| format!("invalid keyvalue regex: {}", e))?,
            privkey: Regex::new(r"-----BEGIN (RSA|OPENSSH|PRIVATE) PRIVATE KEY-----")
                .map_err(|e| format!("invalid privkey regex: {}", e))?,
            // Allow internal hyphens/underscores so modern keys like `sk-proj-…`
            // and `sk-svcacct-…` are caught, not just the legacy `sk-<alnum>` form.
            sk: Regex::new(r"\bsk-[A-Za-z0-9_-]{8,}")
                .map_err(|e| format!("invalid sk regex: {}", e))?,
            ghp: Regex::new(r"\bghp_[A-Za-z0-9]{8,}\b")
                .map_err(|e| format!("invalid ghp regex: {}", e))?,
            akia: Regex::new(r"\bAKIA[0-9A-Z]{8,}\b")
                .map_err(|e| format!("invalid akia regex: {}", e))?,
            xox: Regex::new(r"\bxox[boprs]-[A-Za-z0-9-]{8,}\b")
                .map_err(|e| format!("invalid xox regex: {}", e))?,
            apikey: Regex::new(r"\bAIza[0-9A-Za-z-_]{7,}\b")
                .map_err(|e| format!("invalid apikey regex: {}", e))?,
        })
    }
}

/// Redact secrets from a single string. Exposed so other crates (e.g. the scanner)
/// can sanitize evidence snippets before surfacing them.
pub fn redact_str(s: &str) -> String {
    // Limit redaction to reasonable string lengths to avoid DOS from huge payloads
    const MAX_REDACT_LEN: usize = 1_000_000;
    if s.len() > MAX_REDACT_LEN {
        return format!("[REDACTED_OVERSIZED_STRING: {} bytes]", s.len());
    }

    let regexes = match get_redaction_regexes() {
        Ok(r) => r,
        Err(_) => {
            // Regex compilation failed; fail safely by returning the original string redacted to signal error
            return "[REDACTION_ERROR]".to_string();
        }
    };
    let mut out = s.to_owned();
    out = regexes
        .aws
        .replace_all(&out, "[REDACTED_AWS_KEY]")
        .to_string();
    out = regexes
        .keyvalue
        .replace_all(&out, "[REDACTED_TOKEN]")
        .to_string();
    out = regexes
        .privkey
        .replace_all(&out, "[REDACTED_PRIVATE_KEY]")
        .to_string();
    out = regexes.sk.replace_all(&out, "[REDACTED_TOKEN]").to_string();
    out = regexes
        .ghp
        .replace_all(&out, "[REDACTED_TOKEN]")
        .to_string();
    out = regexes
        .akia
        .replace_all(&out, "[REDACTED_AWS_KEY]")
        .to_string();
    out = regexes
        .xox
        .replace_all(&out, "[REDACTED_TOKEN]")
        .to_string();
    out = regexes
        .apikey
        .replace_all(&out, "[REDACTED_TOKEN]")
        .to_string();
    out
}

pub fn redact_json(v: &Value) -> Value {
    match v {
        Value::String(s) => Value::String(redact_str(s)),
        Value::Array(arr) => Value::Array(arr.iter().map(redact_json).collect()),
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, val)| (k.clone(), redact_json(val)))
                .collect(),
        ),
        other => other.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_redact_simple() {
        let v = json!({"token":"sk-ABCDEF1234567890"});
        let r = redact_json(&v);
        assert!(r.to_string().contains("REDACTED"));
    }

    #[test]
    fn test_redact_aws_key() {
        let v = json!({"cred":"AKIA2E1B2C3D4E5F6G7H"});
        let r = redact_json(&v);
        assert!(r.to_string().contains("REDACTED"));
    }

    #[test]
    fn test_redact_github_token() {
        let v = json!({"pat":"ghp_1234567890abcdefghij"});
        let r = redact_json(&v);
        assert!(r.to_string().contains("REDACTED"));
    }

    #[test]
    fn test_redact_oversized_string() {
        // Even without secret patterns, massive strings should be flagged
        let huge = "x".repeat(2_000_000);
        let result = redact_str(&huge);
        assert!(result.contains("REDACTED_OVERSIZED_STRING"));
    }

    #[test]
    fn test_modern_openai_project_key_redacted() {
        // Regression: the legacy `sk-<alnum>` pattern missed hyphenated project keys.
        let raw = "sk-proj-FAKEFAKEFAKEFAKEFAKEFAKE";
        let out = redact_json(&json!({ "api_key": raw })).to_string();
        assert!(out.contains("REDACTED"));
        assert!(!out.contains(raw), "raw OpenAI key leaked: {out}");
    }

    #[test]
    fn test_private_key_block_redacted() {
        let out = redact_json(&json!({ "pem": "-----BEGIN OPENSSH PRIVATE KEY-----\nzzz\n" }))
            .to_string();
        assert!(out.contains("REDACTED_PRIVATE_KEY"));
        assert!(!out.contains("BEGIN OPENSSH PRIVATE KEY"));
    }

    #[test]
    fn test_no_fake_secret_survives_redaction() {
        // All clearly-fake fixtures. None may appear verbatim in the output.
        let fakes = [
            "AKIAIOSFODNN7EXAMPLE",
            "ghp_FAKE0000000000000000000000000000000000",
            "sk-proj-FAKEFAKEFAKEFAKEFAKEFAKE",
        ];
        let v = json!({
            "aws": fakes[0],
            "nested": { "gh": fakes[1], "list": [fakes[2]] },
        });
        let out = redact_json(&v).to_string();
        for f in fakes {
            assert!(!out.contains(f), "secret leaked through redaction: {f}");
        }
    }
}
