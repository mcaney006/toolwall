use globset::{GlobBuilder, GlobSet, GlobSetBuilder};
use serde::Deserialize;
use serde_json::Value as JsonValue;
use std::path::Path;
use toolwall_core::{Decision, PolicyDecision, ServerName, ToolName};

#[derive(Debug)]
pub enum PolicyError {
    TomlError(String),
    InvalidGlob(Vec<String>),
    GlobBuild(String),
    UnsupportedArgs(String),
}

impl std::error::Error for PolicyError {}

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PolicyError::TomlError(e) => write!(f, "policy toml error: {}", e),
            PolicyError::InvalidGlob(patterns) => {
                write!(f, "invalid glob patterns: {}", patterns.join(", "))
            }
            PolicyError::GlobBuild(e) => write!(f, "failed to build glob set: {}", e),
            PolicyError::UnsupportedArgs(msg) => write!(f, "unsupported args constraint: {}", msg),
        }
    }
}

impl From<toml::de::Error> for PolicyError {
    fn from(e: toml::de::Error) -> Self {
        PolicyError::TomlError(e.to_string())
    }
}

#[derive(Debug, Deserialize)]
pub struct PolicyFile {
    pub version: Option<u32>,
    pub defaults: Option<Defaults>,
    pub secrets: Option<Secrets>,
    #[serde(default)]
    pub rules: Vec<Rule>,
}

/// The effect a rule (or the default) applies when it matches. Deserializing an
/// unknown value fails the whole policy load — an unrecognised effect is a config
/// error we refuse to run with, rather than a rule we silently treat as something.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicyEffect {
    Allow,
    Deny,
    #[serde(rename = "approval")]
    RequireApproval,
}

impl PolicyEffect {
    fn to_decision(self) -> Decision {
        match self {
            PolicyEffect::Allow => Decision::Allow,
            PolicyEffect::Deny => Decision::Deny,
            PolicyEffect::RequireApproval => Decision::ApprovalRequired,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct Defaults {
    pub decision: Option<PolicyEffect>,
    pub log: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct Secrets {
    pub protected_paths: Vec<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Rule {
    pub id: String,
    pub effect: PolicyEffect,
    pub server: Option<String>,
    pub tool: Option<toml::Value>,
    pub args: Option<toml::Value>,
}

pub struct PolicyEngine {
    file: PolicyFile,
    protected_globset: Option<GlobSet>,
    /// Compiled `args` constraints, one entry per rule in `file.rules` (same order).
    rule_arg_matchers: Vec<Vec<ArgMatcher>>,
}

/// A single compiled `args` constraint. All matchers on a rule must hold for the
/// rule to match (logical AND), so an unsatisfied constraint causes the rule to be
/// skipped — including allow rules, which is the fail-closed behaviour we want.
#[derive(Debug)]
enum ArgMatcher {
    /// `any_path = { matches_any_secret = <bool> }`: whether any path-like string in
    /// the args matches a protected secret glob must equal the expected boolean.
    AnyPathMatchesSecret(bool),
    /// `<key> = { within = "<prefix>" }`: the string at `key` must be a path inside `prefix`.
    Within { key: String, prefix: String },
    /// `<key> = "<value>"`: the string at `key` must equal `value` exactly.
    Equals { key: String, value: String },
}

impl ArgMatcher {
    fn matches(&self, args: &JsonValue, globset: Option<&GlobSet>) -> bool {
        match self {
            ArgMatcher::AnyPathMatchesSecret(expected) => {
                // With no configured globset, nothing can match a secret path.
                let found = globset
                    .map(|gs| find_any_path_matches(args, gs))
                    .unwrap_or(false);
                found == *expected
            }
            ArgMatcher::Within { key, prefix } => args
                .get(key)
                .and_then(|v| v.as_str())
                .is_some_and(|s| path_within(s, prefix)),
            ArgMatcher::Equals { key, value } => {
                args.get(key).and_then(|v| v.as_str()) == Some(value.as_str())
            }
        }
    }
}

/// Compile a rule's `args` table into matchers, rejecting any shape we cannot enforce.
/// Rejecting (rather than ignoring) unknown constraints keeps the engine fail-closed:
/// a policy author never gets a rule that silently matches more than they wrote.
fn compile_arg_matchers(args: &toml::Value) -> Result<Vec<ArgMatcher>, PolicyError> {
    let table = args
        .as_table()
        .ok_or_else(|| PolicyError::UnsupportedArgs("rule `args` must be a table".to_string()))?;
    let mut matchers = Vec::with_capacity(table.len());
    for (key, val) in table {
        if key == "any_path" {
            let b = val
                .get("matches_any_secret")
                .and_then(|v| v.as_bool())
                .ok_or_else(|| {
                    PolicyError::UnsupportedArgs(
                        "`any_path` requires a boolean `matches_any_secret`".to_string(),
                    )
                })?;
            matchers.push(ArgMatcher::AnyPathMatchesSecret(b));
        } else if let Some(prefix) = val
            .as_table()
            .and_then(|t| t.get("within"))
            .and_then(|v| v.as_str())
        {
            matchers.push(ArgMatcher::Within {
                key: key.clone(),
                prefix: prefix.to_string(),
            });
        } else if let Some(s) = val.as_str() {
            matchers.push(ArgMatcher::Equals {
                key: key.clone(),
                value: s.to_string(),
            });
        } else {
            return Err(PolicyError::UnsupportedArgs(format!(
                "key `{}` uses an unsupported constraint shape",
                key
            )));
        }
    }
    Ok(matchers)
}

/// Whether `path` is contained within `prefix`, rejecting `..` traversal and
/// absolute/relative mismatches (an absolute or `~`-rooted path is never within `./`).
fn path_within(path: &str, prefix: &str) -> bool {
    if path.split(['/', '\\']).any(|c| c == "..") {
        return false;
    }
    let path_abs = path.starts_with('/') || path.starts_with('~');
    let prefix_abs = prefix.starts_with('/') || prefix.starts_with('~');
    if path_abs != prefix_abs {
        return false;
    }
    let norm = |p: &str| p.trim_start_matches("./").trim_end_matches('/').to_string();
    let np = norm(path);
    let npre = norm(prefix);
    npre.is_empty() || np == npre || np.starts_with(&format!("{}/", npre))
}

impl PolicyEngine {
    pub fn from_toml_str(s: &str) -> Result<Self, PolicyError> {
        let file: PolicyFile = toml::from_str(s)?;
        // Validate that protected paths compile
        let protected_globset = file
            .secrets
            .as_ref()
            .map(|sec| {
                let mut builder = GlobSetBuilder::new();
                let mut failed = Vec::new();
                for p in &sec.protected_paths {
                    // Case-insensitive so `.SSH` can't slip past `~/.ssh/**` on
                    // case-insensitive filesystems. Invalid globs are collected, not
                    // silently dropped.
                    match GlobBuilder::new(p).case_insensitive(true).build() {
                        Ok(g) => {
                            builder.add(g);
                        }
                        Err(_) => failed.push(p.clone()),
                    }
                }
                if !failed.is_empty() {
                    return Err(PolicyError::InvalidGlob(failed));
                }
                builder
                    .build()
                    .map_err(|e| PolicyError::GlobBuild(e.to_string()))
            })
            .transpose()?;
        // Compile each rule's args constraints up front so unsupported shapes are
        // rejected at load time rather than silently ignored during evaluation.
        let rule_arg_matchers = file
            .rules
            .iter()
            .map(|rule| match &rule.args {
                Some(args) => compile_arg_matchers(args),
                None => Ok(Vec::new()),
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(PolicyEngine {
            file,
            protected_globset,
            rule_arg_matchers,
        })
    }

    /// Evaluate a call given server, tool and an args JSON value (may be null)
    pub fn evaluate(
        &self,
        server: &ServerName,
        tool: &ToolName,
        args: &serde_json::Value,
    ) -> PolicyDecision {
        let mut matched: Vec<(&Rule, PolicyEffect)> = Vec::new();
        for (idx, rule) in self.file.rules.iter().enumerate() {
            let server_match = match &rule.server {
                Some(s) if s == "*" => true,
                Some(s) => s == &server.0,
                None => true,
            };
            if !server_match {
                continue;
            }
            // Convert the toml tool value to json so string/array forms match uniformly.
            let tool_match = match &rule.tool {
                Some(v) => {
                    let tv: JsonValue = serde_json::to_value(v).unwrap_or(JsonValue::Null);
                    match tv {
                        JsonValue::String(s) if s == "*" => true,
                        JsonValue::String(s) => s == tool.0,
                        JsonValue::Array(arr) => arr.iter().any(|x| {
                            if let JsonValue::String(s) = x {
                                s == &tool.0
                            } else {
                                false
                            }
                        }),
                        _ => false,
                    }
                }
                None => true,
            };
            if !tool_match {
                continue;
            }

            // All compiled args constraints must hold (logical AND). An empty matcher
            // list means the rule places no constraint on args.
            let args_match = self.rule_arg_matchers[idx]
                .iter()
                .all(|m| m.matches(args, self.protected_globset.as_ref()));

            if args_match {
                matched.push((rule, rule.effect));
            }
        }

        // Final decision priority: deny > approval > allow > default.
        let mut has_deny = false;
        let mut has_approval = false;
        let mut has_allow = false;
        let mut reason = String::from("default");
        let mut rule_id = None;
        for (r, eff) in matched {
            match eff {
                PolicyEffect::Deny => {
                    has_deny = true;
                    reason = format!("matched deny rule {}", r.id);
                    rule_id = Some(r.id.clone());
                }
                PolicyEffect::RequireApproval => {
                    has_approval = true;
                    if rule_id.is_none() {
                        reason = format!("matched approval rule {}", r.id);
                        rule_id = Some(r.id.clone());
                    }
                }
                PolicyEffect::Allow => {
                    has_allow = true;
                    if rule_id.is_none() {
                        reason = format!("matched allow rule {}", r.id);
                        rule_id = Some(r.id.clone());
                    }
                }
            }
        }

        let decision = if has_deny {
            Decision::Deny
        } else if has_approval {
            Decision::ApprovalRequired
        } else if has_allow {
            Decision::Allow
        } else {
            // No rule matched: fall back to the configured default, or deny if unset.
            self.file
                .defaults
                .as_ref()
                .and_then(|d| d.decision)
                .map(PolicyEffect::to_decision)
                .unwrap_or(Decision::Deny)
        };

        PolicyDecision {
            decision,
            reason,
            rule_id,
        }
    }
}

fn find_any_path_matches(v: &JsonValue, gs: &GlobSet) -> bool {
    match v {
        JsonValue::String(s) => path_match_candidates(s)
            .iter()
            .any(|c| gs.is_match(Path::new(c))),
        JsonValue::Array(arr) => arr.iter().any(|x| find_any_path_matches(x, gs)),
        JsonValue::Object(map) => map.values().any(|x| find_any_path_matches(x, gs)),
        _ => false,
    }
}

/// Lexically normalize a path string (no filesystem access, so no symlink TOCTOU):
/// unify separators, drop empty/`.` components, and resolve `..` textually. Keeps a
/// leading `/` or `~`. This collapses traversal tricks like `~/.ssh/../.ssh/id_rsa`
/// down to their canonical form before matching.
fn lexical_normalize(s: &str) -> String {
    let unified = s.replace('\\', "/");
    let is_abs = unified.starts_with('/');
    let mut out: Vec<&str> = Vec::new();
    for comp in unified.split('/') {
        match comp {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            other => out.push(other),
        }
    }
    let joined = out.join("/");
    if is_abs {
        format!("/{joined}")
    } else {
        joined
    }
}

/// Candidate forms of a path to test against the protected globset. Beyond the
/// normalized path, this bridges `~` and the real home directory in both directions
/// so a glob written as `~/.ssh/**` also catches a fully-expanded `/home/u/.ssh/...`
/// argument (and vice versa).
fn path_match_candidates(s: &str) -> Vec<String> {
    let norm = lexical_normalize(s);
    let mut candidates = vec![norm.clone()];
    if let Some(home) = home_dir() {
        let home = lexical_normalize(&home);
        if let Some(rest) = norm.strip_prefix("~/") {
            candidates.push(format!("{home}/{rest}"));
        } else if norm == "~" {
            candidates.push(home.clone());
        } else if let Some(rest) = norm.strip_prefix(&format!("{home}/")) {
            candidates.push(format!("~/{rest}"));
        } else if norm == home {
            candidates.push("~".to_string());
        }
    }
    candidates
}

fn home_dir() -> Option<String> {
    std::env::var("HOME")
        .ok()
        .or_else(|| std::env::var("USERPROFILE").ok())
        .filter(|h| !h.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const EXAMPLE: &str = r#"
version = 1

[defaults]
decision = "deny"

[[rules]]
id = "allow_project_reads"
effect = "allow"
server = "filesystem"
tool = "read_file"
"#;

    #[test]
    fn test_allow_rule() {
        let eng = PolicyEngine::from_toml_str(EXAMPLE).unwrap();
        let server = ServerName("filesystem".into());
        let tool = ToolName("read_file".into());
        let args = json!({"path":"./README.md"});
        let pd = eng.evaluate(&server, &tool, &args);
        assert!(matches!(pd.decision, toolwall_core::Decision::Allow));
    }

    #[test]
    fn test_unknown_effect_rejected_at_load() {
        let policy = r#"
version = 1
[defaults]
decision = "deny"
[[rules]]
id = "bad_effect"
effect = "unknown_effect_type"
server = "*"
tool = "*"
"#;
        // An unrecognised effect is a config error: refuse to load rather than run
        // with a rule whose meaning we can't represent.
        assert!(PolicyEngine::from_toml_str(policy).is_err());
    }

    #[test]
    fn test_invalid_glob_pattern_rejected() {
        let policy = r#"
version = 1
[defaults]
decision = "deny"
[secrets]
protected_paths = ["[invalid(glob"]
"#;
        let result = PolicyEngine::from_toml_str(policy);
        // Invalid glob patterns must be rejected at parse time, not silently ignored
        assert!(result.is_err());
    }

    #[test]
    fn test_deny_beats_allow() {
        let policy = r#"
version = 1
[defaults]
decision = "deny"
[[rules]]
id = "allow_all"
effect = "allow"
server = "*"
tool = "*"
[[rules]]
id = "deny_dangerous"
effect = "deny"
server = "*"
tool = "*"
"#;
        let eng = PolicyEngine::from_toml_str(policy).unwrap();
        let server = ServerName("anything".into());
        let tool = ToolName("anything".into());
        let args = json!({});
        let pd = eng.evaluate(&server, &tool, &args);
        // Deny must win even if allow rule also matches
        assert!(matches!(pd.decision, toolwall_core::Decision::Deny));
    }

    const OWNER_POLICY: &str = r#"
version = 1
[defaults]
decision = "deny"
[[rules]]
id = "restrict-github-org"
effect = "allow"
server = "github"
tool = "*"
args = { owner = "trusted-org" }
"#;

    #[test]
    fn test_equals_constraint_matches_only_exact_value() {
        let eng = PolicyEngine::from_toml_str(OWNER_POLICY).unwrap();
        let server = ServerName("github".into());
        let tool = ToolName("create_issue".into());

        let allowed = eng.evaluate(&server, &tool, &json!({"owner": "trusted-org"}));
        assert!(matches!(allowed.decision, Decision::Allow));

        // Previously this matched the allow rule regardless of owner (fail-open);
        // now a non-matching owner falls through to the default deny.
        let denied = eng.evaluate(&server, &tool, &json!({"owner": "attacker"}));
        assert!(matches!(denied.decision, Decision::Deny));
        let missing = eng.evaluate(&server, &tool, &json!({}));
        assert!(matches!(missing.decision, Decision::Deny));
    }

    #[test]
    fn test_within_constraint() {
        let policy = r#"
version = 1
[defaults]
decision = "deny"
[[rules]]
id = "allow-project-reads"
effect = "allow"
server = "filesystem"
tool = "read_file"
args = { path = { within = "./" } }
"#;
        let eng = PolicyEngine::from_toml_str(policy).unwrap();
        let server = ServerName("filesystem".into());
        let tool = ToolName("read_file".into());

        let inside = eng.evaluate(&server, &tool, &json!({"path": "./src/main.rs"}));
        assert!(matches!(inside.decision, Decision::Allow));
        // Absolute / home paths and traversal are not "within ./" -> default deny.
        assert!(matches!(
            eng.evaluate(&server, &tool, &json!({"path": "/etc/passwd"}))
                .decision,
            Decision::Deny
        ));
        assert!(matches!(
            eng.evaluate(&server, &tool, &json!({"path": "./../secret"}))
                .decision,
            Decision::Deny
        ));
    }

    #[test]
    fn test_matches_any_secret_requires_globset() {
        // A deny rule keyed on matches_any_secret=true must NOT fire when no path
        // matches (and must not fire at all when there is no [secrets] globset).
        let policy = r#"
version = 1
[defaults]
decision = "allow"
[secrets]
protected_paths = ["**/.env"]
[[rules]]
id = "deny-secret-paths"
effect = "deny"
server = "*"
tool = "*"
args = { any_path = { matches_any_secret = true } }
"#;
        let eng = PolicyEngine::from_toml_str(policy).unwrap();
        let server = ServerName("filesystem".into());
        let tool = ToolName("read_file".into());

        assert!(matches!(
            eng.evaluate(&server, &tool, &json!({"path": "config/.env"}))
                .decision,
            Decision::Deny
        ));
        assert!(matches!(
            eng.evaluate(&server, &tool, &json!({"path": "config/app.toml"}))
                .decision,
            Decision::Allow
        ));
    }

    #[test]
    fn test_unsupported_args_constraint_rejected_at_load() {
        let policy = r#"
version = 1
[[rules]]
id = "bad"
effect = "allow"
server = "*"
tool = "*"
args = { size = { greater_than = 100 } }
"#;
        match PolicyEngine::from_toml_str(policy) {
            Err(PolicyError::UnsupportedArgs(_)) => {}
            other => panic!("expected UnsupportedArgs, got {:?}", other.err()),
        }
    }

    #[test]
    fn test_shipped_example_config_loads() {
        // Guards against the example drifting out of sync with what the engine supports.
        let example = include_str!("../../../examples/toolwall.toml");
        assert!(PolicyEngine::from_toml_str(example).is_ok());
    }

    const SECRETS_POLICY: &str = r#"
version = 1
[defaults]
decision = "allow"
[secrets]
protected_paths = ["~/.ssh/**", "**/.env", "**/id_rsa"]
[[rules]]
id = "deny-secrets"
effect = "deny"
server = "*"
tool = "*"
args = { any_path = { matches_any_secret = true } }
"#;

    fn denies_path(eng: &PolicyEngine, path: &str) -> bool {
        let pd = eng.evaluate(
            &ServerName("fs".into()),
            &ToolName("read_file".into()),
            &json!({ "path": path }),
        );
        matches!(pd.decision, Decision::Deny)
    }

    #[test]
    fn test_secret_path_bypasses_are_caught() {
        let eng = PolicyEngine::from_toml_str(SECRETS_POLICY).unwrap();
        // Direct hits.
        assert!(denies_path(&eng, "~/.ssh/id_rsa"));
        assert!(denies_path(&eng, "project/.env"));
        assert!(denies_path(&eng, "a/b/c/.env"));
        assert!(denies_path(&eng, "./id_rsa"));
        // Evasion attempts that lexical normalization must defeat.
        assert!(denies_path(&eng, "~/.ssh/../.ssh/id_rsa"), "traversal");
        assert!(denies_path(&eng, "~/.ssh//config"), "repeated slashes");
        assert!(denies_path(&eng, "~\\.ssh\\id_rsa"), "windows separators");
        assert!(denies_path(&eng, "~/.SSH/id_rsa"), "case folding");
        // Benign paths stay allowed (no over-blocking).
        assert!(!denies_path(&eng, "src/main.rs"));
        assert!(!denies_path(&eng, "README.md"));
    }

    #[test]
    fn test_expanded_home_matches_tilde_glob() {
        std::env::set_var("HOME", "/home/tester");
        let eng = PolicyEngine::from_toml_str(SECRETS_POLICY).unwrap();
        // A fully-expanded absolute path must still match a glob written with `~`.
        assert!(denies_path(&eng, "/home/tester/.ssh/id_rsa"));
        assert!(denies_path(&eng, "/home/tester/.ssh/config"));
        assert!(!denies_path(&eng, "/home/tester/projects/app.rs"));
    }
}
