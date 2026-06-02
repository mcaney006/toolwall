use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum ToolwallError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("other: {0}")]
    Other(String),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct ServerName(pub String);

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct ToolName(pub String);

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct SessionId(pub Uuid);

impl Default for SessionId {
    fn default() -> Self {
        SessionId(Uuid::new_v4())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny,
    ApprovalRequired,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ToolDescriptor {
    pub name: ToolName,
    pub description: Option<String>,
    pub input_schema: Option<serde_json::Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ToolFingerprint {
    pub server: ServerName,
    pub name: ToolName,
    pub hash: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ToolCall {
    pub server: ServerName,
    pub tool: ToolName,
    pub args: serde_json::Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditEvent {
    pub event_id: Uuid,
    pub timestamp: time::OffsetDateTime,
    pub session_id: SessionId,
    pub client: Option<String>,
    pub server: Option<String>,
    pub method: String,
    pub tool_name: Option<String>,
    pub decision: Decision,
    pub reason: Option<String>,
    pub rule_id: Option<String>,
    pub risk_level: Option<RiskLevel>,
    pub args_redacted: bool,
    pub fingerprint_before: Option<String>,
    pub fingerprint_after: Option<String>,
    pub findings: Vec<String>,
    pub latency_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DriftEvent {
    pub server: ServerName,
    pub tool: ToolName,
    pub message: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PolicyDecision {
    pub decision: Decision,
    pub reason: String,
    pub rule_id: Option<String>,
}
