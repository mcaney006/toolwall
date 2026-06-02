//! Error types for proxy operations.

use std::fmt;

#[derive(Debug)]
pub enum ProxyError {
    Io(std::io::Error),
    JsonDecode(serde_json::Error),
    MalformedToolCall(String),
    ProcessSpawn(String),
    InvalidServerResponse(String),
    PolicyEvaluation(String),
}

impl fmt::Display for ProxyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProxyError::Io(e) => write!(f, "io error: {}", e),
            ProxyError::JsonDecode(e) => write!(f, "json decode error: {}", e),
            ProxyError::MalformedToolCall(msg) => write!(f, "malformed tool call: {}", msg),
            ProxyError::ProcessSpawn(msg) => write!(f, "failed to spawn process: {}", msg),
            ProxyError::InvalidServerResponse(msg) => write!(f, "invalid server response: {}", msg),
            ProxyError::PolicyEvaluation(msg) => write!(f, "policy evaluation error: {}", msg),
        }
    }
}

impl std::error::Error for ProxyError {}

impl From<std::io::Error> for ProxyError {
    fn from(e: std::io::Error) -> Self {
        ProxyError::Io(e)
    }
}

impl From<serde_json::Error> for ProxyError {
    fn from(e: serde_json::Error) -> Self {
        ProxyError::JsonDecode(e)
    }
}
