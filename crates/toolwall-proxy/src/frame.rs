//! Line-delimited JSON-RPC frame handling.

use crate::error::ProxyError;
use serde_json::{json, Value};
use std::io::{BufRead, Write};

/// A JSON-RPC message frame.
#[derive(Debug, Clone)]
pub struct JsonRpcFrame {
    pub data: Value,
}

impl JsonRpcFrame {
    pub fn new(data: Value) -> Self {
        JsonRpcFrame { data }
    }

    /// Parse a frame from a JSON string.
    pub fn parse(s: &str) -> Result<Self, ProxyError> {
        let data = serde_json::from_str(s)?;
        Ok(JsonRpcFrame { data })
    }

    /// Serialize frame to JSON string (no newline).
    pub fn to_string(&self) -> Result<String, ProxyError> {
        Ok(serde_json::to_string(&self.data)?)
    }

    /// Get the JSON-RPC method name, if this is a request.
    pub fn method(&self) -> Option<String> {
        self.data
            .get("method")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    }

    /// Get the request ID if present.
    pub fn id(&self) -> Option<Value> {
        self.data.get("id").cloned()
    }

    /// Get params if present.
    pub fn params(&self) -> Option<Value> {
        self.data.get("params").cloned()
    }

    /// Create a JSON-RPC error response.
    pub fn error_response(
        request_id: Option<Value>,
        code: i32,
        message: &str,
    ) -> Result<Self, ProxyError> {
        let response = json!({
            "jsonrpc": "2.0",
            "id": request_id.unwrap_or(Value::Null),
            "error": {
                "code": code,
                "message": message,
            }
        });
        Ok(JsonRpcFrame::new(response))
    }

    pub fn is_result(&self) -> bool {
        self.data.get("result").is_some()
    }

    pub fn is_error(&self) -> bool {
        self.data.get("error").is_some()
    }
}

/// Reader for line-delimited JSON-RPC frames.
pub struct FrameReader<R: BufRead> {
    reader: R,
}

impl<R: BufRead> FrameReader<R> {
    pub fn new(reader: R) -> Self {
        FrameReader { reader }
    }

    /// Read the next frame.
    pub fn read_frame(&mut self) -> Result<Option<JsonRpcFrame>, ProxyError> {
        let mut line = String::new();
        let n = self.reader.read_line(&mut line)?;
        if n == 0 {
            return Ok(None);
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return Ok(None);
        }
        let frame = JsonRpcFrame::parse(trimmed)?;
        Ok(Some(frame))
    }
}

/// Writer for line-delimited JSON-RPC frames.
pub struct FrameWriter<W: Write> {
    writer: W,
}

impl<W: Write> FrameWriter<W> {
    pub fn new(writer: W) -> Self {
        FrameWriter { writer }
    }

    /// Write a frame (appends newline).
    pub fn write_frame(&mut self, frame: &JsonRpcFrame) -> Result<(), ProxyError> {
        let s = frame.to_string()?;
        self.writer.write_all(s.as_bytes())?;
        self.writer.write_all(b"\n")?;
        self.writer.flush()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_from_string() {
        let s = r#"{"jsonrpc":"2.0","method":"test","id":1}"#;
        let frame = JsonRpcFrame::parse(s).unwrap();
        assert_eq!(frame.method(), Some("test".to_string()));
    }

    #[test]
    fn test_error_response() {
        let frame =
            JsonRpcFrame::error_response(Some(json!(1)), -32600, "Invalid Request").unwrap();
        assert!(frame.is_error());
        assert_eq!(
            frame
                .data
                .get("error")
                .and_then(|e| e.get("message"))
                .and_then(|m| m.as_str()),
            Some("Invalid Request")
        );
    }
}
