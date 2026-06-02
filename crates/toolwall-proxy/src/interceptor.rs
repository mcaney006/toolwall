//! Request and response interceptors.

use crate::error::ProxyError;
use crate::frame::JsonRpcFrame;
use serde_json::Value;
use toolwall_core::{Decision, ServerName, ToolDescriptor, ToolFingerprint, ToolName};
use toolwall_fingerprint::compute_fingerprint;
use toolwall_policy::PolicyEngine;
use toolwall_scan::{scan_tool_metadata, ScanFinding};

/// Intercept a tools/call request. Return None if should be forwarded as-is, Some(error_frame) if denied.
pub fn intercept_tools_call(
    frame: &JsonRpcFrame,
    server: &ServerName,
    policy_engine: &PolicyEngine,
) -> Result<Option<JsonRpcFrame>, ProxyError> {
    let method = frame.method();
    if method.as_deref() != Some("tools/call") {
        return Ok(None);
    }

    let params = frame
        .params()
        .ok_or_else(|| ProxyError::MalformedToolCall("tools/call requires 'params'".to_string()))?;
    let params_obj = params.as_object().ok_or_else(|| {
        ProxyError::MalformedToolCall("tools/call params must be an object".to_string())
    })?;

    let tool_name = params_obj
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ProxyError::MalformedToolCall("params.name must be a string".to_string()))?;

    let tool_args = params_obj.get("arguments").cloned().unwrap_or(Value::Null);

    let tool = ToolName(tool_name.to_string());
    let decision = policy_engine.evaluate(server, &tool, &tool_args);

    match decision.decision {
        Decision::Allow => Ok(None),
        Decision::Deny => {
            let error_frame = JsonRpcFrame::error_response(
                frame.id(),
                -32603,
                &format!("tool call denied: {}", decision.reason),
            )?;
            Ok(Some(error_frame))
        }
        Decision::ApprovalRequired => {
            let error_frame = JsonRpcFrame::error_response(
                frame.id(),
                -32603,
                "tool call requires approval (not yet implemented)",
            )?;
            Ok(Some(error_frame))
        }
    }
}

pub struct ToolInspection {
    pub descriptor: ToolDescriptor,
    pub fingerprint: ToolFingerprint,
    pub findings: Vec<ScanFinding>,
}

/// Extract tool descriptors from a tools/list response and inspect them.
pub fn inspect_tool_list(
    frame: &JsonRpcFrame,
    server: &ServerName,
) -> Result<Vec<ToolInspection>, ProxyError> {
    if frame.is_error() {
        return Ok(Vec::new());
    }

    let result = frame.data.get("result").ok_or_else(|| {
        ProxyError::InvalidServerResponse("tools/list response missing 'result'".to_string())
    })?;

    let result_obj = result.as_object().ok_or_else(|| {
        ProxyError::InvalidServerResponse("tools/list result must be an object".to_string())
    })?;

    let tools = result_obj
        .get("tools")
        .and_then(|v| v.as_array())
        .ok_or_else(|| {
            ProxyError::InvalidServerResponse(
                "tools/list result.tools must be an array".to_string(),
            )
        })?;

    let mut inspections = Vec::new();
    for tool_val in tools {
        let name = tool_val
            .get("name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ProxyError::InvalidServerResponse("tool missing 'name'".to_string()))?;
        let description = tool_val.get("description").and_then(|v| v.as_str());
        let input_schema = tool_val.get("inputSchema");

        let tool_name = ToolName(name.to_string());
        let descriptor = ToolDescriptor {
            name: tool_name.clone(),
            description: description.map(|s| s.to_string()),
            input_schema: input_schema.cloned(),
        };

        let fingerprint = compute_fingerprint(
            server,
            &tool_name,
            description,
            input_schema,
            None, // command/args not available in tool list
            None,
        );

        let findings = scan_tool_metadata(server, &tool_name, description, input_schema);

        inspections.push(ToolInspection {
            descriptor,
            fingerprint,
            findings,
        });
    }

    Ok(inspections)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_inspect_tool_list_valid() {
        let frame = JsonRpcFrame::new(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "tools": [
                    { "name": "read_file", "description": "Read a file" },
                    { "name": "write_file", "description": "Write a file" }
                ]
            }
        }));
        let server = ServerName("test".into());
        let tools = inspect_tool_list(&frame, &server).unwrap();
        assert_eq!(tools.len(), 2);
    }

    #[test]
    fn test_inspect_tool_list_error_response() {
        let frame = JsonRpcFrame::new(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "error": {
                "code": -1,
                "message": "server error"
            }
        }));
        let server = ServerName("test".into());
        let tools = inspect_tool_list(&frame, &server).unwrap();
        assert_eq!(tools.len(), 0);
    }
}
