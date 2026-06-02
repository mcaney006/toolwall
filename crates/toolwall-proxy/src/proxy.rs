//! Main MCP proxy orchestrator.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Instant;

use toolwall_audit::AuditWriter;
use toolwall_core::{AuditEvent, Decision, DriftEvent, RiskLevel, ServerName, SessionId};
use toolwall_fingerprint::{load_baseline, save_baseline, ToolFingerprintRecord};
use toolwall_policy::PolicyEngine;
use toolwall_scan::ScanFinding;
use uuid::Uuid;

/// Identifies a tool within a server for baseline lookups: `(server, tool)`.
type ToolKey = (String, String);

use crate::error::ProxyError;
use crate::frame::JsonRpcFrame;
use crate::interceptor;

/// Variable, per-event fields recorded in an [`AuditEvent`].
///
/// The shared context (audit writer, server, session) is passed separately so
/// only the outcome-specific fields travel together.
struct AuditOutcome {
    decision: Decision,
    reason: &'static str,
    risk_level: Option<RiskLevel>,
    findings: Vec<String>,
    fingerprint_before: Option<String>,
    fingerprint_after: Option<String>,
    latency_ms: u64,
}

impl AuditOutcome {
    /// A deny with no risk/findings/fingerprints — used for policy and malformed-request denials.
    fn denied(reason: &'static str, latency_ms: u64) -> Self {
        AuditOutcome {
            decision: Decision::Deny,
            reason,
            risk_level: None,
            findings: Vec::new(),
            fingerprint_before: None,
            fingerprint_after: None,
            latency_ms,
        }
    }

    /// An allow with no risk/findings/fingerprints — used for completed forwarded calls.
    fn allowed(reason: &'static str, latency_ms: u64) -> Self {
        AuditOutcome {
            decision: Decision::Allow,
            reason,
            risk_level: None,
            findings: Vec::new(),
            fingerprint_before: None,
            fingerprint_after: None,
            latency_ms,
        }
    }
}

fn risk_rank(r: &RiskLevel) -> u8 {
    match r {
        RiskLevel::Low => 1,
        RiskLevel::Medium => 2,
        RiskLevel::High => 3,
        RiskLevel::Critical => 4,
    }
}

/// Highest risk level among scan findings, if any.
fn max_scan_risk(findings: &[ScanFinding]) -> Option<RiskLevel> {
    findings
        .iter()
        .map(|f| f.risk_level.clone())
        .max_by_key(risk_rank)
}

/// Raise a risk level to at least Medium (used when a tool is absent from the baseline).
fn at_least_medium(current: Option<RiskLevel>) -> RiskLevel {
    match current {
        Some(r) if risk_rank(&r) >= risk_rank(&RiskLevel::Medium) => r,
        _ => RiskLevel::Medium,
    }
}

/// MCP proxy configuration.
pub struct ProxyConfig {
    pub server_name: ServerName,
    pub server_command: String,
    pub server_args: Vec<String>,
    pub session_id: SessionId,
    pub audit_path: String,
    /// Relative path to the tool-fingerprint baseline used for drift detection.
    pub baseline_path: String,
}

/// Synchronous MCP proxy with policy enforcement and auditing.
pub struct McpProxy {
    config: ProxyConfig,
    policy_engine: Arc<PolicyEngine>,
    audit_writer: Arc<AuditWriter>,
}

impl McpProxy {
    /// Create a new proxy.
    pub fn new(
        config: ProxyConfig,
        policy_engine: Arc<PolicyEngine>,
        audit_writer: Arc<AuditWriter>,
    ) -> Self {
        McpProxy {
            config,
            policy_engine,
            audit_writer,
        }
    }

    /// Run the proxy in blocking mode: proxy stdin/stdout with interception.
    pub fn run(&self) -> Result<(), ProxyError> {
        let mut child = Command::new(&self.config.server_command)
            .args(&self.config.server_args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .map_err(|e| ProxyError::ProcessSpawn(e.to_string()))?;

        let server_stdin = child
            .stdin
            .take()
            .ok_or_else(|| ProxyError::ProcessSpawn("failed to open stdin".to_string()))?;
        let server_stdout = child
            .stdout
            .take()
            .ok_or_else(|| ProxyError::ProcessSpawn("failed to open stdout".to_string()))?;

        let client_stdin = std::io::stdin();
        let client_stdout = std::io::stdout();

        let server_reader = BufReader::new(server_stdout);

        let (baseline, baseline_existed) = Self::load_baseline_map(&self.config.baseline_path);

        self.proxy_loop(
            client_stdin.lock(),
            client_stdout.lock(),
            server_stdin,
            server_reader,
            baseline,
            baseline_existed,
        )?;

        let _ = child.wait();
        Ok(())
    }

    /// Load the fingerprint baseline into a lookup map. A missing file is normal on
    /// first run (trust-on-first-use); a corrupt one is logged and treated as missing.
    fn load_baseline_map(path: &str) -> (HashMap<ToolKey, String>, bool) {
        match load_baseline(Path::new(path)) {
            Ok(records) => {
                let map = records
                    .into_iter()
                    .map(|r| ((r.server, r.name), r.hash))
                    .collect();
                (map, true)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (HashMap::new(), false),
            Err(e) => {
                tracing::warn!("could not read baseline ({e}); starting trust-on-first-use");
                (HashMap::new(), false)
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn proxy_loop<R: BufRead, W: Write, SR: BufRead, SW: Write>(
        &self,
        mut client_in: R,
        mut client_out: W,
        mut server_in: SW,
        mut server_out: SR,
        mut baseline: HashMap<ToolKey, String>,
        mut baseline_existed: bool,
    ) -> Result<(), ProxyError> {
        let server_name = self.config.server_name.clone();
        let policy = self.policy_engine.as_ref();
        let audit = self.audit_writer.as_ref();
        let session_id = self.config.session_id.clone();
        let baseline_path = self.config.baseline_path.clone();

        tracing::info!("proxy loop started for server: {}", server_name.0);

        let mut line = String::new();
        loop {
            line.clear();
            let start_time = Instant::now();
            let n = client_in.read_line(&mut line).map_err(ProxyError::Io)?;
            if n == 0 {
                break; // EOF from client
            }

            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            let frame = JsonRpcFrame::parse(trimmed)?;
            let method = frame.method();
            // JSON-RPC requests carry an `id`; notifications do not and receive no response.
            let request_id = frame.id();

            // Intercept tools/call before forwarding it to the server.
            if method.as_deref() == Some("tools/call") {
                match interceptor::intercept_tools_call(&frame, &server_name, policy) {
                    Ok(Some(error_frame)) => {
                        Self::write_audit_event(
                            audit,
                            &frame,
                            &server_name,
                            &session_id,
                            AuditOutcome::denied(
                                "policy denied",
                                start_time.elapsed().as_millis() as u64,
                            ),
                        )?;
                        Self::write_frame_line(&mut client_out, &error_frame)?;
                        tracing::info!("tool call denied");
                        continue;
                    }
                    Ok(None) => {
                        tracing::info!("tool call allowed");
                    }
                    Err(e) => {
                        let error_frame = JsonRpcFrame::error_response(
                            frame.id(),
                            -32603,
                            "malformed tool call",
                        )?;
                        Self::write_audit_event(
                            audit,
                            &frame,
                            &server_name,
                            &session_id,
                            AuditOutcome::denied(
                                "malformed request",
                                start_time.elapsed().as_millis() as u64,
                            ),
                        )?;
                        let _ = Self::write_frame_line(&mut client_out, &error_frame);
                        tracing::warn!("malformed tool call denied: {}", e);
                        continue;
                    }
                }
            }

            // Forward the client message to the server.
            server_in
                .write_all(trimmed.as_bytes())
                .map_err(ProxyError::Io)?;
            server_in.write_all(b"\n").map_err(ProxyError::Io)?;
            server_in.flush().map_err(ProxyError::Io)?;

            // Notifications get no response, so don't block waiting for one.
            if request_id.is_none() {
                continue;
            }

            // Read server messages until the response matching this request arrives,
            // relaying any server-initiated messages (e.g. progress) to the client first.
            loop {
                let mut response_line = String::new();
                let n = server_out
                    .read_line(&mut response_line)
                    .map_err(ProxyError::Io)?;
                if n == 0 {
                    return Ok(()); // server closed its stdout
                }
                let response_trimmed = response_line.trim();
                if response_trimmed.is_empty() {
                    continue;
                }

                let response_frame = JsonRpcFrame::parse(response_trimmed)?;
                let is_matching_response = (response_frame.is_result()
                    || response_frame.is_error())
                    && response_frame.id() == request_id;

                if is_matching_response {
                    let latency_ms = start_time.elapsed().as_millis() as u64;
                    match method.as_deref() {
                        Some("tools/list") => Self::audit_tool_list(
                            audit,
                            &frame,
                            &server_name,
                            &session_id,
                            &response_frame,
                            &mut baseline,
                            &mut baseline_existed,
                            &baseline_path,
                            latency_ms,
                        )?,
                        Some("tools/call") => Self::write_audit_event(
                            audit,
                            &frame,
                            &server_name,
                            &session_id,
                            AuditOutcome::allowed("forwarded tool call completed", latency_ms),
                        )?,
                        _ => {}
                    }
                }

                Self::write_line(&mut client_out, response_trimmed)?;

                if is_matching_response {
                    break;
                }
            }
        }

        Ok(())
    }

    /// Inspect a `tools/list` response: fingerprint each tool, compare against the
    /// baseline to detect drift, scan metadata, and emit one audit event per tool.
    #[allow(clippy::too_many_arguments)]
    fn audit_tool_list(
        audit: &AuditWriter,
        request_frame: &JsonRpcFrame,
        server: &ServerName,
        session_id: &SessionId,
        response_frame: &JsonRpcFrame,
        baseline: &mut HashMap<ToolKey, String>,
        baseline_existed: &mut bool,
        baseline_path: &str,
        latency_ms: u64,
    ) -> Result<(), ProxyError> {
        let inspections = interceptor::inspect_tool_list(response_frame, server)?;
        if inspections.is_empty() {
            return Ok(());
        }

        let mut records = Vec::with_capacity(inspections.len());
        for inspection in &inspections {
            let name = inspection.descriptor.name.0.clone();
            let key = (server.0.clone(), name.clone());
            let new_hash = inspection.fingerprint.hash.clone();
            records.push(ToolFingerprintRecord::from_fingerprint(
                &inspection.fingerprint,
            ));

            let mut findings: Vec<String> = inspection
                .findings
                .iter()
                .map(|f| f.message.clone())
                .collect();
            let mut risk = max_scan_risk(&inspection.findings);
            let mut fingerprint_before = None;

            match baseline.get(&key) {
                Some(old_hash) if old_hash != &new_hash => {
                    // The server changed a tool's definition out from under the baseline.
                    let drift = DriftEvent {
                        server: server.clone(),
                        tool: inspection.descriptor.name.clone(),
                        message: format!(
                            "tool '{name}' definition changed since baseline (possible rug-pull)"
                        ),
                    };
                    findings.push(drift.message);
                    fingerprint_before = Some(old_hash.clone());
                    risk = Some(RiskLevel::High);
                }
                None if *baseline_existed => {
                    findings.push(format!("tool '{name}' is not present in the baseline"));
                    risk = Some(at_least_medium(risk));
                }
                _ => {}
            }

            Self::write_audit_event(
                audit,
                request_frame,
                server,
                session_id,
                AuditOutcome {
                    decision: Decision::Allow,
                    reason: "tool inspected",
                    risk_level: risk,
                    findings,
                    fingerprint_before,
                    fingerprint_after: Some(new_hash),
                    latency_ms,
                },
            )?;
        }

        // Trust-on-first-use: record what we saw so future sessions can detect drift.
        if !*baseline_existed {
            for rec in &records {
                baseline.insert((rec.server.clone(), rec.name.clone()), rec.hash.clone());
            }
            match save_baseline(Path::new(baseline_path), &records) {
                Ok(()) => {
                    tracing::info!("recorded {} tool fingerprints to baseline", records.len())
                }
                Err(e) => tracing::warn!("failed to save baseline: {e}"),
            }
            *baseline_existed = true;
        }

        Ok(())
    }

    /// Write a frame as one line (with trailing newline + flush) to `out`.
    fn write_frame_line<W: Write>(out: &mut W, frame: &JsonRpcFrame) -> Result<(), ProxyError> {
        let s = frame.to_string()?;
        Self::write_line(out, &s)
    }

    fn write_line<W: Write>(out: &mut W, s: &str) -> Result<(), ProxyError> {
        out.write_all(s.as_bytes()).map_err(ProxyError::Io)?;
        out.write_all(b"\n").map_err(ProxyError::Io)?;
        out.flush().map_err(ProxyError::Io)?;
        Ok(())
    }

    fn write_audit_event(
        audit: &AuditWriter,
        frame: &JsonRpcFrame,
        server: &ServerName,
        session_id: &SessionId,
        outcome: AuditOutcome,
    ) -> Result<(), ProxyError> {
        let AuditOutcome {
            decision,
            reason,
            risk_level,
            findings,
            fingerprint_before,
            fingerprint_after,
            latency_ms,
        } = outcome;
        let tool_name = frame
            .params()
            .as_ref()
            .and_then(|p| p.get("name"))
            .and_then(|n| n.as_str())
            .map(|s| s.to_string());

        let event = AuditEvent {
            event_id: Uuid::new_v4(),
            timestamp: time::OffsetDateTime::now_utc(),
            session_id: session_id.clone(),
            client: None,
            server: Some(server.0.clone()),
            method: frame.method().unwrap_or_else(|| "unknown".to_string()),
            tool_name,
            decision,
            reason: Some(reason.to_string()),
            rule_id: None,
            risk_level,
            args_redacted: true, // AuditWriter redacts everything anyway
            fingerprint_before,
            fingerprint_after,
            findings,
            latency_ms,
        };

        audit.append_event(&event).map_err(ProxyError::Io)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_fs::fixture::PathChild;
    use assert_fs::TempDir;
    use std::io::Cursor;

    fn make_proxy(audit_path: &Path, baseline_path: &str) -> McpProxy {
        let config = ProxyConfig {
            server_name: ServerName("test".into()),
            server_command: "true".into(),
            server_args: vec![],
            session_id: SessionId::default(),
            audit_path: audit_path.to_string_lossy().into_owned(),
            baseline_path: baseline_path.to_string(),
        };
        let policy = Arc::new(
            PolicyEngine::from_toml_str("version = 1\n[defaults]\ndecision = \"allow\"").unwrap(),
        );
        let audit = Arc::new(AuditWriter::new(audit_path));
        McpProxy::new(config, policy, audit)
    }

    #[test]
    fn test_proxy_creation() {
        let td = TempDir::new().unwrap();
        let _proxy = make_proxy(td.child("audit.jsonl").path(), ".toolwall/baseline.json");
    }

    #[test]
    fn test_notification_does_not_consume_a_response() {
        // Regression for the one-request-one-response desync: a notification (no id)
        // must be forwarded without blocking for a server response, so the later
        // request's response stays correctly paired.
        let td = TempDir::new().unwrap();
        let proxy = make_proxy(td.child("audit.jsonl").path(), "unused-baseline.json");

        let client_in = Cursor::new(
            b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n\
              {\"jsonrpc\":\"2.0\",\"method\":\"ping\",\"id\":1}\n"
                .to_vec(),
        );
        let mut client_out: Vec<u8> = Vec::new();
        let mut server_in: Vec<u8> = Vec::new();
        // Server replies only to the request, never to the notification.
        let server_out = Cursor::new(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n".to_vec());

        proxy
            .proxy_loop(
                client_in,
                &mut client_out,
                &mut server_in,
                server_out,
                HashMap::new(),
                true,
            )
            .unwrap();

        let forwarded = String::from_utf8(server_in).unwrap();
        assert!(forwarded.contains("notifications/initialized"));
        assert!(forwarded.contains("\"ping\""));
        let returned = String::from_utf8(client_out).unwrap();
        assert!(
            returned.contains("\"id\":1"),
            "response should reach client: {returned}"
        );
    }

    #[test]
    fn test_drift_detected_against_baseline() {
        let td = TempDir::new().unwrap();
        let audit = td.child("audit.jsonl");
        let proxy = make_proxy(audit.path(), "unused-baseline.json");

        let mut baseline = HashMap::new();
        baseline.insert(
            ("test".to_string(), "read_file".to_string()),
            "stale-fp".to_string(),
        );

        let client_in =
            Cursor::new(b"{\"jsonrpc\":\"2.0\",\"method\":\"tools/list\",\"id\":7}\n".to_vec());
        let mut client_out: Vec<u8> = Vec::new();
        let mut server_in: Vec<u8> = Vec::new();
        let server_out = Cursor::new(
            b"{\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{\"tools\":[{\"name\":\"read_file\",\"description\":\"Read a file\"}]}}\n"
                .to_vec(),
        );

        proxy
            .proxy_loop(
                client_in,
                &mut client_out,
                &mut server_in,
                server_out,
                baseline,
                true,
            )
            .unwrap();

        let log = std::fs::read_to_string(audit.path()).unwrap();
        assert!(
            log.contains("rug-pull"),
            "expected drift finding, got: {log}"
        );
        assert!(
            log.contains("stale-fp"),
            "expected fingerprint_before recorded"
        );
    }

    #[test]
    fn test_trust_on_first_use_writes_baseline() {
        let td = TempDir::new().unwrap();
        // save_baseline requires a relative path; keep it in its own dir for cleanup.
        let baseline_rel = ".tw-tofu-test/baseline.json";
        let _ = std::fs::remove_dir_all(".tw-tofu-test");
        let proxy = make_proxy(td.child("audit.jsonl").path(), baseline_rel);

        let client_in =
            Cursor::new(b"{\"jsonrpc\":\"2.0\",\"method\":\"tools/list\",\"id\":1}\n".to_vec());
        let mut client_out: Vec<u8> = Vec::new();
        let mut server_in: Vec<u8> = Vec::new();
        let server_out = Cursor::new(
            b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[{\"name\":\"read_file\"}]}}\n"
                .to_vec(),
        );

        proxy
            .proxy_loop(
                client_in,
                &mut client_out,
                &mut server_in,
                server_out,
                HashMap::new(),
                false,
            )
            .unwrap();

        let saved = std::fs::read_to_string(baseline_rel).unwrap();
        assert!(saved.contains("read_file"));
        let _ = std::fs::remove_dir_all(".tw-tofu-test");
    }
}
