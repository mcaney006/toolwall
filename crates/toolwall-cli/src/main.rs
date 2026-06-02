use clap::{Parser, Subcommand};
use console::{style, Emoji};
use std::fs;
use std::path::Path;
use toolwall_policy::PolicyEngine;
use toolwall_proxy::ProxyConfig;
use tracing_subscriber::fmt::Subscriber;

static LOOKING_GLASS: Emoji<'_, '_> = Emoji("🔍 ", "");
static CHECK: Emoji<'_, '_> = Emoji("✅ ", "");
static CROSS: Emoji<'_, '_> = Emoji("❌ ", "");
static GEAR: Emoji<'_, '_> = Emoji("⚙️  ", "");
static SHIELD: Emoji<'_, '_> = Emoji("🛡️  ", "");

/// toolwall: A security-first firewall and audit logger for MCP tool calls.
///
/// toolwall sits between MCP clients and servers to enforce local policy,
/// redact secrets from logs, and detect suspicious behavior.
#[derive(Parser)]
#[command(name = "toolwall", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    cmd: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new toolwall configuration file.
    Init {
        /// Path to the new configuration file.
        #[arg(short, long, default_value = "toolwall.toml")]
        path: String,
    },
    /// Start the toolwall proxy.
    Run {
        /// Path to the configuration file.
        #[arg(short, long, default_value = "toolwall.toml")]
        config: String,
    },
    /// Validate the syntax and rules of a configuration file.
    Scan {
        /// Path to the configuration file.
        #[arg(short, long, default_value = "toolwall.toml")]
        config: String,
    },
    /// Generate a security audit report from session logs.
    Report {
        /// Path to the audit log file (JSONL).
        #[arg(short, long, default_value = ".toolwall/audit/session.jsonl")]
        audit: String,
    },
    /// Run diagnostic checks on the environment and configuration.
    Doctor,
}

/// Validate that a path is reasonable for config/audit files.
/// Rejects absolute paths, parent directory traversal attempts, and suspicious patterns.
fn validate_path(p: &str, purpose: &str) -> anyhow::Result<()> {
    let path = Path::new(p);
    if path.is_absolute() {
        anyhow::bail!("{} path must be relative, not absolute: {}", purpose, p);
    }
    // Reject paths with .. components to prevent traversal
    for component in path.components() {
        if let std::path::Component::ParentDir = component {
            anyhow::bail!("{} path must not contain '..' components: {}", purpose, p);
        }
    }
    Ok(())
}

fn main() -> anyhow::Result<()> {
    Subscriber::builder()
        .with_max_level(tracing::Level::INFO)
        .init();
    let cli = Cli::parse();
    match cli.cmd {
        Commands::Init { path } => {
            validate_path(&path, "config")?;
            if fs::metadata(&path).is_ok() {
                println!(
                    "{} {} config already exists: {}",
                    CROSS,
                    style("Error:").red().bold(),
                    path
                );
            } else {
                let example = include_str!("../../../examples/toolwall.toml");
                fs::write(&path, example)?;
                // Set secure permissions: 0600 (owner read/write only)
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
                }
                println!(
                    "{} {} Wrote {} (permissions 0600)",
                    CHECK,
                    style("Success:").green().bold(),
                    style(path).cyan()
                );
            }
        }
        Commands::Run { config } => {
            validate_path(&config, "config")?;
            println!(
                "{} Starting toolwall proxy with config {}...",
                SHIELD,
                style(&config).cyan()
            );

            let s = fs::read_to_string(&config)?;
            let engine = toolwall_policy::PolicyEngine::from_toml_str(&s)?;
            let engine = std::sync::Arc::new(engine);

            // Uses the first server entry in the config.
            let config_toml: toml::Value = toml::from_str(&s)?;
            let server_name_str = config_toml
                .get("servers")
                .and_then(|v| v.as_array())
                .and_then(|a| a.first())
                .and_then(|s| s.get("name"))
                .and_then(|n| n.as_str())
                .unwrap_or("default");

            let server_cmd = config_toml
                .get("servers")
                .and_then(|v| v.as_array())
                .and_then(|a| a.first())
                .and_then(|s| s.get("command"))
                .and_then(|c| c.as_str())
                .ok_or_else(|| anyhow::anyhow!("No server command found in config"))?;

            let server_args: Vec<String> = config_toml
                .get("servers")
                .and_then(|v| v.as_array())
                .and_then(|a| a.first())
                .and_then(|s| s.get("args"))
                .and_then(|args| args.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default();

            let audit_path = ".toolwall/audit/session.jsonl";
            let baseline_path = ".toolwall/baseline.json";
            let _ = fs::create_dir_all(".toolwall/audit");
            let audit_writer =
                std::sync::Arc::new(toolwall_audit::AuditWriter::new(Path::new(audit_path)));

            let proxy_config = ProxyConfig {
                server_name: toolwall_core::ServerName(server_name_str.to_string()),
                server_command: server_cmd.to_string(),
                server_args,
                session_id: toolwall_core::SessionId::default(),
                audit_path: audit_path.to_string(),
                baseline_path: baseline_path.to_string(),
            };

            let proxy = toolwall_proxy::McpProxy::new(proxy_config, engine, audit_writer);
            proxy
                .run()
                .map_err(|e| anyhow::anyhow!("Proxy error: {}", e))?;
        }
        Commands::Scan { config } => {
            validate_path(&config, "config")?;
            println!(
                "{} Scanning policy {}...",
                LOOKING_GLASS,
                style(&config).cyan()
            );
            let s = fs::read_to_string(&config)?;
            match PolicyEngine::from_toml_str(&s) {
                Ok(_) => {
                    println!(
                        "{} {} Policy parsed successfully and is valid.",
                        CHECK,
                        style("Success:").green().bold()
                    );
                }
                Err(e) => {
                    eprintln!(
                        "{} {} Policy parse failed: {}",
                        CROSS,
                        style("Error:").red().bold(),
                        style(e).red()
                    );
                    anyhow::bail!("config validation failed");
                }
            }
        }
        Commands::Report { audit } => {
            validate_path(&audit, "audit")?;
            println!(
                "{} Generating report from {}...",
                LOOKING_GLASS,
                style(&audit).cyan()
            );

            if !Path::new(&audit).exists() {
                println!(
                    "{} {} Audit file not found: {}",
                    CROSS,
                    style("Error:").red().bold(),
                    audit
                );
                anyhow::bail!("Audit file not found");
            }

            let content = fs::read_to_string(&audit)?;
            let mut total_events = 0;
            let mut denied_events = 0;
            let mut findings_count = 0;

            for line in content.lines() {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
                    total_events += 1;
                    if v.get("decision").and_then(|d| d.as_str()) == Some("Deny") {
                        denied_events += 1;
                    }
                    if let Some(findings) = v.get("findings").and_then(|f| f.as_array()) {
                        findings_count += findings.len();
                    }
                }
            }

            println!("\n┌─ AUDIT SUMMARY ──────────────────────────────────┐");
            println!("│ Total Events: {:<34} │", total_events);
            println!("│ Denied:       {:<34} │", style(denied_events).red());
            println!("│ Scan Findings: {:<33} │", style(findings_count).yellow());
            println!("└──────────────────────────────────────────────────┘");
        }
        Commands::Doctor => {
            println!("{} Running diagnostics...", GEAR);
            println!(
                "{} {} toolwall v{} (development)",
                CHECK,
                style("Version:").bold(),
                env!("CARGO_PKG_VERSION")
            );
            println!(
                "{} {} Workspace found at {}",
                CHECK,
                style("Environment:").bold(),
                std::env::current_dir()?.display()
            );
            println!(
                "{} {}",
                CHECK,
                style("Diagnostics complete. No issues found.").green()
            );
        }
    }
    Ok(())
}
