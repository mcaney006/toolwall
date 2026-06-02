# 🛡️ toolwall

[![Status](https://img.shields.io/badge/status-experimental-yellow.svg)](SECURITY_AUDIT.md)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-blue.svg)](https://www.rust-lang.org)
[![MCP](https://img.shields.io/badge/protocol-MCP-orange.svg)](https://modelcontextprotocol.io)

**toolwall** is an experimental, defense-in-depth firewall and audit logger for the Model Context Protocol (MCP). It adds a policy-enforcing, secret-redacting perimeter between LLMs and your local system. It is one layer of defense, not a guarantee.

---

## ⚡ The 30-Second Pitch

**Stop AI agents from turning your tools into an incident report.**

**The Problem:** MCP allows LLMs to execute tools on your machine. However, a single prompt injection or a malicious MCP server can lead to LLMs exfiltrating `~/.ssh` keys, deleting production databases, or reading sensitive `.env` files.

**The Solution:** `toolwall` sits as a transparent proxy between your MCP client (like Claude Desktop) and MCP servers. It enforces a **fail-closed** security policy, redacts secrets from logs, scans tool metadata for malicious instructions, and fingerprints tools to detect "schema drift".

---

## 🚀 Why MCP Needs Runtime Controls

1.  **Prompt Injection:** Even trusted tools can be abused if the LLM is tricked into calling them with malicious arguments.
2.  **Over-privileged Tools:** Many MCP servers ask for broad filesystem access when they only need one directory.
3.  **No Audit Trail:** Standard MCP implementations lack high-fidelity, redacted logging of what *actually* happened inside a tool call.
4.  **Metadata Poisoning:** Malicious servers can provide tool descriptions that "nudge" the LLM toward dangerous actions.

---

## 🛠️ Quickstart

### 1. Install
```bash
# Installs the `toolwall` binary from the CLI package.
cargo install --path crates/toolwall-cli
```

### 2. Initialize Policy
```bash
toolwall init --path toolwall.toml
```

### 3. Verify Config
```bash
toolwall scan
```

### 4. Run Proxy
```bash
toolwall run --config toolwall.toml
```

---

## 🧰 Development Commands

This is a Cargo **workspace**: it emits many artifacts (8 library crates + the
`toolwall` binary, plus a test executable per crate under `--all-targets`). Any
command that must select a *single* artifact has to name it explicitly, or Cargo /
tooling fails with *"More than one artifact was produced."* Use these:

```bash
# Run / build / check the CLI — pin the package and the binary by name.
cargo run   --package toolwall-cli --bin toolwall -- --help
cargo build --package toolwall-cli --bin toolwall --release
cargo check --package toolwall-cli --bin toolwall

# Whole-workspace gates (these intentionally cover every artifact).
cargo check  --workspace --all-targets
cargo test   --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

A `justfile` wraps these as `just run`, `just build`, `just check`, `just test`,
and `just lint` so the default commands are never ambiguous.

---

## 📊 The "Top-Tier" Experience

### Example: Blocked Event
When a tool tries to access a protected path, `toolwall` blocks the call and returns a clean JSON-RPC error:

```text
┌─ TOOLWALL BLOCKED ───────────────────────────────┐
│ server   filesystem                              │
│ tool     read_file                               │
│ target   ~/.aws/credentials                      │
│ reason   protected secret path                   │
│ action   denied                                  │
└──────────────────────────────────────────────────┘
```

### Example: Scan Output
Suspicious tool metadata is flagged during tool discovery:

```text
HIGH    filesystem.read_file    Tool can read protected credential paths
MEDIUM  github.create_issue     Description contains instruction-like text
LOW     slack.send_message      Tool may transmit user-provided content externally
```

### Example: Audit Report
High-fidelity JSONL logs with automatic credential redaction:

```bash
toolwall report --audit .toolwall/audit/session.jsonl
```

```text
┌─ AUDIT SUMMARY ──────────────────────────────────┐
│ Total Events: 42                                 │
│ Denied:       3                                  │
│ Scan Findings: 5                                 │
└──────────────────────────────────────────────────┘
```

---

## 🏗️ Architecture

```text
  ┌─────────────┐      ┌─────────────┐      ┌─────────────┐
  │  MCP Client │◄────►│   toolwall  │◄────►│ MCP Servers │
  │  (Claude)   │      │   (Proxy)   │      │ (Filesystem)│
  └─────────────┘      └──────┬──────┘      └─────────────┘
                              │
                    ┌─────────▼─────────┐
                    │  Policy Engine    │
                    ├───────────────────┤
                    │  - Path Guards    │
                    │  - Redaction      │
                    │  - Fingerprinting │
                    └───────────────────┘
```

---

## 🛡️ Threat Model & Non-Goals

### Threat Model
*   **In-Scope:** Prevent unauthorized tool execution, block access to sensitive files/patterns, redact credentials in transit, detect unexpected tool schema changes.
*   **Trust Boundary:** We assume the host OS is secure. toolwall protects the boundary between the *LLM/MCP Server* and the *Host*.

### Non-Goals
*   **OS Sandbox:** toolwall is not a VM or Container. Use `docker` or `gVisor` for deep isolation.
*   **Malware Analysis:** toolwall does not scan for viruses; it enforces behavioral policy.
*   **Network Firewall:** Use `iptables` or `ufw` for lower-level packet filtering.

---

## 🗺️ Roadmap

- [x] **v0.1.0 (MVP):** Policy engine, TOML config, audit logging, path protection, tool metadata scanning.
- [x] **v0.2.0:** Stdio proxy with real-time interception.
- [x] **v0.3.0:** Tool fingerprinting & trust-on-first-use drift detection.
- [ ] **v0.4.0:** Interactive "Approval" workflow (currently denied as not-yet-implemented).
- [ ] **v0.5.0:** Full async bidirectional proxying (server-initiated requests).
- [ ] **v0.6.0:** Plugin system for custom validators (e.g., SQL injection scanning).

---

## 🤝 Contributing

We follow a **security-first** contribution model. No `unsafe` code without justification, strong test coverage on policy and redaction logic, and mandatory fail-closed defaults.

---
*Built with 🦀 in Rust for the MCP ecosystem.*
