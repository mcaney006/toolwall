//! Stdio MCP proxy with policy enforcement, fingerprinting, and auditing.

pub mod error;
pub mod frame;
pub mod interceptor;
pub mod proxy;

pub use error::ProxyError;
pub use frame::{FrameReader, FrameWriter, JsonRpcFrame};
pub use proxy::{McpProxy, ProxyConfig};
