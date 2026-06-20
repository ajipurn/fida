//! `fida-mcp` — MCP_Proxy: inspect tools, label risk, and intercept
//! `tools/call` requests over a stdio JSON-RPC pump (see spec tasks 16.x;
//! design "MCP Proxy Design").
//!
//! MCP is JSON-RPC 2.0 over stdio: Fida sits between an agent (the MCP
//! client) and a configured MCP server, reading line-delimited JSON-RPC
//! messages from one side and forwarding them to the other. This crate
//! provides three capabilities:
//!
//! * [`inspect`](McpProxy::inspect) / list-tools — issue the MCP `tools/list`
//!   handshake to enumerate each tool's name, description, and input schema.
//! * [`risk_label`](McpProxy::risk_label) — classify a tool's risk
//!   heuristically from its name/description.
//! * the stdio JSON-RPC **pump** — intercept only `tools/call`, evaluate an
//!   `mcp.tool_call` Action, forward unchanged on `allow`, and return a
//!   JSON-RPC error carrying the matched rule on `deny` / non-interactive
//!   `ask` without contacting the server; pass every other method through
//!   untouched.
//!
//! # Testability
//!
//! The transport is injectable: the handshake ([`inspect_via`]) and the pump
//! ([`McpPump::pump`]) are generic over [`BufRead`]/[`Write`], so tests — and
//! the integration test in task 16.2 — drive them against in-memory buffers or
//! a stub stdio server without spawning a real process. The gating decision is
//! a pure function ([`gate_message`]) over `(message, policy)` with no I/O.

use std::collections::BTreeSet;
use std::io::{self, BufRead, Write};
use std::path::Path;
use std::process::{Child, Command, Stdio};

use chrono::Utc;
use serde_json::{Value, json};

use fida_action::SessionHandle;
use fida_action::{Action, ActionKind, ActionPayload, Actor, Decision, DecisionResult, Risk};
use fida_audit::{AuditAction, AuditEvent, AuditResult, AuditStore};
use fida_policy::CompiledPolicy;
use fida_secrets::{Scanner, SecretScanner};

pub mod sandbox;
pub mod server;
pub use server::{GatewayServer, READ_TOOL, SHELL_TOOL};

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// The JSON-RPC error code returned to the caller when policy blocks a
/// `tools/call` (deny or non-interactive ask). A server-defined code in the
/// reserved-for-implementation range, distinct from the standard JSON-RPC
/// codes.
pub const POLICY_DENIED_CODE: i64 = -32001;

/// The JSON-RPC error code returned when a `tools/call` names a tool the server
/// never advertised through `tools/list`.
pub const UNKNOWN_TOOL_CODE: i64 = -32002;

/// Failures raised by the MCP_Proxy.
///
/// Every variant is a load/transport/protocol fault that the CLI maps to a
/// non-zero exit code; an unparseable definition or an unknown tool never lets
/// a proxy run.
#[derive(Debug)]
pub enum McpError {
    /// The server definition could not be read or parsed. Carries a
    /// human-readable cause; never starts a proxy.
    DefinitionLoad(String),
    /// Spawning the configured MCP server process failed.
    ServerSpawn(io::Error),
    /// Underlying stdio transport I/O failed.
    Transport(io::Error),
    /// A JSON-RPC message was malformed or violated the expected shape.
    Protocol(String),
    /// A `tools/call` referenced a tool not advertised by `tools/list`.
    UnknownTool(String),
}

impl std::fmt::Display for McpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            McpError::DefinitionLoad(why) => {
                write!(f, "failed to load MCP server definition: {why}")
            }
            McpError::ServerSpawn(e) => write!(f, "failed to start MCP server: {e}"),
            McpError::Transport(e) => write!(f, "MCP transport error: {e}"),
            McpError::Protocol(why) => write!(f, "malformed JSON-RPC message: {why}"),
            McpError::UnknownTool(tool) => write!(f, "unknown MCP tool: {tool}"),
        }
    }
}

impl std::error::Error for McpError {}

impl From<io::Error> for McpError {
    fn from(e: io::Error) -> Self {
        McpError::Transport(e)
    }
}

// ---------------------------------------------------------------------------
// Tool model and risk labeling
// ---------------------------------------------------------------------------

/// One tool exposed by an MCP server (design "MCP_Proxy").
///
/// Mirrors the MCP `tools/list` entry: a `name`, a human `description`, and the
/// JSON `inputSchema` describing the tool's arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpTool {
    /// The tool's invocation name (e.g. `shell.exec`, `fs.read`).
    pub name: String,
    /// Human-readable description advertised by the server.
    pub description: String,
    /// The JSON Schema for the tool's arguments.
    pub input_schema: Value,
}

/// Substrings that strongly imply a tool can change state or run arbitrary
/// code — classified [`Risk::High`].
const HIGH_RISK_MARKERS: &[&str] = &[
    "shell",
    "exec",
    "command",
    "spawn",
    "subprocess",
    "process",
    "terminal",
    "eval",
    "run_",
    "write",
    "delete",
    "remove",
    "rm",
    "unlink",
    "create",
    "edit",
    "modify",
    "patch",
    "update",
    "put",
    "post",
    "upload",
    "deploy",
    "install",
    "kill",
    "sudo",
    "chmod",
    "chown",
    "sql",
    "drop",
];

/// Substrings that imply a read-only / inspecting tool — classified
/// [`Risk::Low`] when no high-risk marker is present.
const LOW_RISK_MARKERS: &[&str] = &[
    "read", "list", "get", "search", "find", "describe", "inspect", "status", "view", "show",
    "query", "lookup", "fetch", "info",
];

/// Heuristically classify a tool's risk from its name and description.
///
/// A high-risk marker (state-changing or code-executing verbs like
/// `shell`/`exec`/`write`/`delete`) dominates: any match yields [`Risk::High`].
/// Otherwise a read-only marker (`read`/`list`/`get`) yields [`Risk::Low`].
/// Anything unclassified is [`Risk::Medium`] — the safe middle for an unknown
/// capability. The tool's `name` is weighted over its free-text description.
pub fn risk_label(tool: &McpTool) -> Risk {
    let name = tool.name.to_ascii_lowercase();
    let haystack = format!("{} {}", name, tool.description.to_ascii_lowercase());

    if HIGH_RISK_MARKERS.iter().any(|m| haystack.contains(m)) {
        Risk::High
    } else if LOW_RISK_MARKERS.iter().any(|m| haystack.contains(m)) {
        Risk::Low
    } else {
        Risk::Medium
    }
}

// ---------------------------------------------------------------------------
// Server definition loading
// ---------------------------------------------------------------------------

/// How to launch a configured MCP server (the `<server-definition>` file).
///
/// A small JSON document describing the child process that speaks MCP over its
/// stdio: `{ "command": "node", "args": ["server.js"], "env": {.. } }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerDefinition {
    /// The executable to launch.
    pub command: String,
    /// Arguments passed to the executable.
    pub args: Vec<String>,
    /// Extra environment variables for the child process.
    pub env: Vec<(String, String)>,
}

/// Load and parse a server definition file.
///
/// A missing file or one that cannot be parsed into the expected shape yields
/// [`McpError::DefinitionLoad`] so the CLI exits non-zero and **never** starts a
/// proxy.
pub fn load_definition(def: &Path) -> Result<ServerDefinition, McpError> {
    let raw = std::fs::read_to_string(def)
        .map_err(|e| McpError::DefinitionLoad(format!("{}: {e}", def.display())))?;
    parse_definition(&raw)
}

/// Parse a server definition from raw JSON text (pure; used by
/// [`load_definition`] and unit tests).
pub fn parse_definition(raw: &str) -> Result<ServerDefinition, McpError> {
    let value: Value = serde_json::from_str(raw)
        .map_err(|e| McpError::DefinitionLoad(format!("invalid JSON: {e}")))?;

    let command = value
        .get("command")
        .and_then(Value::as_str)
        .ok_or_else(|| McpError::DefinitionLoad("missing string field `command`".to_string()))?
        .to_string();

    let args = match value.get("args") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(items)) => items
            .iter()
            .map(|v| {
                v.as_str()
                    .map(str::to_string)
                    .ok_or_else(|| McpError::DefinitionLoad("`args` must be strings".to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?,
        Some(_) => {
            return Err(McpError::DefinitionLoad(
                "`args` must be an array".to_string(),
            ));
        }
    };

    let env = match value.get("env") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Object(map)) => map
            .iter()
            .map(|(k, v)| {
                v.as_str()
                    .map(|s| (k.clone(), s.to_string()))
                    .ok_or_else(|| {
                        McpError::DefinitionLoad("`env` values must be strings".to_string())
                    })
            })
            .collect::<Result<Vec<_>, _>>()?,
        Some(_) => {
            return Err(McpError::DefinitionLoad(
                "`env` must be an object".to_string(),
            ));
        }
    };

    Ok(ServerDefinition { command, args, env })
}

// ---------------------------------------------------------------------------
// JSON-RPC message helpers
// ---------------------------------------------------------------------------

/// Parse one line of stdio as a JSON-RPC message object.
pub(crate) fn parse_message(line: &str) -> Result<Value, McpError> {
    let value: Value = serde_json::from_str(line.trim())
        .map_err(|e| McpError::Protocol(format!("not valid JSON: {e}")))?;
    if !value.is_object() {
        return Err(McpError::Protocol(
            "message is not a JSON object".to_string(),
        ));
    }
    Ok(value)
}

/// The `method` of a JSON-RPC message, if present.
fn method_of(msg: &Value) -> Option<&str> {
    msg.get("method").and_then(Value::as_str)
}

/// Extract the tool name from a `tools/call` request's `params.name`.
fn tool_name_of(msg: &Value) -> Option<&str> {
    msg.get("params")
        .and_then(|p| p.get("name"))
        .and_then(Value::as_str)
}

/// Build a JSON-RPC error response carrying a policy denial and the matched
/// rule, echoing the request's `id`.
pub(crate) fn policy_denied_response(id: &Value, decision: &DecisionResult) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": POLICY_DENIED_CODE,
            "message": format!("blocked by Fida policy: {}", decision.reason),
            "data": {
                "decision": decision.decision,
                "matched_rule": decision.matched_rule,
                "risk": decision.risk,
                "reason": decision.reason,
            }
        }
    })
}

/// Build a JSON-RPC error response for a `tools/call` naming an unadvertised
/// tool.
fn unknown_tool_response(id: &Value, tool: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": UNKNOWN_TOOL_CODE,
            "message": format!("unknown MCP tool: {tool}"),
        }
    })
}

// ---------------------------------------------------------------------------
// Pure gating decision
// ---------------------------------------------------------------------------

/// The outcome of inspecting a single client→server JSON-RPC message
/// (the pure heart of the pump).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Gating {
    /// Not a `tools/call`: forward upstream unchanged (— only
    /// `tools/call` is gated; every other method passes through).
    Passthrough,
    /// A `tools/call` whose `mcp.tool_call` Action resolved to `allow`:
    /// forward the request upstream unchanged.
    Allow {
        tool: String,
        decision: DecisionResult,
    },
    /// A `tools/call` blocked by policy — `deny`, or `ask` while
    /// non-interactive: return a JSON-RPC error carrying the matched rule and
    /// do **not** contact the server.
    Block {
        tool: String,
        decision: DecisionResult,
    },
    /// A `tools/call` for a tool not advertised by `tools/list`.
    UnknownTool { tool: String },
}

/// Evaluate one client→server message against policy.
///
/// Only `tools/call` is gated: the tool name becomes an `mcp.tool_call`
/// [`Action`] evaluated by [`fida_policy::evaluate`] against the allow/ask/
/// deny tool patterns in their fixed order. `allow` ⇒ forward;
/// `deny` (and `ask` while non-interactive) ⇒ block with the matched rule. A
/// `tools/call` for a tool outside `known_tools` is rejected. Every other
/// method is [`Gating::Passthrough`].
///
/// This is a pure function: no I/O, deterministic in `(msg, policy,
/// known_tools, interactive)`.
pub fn gate_message(
    msg: &Value,
    policy: &CompiledPolicy,
    known_tools: &BTreeSet<String>,
    interactive: bool,
) -> Result<Gating, McpError> {
    if method_of(msg) != Some("tools/call") {
        return Ok(Gating::Passthrough);
    }

    let tool = tool_name_of(msg)
        .ok_or_else(|| McpError::Protocol("tools/call missing params.name".to_string()))?
        .to_string();

    // A tools/call for a tool the server never advertised is rejected.
    // An empty known set means "not yet enumerated"; skip the
    // check so the pump still gates by policy.
    if !known_tools.is_empty() && !known_tools.contains(&tool) {
        return Ok(Gating::UnknownTool { tool });
    }

    let action = Action {
        kind: ActionKind::McpToolCall,
        actor: Actor::Agent,
        payload: ActionPayload::Mcp {
            tool_name: tool.clone(),
        },
    };
    let decision = fida_policy::evaluate(policy, &action);

    let gating = match decision.decision {
        // allow ⇒ forward unchanged.
        Decision::Allow => Gating::Allow { tool, decision },
        // deny ⇒ block, return matched rule.
        Decision::Deny => Gating::Block { tool, decision },
        // ask ⇒ fail closed while non-interactive. No interactive
        // approval UI is wired into the proxy, so an interactive proxy also
        // blocks rather than silently forwarding — fail-closed is the safe
        // default; the matched rule is still surfaced to the caller.
        Decision::Ask => Gating::Block { tool, decision },
        // dry_run ⇒ describe, never forward.
        Decision::DryRun => Gating::Block { tool, decision },
    };
    let _ = interactive; // reserved for future interactive approval wiring.
    Ok(gating)
}

// ---------------------------------------------------------------------------
// Line-delimited JSON-RPC transport
// ---------------------------------------------------------------------------

/// Write one JSON-RPC message as a single line, then flush.
pub(crate) fn write_message<W: Write>(writer: &mut W, msg: &Value) -> Result<(), McpError> {
    let line = serde_json::to_string(msg)
        .map_err(|e| McpError::Protocol(format!("failed to serialize message: {e}")))?;
    writer.write_all(line.as_bytes())?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    Ok(())
}

/// Read the next non-empty line from `reader`, returning `None` at EOF.
pub(crate) fn read_line<R: BufRead>(reader: &mut R) -> Result<Option<String>, McpError> {
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line)?;
        if n == 0 {
            return Ok(None);
        }
        if line.trim().is_empty() {
            continue;
        }
        return Ok(Some(line));
    }
}

/// Read response lines until one whose `id` equals `id`, returning its parsed
/// message. Notifications and unrelated responses are skipped.
fn read_response_for<R: BufRead>(reader: &mut R, id: &Value) -> Result<Value, McpError> {
    loop {
        let line = read_line(reader)?
            .ok_or_else(|| McpError::Protocol("server closed before responding".to_string()))?;
        let msg = parse_message(&line)?;
        if msg.get("id") == Some(id) {
            return Ok(msg);
        }
    }
}

// ---------------------------------------------------------------------------
// tools/list handshake (inspect / list-tools)
// ---------------------------------------------------------------------------

/// Perform the MCP `initialize` + `tools/list` handshake over an injected
/// transport and parse the advertised tools.
///
/// Generic over [`BufRead`]/[`Write`] so it runs against a real server's stdio
/// or an in-memory stub (task 16.2). Any malformed reply is an
/// [`McpError::Protocol`] so the caller exits non-zero without starting a proxy.
pub fn inspect_via<R: BufRead, W: Write>(
    reader: &mut R,
    writer: &mut W,
) -> Result<Vec<McpTool>, McpError> {
    // 1. initialize handshake; ignore the negotiated capabilities.
    let init_id = json!("fida-init");
    write_message(
        writer,
        &json!({
            "jsonrpc": "2.0",
            "id": init_id,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": { "name": "fida", "version": env!("CARGO_PKG_VERSION") }
            }
        }),
    )?;
    let _ = read_response_for(reader, &init_id)?;

    // 2. initialized notification (no response expected).
    write_message(
        writer,
        &json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
    )?;

    // 3. tools/list.
    let list_id = json!("fida-tools-list");
    write_message(
        writer,
        &json!({ "jsonrpc": "2.0", "id": list_id, "method": "tools/list" }),
    )?;
    let response = read_response_for(reader, &list_id)?;

    if let Some(err) = response.get("error") {
        return Err(McpError::Protocol(format!("tools/list failed: {err}")));
    }

    let tools = response
        .get("result")
        .and_then(|r| r.get("tools"))
        .and_then(Value::as_array)
        .ok_or_else(|| McpError::Protocol("tools/list result missing `tools` array".to_string()))?;

    tools.iter().map(parse_tool).collect()
}

/// Parse one `tools/list` entry into an [`McpTool`].
fn parse_tool(entry: &Value) -> Result<McpTool, McpError> {
    let name = entry
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| McpError::Protocol("tool entry missing `name`".to_string()))?
        .to_string();
    let description = entry
        .get("description")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let input_schema = entry
        .get("inputSchema")
        .cloned()
        .unwrap_or_else(|| json!({}));
    Ok(McpTool {
        name,
        description,
        input_schema,
    })
}

// ---------------------------------------------------------------------------
// The proxy / pump
// ---------------------------------------------------------------------------

/// The MCP_Proxy contract (design "MCP_Proxy").
pub trait McpProxy {
    /// Load the server definition and enumerate its tools via `tools/list`.
    fn inspect(&self, def: &Path) -> Result<Vec<McpTool>, McpError>;

    /// Classify a tool's risk label.
    fn risk_label(&self, tool: &McpTool) -> Risk;
}

/// The stdio JSON-RPC pump and inspector.
///
/// Holds the compiled policy, the secret [`Scanner`] used to redact recorded
/// metadata, and whether the session is interactive (proxies run
/// non-interactive and fail closed on `ask`).
#[derive(Debug, Clone)]
pub struct McpPump {
    policy: CompiledPolicy,
    scanner: Scanner,
    interactive: bool,
}

impl McpPump {
    /// Build a pump for `policy`. The secret scanner is derived from the
    /// policy's secret section so recorded metadata is redacted with the same
    /// patterns as everywhere else.
    pub fn new(policy: CompiledPolicy) -> Self {
        let scanner = Scanner::new(&policy.secrets);
        McpPump {
            policy,
            scanner,
            interactive: false,
        }
    }

    /// Set whether the session is interactive (default `false`).
    pub fn with_interactive(mut self, interactive: bool) -> Self {
        self.interactive = interactive;
        self
    }

    /// Spawn the configured MCP server as a child process speaking JSON-RPC
    /// over its stdio.
    fn spawn(def: &ServerDefinition) -> Result<Child, McpError> {
        let mut command = Command::new(&def.command);
        command
            .args(&def.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        for (k, v) in &def.env {
            command.env(k, v);
        }
        command.spawn().map_err(McpError::ServerSpawn)
    }

    /// Drive the line-synchronous gating pump between a client and an upstream
    /// server.
    ///
    /// For each client→server message: `tools/call` is gated by
    /// [`gate_message`] — `allow` forwards the original request unchanged and
    /// relays the server's response; `deny` / non-interactive `ask` returns a
    /// JSON-RPC error carrying the matched rule **without** contacting the
    /// server. Every other method is forwarded untouched. Each gated call
    /// records exactly one audit event with secret redaction applied. Returns
    /// at client EOF, or `Err` on an unknown tool or
    /// transport/protocol fault.
    #[allow(clippy::too_many_arguments)]
    pub fn pump<CIn, COut, SIn, SOut>(
        &self,
        client_in: &mut CIn,
        client_out: &mut COut,
        server_in: &mut SIn,
        server_out: &mut SOut,
        known_tools: &BTreeSet<String>,
        audit: &mut dyn AuditStore,
        session: &mut SessionHandle,
    ) -> Result<(), McpError>
    where
        CIn: BufRead,
        COut: Write,
        SIn: Write,
        SOut: BufRead,
    {
        while let Some(line) = read_line(client_in)? {
            let msg = parse_message(&line)?;
            match gate_message(&msg, &self.policy, known_tools, self.interactive)? {
                Gating::Passthrough => {
                    // Forward untouched. Await a reply only when the
                    // message is a request (carries an id), not a notification.
                    write_message(server_in, &msg)?;
                    if let Some(id) = msg.get("id").filter(|v| !v.is_null()) {
                        let response = read_response_for(server_out, &id.clone())?;
                        write_message(client_out, &response)?;
                    }
                }
                Gating::Allow { tool, decision } => {
                    // Forward the original request unchanged.
                    write_message(server_in, &msg)?;
                    let id = msg.get("id").cloned().unwrap_or(Value::Null);
                    let response = read_response_for(server_out, &id)?;
                    // Audit request + response metadata, redacted.
                    let redacted = self.metadata_has_secret(&line)
                        || self.metadata_has_secret(&response.to_string());
                    self.record(
                        audit,
                        session,
                        &tool,
                        &decision,
                        AuditResult::Allowed,
                        redacted,
                    );
                    write_message(client_out, &response)?;
                }
                Gating::Block { tool, decision } => {
                    // Do NOT contact the server; return the matched rule.
                    let id = msg.get("id").cloned().unwrap_or(Value::Null);
                    let result = if decision.decision == Decision::Deny {
                        AuditResult::Denied
                    } else {
                        AuditResult::Blocked
                    };
                    let redacted = self.metadata_has_secret(&line);
                    self.record(audit, session, &tool, &decision, result, redacted);
                    write_message(client_out, &policy_denied_response(&id, &decision))?;
                }
                Gating::UnknownTool { tool } => {
                    let id = msg.get("id").cloned().unwrap_or(Value::Null);
                    write_message(client_out, &unknown_tool_response(&id, &tool))?;
                    return Err(McpError::UnknownTool(tool));
                }
            }
        }
        Ok(())
    }

    /// Whether `metadata` contains any detectable secret. The metadata string
    /// itself is **never** persisted — only this boolean flag and the
    /// redaction-safe [`AuditAction`] reach the store. Redaction
    /// failure is treated as "secret present" (fail-closed).
    fn metadata_has_secret(&self, metadata: &str) -> bool {
        !self.scanner.scan(metadata).is_empty() || self.scanner.redact(metadata).is_err()
    }

    /// Append exactly one redaction-safe audit event for a gated `tools/call`.
    /// Only the tool name, decision, matched rule, and risk are
    /// recorded — never the request/response payload.
    fn record(
        &self,
        audit: &mut dyn AuditStore,
        session: &mut SessionHandle,
        tool: &str,
        decision: &DecisionResult,
        result: AuditResult,
        redacted: bool,
    ) {
        let event = AuditEvent {
            id: session.next_event_id(),
            session_id: session.session_id().to_string(),
            time: Utc::now(),
            actor: Actor::Agent,
            action: AuditAction::McpToolCall {
                tool: tool.to_string(),
            },
            decision: decision.decision,
            result,
            matched_rule: decision.matched_rule.clone(),
            risk: decision.risk,
            redacted,
            metrics: None,
        };
        let _ = audit.append(&event);
    }
}

impl McpProxy for McpPump {
    fn inspect(&self, def: &Path) -> Result<Vec<McpTool>, McpError> {
        let definition = load_definition(def)?;
        let mut child = Self::spawn(&definition)?;
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| McpError::Protocol("server stdin unavailable".to_string()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| McpError::Protocol("server stdout unavailable".to_string()))?;
        let mut reader = io::BufReader::new(stdout);
        let tools = inspect_via(&mut reader, &mut stdin);
        // Best-effort teardown of the inspected server.
        let _ = child.kill();
        let _ = child.wait();
        tools
    }

    fn risk_label(&self, tool: &McpTool) -> Risk {
        risk_label(tool)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use fida_action::MatchedRule;
    use fida_audit::AuditStore;
    use fida_audit::testing::MemoryAuditStore;
    use fida_policy::{CompiledPolicy, PolicySource, load_source};
    use std::io::Cursor;

    const SESSION: &str = "2026-06-12T070000Z-mcp001";

    /// A policy that allows `fs.read`, denies `shell.exec`, and asks for
    /// `net.fetch`; the global default is `ask`.
    const TEST_POLICY: &str = r#"
version: 1
default_decision: ask

commands: {}
files:
  read:
    allow: ["**/*"]
network: {}
mcp:
  tools:
    allow:
      - pattern: fs.read
    deny:
      - pattern: shell.exec
    ask:
      - pattern: net.fetch
secrets:
  redact: true
  block_in_diffs: true
  patterns:
    - name: api_token
      regex: "tok_[A-Za-z0-9]{8,}"
audit:
  path: .fida/sessions
  format: jsonl
  redact_stdout: true
  redact_stderr: true
"#;

    fn policy() -> CompiledPolicy {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fida.yaml");
        std::fs::write(&path, TEST_POLICY).unwrap();
        load_source(&PolicySource::Config(path), None).expect("policy compiles")
    }

    fn known() -> BTreeSet<String> {
        ["fs.read", "shell.exec", "net.fetch"]
            .into_iter()
            .map(str::to_string)
            .collect()
    }

    fn tool(name: &str, desc: &str) -> McpTool {
        McpTool {
            name: name.to_string(),
            description: desc.to_string(),
            input_schema: json!({}),
        }
    }

    // -- risk_label -------------------------------------------------------

    #[test]
    fn risk_label_high_for_state_changing_tools() {
        assert_eq!(
            risk_label(&tool("shell.exec", "run a shell command")),
            Risk::High
        );
        assert_eq!(risk_label(&tool("fs.write", "write a file")), Risk::High);
        assert_eq!(risk_label(&tool("db.drop", "drop a table")), Risk::High);
    }

    #[test]
    fn risk_label_low_for_read_only_tools() {
        assert_eq!(risk_label(&tool("fs.read", "read a file")), Risk::Low);
        assert_eq!(
            risk_label(&tool("tools.list", "list available tools")),
            Risk::Low
        );
    }

    #[test]
    fn risk_label_high_marker_dominates_low_marker() {
        // "read" is low, but "write" is high -> high wins.
        assert_eq!(
            risk_label(&tool("sync", "read then write back changes")),
            Risk::High
        );
    }

    #[test]
    fn risk_label_medium_when_unclassified() {
        assert_eq!(
            risk_label(&tool("ponder", "contemplate the universe")),
            Risk::Medium
        );
    }

    // -- server definition ------------------------------------------------

    #[test]
    fn parse_definition_reads_command_args_env() {
        let def = parse_definition(
            r#"{ "command": "node", "args": ["server.js"], "env": { "KEY": "v" } }"#,
        )
        .expect("parses");
        assert_eq!(def.command, "node");
        assert_eq!(def.args, vec!["server.js".to_string()]);
        assert_eq!(def.env, vec![("KEY".to_string(), "v".to_string())]);
    }

    #[test]
    fn unparseable_definition_is_load_error() {
        let err = parse_definition("not json at all").unwrap_err();
        assert!(matches!(err, McpError::DefinitionLoad(_)));
    }

    #[test]
    fn definition_missing_command_is_load_error() {
        let err = parse_definition(r#"{ "args": [] }"#).unwrap_err();
        assert!(matches!(err, McpError::DefinitionLoad(_)));
    }

    #[test]
    fn load_definition_missing_file_is_load_error() {
        let err = load_definition(Path::new("/nonexistent/fida-mcp-server.json")).unwrap_err();
        assert!(matches!(err, McpError::DefinitionLoad(_)));
    }

    // -- inspect_via (tools/list handshake) -------------------------------

    /// A canned stub stdout: an `initialize` result then a `tools/list` result.
    fn stub_server_stdout() -> String {
        let init = json!({ "jsonrpc": "2.0", "id": "fida-init", "result": { "capabilities": {} } });
        let tools = json!({
            "jsonrpc": "2.0",
            "id": "fida-tools-list",
            "result": {
                "tools": [
                    { "name": "fs.read", "description": "read a file", "inputSchema": { "type": "object" } },
                    { "name": "shell.exec", "description": "run a shell command" }
                ]
            }
        });
        format!("{init}\n{tools}\n")
    }

    #[test]
    fn inspect_via_parses_tools_list() {
        let mut reader = Cursor::new(stub_server_stdout());
        let mut writer: Vec<u8> = Vec::new();
        let tools = inspect_via(&mut reader, &mut writer).expect("handshake");

        assert_eq!(tools.len(), 2);
        assert_eq!(tools[0].name, "fs.read");
        assert_eq!(tools[0].description, "read a file");
        assert_eq!(tools[0].input_schema, json!({ "type": "object" }));
        assert_eq!(tools[1].name, "shell.exec");
        // Missing inputSchema defaults to empty object.
        assert_eq!(tools[1].input_schema, json!({}));

        // The client must have written initialize, initialized, tools/list.
        let written = String::from_utf8(writer).unwrap();
        assert!(written.contains("\"initialize\""));
        assert!(written.contains("notifications/initialized"));
        assert!(written.contains("tools/list"));
    }

    #[test]
    fn inspect_via_errors_on_missing_tools_array() {
        let init = json!({ "jsonrpc": "2.0", "id": "fida-init", "result": {} });
        let bad = json!({ "jsonrpc": "2.0", "id": "fida-tools-list", "result": {} });
        let mut reader = Cursor::new(format!("{init}\n{bad}\n"));
        let mut writer: Vec<u8> = Vec::new();
        let err = inspect_via(&mut reader, &mut writer).unwrap_err();
        assert!(matches!(err, McpError::Protocol(_)));
    }

    // -- gate_message (pure gating) ---------------------------------------

    fn tools_call(id: i64, name: &str) -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": { "name": name, "arguments": {} }
        })
    }

    #[test]
    fn gate_allows_allowed_tool() {
        let p = policy();
        let known = known();
        let g = gate_message(&tools_call(1, "fs.read"), &p, &known, false).unwrap();
        match g {
            Gating::Allow { tool, decision } => {
                assert_eq!(tool, "fs.read");
                assert_eq!(decision.decision, Decision::Allow);
            }
            other => panic!("expected Allow, got {other:?}"),
        }
    }

    #[test]
    fn gate_blocks_denied_tool_with_matched_rule() {
        let p = policy();
        let known = known();
        let g = gate_message(&tools_call(2, "shell.exec"), &p, &known, false).unwrap();
        match g {
            Gating::Block { tool, decision } => {
                assert_eq!(tool, "shell.exec");
                assert_eq!(decision.decision, Decision::Deny);
                assert!(matches!(decision.matched_rule, MatchedRule::Rule(_)));
            }
            other => panic!("expected Block, got {other:?}"),
        }
    }

    #[test]
    fn gate_blocks_ask_when_non_interactive() {
        let p = policy();
        let known = known();
        let g = gate_message(&tools_call(3, "net.fetch"), &p, &known, false).unwrap();
        match g {
            Gating::Block { decision, .. } => assert_eq!(decision.decision, Decision::Ask),
            other => panic!("expected Block, got {other:?}"),
        }
    }

    #[test]
    fn gate_passes_through_non_tools_call() {
        let p = policy();
        let known = known();
        let msg = json!({ "jsonrpc": "2.0", "id": 9, "method": "tools/list" });
        assert_eq!(
            gate_message(&msg, &p, &known, false).unwrap(),
            Gating::Passthrough
        );
    }

    #[test]
    fn gate_rejects_unknown_tool() {
        let p = policy();
        let known = known();
        let g = gate_message(&tools_call(4, "mystery.tool"), &p, &known, false).unwrap();
        assert_eq!(
            g,
            Gating::UnknownTool {
                tool: "mystery.tool".to_string()
            }
        );
    }

    // -- pump end-to-end (in-memory transports) ---------------------------

    struct Harness {
        pump: McpPump,
        audit: MemoryAuditStore,
        session: SessionHandle,
    }

    impl Harness {
        fn new() -> Self {
            Harness {
                pump: McpPump::new(policy()),
                audit: MemoryAuditStore::new(),
                session: SessionHandle::new(SESSION),
            }
        }

        fn run(&mut self, client_msgs: &str, server_msgs: &str) -> (String, Vec<u8>) {
            let mut client_in = Cursor::new(client_msgs.to_string());
            let mut client_out: Vec<u8> = Vec::new();
            let mut server_out = Cursor::new(server_msgs.to_string());
            let mut server_in: Vec<u8> = Vec::new();
            let result = self.pump.pump(
                &mut client_in,
                &mut client_out,
                &mut server_in,
                &mut server_out,
                &known(),
                &mut self.audit,
                &mut self.session,
            );
            // Ignore the UnknownTool early-return for inspection in that test.
            let _ = result;
            (String::from_utf8(client_out).unwrap(), server_in)
        }

        fn events(&self) -> Vec<AuditEvent> {
            self.audit.read(SESSION).unwrap()
        }
    }

    #[test]
    fn pump_forwards_allowed_call_and_relays_response() {
        let mut h = Harness::new();
        let client = format!("{}\n", tools_call(1, "fs.read"));
        let server_resp = json!({ "jsonrpc": "2.0", "id": 1, "result": { "content": "ok" } });
        let (client_out, server_in) = h.run(&client, &format!("{server_resp}\n"));

        // Request forwarded upstream unchanged.
        let forwarded = String::from_utf8(server_in).unwrap();
        assert!(forwarded.contains("\"fs.read\""));
        // Server response relayed back to the client.
        assert!(client_out.contains("\"content\":\"ok\""));
        // Exactly one audit event, allowed.
        let events = h.events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].result, AuditResult::Allowed);
        assert_eq!(events[0].decision, Decision::Allow);
        assert!(matches!(
            events[0].action,
            AuditAction::McpToolCall { ref tool } if tool == "fs.read"
        ));
    }

    #[test]
    fn pump_denies_without_contacting_server() {
        let mut h = Harness::new();
        let client = format!("{}\n", tools_call(2, "shell.exec"));
        let (client_out, server_in) = h.run(&client, "");

        // Nothing was forwarded upstream.
        assert!(server_in.is_empty(), "deny must not contact the server");
        // A JSON-RPC error carrying the matched rule went back to the client.
        let response: Value = serde_json::from_str(client_out.trim()).unwrap();
        assert_eq!(response["error"]["code"], POLICY_DENIED_CODE);
        assert!(response["error"]["data"]["matched_rule"].is_string());
        assert_eq!(response["error"]["data"]["decision"], "deny");
        // Audited as denied.
        assert_eq!(h.events()[0].result, AuditResult::Denied);
    }

    #[test]
    fn pump_passes_through_other_methods() {
        let mut h = Harness::new();
        let client = json!({ "jsonrpc": "2.0", "id": 7, "method": "ping" });
        let server_resp = json!({ "jsonrpc": "2.0", "id": 7, "result": "pong" });
        let (client_out, server_in) = h.run(&format!("{client}\n"), &format!("{server_resp}\n"));

        // Forwarded unchanged and response relayed; no audit event recorded.
        assert!(String::from_utf8(server_in).unwrap().contains("\"ping\""));
        assert!(client_out.contains("pong"));
        assert!(h.events().is_empty(), "only tools/call is audited");
    }

    #[test]
    fn pump_records_redaction_flag_when_arguments_carry_secret() {
        let mut h = Harness::new();
        // fs.read is allowed; its arguments embed a policy-pattern secret.
        let call = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": { "name": "fs.read", "arguments": { "token": "tok_abcd1234" } }
        });
        let server_resp = json!({ "jsonrpc": "2.0", "id": 1, "result": {} });
        h.run(&format!("{call}\n"), &format!("{server_resp}\n"));

        let events = h.events();
        assert_eq!(events.len(), 1);
        assert!(
            events[0].redacted,
            "secret in arguments must flag redaction"
        );
        // The raw secret never reaches the audit record.
        let serialized = serde_json::to_string(&events[0]).unwrap();
        assert!(!serialized.contains("tok_abcd1234"));
    }
}
