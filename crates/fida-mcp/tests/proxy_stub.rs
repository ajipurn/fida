//! Integration test for the MCP_Proxy against a *stub stdio server*
//! (spec task 16.2; design "MCP Proxy Design").
//!
//! The "stub stdio server" is modeled with in-memory [`Cursor`] buffers: the
//! server's stdout is a canned sequence of JSON-RPC reply lines and its stdin
//! is a writable buffer we inspect to prove what (if anything) the proxy
//! forwarded. This drives the public, transport-injectable surface of the
//! crate — [`inspect_via`] for the `tools/list` handshake and [`McpPump::pump`]
//! for `tools/call` gating — without spawning a real process.
//!
//! Coverage:
//! * `tools/list` inspection — parse advertised tools.
//! * `tools/call` allow — forward to the server, relay its reply,
//!   audit `Allowed`.
//! * `tools/call` deny — return a JSON-RPC error carrying the
//!   matched rule, never contact the server, audit `Denied`.

use std::collections::BTreeSet;
use std::io::Cursor;

use serde_json::{Value, json};

use fida_action::SessionHandle;
use fida_audit::testing::MemoryAuditStore;
use fida_audit::{AuditAction, AuditResult, AuditStore};
use fida_mcp::{McpPump, POLICY_DENIED_CODE, inspect_via};
use fida_policy::{CompiledPolicy, PolicySource, load_source};

const SESSION: &str = "2026-06-12T070000Z-proxy01";

/// A policy that allows the `fs.read` MCP tool and denies `shell.exec`; the
/// global default is `ask`.
const POLICY_YAML: &str = r#"
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
secrets:
  redact: true
  block_in_diffs: true
  patterns: []
audit:
  path: .fida/sessions
  format: jsonl
  redact_stdout: true
  redact_stderr: true
"#;

/// Compile [`POLICY_YAML`] through the real loader from a temp file.
fn policy() -> CompiledPolicy {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("fida.yaml");
    std::fs::write(&path, POLICY_YAML).unwrap();
    load_source(&PolicySource::Config(path), None).expect("policy compiles")
}

/// The tools the stub server advertises through `tools/list`.
fn known_tools() -> BTreeSet<String> {
    ["fs.read", "shell.exec"]
        .into_iter()
        .map(str::to_string)
        .collect()
}

/// A `tools/call` request line for `name` with the given JSON-RPC `id`.
fn tools_call(id: i64, name: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": { "name": name, "arguments": {} }
    })
}

// ---------------------------------------------------------------------------
// 1. tools/list inspection
// ---------------------------------------------------------------------------

#[test]
fn tools_list_inspection_parses_advertised_tools() {
    // The stub server's stdout: an `initialize` result then a `tools/list`
    // result advertising two tools with distinct schemas.
    let init = json!({ "jsonrpc": "2.0", "id": "fida-init", "result": { "capabilities": {} } });
    let list = json!({
        "jsonrpc": "2.0",
        "id": "fida-tools-list",
        "result": {
            "tools": [
                {
                    "name": "fs.read",
                    "description": "read a file from disk",
                    "inputSchema": { "type": "object", "properties": { "path": { "type": "string" } } }
                },
                {
                    "name": "shell.exec",
                    "description": "run a shell command",
                    "inputSchema": { "type": "object", "properties": { "cmd": { "type": "string" } } }
                }
            ]
        }
    });
    let mut server_stdout = Cursor::new(format!("{init}\n{list}\n"));
    let mut server_stdin: Vec<u8> = Vec::new();

    let tools = inspect_via(&mut server_stdout, &mut server_stdin).expect("handshake succeeds");

    assert_eq!(tools.len(), 2);

    assert_eq!(tools[0].name, "fs.read");
    assert_eq!(tools[0].description, "read a file from disk");
    assert_eq!(
        tools[0].input_schema,
        json!({ "type": "object", "properties": { "path": { "type": "string" } } })
    );

    assert_eq!(tools[1].name, "shell.exec");
    assert_eq!(tools[1].description, "run a shell command");
    assert_eq!(
        tools[1].input_schema,
        json!({ "type": "object", "properties": { "cmd": { "type": "string" } } })
    );

    // The proxy must have driven the full handshake on the wire.
    let written = String::from_utf8(server_stdin).unwrap();
    assert!(written.contains("\"initialize\""));
    assert!(written.contains("notifications/initialized"));
    assert!(written.contains("tools/list"));
}

// ---------------------------------------------------------------------------
// 2. tools/call allow -> forwarded and relayed
// ---------------------------------------------------------------------------

#[test]
fn tools_call_allow_is_forwarded_and_response_relayed() {
    let pump = McpPump::new(policy());
    let mut audit = MemoryAuditStore::new();
    let mut session = SessionHandle::new(SESSION);

    // Client issues an allowed `fs.read` call.
    let mut client_in = Cursor::new(format!("{}\n", tools_call(1, "fs.read")));
    let mut client_out: Vec<u8> = Vec::new();
    // Stub server's canned reply to the forwarded call.
    let server_reply = json!({ "jsonrpc": "2.0", "id": 1, "result": { "content": "file body" } });
    let mut server_out = Cursor::new(format!("{server_reply}\n"));
    let mut server_in: Vec<u8> = Vec::new();

    pump.pump(
        &mut client_in,
        &mut client_out,
        &mut server_in,
        &mut server_out,
        &known_tools(),
        &mut audit,
        &mut session,
    )
    .expect("pump runs to client EOF");

    // The request was forwarded to the stub server unchanged.
    let forwarded = String::from_utf8(server_in).unwrap();
    assert!(
        forwarded.contains("\"fs.read\""),
        "allowed call must reach the server: {forwarded}"
    );

    // The server's response was relayed back to the client.
    let relayed = String::from_utf8(client_out).unwrap();
    assert!(
        relayed.contains("\"content\":\"file body\""),
        "server response must be relayed to the client: {relayed}"
    );

    // Exactly one audit event, recording the allow.
    let events = audit.read(SESSION).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].result, AuditResult::Allowed);
    assert!(matches!(
        events[0].action,
        AuditAction::McpToolCall { ref tool } if tool == "fs.read"
    ));
}

// ---------------------------------------------------------------------------
// 3. tools/call deny -> JSON-RPC error, no forward
// ---------------------------------------------------------------------------

#[test]
fn tools_call_deny_returns_error_and_never_contacts_server() {
    let pump = McpPump::new(policy());
    let mut audit = MemoryAuditStore::new();
    let mut session = SessionHandle::new(SESSION);

    // Client issues a denied `shell.exec` call.
    let mut client_in = Cursor::new(format!("{}\n", tools_call(2, "shell.exec")));
    let mut client_out: Vec<u8> = Vec::new();
    // The server stdout is empty: a correct proxy never reads from it on deny.
    let mut server_out = Cursor::new(String::new());
    let mut server_in: Vec<u8> = Vec::new();

    pump.pump(
        &mut client_in,
        &mut client_out,
        &mut server_in,
        &mut server_out,
        &known_tools(),
        &mut audit,
        &mut session,
    )
    .expect("pump runs to client EOF");

    // Nothing was forwarded to the stub server.
    assert!(
        server_in.is_empty(),
        "deny must not contact the server, but forwarded: {:?}",
        String::from_utf8_lossy(&server_in)
    );

    // The client received a JSON-RPC error carrying the policy denial and the
    // matched rule.
    let response: Value = serde_json::from_str(String::from_utf8(client_out).unwrap().trim())
        .expect("client received a JSON-RPC object");
    assert_eq!(response["id"], json!(2));
    assert_eq!(response["error"]["code"], POLICY_DENIED_CODE);
    assert_eq!(response["error"]["data"]["decision"], "deny");
    assert!(
        response["error"]["data"]["matched_rule"].is_string(),
        "the error must carry the matched rule: {response}"
    );

    // The denial was audited exactly once.
    let events = audit.read(SESSION).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].result, AuditResult::Denied);
    assert!(matches!(
        events[0].action,
        AuditAction::McpToolCall { ref tool } if tool == "shell.exec"
    ));
}
