//! `fida-mcp::server` — the **gateway** MCP server.
//!
//! Where [`crate::McpPump`] is a *proxy* that gates another server's
//! `tools/call`, this module makes Fida itself an MCP **server**: it advertises
//! a small set of Fida-mediated tools and runs each call through the same
//! policy → execute → redact → audit path as the rest of Fida.
//!
//! It exists to close the gap that file-and-shell-capable agents (IDE-embedded
//! ones like Kiro, Cursor, Cline) leave open: their *native* file/shell tools
//! never pass through Fida, so their output cannot be inspected or redacted.
//! Pointing such an agent at this server, and steering it to use these tools
//! instead of its native ones, routes the operations through leak prevention.
//!
//! Two tools are exposed (one per enforceable surface):
//!
//! * [`READ_TOOL`] (`fida_read`) — read a file's text, gated by `files.read`,
//!   with secret redaction applied to the returned content.
//! * [`SHELL_TOOL`] (`fida_shell`) — run a command, gated by `commands.run`,
//!   with redacted stdout/stderr and the exit code returned.
//!
//! This is **not** an OS sandbox: it only mediates calls that actually arrive
//! as `fida_read`/`fida_shell`. An agent that ignores the steering and uses its
//! native tools bypasses it — that is what the companion `preToolUse` hook
//! backstops. See the project README "Guarding IDE-embedded agents".
//!
//! # Testability
//!
//! [`GatewayServer::serve`] is generic over [`BufRead`]/[`Write`] so tests drive
//! it against in-memory buffers, and the gating decision is the pure
//! [`fida_policy::evaluate`] over a built [`Action`].

use std::io::{BufRead, Write};
use std::path::{Component, Path, PathBuf};

use chrono::Utc;
use serde_json::{Value, json};

use fida_action::SessionHandle;
use fida_action::{
    Action, ActionKind, ActionPayload, Actor, Decision, DecisionResult, EvalStage, MatchedRule,
    Risk,
};
use fida_audit::{AuditAction, AuditEvent, AuditResult, AuditStore};
use fida_policy::CompiledPolicy;
use fida_secrets::{Scanner, SecretScanner};

use crate::{
    McpError, UNKNOWN_TOOL_CODE, parse_message, policy_denied_response, read_line, write_message,
};

/// The MCP protocol version advertised in the `initialize` handshake.
const PROTOCOL_VERSION: &str = "2024-11-05";

/// JSON-RPC standard "method not found" error code.
const METHOD_NOT_FOUND_CODE: i64 = -32601;
/// JSON-RPC standard "invalid params" error code.
const INVALID_PARAMS_CODE: i64 = -32602;

/// The gateway file-read tool name (gated by `files.read`).
pub const READ_TOOL: &str = "fida_read";
/// The gateway command tool name (gated by `commands.run`).
pub const SHELL_TOOL: &str = "fida_shell";

/// JSON-RPC error code returned when PathJail blocks an out-of-workspace path.
pub const PATHJAIL_DENIED_CODE: i64 = -32003;

/// A Fida-mediated MCP server.
///
/// Holds the compiled policy, a secret [`Scanner`] (derived from the policy so
/// redaction uses the same patterns as everywhere else), the workspace root
/// that relative paths and command working directories resolve against, and the
/// command executor used by [`SHELL_TOOL`].
#[derive(Debug, Clone)]
pub struct GatewayServer {
    policy: CompiledPolicy,
    scanner: Scanner,
    workspace: PathBuf,
    /// Canonical workspace root used as the PathJail boundary.
    workspace_canon: PathBuf,
    /// Canonical roots `fida_read` may read from. Always includes workspace.
    read_roots_canon: Vec<PathBuf>,
    /// When true (default), confine reads to configured roots and shell cwd to workspace.
    jail: bool,
    /// When true, wrap `fida_shell` commands in an OS sandbox (opt-in).
    sandbox: bool,
}

impl GatewayServer {
    /// Build a gateway for `policy`, resolving relative paths against
    /// `workspace`. PathJail is enabled by default.
    pub fn new(policy: CompiledPolicy, workspace: impl Into<PathBuf>) -> Self {
        let scanner = Scanner::new(&policy.secrets);
        let workspace = workspace.into();
        let workspace_canon =
            std::fs::canonicalize(&workspace).unwrap_or_else(|_| normalize_lexical(&workspace));
        GatewayServer {
            policy,
            scanner,
            workspace,
            workspace_canon: workspace_canon.clone(),
            read_roots_canon: vec![workspace_canon],
            jail: true,
            sandbox: false,
        }
    }

    /// Add roots that `fida_read` may read from in addition to the workspace.
    ///
    /// This is intentionally read-only: `fida_shell` working directories remain
    /// confined to the workspace root. Integrations can use this for
    /// user-provided attachment directories while preserving the default
    /// workspace jail for everything else.
    pub fn with_extra_read_roots<I, P>(mut self, roots: I) -> Self
    where
        I: IntoIterator<Item = P>,
        P: Into<PathBuf>,
    {
        for root in roots {
            let canon = canonicalize_root(root.into(), &self.workspace);
            if !self.read_roots_canon.contains(&canon) {
                self.read_roots_canon.push(canon);
            }
        }
        self
    }

    /// Enable or disable PathJail confinement (default: enabled).
    ///
    /// Disabling still evaluates policy and audits, but no longer blocks paths
    /// resolved outside configured roots — useful for containers or monorepos
    /// with external mounts.
    pub fn with_jail(mut self, jail: bool) -> Self {
        self.jail = jail;
        self
    }

    /// Enable OS-level sandboxing of `fida_shell` commands (default: disabled).
    ///
    /// When enabled and a backend is available (Seatbelt on macOS, bubblewrap
    /// on Linux), each command's argv is wrapped so the spawned process is
    /// network-isolated and blocked from reading common secret stores.
    pub fn with_sandbox(mut self, sandbox: bool) -> Self {
        self.sandbox = sandbox;
        self
    }

    /// Run the stdio JSON-RPC server loop until the client closes its input.
    ///
    /// Each request is dispatched by [`GatewayServer::dispatch`]; notifications
    /// (messages without an `id`) produce no response. Every gated `tools/call`
    /// appends exactly one redaction-safe audit event.
    pub fn serve<R: BufRead, W: Write>(
        &self,
        reader: &mut R,
        writer: &mut W,
        audit: &mut dyn AuditStore,
        session: &mut SessionHandle,
    ) -> Result<(), McpError> {
        while let Some(line) = read_line(reader)? {
            let msg = parse_message(&line)?;
            if let Some(response) = self.dispatch(&msg, audit, session) {
                write_message(writer, &response)?;
            }
        }
        Ok(())
    }

    /// Route one client message to a response, or `None` for a notification.
    ///
    /// Pure with respect to the protocol shape; `tools/call` delegates to
    /// [`GatewayServer::handle_call`], which performs the gated side effects.
    fn dispatch(
        &self,
        msg: &Value,
        audit: &mut dyn AuditStore,
        session: &mut SessionHandle,
    ) -> Option<Value> {
        let method = msg.get("method").and_then(Value::as_str)?;
        let id = msg.get("id").cloned();

        match method {
            "initialize" => id.map(initialize_response),
            "tools/list" => id.map(tools_list_response),
            "tools/call" => {
                let id = id.unwrap_or(Value::Null);
                Some(self.handle_call(msg, id, audit, session))
            }
            // Notifications (`notifications/initialized`, etc.) expect no reply.
            m if m.starts_with("notifications/") => None,
            // Any other method: error only when it is a request (has an id).
            other => id.map(|id| method_not_found(&id, other)),
        }
    }

    /// Handle a `tools/call` request: parse the tool + arguments, gate by
    /// policy, and either execute (allow) or return a JSON-RPC policy denial.
    fn handle_call(
        &self,
        msg: &Value,
        id: Value,
        audit: &mut dyn AuditStore,
        session: &mut SessionHandle,
    ) -> Value {
        let params = msg.get("params");
        let name = params
            .and_then(|p| p.get("name"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        let args = params
            .and_then(|p| p.get("arguments"))
            .cloned()
            .unwrap_or_else(|| json!({}));

        match name {
            READ_TOOL => self.call_read(&id, &args, audit, session),
            SHELL_TOOL => self.call_shell(&id, &args, audit, session),
            other => json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {
                    "code": UNKNOWN_TOOL_CODE,
                    "message": format!("unknown Fida gateway tool: {other}"),
                }
            }),
        }
    }

    // -- fida_read ----------------------------------------------------------

    /// Evaluate and, when allowed, perform a `files.read`-gated file read.
    fn call_read(
        &self,
        id: &Value,
        args: &Value,
        audit: &mut dyn AuditStore,
        session: &mut SessionHandle,
    ) -> Value {
        let Some(path_arg) = args.get("path").and_then(Value::as_str) else {
            return invalid_params(id, "`fida_read` requires a string `path` argument");
        };

        let (abs, policy_path) = self.resolve_path(path_arg);

        // PathJail: confine reads to the workspace and any explicitly trusted
        // read roots. Checked before policy so arbitrary escapes never touch disk.
        if let Err(reason) = self.read_jail_check(&abs) {
            let decision = pathjail_decision(reason);
            self.record_path(
                audit,
                session,
                ActionKind::FileRead,
                &policy_path,
                &decision,
            );
            return pathjail_response(id, &decision);
        }

        let action = Action {
            kind: ActionKind::FileRead,
            actor: Actor::Agent,
            payload: ActionPayload::File {
                path: policy_path.clone(),
            },
        };
        let decision = fida_policy::evaluate(&self.policy, &action);

        if decision.decision != Decision::Allow {
            self.record(
                audit,
                session,
                &action,
                &decision,
                block_result(&decision),
                false,
            );
            return policy_denied_response(id, &decision);
        }

        // Allowed: read the file, then redact secrets from the returned text.
        match std::fs::read_to_string(&abs) {
            Ok(content) => match self.scanner.redact(&content) {
                Ok(redacted) => {
                    let had_secret = redacted != content;
                    self.record(
                        audit,
                        session,
                        &action,
                        &decision,
                        AuditResult::Allowed,
                        had_secret,
                    );
                    tool_text_result(id, &redacted)
                }
                Err(_) => {
                    // Fail closed: never return content we could not redact.
                    self.record(
                        audit,
                        session,
                        &action,
                        &decision,
                        AuditResult::Blocked,
                        true,
                    );
                    tool_error_result(
                        id,
                        "secret redaction could not be completed; content suppressed",
                    )
                }
            },
            Err(e) => {
                self.record(
                    audit,
                    session,
                    &action,
                    &decision,
                    AuditResult::Allowed,
                    false,
                );
                tool_error_result(id, &format!("cannot read {}: {e}", abs.display()))
            }
        }
    }

    // -- fida_shell ---------------------------------------------------------

    /// Evaluate and, when allowed, perform a `commands.run`-gated command.
    fn call_shell(
        &self,
        id: &Value,
        args: &Value,
        audit: &mut dyn AuditStore,
        session: &mut SessionHandle,
    ) -> Value {
        let Some(command) = args.get("command").and_then(Value::as_str) else {
            return invalid_params(id, "`fida_shell` requires a string `command` argument");
        };
        let argv: Vec<String> = command.split_whitespace().map(str::to_string).collect();
        if argv.is_empty() {
            return invalid_params(id, "`fida_shell` `command` was empty");
        }

        let cwd = match args.get("cwd").and_then(Value::as_str) {
            Some(dir) => self.resolve_path(dir).0,
            None => self.workspace.clone(),
        };

        // PathJail: the command's working directory must stay in the workspace.
        if let Err(reason) = self.workspace_jail_check(&cwd) {
            let decision = pathjail_decision(reason);
            let policy_path = PathBuf::from(command);
            self.record_path(
                audit,
                session,
                ActionKind::CommandRun,
                &policy_path,
                &decision,
            );
            return pathjail_response(id, &decision);
        }

        let action = Action {
            kind: ActionKind::CommandRun,
            actor: Actor::Agent,
            payload: ActionPayload::Command {
                argv: argv.clone(),
                cwd: cwd.clone(),
            },
        };
        let decision = fida_policy::evaluate(&self.policy, &action);

        if decision.decision != Decision::Allow {
            self.record(
                audit,
                session,
                &action,
                &decision,
                block_result(&decision),
                false,
            );
            return policy_denied_response(id, &decision);
        }

        // Capture output directly (never stream to our stdout — that is the
        // JSON-RPC channel). stdin is null so commands like `cat` with no args
        // cannot hang waiting on input.
        let exec_argv = if self.sandbox {
            crate::sandbox::wrap(&argv, &self.workspace)
        } else {
            argv
        };
        let output = std::process::Command::new(&exec_argv[0])
            .args(&exec_argv[1..])
            .current_dir(&cwd)
            .stdin(std::process::Stdio::null())
            .output();

        match output {
            Ok(out) => {
                let (text, redacted) = self.render_output(&out);
                self.record(
                    audit,
                    session,
                    &action,
                    &decision,
                    AuditResult::Allowed,
                    redacted,
                );
                tool_text_result(id, &text)
            }
            Err(e) => {
                self.record(
                    audit,
                    session,
                    &action,
                    &decision,
                    AuditResult::Allowed,
                    false,
                );
                tool_error_result(id, &format!("command failed to start: {e}"))
            }
        }
    }

    /// Render captured command output into a tool-result text block, redacting
    /// secrets. Returns `(text, any_redaction_failed)`.
    fn render_output(&self, out: &std::process::Output) -> (String, bool) {
        let mut failed = false;
        let mut redact = |bytes: &[u8]| -> String {
            let raw = String::from_utf8_lossy(bytes);
            match self.scanner.redact(&raw) {
                Ok(clean) => clean,
                Err(_) => {
                    failed = true;
                    String::new()
                }
            }
        };
        let stdout = redact(&out.stdout);
        let stderr = redact(&out.stderr);

        let mut text = String::new();
        if !stdout.is_empty() {
            text.push_str(&stdout);
        }
        if !stderr.is_empty() {
            if !text.is_empty() && !text.ends_with('\n') {
                text.push('\n');
            }
            text.push_str("[stderr]\n");
            text.push_str(&stderr);
        }
        if !text.is_empty() && !text.ends_with('\n') {
            text.push('\n');
        }
        text.push_str(&format!("[exit code: {}]", out.status.code().unwrap_or(-1)));
        if failed {
            text.push_str("\n[some output suppressed: secret redaction failed]");
        }
        (text, failed)
    }

    // -- shared helpers -----------------------------------------------------

    /// Resolve a tool path argument into `(absolute_path, policy_path)`.
    ///
    /// The *policy path* is what `files.read` globs are matched against: a path
    /// relative to the workspace when the target lives inside it (so a repo
    /// rule like `.env` matches), otherwise the original argument. The
    /// *absolute path* is what is actually read from disk.
    fn resolve_path(&self, raw: &str) -> (PathBuf, PathBuf) {
        let given = PathBuf::from(raw);
        let abs = if given.is_absolute() {
            given.clone()
        } else {
            self.workspace.join(&given)
        };
        let policy_path = abs
            .strip_prefix(&self.workspace)
            .map(Path::to_path_buf)
            .unwrap_or(given);
        (abs, policy_path)
    }

    /// Append exactly one redaction-safe audit event for a gated tool call.
    fn record(
        &self,
        audit: &mut dyn AuditStore,
        session: &mut SessionHandle,
        action: &Action,
        decision: &DecisionResult,
        result: AuditResult,
        redacted: bool,
    ) {
        let event = AuditEvent {
            id: session.next_event_id(),
            session_id: session.session_id().to_string(),
            time: Utc::now(),
            actor: Actor::Agent,
            action: AuditAction::from_action(action),
            decision: decision.decision,
            result,
            matched_rule: decision.matched_rule.clone(),
            risk: decision.risk,
            redacted,
            metrics: None,
        };
        let _ = audit.append(&event);
    }

    /// Append a redaction-safe audit event for a synthesized (non-policy)
    /// block such as a PathJail violation, keyed by action kind + path.
    fn record_path(
        &self,
        audit: &mut dyn AuditStore,
        session: &mut SessionHandle,
        kind: ActionKind,
        path: &Path,
        decision: &DecisionResult,
    ) {
        let display = path.to_string_lossy().into_owned();
        let action = match kind {
            ActionKind::CommandRun => AuditAction::CommandRun { command: display },
            _ => AuditAction::FileRead { path: display },
        };
        let event = AuditEvent {
            id: session.next_event_id(),
            session_id: session.session_id().to_string(),
            time: Utc::now(),
            actor: Actor::Agent,
            action,
            decision: decision.decision,
            result: AuditResult::Denied,
            matched_rule: decision.matched_rule.clone(),
            risk: decision.risk,
            redacted: false,
            metrics: None,
        };
        let _ = audit.append(&event);
    }

    /// PathJail: verify a read resolves inside the workspace or an extra read root.
    fn read_jail_check(&self, abs: &Path) -> Result<(), String> {
        let label = if self.read_roots_canon.len() == 1 {
            "workspace root"
        } else {
            "configured read roots"
        };
        self.jail_check_against(abs, &self.read_roots_canon, label)
    }

    /// PathJail: verify a command cwd resolves inside the workspace root.
    fn workspace_jail_check(&self, abs: &Path) -> Result<(), String> {
        self.jail_check_against(
            abs,
            std::slice::from_ref(&self.workspace_canon),
            "workspace root",
        )
    }

    /// PathJail: verify `abs` resolves inside one of `roots`.
    ///
    /// Returns `Ok(())` when jailing is disabled or the resolved path is within a
    /// root, else `Err(reason)`. Symlinks and `..` are resolved first so an escape
    /// via either is caught (mirrors lean-ctx PathJail).
    fn jail_check_against(&self, abs: &Path, roots: &[PathBuf], label: &str) -> Result<(), String> {
        if !self.jail {
            return Ok(());
        }
        let resolved = resolve_existing(abs);
        if roots.iter().any(|root| resolved.starts_with(root)) {
            Ok(())
        } else {
            Err(format!("`{}` is outside the {label}", abs.display()))
        }
    }
}

fn canonicalize_root(root: PathBuf, workspace: &Path) -> PathBuf {
    let abs = if root.is_absolute() {
        root
    } else {
        workspace.join(root)
    };
    std::fs::canonicalize(&abs).unwrap_or_else(|_| normalize_lexical(&abs))
}

/// Resolve a path for jail checking: canonicalize when it exists (following
/// symlinks), otherwise canonicalize the nearest existing ancestor and
/// re-append the remaining (lexically normalized) components.
fn resolve_existing(path: &Path) -> PathBuf {
    let norm = normalize_lexical(path);
    if let Ok(canon) = std::fs::canonicalize(&norm) {
        return canon;
    }
    let mut current = norm.as_path();
    let mut tail: Vec<std::ffi::OsString> = Vec::new();
    while let Some(parent) = current.parent() {
        if let Ok(canon) = std::fs::canonicalize(parent) {
            let mut result = canon;
            if let Some(name) = current.file_name() {
                result.push(name);
            }
            for comp in tail.iter().rev() {
                result.push(comp);
            }
            return result;
        }
        if let Some(name) = current.file_name() {
            tail.push(name.to_os_string());
        }
        current = parent;
    }
    norm
}

/// Lexically resolve `.` and `..` without touching the filesystem.
fn normalize_lexical(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::ParentDir => {
                // Pop a normal segment; keep `..` only when nothing to pop.
                if !out.pop() {
                    out.push("..");
                }
            }
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// A synthesized deny decision for a PathJail violation.
fn pathjail_decision(reason: String) -> DecisionResult {
    DecisionResult {
        decision: Decision::Deny,
        reason,
        matched_rule: MatchedRule::Rule("builtin.pathjail.outside_root".to_string()),
        risk: Risk::High,
        stage: EvalStage::HardDeny,
    }
}

/// A JSON-RPC error response for a PathJail block (mirrors a policy denial).
fn pathjail_response(id: &Value, decision: &DecisionResult) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": PATHJAIL_DENIED_CODE,
            "message": format!("blocked by Fida PathJail: {}", decision.reason),
            "data": {
                "decision": decision.decision,
                "matched_rule": decision.matched_rule,
                "risk": decision.risk,
                "reason": decision.reason,
            }
        }
    })
}
fn block_result(decision: &DecisionResult) -> AuditResult {
    match decision.decision {
        Decision::Deny => AuditResult::Denied,
        Decision::DryRun => AuditResult::WouldRun,
        // `ask` while non-interactive fails closed.
        _ => AuditResult::Blocked,
    }
}

/// The `initialize` handshake response advertising tool capability.
fn initialize_response(id: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": { "tools": {} },
            "serverInfo": { "name": "fida-gateway", "version": env!("CARGO_PKG_VERSION") }
        }
    })
}

/// The `tools/list` response advertising the gateway tools and their schemas.
fn tools_list_response(id: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {
            "tools": [
                {
                    "name": READ_TOOL,
                    "description": "Read a file's text through Fida policy (files.read). \
                                    Use this for every file read, ahead of native reads, \
                                    workspace context, reviewed-file context, lean-ctx/ctx_read, \
                                    or other MCP file tools, so policy can block denied paths and \
                                    secret values in returned content are redacted.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "path": {
                                "type": "string",
                                "description": "File path, relative to the workspace, or absolute under the workspace or a configured read root."
                            }
                        },
                        "required": ["path"]
                    }
                },
                {
                    "name": SHELL_TOOL,
                    "description": "Run a command through Fida policy (commands.run). Use this \
                                    instead of native shell execution or non-Fida MCP shell tools \
                                    so the policy can gate the command. Stdout/stderr are returned \
                                    with secrets redacted.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "command": {
                                "type": "string",
                                "description": "Command line; split on whitespace into argv."
                            },
                            "cwd": {
                                "type": "string",
                                "description": "Working directory; defaults to the workspace root."
                            }
                        },
                        "required": ["command"]
                    }
                }
            ]
        }
    })
}

/// A JSON-RPC "method not found" error response.
fn method_not_found(id: &Value, method: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": METHOD_NOT_FOUND_CODE, "message": format!("method not found: {method}") }
    })
}

/// A JSON-RPC "invalid params" error response.
fn invalid_params(id: &Value, message: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": INVALID_PARAMS_CODE, "message": message }
    })
}

/// A successful `tools/call` result carrying a single text block.
fn tool_text_result(id: &Value, text: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": { "content": [ { "type": "text", "text": text } ], "isError": false }
    })
}

/// A `tools/call` result flagged as a tool-level error (distinct from a
/// JSON-RPC protocol error): the model sees the message and can react.
fn tool_error_result(id: &Value, text: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": { "content": [ { "type": "text", "text": text } ], "isError": true }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use fida_audit::testing::MemoryAuditStore;
    use fida_policy::{PolicySource, load_source};
    use std::io::Cursor;

    use crate::POLICY_DENIED_CODE;

    /// Allow reading everything except `.env`; allow `echo`, deny `cat`.
    const POLICY: &str = r#"
version: 1
default_decision: ask
commands:
  allow:
    - prefix: echo
  deny:
    - prefix: cat
files:
  read:
    allow: ["**/*"]
    deny: [".env"]
secrets:
  redact: true
  block_in_diffs: true
  patterns:
    - name: secret_word
      regex: "SECRET_[A-Za-z0-9_]+=\\S+"
audit:
  path: .fida/sessions
  format: jsonl
  redact_stdout: true
  redact_stderr: true
"#;

    fn server(workspace: &Path) -> GatewayServer {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fida.yaml");
        std::fs::write(&path, POLICY).unwrap();
        let policy = load_source(&PolicySource::Config(path), None).expect("policy compiles");
        GatewayServer::new(policy, workspace.to_path_buf())
    }

    fn builtin_server(workspace: &Path) -> GatewayServer {
        let policy = load_source(&PolicySource::BuiltinDefault, None)
            .expect("built-in default policy compiles");
        GatewayServer::new(policy, workspace.to_path_buf())
    }

    fn call(tool: &str, args: Value) -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": { "name": tool, "arguments": args }
        })
    }

    /// Drive one request through `serve` and return the single response line.
    fn roundtrip(server: &GatewayServer, request: &Value) -> Value {
        let input = format!("{request}\n");
        let mut reader = Cursor::new(input.into_bytes());
        let mut output: Vec<u8> = Vec::new();
        let mut audit = MemoryAuditStore::new();
        let mut session = SessionHandle::new("test-session");
        server
            .serve(&mut reader, &mut output, &mut audit, &mut session)
            .expect("serve loop ok");
        let line = String::from_utf8(output).unwrap();
        serde_json::from_str(line.trim()).expect("response is json")
    }

    #[test]
    fn tools_list_advertises_read_and_shell() {
        let dir = tempfile::tempdir().unwrap();
        let srv = server(dir.path());
        let req = json!({ "jsonrpc": "2.0", "id": 7, "method": "tools/list" });
        let resp = roundtrip(&srv, &req);
        let names: Vec<&str> = resp["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        assert!(names.contains(&READ_TOOL));
        assert!(names.contains(&SHELL_TOOL));
    }

    #[test]
    fn read_allowed_file_returns_content() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("hello.txt"), "hi there").unwrap();
        let srv = server(dir.path());
        let resp = roundtrip(&srv, &call(READ_TOOL, json!({ "path": "hello.txt" })));
        assert_eq!(resp["result"]["isError"], false);
        assert_eq!(resp["result"]["content"][0]["text"], "hi there");
    }

    #[test]
    fn read_denied_file_is_blocked_with_matched_rule() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(".env"), "SECRET_WORD=apaajadah").unwrap();
        let srv = server(dir.path());
        let resp = roundtrip(&srv, &call(READ_TOOL, json!({ "path": ".env" })));
        // A policy denial is a JSON-RPC error, not a tool result.
        assert_eq!(resp["error"]["code"], POLICY_DENIED_CODE);
        assert!(resp["error"]["data"]["matched_rule"].is_string());
        // The secret value never appears anywhere in the response.
        assert!(!resp.to_string().contains("apaajadah"));
    }

    #[test]
    fn builtin_read_returns_redacted_dotenv_view() {
        let dir = tempfile::tempdir().unwrap();
        let secret = "abcdefghijklmnopqrstuvwxyz123456";
        std::fs::write(dir.path().join(".env"), format!("API_KEY={secret}\n")).unwrap();
        let srv = builtin_server(dir.path());
        let resp = roundtrip(&srv, &call(READ_TOOL, json!({ "path": ".env" })));

        assert_eq!(resp["result"]["isError"], false);
        let text = resp["result"]["content"][0]["text"].as_str().unwrap();
        assert!(!text.contains(secret));
        assert!(text.contains(fida_secrets::REDACTION_MARKER));
    }

    #[test]
    fn read_allowed_file_redacts_secret_values() {
        let dir = tempfile::tempdir().unwrap();
        // Allowed path, but the content carries a secret-shaped value.
        std::fs::write(dir.path().join("notes.txt"), "SECRET_TOKEN=abcd1234").unwrap();
        let srv = server(dir.path());
        let resp = roundtrip(&srv, &call(READ_TOOL, json!({ "path": "notes.txt" })));
        assert_eq!(resp["result"]["isError"], false);
        let text = resp["result"]["content"][0]["text"].as_str().unwrap();
        assert!(!text.contains("abcd1234"), "secret value must be redacted");
    }

    #[test]
    fn shell_allowed_command_runs() {
        let dir = tempfile::tempdir().unwrap();
        let srv = server(dir.path());
        let resp = roundtrip(&srv, &call(SHELL_TOOL, json!({ "command": "echo hello" })));
        assert_eq!(resp["result"]["isError"], false);
        let text = resp["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("hello"));
        assert!(text.contains("[exit code: 0]"));
    }

    #[test]
    fn shell_denied_command_is_blocked() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(".env"), "SECRET_WORD=apaajadah").unwrap();
        let srv = server(dir.path());
        let resp = roundtrip(&srv, &call(SHELL_TOOL, json!({ "command": "cat .env" })));
        assert_eq!(resp["error"]["code"], POLICY_DENIED_CODE);
    }

    #[test]
    fn builtin_shell_redacts_secret_output_before_returning() {
        let dir = tempfile::tempdir().unwrap();
        let secret = "abcdefghijklmnopqrstuvwxyz123456";
        std::fs::write(dir.path().join(".env"), format!("API_KEY={secret}\n")).unwrap();
        let srv = builtin_server(dir.path());
        let resp = roundtrip(&srv, &call(SHELL_TOOL, json!({ "command": "cat .env" })));

        assert_eq!(resp["result"]["isError"], false);
        let text = resp["result"]["content"][0]["text"].as_str().unwrap();
        assert!(!text.contains(secret));
        assert!(text.contains(fida_secrets::REDACTION_MARKER));
    }

    #[test]
    fn missing_path_argument_is_invalid_params() {
        let dir = tempfile::tempdir().unwrap();
        let srv = server(dir.path());
        let resp = roundtrip(&srv, &call(READ_TOOL, json!({})));
        assert_eq!(resp["error"]["code"], INVALID_PARAMS_CODE);
    }

    #[test]
    fn unknown_tool_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let srv = server(dir.path());
        let resp = roundtrip(&srv, &call("fida_teleport", json!({})));
        assert_eq!(resp["error"]["code"], UNKNOWN_TOOL_CODE);
    }

    #[test]
    fn pathjail_blocks_absolute_path_outside_root() {
        let dir = tempfile::tempdir().unwrap();
        let srv = server(dir.path());
        let resp = roundtrip(&srv, &call(READ_TOOL, json!({ "path": "/etc/hosts" })));
        assert_eq!(resp["error"]["code"], PATHJAIL_DENIED_CODE);
    }

    #[test]
    fn extra_read_root_allows_attachment_read() {
        let workspace = tempfile::tempdir().unwrap();
        let attachments = tempfile::tempdir().unwrap();
        let attachment = attachments.path().join("pasted-text.txt");
        std::fs::write(&attachment, "plain user-provided text").unwrap();

        let srv = builtin_server(workspace.path())
            .with_extra_read_roots([attachments.path().to_path_buf()]);
        let resp = roundtrip(
            &srv,
            &call(
                READ_TOOL,
                json!({ "path": attachment.display().to_string() }),
            ),
        );

        assert_eq!(resp["result"]["isError"], false);
        assert_eq!(
            resp["result"]["content"][0]["text"],
            "plain user-provided text"
        );
    }

    #[test]
    fn extra_read_root_redacts_attachment_secrets() {
        let workspace = tempfile::tempdir().unwrap();
        let attachments = tempfile::tempdir().unwrap();
        let attachment = attachments.path().join("pasted-text.txt");
        let secret = "abcdefghijklmnopqrstuvwxyz123456";
        std::fs::write(&attachment, format!("API_KEY={secret}\n")).unwrap();

        let srv = builtin_server(workspace.path())
            .with_extra_read_roots([attachments.path().to_path_buf()]);
        let resp = roundtrip(
            &srv,
            &call(
                READ_TOOL,
                json!({ "path": attachment.display().to_string() }),
            ),
        );

        assert_eq!(resp["result"]["isError"], false);
        let text = resp["result"]["content"][0]["text"].as_str().unwrap();
        assert!(!text.contains(secret));
        assert!(text.contains(fida_secrets::REDACTION_MARKER));
    }

    #[test]
    fn extra_read_root_does_not_allow_shell_cwd_escape() {
        let workspace = tempfile::tempdir().unwrap();
        let attachments = tempfile::tempdir().unwrap();

        let srv =
            server(workspace.path()).with_extra_read_roots([attachments.path().to_path_buf()]);
        let resp = roundtrip(
            &srv,
            &call(
                SHELL_TOOL,
                json!({
                    "command": "echo hi",
                    "cwd": attachments.path().display().to_string()
                }),
            ),
        );

        assert_eq!(resp["error"]["code"], PATHJAIL_DENIED_CODE);
    }

    #[test]
    fn pathjail_blocks_parent_traversal() {
        let dir = tempfile::tempdir().unwrap();
        // A secret living outside the workspace root.
        std::fs::write(dir.path().join("outside.txt"), "top secret").unwrap();
        let sub = dir.path().join("project");
        std::fs::create_dir_all(&sub).unwrap();
        let srv = server(&sub);
        let resp = roundtrip(&srv, &call(READ_TOOL, json!({ "path": "../outside.txt" })));
        assert_eq!(resp["error"]["code"], PATHJAIL_DENIED_CODE);
        assert!(!resp.to_string().contains("top secret"));
    }

    #[cfg(unix)]
    #[test]
    fn pathjail_blocks_symlink_escape() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("outside.txt"), "top secret").unwrap();
        let sub = dir.path().join("project");
        std::fs::create_dir_all(&sub).unwrap();
        // A symlink inside the workspace pointing outside it.
        std::os::unix::fs::symlink(dir.path().join("outside.txt"), sub.join("link.txt")).unwrap();
        let srv = server(&sub);
        let resp = roundtrip(&srv, &call(READ_TOOL, json!({ "path": "link.txt" })));
        assert_eq!(resp["error"]["code"], PATHJAIL_DENIED_CODE);
        assert!(!resp.to_string().contains("top secret"));
    }

    #[test]
    fn pathjail_can_be_disabled() {
        let dir = tempfile::tempdir().unwrap();
        let outside = dir.path().join("outside.txt");
        std::fs::write(&outside, "ok").unwrap();
        let sub = dir.path().join("project");
        std::fs::create_dir_all(&sub).unwrap();
        let srv = server(&sub).with_jail(false);
        // With jail off, the read is allowed by policy (default allow) and runs.
        let resp = roundtrip(&srv, &call(READ_TOOL, json!({ "path": "../outside.txt" })));
        assert_eq!(resp["result"]["isError"], false);
    }

    #[test]
    fn notifications_get_no_response() {
        let dir = tempfile::tempdir().unwrap();
        let srv = server(dir.path());
        let req = json!({ "jsonrpc": "2.0", "method": "notifications/initialized" });
        let input = format!("{req}\n");
        let mut reader = Cursor::new(input.into_bytes());
        let mut output: Vec<u8> = Vec::new();
        let mut audit = MemoryAuditStore::new();
        let mut session = SessionHandle::new("s");
        srv.serve(&mut reader, &mut output, &mut audit, &mut session)
            .unwrap();
        assert!(output.is_empty(), "notifications must not produce a reply");
    }

    #[test]
    fn initialize_handshake_responds_with_capabilities() {
        let dir = tempfile::tempdir().unwrap();
        let srv = server(dir.path());
        let req = json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize" });
        let resp = roundtrip(&srv, &req);
        assert_eq!(resp["result"]["protocolVersion"], PROTOCOL_VERSION);
        assert!(resp["result"]["capabilities"]["tools"].is_object());
    }
}
