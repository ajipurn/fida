//! `fida mcp …` — inspect and proxy MCP servers. **Owner: task 19.8.**
//!
//! Wires the four `mcp` subcommands to the `fida-mcp` MCP_Proxy:
//!
//! * `mcp inspect <server-file>` — enumerate each tool's name / description /
//!   input-schema via the `tools/list` handshake. An unparseable
//!   definition is a non-zero exit.
//! * `mcp list-tools <server-file>` — for each inspected tool, report its risk
//!   label and the policy Decision that applies.
//! * `mcp explain-tool <tool>` — evaluate an `mcp.tool_call` Action for the
//!   named tool and report decision / risk / reason / matched-rule. The CLI
//!   surface carries only the dotted tool name (no server file), so this reports
//!   the *policy* decision for the tool pattern; it never contacts a server.
//! * `mcp proxy --server <file>` — start the policy-gated stdio pump that
//!   forwards MCP requests to the configured server, gating every `tools/call`
//!   An unparseable definition is a non-zero exit and no proxy starts.

use std::collections::BTreeSet;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use clap::{Args, Subcommand};

use fida_action::SessionHandle;
use fida_action::{Action, ActionKind, ActionPayload, Actor, Decision, DecisionResult, Risk};
use fida_audit::JsonlAuditStore;
use fida_mcp::{GatewayServer, McpError, McpProxy, McpPump, McpTool, load_definition, risk_label};
use fida_policy::{
    CompiledPolicy, PolicySource, evaluate, load_secret_guard_policy, load_source,
    resolve_source_in,
};

use crate::context::GlobalContext;
use crate::error::{CliError, CliResult};

/// Arguments for the `fida mcp` command family.
#[derive(Debug, Args)]
pub struct McpArgs {
    #[command(subcommand)]
    pub command: McpCommand,
}

/// `fida mcp` subcommands.
#[derive(Debug, Subcommand)]
pub enum McpCommand {
    /// Inspect server capabilities.
    Inspect(ServerFileArgs),
    /// List tools with risk labels and decisions.
    ListTools(ServerFileArgs),
    /// Explain policy for one MCP tool.
    ExplainTool(ExplainToolArgs),
    /// Start a policy-gated MCP proxy.
    Proxy(ProxyArgs),
    /// Serve Fida's own gateway tools (`fida_read`, `fida_shell`) over MCP.
    Serve(ServeArgs),
}

/// A positional path to an MCP server definition file.
#[derive(Debug, Args)]
pub struct ServerFileArgs {
    /// Path to the MCP server definition (JSON).
    pub server_file: std::path::PathBuf,
}

/// `fida mcp explain-tool <tool>`.
#[derive(Debug, Args)]
pub struct ExplainToolArgs {
    /// Fully-qualified tool name, e.g. `browser.navigate`.
    pub tool: String,
}

/// `fida mcp proxy --server <file>`.
#[derive(Debug, Args)]
pub struct ProxyArgs {
    /// Path to the MCP server definition (JSON).
    #[arg(long)]
    pub server: std::path::PathBuf,
}

/// `fida mcp serve [--workspace <dir>]`.
#[derive(Debug, Args)]
pub struct ServeArgs {
    /// Workspace root that relative paths and command working directories
    /// resolve against. Defaults to the current directory.
    #[arg(long)]
    pub workspace: Option<std::path::PathBuf>,

    /// Additional root `fida_read` may read from, such as a user attachment
    /// directory. Repeatable. Relative paths resolve against the workspace.
    #[arg(long = "read-root", value_name = "PATH")]
    pub read_roots: Vec<std::path::PathBuf>,
}

/// Dispatch the `mcp` subcommands (task 19.8).
pub async fn run(args: &McpArgs, ctx: &GlobalContext) -> CliResult {
    match &args.command {
        McpCommand::Inspect(a) => inspect(a, ctx),
        McpCommand::ListTools(a) => list_tools(a, ctx),
        McpCommand::ExplainTool(a) => explain_tool(a, ctx),
        McpCommand::Proxy(a) => proxy(a, ctx),
        McpCommand::Serve(a) => serve(a, ctx),
    }
}

// ---------------------------------------------------------------------------
// `mcp inspect`
// ---------------------------------------------------------------------------

/// Enumerate the server's tools and report name / description / input-schema.
///
/// Loads the server definition and issues the `tools/list` handshake via the
/// MCP_Proxy. An unparseable definition or a transport/protocol
/// fault becomes a non-zero exit.
fn inspect(args: &ServerFileArgs, ctx: &GlobalContext) -> CliResult {
    let policy = load_policy(ctx)?;
    let pump = McpPump::new(policy);
    let tools = pump.inspect(&args.server_file).map_err(mcp_to_cli)?;

    if ctx.json {
        let entries = tools
            .iter()
            .map(|t| {
                format!(
                    "{{\"name\":{},\"description\":{},\"input_schema\":{}}}",
                    json_string(&t.name),
                    json_string(&t.description),
                    t.input_schema
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        println!("{{\"tools\":[{entries}]}}");
        return Ok(());
    }

    if ctx.is_quiet() {
        for t in &tools {
            println!("{}", t.name);
        }
        return Ok(());
    }

    if tools.is_empty() {
        println!("No tools advertised by {}.", args.server_file.display());
        return Ok(());
    }
    for t in &tools {
        println!("{}", t.name);
        if !t.description.is_empty() {
            println!("  description:  {}", t.description);
        }
        println!("  input-schema: {}", t.input_schema);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// `mcp list-tools`
// ---------------------------------------------------------------------------

/// List each tool with its risk label and the policy Decision that applies.
///
/// For every tool the server advertises, compute its heuristic risk label
/// and evaluate an `mcp.tool_call` Action for the tool name to
/// resolve the policy Decision.
fn list_tools(args: &ServerFileArgs, ctx: &GlobalContext) -> CliResult {
    let policy = load_policy(ctx)?;
    // `inspect` consumes a pump; clone the policy so we keep one for evaluation.
    let pump = McpPump::new(policy.clone());
    let tools = pump.inspect(&args.server_file).map_err(mcp_to_cli)?;

    let rows: Vec<(McpTool, Risk, DecisionResult)> = tools
        .into_iter()
        .map(|t| {
            let risk = risk_label(&t);
            let decision = evaluate(&policy, &tool_action(&t.name));
            (t, risk, decision)
        })
        .collect();

    if ctx.json {
        let entries = rows
            .iter()
            .map(|(t, risk, decision)| {
                format!(
                    "{{\"name\":{},\"risk\":{},\"decision\":{},\"matched_rule\":{}}}",
                    json_string(&t.name),
                    json_string(risk_str(*risk)),
                    json_string(decision_label(decision.decision)),
                    json_string(decision.matched_rule.as_str())
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        println!("{{\"tools\":[{entries}]}}");
        return Ok(());
    }

    if rows.is_empty() && !ctx.is_quiet() {
        println!("No tools advertised by {}.", args.server_file.display());
        return Ok(());
    }

    for (t, risk, decision) in &rows {
        println!(
            "{}\trisk={}\tdecision={}",
            t.name,
            risk_str(*risk),
            decision_label(decision.decision)
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// `mcp explain-tool`
// ---------------------------------------------------------------------------

/// Evaluate the policy decision for a single MCP tool name and report it.
///
/// The CLI surface for this command carries only the dotted tool name (there is
/// no server-definition argument), so it reports the *policy* decision for the
/// `mcp.tool_call` pattern rather than contacting a server to confirm the tool
/// exists. The decision/risk/reason/matched-rule mirror `policy explain`
///. Evaluation always resolves to a defined Decision via the policy
/// default chain, so this exits 0 on success.
fn explain_tool(args: &ExplainToolArgs, ctx: &GlobalContext) -> CliResult {
    let policy = load_policy(ctx)?;
    let result = evaluate(&policy, &tool_action(&args.tool));

    if ctx.json {
        println!("{}", decision_json(&result));
        return Ok(());
    }
    if ctx.is_quiet() {
        println!("{}", decision_label(result.decision));
        return Ok(());
    }
    println!("mcp.tool_call {}", args.tool);
    println!("  decision:     {}", decision_label(result.decision));
    println!("  risk:         {}", risk_str(result.risk));
    println!("  reason:       {}", result.reason);
    println!("  matched-rule: {}", result.matched_rule.as_str());
    Ok(())
}

// ---------------------------------------------------------------------------
// `mcp proxy --server`
// ---------------------------------------------------------------------------

/// Start the policy-gated stdio MCP proxy.
///
/// Loads the server definition (an unparseable definition is a non-zero exit
/// and no proxy starts), spawns the configured server, and runs the
/// `fida-mcp` pump bridging this process's stdin/stdout to the server's
/// stdio. The pump gates every `tools/call` against policy:
/// `allow` forwards unchanged, `deny`/`ask` returns a JSON-RPC policy denial,
/// and every other method passes through. Each gated call is audited with
/// secret redaction applied.
///
/// MVP simplification: the proxy keeps a single live connection to the server
/// and does not pre-enumerate tools, so the pump's `known_tools` set is empty.
/// The pump treats an empty set as "not yet enumerated" and still gates every
/// `tools/call` by policy; unknown-tool rejection is deferred to
/// avoid spawning the server twice. The pump runs synchronously on the CLI's
/// async task because it is line-synchronous stdio bridging.
fn proxy(args: &ProxyArgs, ctx: &GlobalContext) -> CliResult {
    let policy = load_policy(ctx)?;

    // Load + validate the definition first: a parse failure must exit non-zero
    // and never start a proxy.
    let definition = load_definition(&args.server).map_err(mcp_to_cli)?;

    if !ctx.is_quiet() && !ctx.json {
        // Human notice goes to stderr so it never corrupts the JSON-RPC stream
        // framed on stdout.
        eprintln!(
            "fida mcp proxy: gating tools/call for `{}` (non-interactive: ask/deny fail closed)",
            args.server.display()
        );
    }

    // Spawn the configured MCP server speaking JSON-RPC over its stdio.
    let mut child = Command::new(&definition.command)
        .args(&definition.args)
        .envs(definition.env.iter().map(|(k, v)| (k.clone(), v.clone())))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| {
            CliError::general(format!(
                "failed to start MCP server `{}`: {e}",
                definition.command
            ))
        })?;

    let mut server_in = child
        .stdin
        .take()
        .ok_or_else(|| CliError::general("MCP server stdin unavailable"))?;
    let server_out_raw = child
        .stdout
        .take()
        .ok_or_else(|| CliError::general("MCP server stdout unavailable"))?;
    let mut server_out = io::BufReader::new(server_out_raw);

    // Bridge this process's stdio as the MCP client side.
    let stdin = io::stdin();
    let mut client_in = stdin.lock();
    let stdout = io::stdout();
    let mut client_out = stdout.lock();

    let audit_dir = policy.audit.path.clone();
    let pump = McpPump::new(policy); // proxies are non-interactive (fail closed on ask).
    let known_tools: BTreeSet<String> = BTreeSet::new();

    let session_id = proxy_session_id();
    let mut session = SessionHandle::new(session_id);
    let mut audit = JsonlAuditStore::new(audit_dir);

    let result = pump.pump(
        &mut client_in,
        &mut client_out,
        &mut server_in,
        &mut server_out,
        &known_tools,
        &mut audit,
        &mut session,
    );

    // Best-effort teardown of the spawned server regardless of the outcome.
    let _ = child.kill();
    let _ = child.wait();

    result.map_err(mcp_to_cli)?;

    if !ctx.is_quiet() && !ctx.json {
        eprintln!("fida mcp proxy: client disconnected, proxy stopped.");
    }
    Ok(())
}

/// A unique-enough session id for a proxy run's audit trail.
fn proxy_session_id() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("mcp-proxy-{secs}")
}

// ---------------------------------------------------------------------------
// `mcp serve` (gateway server — fida_read / fida_shell)
// ---------------------------------------------------------------------------

/// Run Fida's gateway MCP server on stdin/stdout.
///
/// Unlike `mcp proxy` (which gates *another* server's tools), this exposes
/// Fida's own `fida_read` / `fida_shell` tools so an MCP-capable agent can route
/// its file reads and shell commands through redaction. Each call is audited
/// under a per-run session without applying repository command policies.
///
/// The JSON-RPC stream is framed on stdout, so human notices go to stderr to
/// avoid corrupting it.
fn serve(args: &ServeArgs, ctx: &GlobalContext) -> CliResult {
    let policy = load_secret_guard_policy()?;
    let workspace = match &args.workspace {
        Some(dir) => dir.clone(),
        None => std::env::current_dir()
            .map_err(|e| CliError::general(format!("cannot determine current directory: {e}")))?,
    };

    if !ctx.is_quiet() && !ctx.json {
        eprintln!(
            "fida mcp serve: exposing redacting fida_read/fida_shell for `{}`",
            workspace.display()
        );
    }

    let audit_dir = policy.audit.path.clone();
    let jail = !matches!(
        std::env::var("FIDA_NO_JAIL").ok().as_deref(),
        Some("1") | Some("true") | Some("yes")
    );
    let sandbox = matches!(
        std::env::var("FIDA_SANDBOX").ok().as_deref(),
        Some("1") | Some("true") | Some("yes")
    );
    let read_roots = collect_read_roots(&args.read_roots);
    let server = GatewayServer::new(policy, workspace)
        .with_extra_read_roots(read_roots)
        .with_jail(jail)
        .with_sandbox(sandbox);

    let session_id = gateway_session_id();
    let mut session = SessionHandle::new(session_id);
    let mut audit = JsonlAuditStore::new(audit_dir);

    let stdin = io::stdin();
    let mut reader = stdin.lock();
    let stdout = io::stdout();
    let mut writer = stdout.lock();

    server
        .serve(&mut reader, &mut writer, &mut audit, &mut session)
        .map_err(mcp_to_cli)?;

    if !ctx.is_quiet() && !ctx.json {
        eprintln!("fida mcp serve: client disconnected, gateway stopped.");
    }
    Ok(())
}

/// A unique-enough session id for a gateway run's audit trail.
fn gateway_session_id() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("mcp-gateway-{secs}")
}

fn collect_read_roots(cli_roots: &[PathBuf]) -> Vec<PathBuf> {
    let mut roots = cli_roots.to_vec();
    if let Some(raw) = std::env::var_os("FIDA_READ_ROOTS") {
        roots.extend(std::env::split_paths(&raw));
    }
    dedupe_paths(roots)
}

fn dedupe_paths(paths: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for path in paths {
        if !out.contains(&path) {
            out.push(path);
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Resolve and load the policy, allowing the built-in default. Loader failures
/// surface as invalid-policy (exit 4) via `From<LoadError>`.
fn load_policy(ctx: &GlobalContext) -> Result<CompiledPolicy, CliError> {
    let source: PolicySource = resolve_source_in(Path::new("."), ctx.config.as_deref())?;
    Ok(load_source(&source, None)?)
}

/// Build an `mcp.tool_call` [`Action`] for a dotted tool name.
fn tool_action(tool: &str) -> Action {
    Action {
        kind: ActionKind::McpToolCall,
        actor: Actor::Agent,
        payload: ActionPayload::Mcp {
            tool_name: tool.to_string(),
        },
    }
}

/// Map an [`McpError`] (load / transport / protocol / unknown-tool) to the
/// generic CLI bucket so it exits non-zero.
fn mcp_to_cli(err: McpError) -> CliError {
    CliError::general(err.to_string())
}

/// Human/CLI-facing decision label (`dry-run`, matching `policy explain`).
fn decision_label(d: Decision) -> &'static str {
    match d {
        Decision::Allow => "allow",
        Decision::Ask => "ask",
        Decision::Deny => "deny",
        Decision::DryRun => "dry-run",
    }
}

/// Human/CLI-facing risk label.
fn risk_str(r: Risk) -> &'static str {
    match r {
        Risk::Low => "low",
        Risk::Medium => "medium",
        Risk::High => "high",
    }
}

/// JSON object for a single decision result (used by `--json`).
fn decision_json(result: &DecisionResult) -> String {
    format!(
        "{{\"decision\":{},\"risk\":{},\"reason\":{},\"matched_rule\":{}}}",
        json_string(decision_label(result.decision)),
        json_string(risk_str(result.risk)),
        json_string(&result.reason),
        json_string(result.matched_rule.as_str())
    )
}

/// Encode a string as a JSON string literal (quoted + escaped).
fn json_string(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_else(|_| "\"\"".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::Verbosity;

    fn ctx_with_config(path: std::path::PathBuf, json: bool) -> GlobalContext {
        GlobalContext {
            json,
            no_color: false,
            verbosity: Verbosity::Normal,
            config: Some(path),
        }
    }

    /// A policy that allows `fs.read`, denies `shell.exec`, asks for
    /// `net.fetch`, and defaults to `ask`.
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

    fn write_temp(dir: &tempfile::TempDir, name: &str, contents: &str) -> std::path::PathBuf {
        let path = dir.path().join(name);
        std::fs::write(&path, contents).unwrap();
        path
    }

    #[test]
    fn read_root_dedupe_preserves_order() {
        let a = std::path::PathBuf::from("/tmp/a");
        let b = std::path::PathBuf::from("/tmp/b");
        assert_eq!(
            dedupe_paths(vec![a.clone(), b.clone(), a.clone()]),
            vec![a, b]
        );
    }

    // --- mcp explain-tool ----------------------------------

    #[tokio::test]
    async fn explain_tool_reports_deny_for_denied_pattern() {
        let dir = tempfile::tempdir().unwrap();
        let policy = write_temp(&dir, "fida.yaml", TEST_POLICY);
        let args = ExplainToolArgs {
            tool: "shell.exec".to_string(),
        };
        // Exits 0 and reports a decision.
        explain_tool(&args, &ctx_with_config(policy.clone(), false)).expect("explain-tool exits 0");

        // The decision itself is `deny` for the denied pattern.
        let pol = load_policy(&ctx_with_config(policy, false)).unwrap();
        let result = evaluate(&pol, &tool_action("shell.exec"));
        assert_eq!(result.decision, Decision::Deny);
    }

    #[tokio::test]
    async fn explain_tool_reports_allow_for_allowed_pattern() {
        let dir = tempfile::tempdir().unwrap();
        let policy = write_temp(&dir, "fida.yaml", TEST_POLICY);
        let cfg = ctx_with_config(policy, true);
        explain_tool(
            &ExplainToolArgs {
                tool: "fs.read".to_string(),
            },
            &cfg,
        )
        .expect("explain-tool --json exits 0");

        let pol = load_policy(&cfg).unwrap();
        assert_eq!(
            evaluate(&pol, &tool_action("fs.read")).decision,
            Decision::Allow
        );
    }

    #[tokio::test]
    async fn explain_tool_unmatched_falls_through_to_default() {
        let dir = tempfile::tempdir().unwrap();
        let policy = write_temp(&dir, "fida.yaml", TEST_POLICY);
        let cfg = ctx_with_config(policy, false);
        // An unknown tool name still resolves to a defined Decision (the
        // global default `ask`) — no error.
        explain_tool(
            &ExplainToolArgs {
                tool: "mystery.tool".to_string(),
            },
            &cfg,
        )
        .expect("explain-tool exits 0 for unmatched tool");

        let pol = load_policy(&cfg).unwrap();
        assert_eq!(
            evaluate(&pol, &tool_action("mystery.tool")).decision,
            Decision::Ask
        );
    }

    // --- list-tools risk + decision labeling ---------------

    #[test]
    fn risk_and_decision_pairing_matches_policy() {
        let dir = tempfile::tempdir().unwrap();
        let policy = write_temp(&dir, "fida.yaml", TEST_POLICY);
        let pol = load_policy(&ctx_with_config(policy, false)).unwrap();

        // shell.exec -> high risk (state-changing marker) AND deny decision.
        let shell = McpTool {
            name: "shell.exec".to_string(),
            description: "run a shell command".to_string(),
            input_schema: serde_json::json!({}),
        };
        assert_eq!(risk_label(&shell), Risk::High);
        assert_eq!(
            evaluate(&pol, &tool_action(&shell.name)).decision,
            Decision::Deny
        );

        // fs.read -> low risk (read-only marker) AND allow decision.
        let read = McpTool {
            name: "fs.read".to_string(),
            description: "read a file".to_string(),
            input_schema: serde_json::json!({}),
        };
        assert_eq!(risk_label(&read), Risk::Low);
        assert_eq!(
            evaluate(&pol, &tool_action(&read.name)).decision,
            Decision::Allow
        );
    }

    // --- definition load failures exit non-zero -----------------

    #[tokio::test]
    async fn inspect_unparseable_definition_exits_one() {
        let dir = tempfile::tempdir().unwrap();
        let policy = write_temp(&dir, "fida.yaml", TEST_POLICY);
        // Not valid JSON / missing `command` -> DefinitionLoad error.
        let server = write_temp(&dir, "server.json", "{ this is not json");
        let err = inspect(
            &ServerFileArgs {
                server_file: server,
            },
            &ctx_with_config(policy, false),
        )
        .expect_err("unparseable definition must error");
        assert_eq!(err.exit_code(), 1);
    }

    #[tokio::test]
    async fn proxy_unparseable_definition_exits_one_without_starting() {
        let dir = tempfile::tempdir().unwrap();
        let policy = write_temp(&dir, "fida.yaml", TEST_POLICY);
        // Valid JSON but missing the required `command` field.
        let server = write_temp(&dir, "server.json", r#"{"args":["x"]}"#);
        let err = proxy(&ProxyArgs { server }, &ctx_with_config(policy, false))
            .expect_err("unparseable definition must error before starting a proxy");
        assert_eq!(err.exit_code(), 1);
    }

    #[test]
    fn labels_are_cli_facing() {
        assert_eq!(decision_label(Decision::DryRun), "dry-run");
        assert_eq!(risk_str(Risk::Medium), "medium");
    }
}
