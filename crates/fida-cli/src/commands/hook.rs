//! `fida hook` — a PreToolUse gate for agents that support command hooks.
//!
//! Claude Code and Codex both run a command hook before a tool executes,
//! passing the tool call as JSON on stdin and honoring a `permissionDecision:
//! "deny"` reply to **block** the call. That is a real, hard block — the only
//! way to stop an IDE agent's *native* read/exec without an OS sandbox.
//!
//! The two agents send the same envelope, so one command serves both:
//! * Claude `Read`/`Grep`/`Glob` carry `tool_input.file_path`/`path`;
//!   `Write`/`Edit` carry `file_path`; `Bash` carries `tool_input.command`.
//! * Codex intercepts `Bash` and `apply_patch`, both via `tool_input.command`.
//!
//! Decision: inspect touched read paths for detected secret content. When a
//! native tool would expose a secret without a redacted view, emit a deny
//! decision and direct the agent to `fida_read`/`fida_shell`; otherwise leave
//! the agent's normal command and permission flow untouched.

use std::io::Read;
use std::path::{Path, PathBuf};

use clap::Args;
use fida_action::{Action, ActionKind, ActionPayload, Actor, DecisionResult};
use fida_policy::{CompiledPolicy, evaluate, load_secret_guard_policy};
use fida_secrets::{Scanner, SecretScanner};
use serde_json::Value;

use crate::context::GlobalContext;
use crate::error::{CliError, CliResult};

#[derive(Debug, Args)]
pub struct HookArgs {
    /// Agent name (informational; the decision logic is agent-agnostic).
    #[arg(value_name = "AGENT")]
    pub agent: Option<String>,
}

pub async fn run(_args: &HookArgs, _ctx: &GlobalContext) -> CliResult {
    let mut raw = String::new();
    if std::io::stdin().read_to_string(&mut raw).is_err() {
        return Ok(()); // No readable input: do not block the agent.
    }
    // Unparseable input fails open: the gateway + skill remain the primary
    // controls, and breaking every tool call on a malformed envelope is worse
    // than missing one backstop check. ponytail: fail-open here is deliberate.
    let Ok(input) = serde_json::from_str::<Value>(&raw) else {
        return Ok(());
    };

    let workspace = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let policy = load_policy()?;

    if let Some(decision) = decide(&policy, &input, &workspace) {
        println!("{}", deny_json(&decision));
    }
    Ok(())
}

/// Hooks use the product's secret-only posture, never a repository's general
/// command policy. A native tool is blocked only when it would expose secret
/// content that cannot be returned as a redacted view.
fn load_policy() -> Result<CompiledPolicy, CliError> {
    Ok(load_secret_guard_policy()?)
}

/// Inspect one PreToolUse envelope and return the first `deny` decision, if any.
fn decide(policy: &CompiledPolicy, input: &Value, workspace: &Path) -> Option<DecisionResult> {
    let tool = input.get("tool_name").and_then(Value::as_str).unwrap_or("");
    let tool_input = input.get("tool_input")?;
    let command_is_fida_mediated = tool_input
        .get("command")
        .and_then(Value::as_str)
        .is_some_and(command_is_fida_exec);

    for action in actions_for(tool, tool_input, workspace) {
        if !command_is_fida_mediated {
            if let Some(secret) = secret_read_decision(policy, &action, workspace) {
                return Some(secret);
            }
        }
    }

    None
}

fn command_is_fida_exec(command: &str) -> bool {
    let argv: Vec<String> = command.split_whitespace().map(str::to_string).collect();
    is_fida_exec(&argv)
}

/// Native tools cannot return a redacted safe view, so inspect readable file
/// content and convert a detected secret into the evaluator's standard
/// `secret.detected` denial. Ordinary clean files continue normally.
fn secret_read_decision(
    policy: &CompiledPolicy,
    action: &Action,
    workspace: &Path,
) -> Option<DecisionResult> {
    if action.kind != ActionKind::FileRead {
        return None;
    }
    let ActionPayload::File { path } = &action.payload else {
        return None;
    };
    let full = if path.is_absolute() {
        path.clone()
    } else {
        workspace.join(path)
    };
    let content = std::fs::read_to_string(&full).ok()?;
    let scanner = Scanner::new(&policy.secrets);
    let finding = if sensitive_path(path) {
        scanner.scan(&content).into_iter().next()
    } else {
        scanner.scan_code(&content).into_iter().next()
    }?;
    let secret_action = Action {
        kind: ActionKind::SecretDetected,
        actor: Actor::Agent,
        payload: ActionPayload::Secret { finding },
    };
    Some(evaluate(policy, &secret_action))
}

fn sensitive_path(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("");
    name == ".env"
        || name.starts_with(".env.")
        || matches!(name, "id_rsa" | "id_ed25519")
        || matches!(
            path.extension().and_then(|ext| ext.to_str()),
            Some("pem" | "key")
        )
}

/// Build the actions to evaluate for a tool call.
fn actions_for(tool: &str, tool_input: &Value, workspace: &Path) -> Vec<Action> {
    let mut actions = Vec::new();

    // Explicit file path (Claude Read/Write/Edit).
    if let Some(fp) = tool_input.get("file_path").and_then(Value::as_str) {
        let kind = if is_write_tool(tool) {
            ActionKind::FileWrite
        } else {
            ActionKind::FileRead
        };
        push_file_actions(&mut actions, kind, fp, workspace);
    }
    // Search path (Claude Grep/Glob).
    if let Some(p) = tool_input.get("path").and_then(Value::as_str) {
        push_file_actions(&mut actions, ActionKind::FileRead, p, workspace);
    }
    // Shell command (Claude Bash, Codex Bash/apply_patch).
    if let Some(cmd) = tool_input.get("command").and_then(Value::as_str) {
        let argv: Vec<String> = cmd.split_whitespace().map(str::to_string).collect();
        if !argv.is_empty() {
            actions.push(Action {
                kind: ActionKind::CommandRun,
                actor: Actor::Agent,
                payload: ActionPayload::Command {
                    argv,
                    cwd: workspace.to_path_buf(),
                },
            });
        }
        // Also treat path-like tokens as reads so native commands such as
        // `cat .env` can be inspected for secret content before they run.
        // ponytail: whitespace tokenization is a heuristic; a shell-aware
        // parser is the upgrade path. It errs toward blocking, which is safe.
        for token in cmd.split_whitespace() {
            let t = token.trim_matches(|c| c == '"' || c == '\'');
            if looks_like_path(t) {
                push_file_actions(&mut actions, ActionKind::FileRead, t, workspace);
            }
        }
    }

    actions
}

fn is_write_tool(tool: &str) -> bool {
    matches!(tool, "Write" | "Edit" | "MultiEdit" | "apply_patch")
}

fn is_fida_exec(argv: &[String]) -> bool {
    let binary = argv
        .first()
        .and_then(|arg| Path::new(arg).file_name())
        .and_then(|name| name.to_str());
    binary == Some("fida") && argv.get(1).map(String::as_str) == Some("exec")
}

/// A token worth checking against file rules: a Unix or Windows path separator,
/// or a leading dot/tilde (e.g. `.env`, `src/x`, `~/.ssh/id_rsa`,
/// `C:\Users\dev\.ssh\id_rsa`). Bare words like `cat` are skipped.
fn looks_like_path(t: &str) -> bool {
    !t.is_empty()
        && (t.contains('/') || t.contains('\\') || t.starts_with('.') || t.starts_with('~'))
}

/// Push file action(s) for `raw`, evaluating both the workspace-relative path
/// (so suffix globs like `**/*.pem` match) and the bare file name (so top-level
/// globs like `.env` / `id_rsa` match regardless of where the hook runs).
fn push_file_actions(actions: &mut Vec<Action>, kind: ActionKind, raw: &str, workspace: &Path) {
    let given = PathBuf::from(raw);
    let relative = given
        .strip_prefix(workspace)
        .map(Path::to_path_buf)
        .unwrap_or_else(|_| given.clone());
    let file_action = |path: PathBuf| Action {
        kind,
        actor: Actor::Agent,
        payload: ActionPayload::File { path },
    };
    actions.push(file_action(relative.clone()));
    if let Some(name) = given.file_name() {
        let name = PathBuf::from(name);
        if name != relative {
            actions.push(file_action(name));
        }
    }
}

/// The PreToolUse deny reply understood by both Claude Code and Codex.
fn deny_json(decision: &DecisionResult) -> String {
    let reason = format!(
        "Fida detected secret content that this native tool cannot redact safely. Use fida_read or fida_shell for a redacted view ({})",
        decision.matched_rule.as_str()
    );
    serde_json::json!({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use fida_action::Decision;
    use fida_policy::{PolicySource, load_source};

    fn policy() -> CompiledPolicy {
        // Built-in default: sensitive reads are allowed through mediated tools,
        // while this native-tool hook blocks only when content contains secrets.
        load_source(&PolicySource::BuiltinDefault, None).expect("builtin default compiles")
    }

    fn input(tool: &str, ti: Value) -> Value {
        serde_json::json!({ "tool_name": tool, "tool_input": ti })
    }

    #[test]
    fn recognizes_windows_paths_in_shell_commands() {
        assert!(looks_like_path(r"C:\Users\dev\.ssh\id_rsa"));
        assert!(looks_like_path(r".\secrets.env"));
        assert!(!looks_like_path("cat"));
    }

    #[test]
    fn claude_read_dotenv_with_secret_is_denied() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".env");
        std::fs::write(&path, "API_KEY=abcdefghijklmnopqrstuvwxyz123456\n").unwrap();
        let d = decide(
            &policy(),
            &input("Read", serde_json::json!({ "file_path": path })),
            dir.path(),
        );
        assert!(d.is_some(), "native reads must not expose detected secrets");
        assert_eq!(d.unwrap().stage, fida_action::EvalStage::SecretDetection);
    }

    #[test]
    fn claude_read_clean_dotenv_is_allowed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".env");
        std::fs::write(&path, "# no values configured yet\n").unwrap();
        let d = decide(
            &policy(),
            &input("Read", serde_json::json!({ "file_path": path })),
            dir.path(),
        );
        assert!(d.is_none(), "a sensitive filename alone is not a denial");
    }

    #[test]
    fn claude_read_source_is_allowed() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src");
        std::fs::create_dir_all(&src).unwrap();
        let path = src.join("main.rs");
        std::fs::write(&path, "fn main() {}\n").unwrap();
        let d = decide(
            &policy(),
            &input("Read", serde_json::json!({ "file_path": path })),
            dir.path(),
        );
        assert!(d.is_none(), "reading an ordinary source file is not denied");
    }

    #[test]
    fn codex_bash_cat_dotenv_with_secret_is_denied() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(".env"),
            "API_KEY=abcdefghijklmnopqrstuvwxyz123456\n",
        )
        .unwrap();
        let d = decide(
            &policy(),
            &input("Bash", serde_json::json!({ "command": "cat .env" })),
            dir.path(),
        );
        assert!(d.is_some(), "native shell output must not expose secrets");
    }

    #[test]
    fn bash_cat_ssh_key_is_denied() {
        let dir = tempfile::tempdir().unwrap();
        let ssh = dir.path().join(".ssh");
        std::fs::create_dir_all(&ssh).unwrap();
        let key = ssh.join("id_rsa");
        std::fs::write(
            &key,
            "-----BEGIN PRIVATE KEY-----\nabcdefghijklmnopqrstuvwxyz123456\n-----END PRIVATE KEY-----\n",
        )
        .unwrap();
        let d = decide(
            &policy(),
            &input(
                "Bash",
                serde_json::json!({ "command": format!("cat {}", key.display()) }),
            ),
            dir.path(),
        );
        assert!(d.is_some(), "reading an SSH key must be denied");
    }

    #[test]
    fn benign_bash_is_allowed() {
        let dir = tempfile::tempdir().unwrap();
        let d = decide(
            &policy(),
            &input("Bash", serde_json::json!({ "command": "ls -la" })),
            dir.path(),
        );
        assert!(d.is_none());
    }

    #[test]
    fn fida_exec_fallback_is_not_blocked_by_native_path_scan() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(".env"),
            "API_KEY=abcdefghijklmnopqrstuvwxyz123456\n",
        )
        .unwrap();
        let d = decide(
            &policy(),
            &input(
                "Bash",
                serde_json::json!({ "command": "fida exec -- cat .env" }),
            ),
            dir.path(),
        );
        assert!(d.is_none(), "fida exec provides its own redaction boundary");
    }

    #[test]
    fn deny_json_uses_pretooluse_deny_shape() {
        let decision = DecisionResult {
            decision: Decision::Deny,
            reason: "secret content detected".to_string(),
            matched_rule: fida_action::MatchedRule::Rule("secret.dotenv_assignment".to_string()),
            risk: fida_action::Risk::High,
            stage: fida_action::EvalStage::SecretDetection,
        };
        let v: Value = serde_json::from_str(&deny_json(&decision)).unwrap();
        assert_eq!(v["hookSpecificOutput"]["hookEventName"], "PreToolUse");
        assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "deny");
        assert!(
            v["hookSpecificOutput"]["permissionDecisionReason"]
                .as_str()
                .unwrap()
                .contains("fida_read")
        );
    }

    #[test]
    fn missing_tool_input_is_allowed() {
        let dir = tempfile::tempdir().unwrap();
        let d = decide(
            &policy(),
            &serde_json::json!({ "tool_name": "Read" }),
            dir.path(),
        );
        assert!(d.is_none());
    }
}
