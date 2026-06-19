//! `fida run -- <agent command>` — run an agent inside a Fida session.
//! **Owners:** session/diff/workspace wiring -> task 19.5; network proxy
//! activation -> task 19.9.
//!
//! This module wires the full agent-session path together:
//!
//! 1. Resolve and load the policy (`--config` + `--profile` honored), surfacing
//!    load failures as exit 4 via the existing `From<LoadError>` impl.
//! 2. Resolve the session [`Mode`]: `--mode` > the active profile/base mode >
//!    [`Mode::Enforce`]. An invalid `--mode` value prevents the
//!    session from starting and exits 1.
//! 3. Validate `--workspace` ([`WorkspaceMode`]) and `--apply` ([`ApplyMode`]);
//!    an unsupported value prevents the session from starting and exits 1.
//! 4. Record the git baseline; a capture failure prevents the session from
//!    starting and is reported as an error.
//! 5. Create the session, then report the session header *before* any agent
//!    output.
//! 6. Prepare the workspace, launch the agent and stream its output,
//!    finalize the session, and apply the resulting diff per
//!    `--apply`. A non-zero agent exit -> exit 5; an
//!    apply failure -> exit 7; a secret-bearing diff -> exit 6.

use std::io::IsTerminal;
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use chrono::Utc;
use clap::Args;
use tokio::sync::Mutex;

use fida_action::{Action, ActionKind, ActionPayload, Mode};
use fida_agent::{AgentSpec, WorkspaceMode, finalize_session, launch_agent};
use fida_approval::TerminalApprovalUi;
use fida_audit::JsonlAuditStore;
use fida_broker::{
    ActionDispatcher, Broker, BrokerContext, DispatchOutcome, EXIT_SECRET_BLOCKED,
    RememberedDecisions, SessionHandle,
};
use fida_diff::{ApplyReport, Baseline as DiffBaseline, FileDiffGate, GitFileDiffGate};
use fida_net::{BEST_EFFORT_ENFORCEMENT_NOTICE, NetworkProxy};
use fida_policy::{CompiledPolicy, PolicySource, load_source, resolve_source_in};
use fida_session::{
    CreateSessionParams, FIDA_DIR, SESSION_EVENTS_FILE, SESSIONS_DIR, SessionId, create_session,
};

use crate::context::GlobalContext;
use crate::error::{CliError, CliResult};

/// Arguments for `fida run`.
#[derive(Debug, Args)]
pub struct RunArgs {
    /// Policy profile to use.
    #[arg(long)]
    pub profile: Option<String>,

    /// Enforcement mode: `observe`, `enforce`, or `dry-run`.
    #[arg(long)]
    pub mode: Option<String>,

    /// Workspace strategy: `current`, `copy`, or `git-worktree`.
    #[arg(long)]
    pub workspace: Option<String>,

    /// Apply strategy: `ask`, `never`, or `auto-if-allowed`.
    #[arg(long)]
    pub apply: Option<String>,

    /// Report format: `markdown`, `json`, or `none`.
    #[arg(long)]
    pub report: Option<String>,

    /// Never prompt; fail closed when approval is required.
    #[arg(long)]
    pub non_interactive: bool,

    /// The agent command and its arguments, after `--`.
    #[arg(last = true, required = true)]
    pub command: Vec<String>,
}

/// How the session's file diff is applied to the main workspace after the agent
/// exits. Mirrors the exact accepted `--apply` values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ApplyMode {
    /// Prompt for non-`allow` paths interactively (skipped when non-interactive).
    Ask,
    /// Never apply; leave changes in the workspace only.
    Never,
    /// Apply every `allow` path automatically; skip `ask` paths.
    AutoIfAllowed,
}

impl ApplyMode {
    /// Parse a `--apply` value, rejecting anything outside the exact set
    /// `ask` | `never` | `auto-if-allowed`.
    fn parse(value: &str) -> CliResult<Self> {
        match value {
            "ask" => Ok(ApplyMode::Ask),
            "never" => Ok(ApplyMode::Never),
            "auto-if-allowed" => Ok(ApplyMode::AutoIfAllowed),
            other => Err(CliError::usage(format!(
                "unsupported apply mode {other:?}: supported modes are ask, never, auto-if-allowed"
            ))),
        }
    }
}

/// Run `fida run`. The async entry point resolves the repository root (the
/// current directory) and delegates to the synchronous [`run_in`] core, which
/// is unit-testable against an explicit repo path.
pub async fn run(args: &RunArgs, ctx: &GlobalContext) -> CliResult {
    let repo = std::env::current_dir()
        .map_err(|e| CliError::general(format!("cannot determine current directory: {e}")))?;
    // Record the project in the global registry (R7.4).

    run_in(&repo, args, ctx).await
}

/// The core of `fida run`, operating on an explicit `repo` root.
///
/// Async because activating the Network_Proxy (task 19.9) binds a loopback
/// socket and drives its accept loop on the CLI's Tokio runtime.
async fn run_in(repo: &Path, args: &RunArgs, ctx: &GlobalContext) -> CliResult {
    // 1. Resolve + load the policy honoring --config and --profile. A load
    // failure surfaces as exit 4 through `From<LoadError>`.
    let source = resolve_source_in(repo, ctx.config.as_deref())?;
    let policy = load_source(&source, args.profile.as_deref())?;

    // 2. Resolve the mode BEFORE starting a session. An invalid --mode value
    // must prevent the session from starting and exit 1.
    let mode = resolve_mode(args.mode.as_deref(), policy.mode)?;

    // 3. Validate --workspace and --apply before starting a session. An invalid
    // value must prevent the session from starting and exit 1.
    let workspace = match &args.workspace {
        Some(value) => WorkspaceMode::parse(value).map_err(|e| CliError::usage(e.to_string()))?,
        None => WorkspaceMode::Copy,
    };
    let apply_mode = match &args.apply {
        Some(value) => ApplyMode::parse(value)?,
        None => ApplyMode::Ask,
    };

    // 4. Record the git baseline. A capture failure prevents the session from
    // starting and is reported as an error. No session directory
    // is created on this path.
    let baseline_gate = GitFileDiffGate::new(Broker::new(TerminalApprovalUi::new()), repo);
    let baseline = baseline_gate
        .record_baseline(repo)
        .map_err(|e| CliError::general(format!("cannot start session: {e}")))?;
    if matches!(workspace, WorkspaceMode::Current) && baseline.dirty {
        return Err(CliError::general(
            "--workspace current requires a clean git working tree so rejected paths can be restored safely",
        ));
    }

    // 5. Create the session and persist its metadata.
    let start_time = Utc::now();
    let created = create_session(CreateSessionParams {
        repo_path: repo.to_path_buf(),
        git_sha: baseline.head_sha.clone(),
        profile: args.profile.clone(),
        mode,
        workspace_mode: workspace.as_str().to_string(),
        agent_command: args.command.clone(),
        start_time,
        baseline: fida_session::Baseline {
            head_sha: baseline.head_sha.clone(),
            dirty: baseline.dirty,
        },
    })
    .map_err(|e| CliError::general(format!("cannot create session: {e}")))?;

    // 6. Report the session header BEFORE the agent produces output.
    print_header(
        ctx,
        &created.id,
        &source,
        args.profile.as_deref(),
        mode,
        &args.command,
    );

    if mode == Mode::DryRun {
        if !ctx.is_quiet() && !ctx.json {
            println!("Dry-run: agent command not executed");
            println!("Apply:   skipped");
        }
        return Ok(());
    }

    // 7. Prepare the working area for the chosen workspace mode.
    let work_dir = workspace
        .prepare(repo, &created.dir)
        .map_err(|e| CliError::general(format!("failed to prepare workspace: {e}")))?;

    // -- SEAM (task 19.9): activate the Network_Proxy when network gating is
    // enabled for the session.
    //
    // Activation condition: the session intends to mediate network traffic,
    // i.e. the policy defines any network rule (allow/ask/deny). Built-in
    // metadata-IP / private-CIDR hard denies always apply *inside* the proxy,
    // but we avoid forcing the proxy on for runs whose policy expresses no
    // network intent so the common no-network path stays untouched.
    //
    // When enabled we bind a loopback proxy, inject `FIDA_HTTP_PROXY` /
    // `FIDA_HTTPS_PROXY` into `agent_env` so the agent's tooling routes
    // through Fida for the session lifetime, drive its accept loop
    // on a background task, and surface the best-effort honesty notice.
    // The `_proxy_guard` aborts that task on every return path from
    // here on, bounding the proxy to the session lifetime.
    let mut agent_env: Vec<(String, String)> = Vec::new();
    let _proxy_guard = if network_gating_enabled(&policy) {
        let proxy = NetworkProxy::bind(Arc::new(policy.clone()), created.id.as_str())
            .await
            .map_err(|e| CliError::general(format!("failed to start network proxy: {e}")))?;

        // Route the agent's HTTP(S) traffic through the proxy for its lifetime.
        agent_env.extend(proxy.proxy_env_vars());

        // Surface the best-effort enforcement honesty notice.
        if !ctx.is_quiet() {
            eprintln!("{BEST_EFFORT_ENFORCEMENT_NOTICE}");
        }

        // Share the session audit log with the proxy's accept loop, which
        // appends one redaction-safe event per gated request.
        let audit = Arc::new(Mutex::new(JsonlAuditStore::new(
            fida_session::sessions_root(repo),
        )));
        let handle = tokio::spawn(async move {
            let _ = proxy.serve(audit).await;
        });
        Some(ProxyGuard { handle })
    } else {
        None
    };

    // 8. Launch the agent as a child process, streaming its output.
    let mut spec = AgentSpec::new(args.command.clone(), &work_dir);
    spec.env = agent_env;
    let agent_exit = launch_agent(&spec)
        .map_err(|e| CliError::general(format!("failed to launch agent: {e}")))?;

    // 9. Finalize the session (compute diff, write result/diff, stamp end_time).
    // Finalization always runs so the result/diff survive an agent failure.
    finalize_session(repo, &created.id, &work_dir, agent_exit.code)
        .map_err(|e| CliError::general(format!("failed to finalize session: {e}")))?;

    // 10. A non-zero agent exit dominates: report it and exit 5; no apply is
    // attempted.
    if !agent_exit.is_success() {
        return Err(CliError::AgentFailed {
            message: format!("exited with status {}", agent_exit.code),
        });
    }

    // 11. Apply the diff per --apply. `never` (and dry-run mode, which executes
    // nothing) skip the apply entirely.
    if apply_mode == ApplyMode::Never || mode == Mode::DryRun {
        if !ctx.is_quiet() && !ctx.json {
            println!("Apply:   skipped");
        }
        return Ok(());
    }

    // `auto-if-allowed` applies only `allow` paths (non-interactive so `ask`
    // paths are skipped); `ask` prompts when an interactive terminal is present.
    let terminal_interactive = !args.non_interactive && std::io::stdin().is_terminal();
    let apply_interactive = match apply_mode {
        ApplyMode::Ask => terminal_interactive,
        ApplyMode::AutoIfAllowed => false,
        ApplyMode::Never => unreachable!("never is handled above"),
    };

    let report = apply_changes(
        repo,
        &work_dir,
        matches!(workspace, WorkspaceMode::Current),
        &policy,
        &baseline,
        apply_interactive,
        created.id.as_str(),
    )?;

    if !ctx.is_quiet() && !ctx.json {
        println!(
            "Apply:   {} applied, {} rejected",
            report.applied, report.rejected
        );
    }

    // 12. Surface the worst apply outcome.
    match report.exit_code {
        fida_broker::EXIT_SUCCESS => Ok(()),
        EXIT_SECRET_BLOCKED => Err(CliError::SecretBlocked {
            reason: "a changed file contains a detected secret".to_string(),
        }),
        _ => Err(CliError::ApplyFailed {
            message: format!("{} change(s) could not be applied", report.failures.len()),
        }),
    }
}

/// Whether the session should activate the Network_Proxy (task 19.9).
///
/// Network gating is meaningful when the policy expresses *any* network intent
/// — i.e. it defines at least one allow/ask/deny network rule. (The built-in
/// metadata-IP and private-CIDR hard denies are enforced inside the proxy once
/// it is active; we do not spin the proxy up for policies with no network
/// section so the common no-network run path is unaffected.)
fn network_gating_enabled(policy: &CompiledPolicy) -> bool {
    !policy.network.allow.is_empty()
        || !policy.network.ask.is_empty()
        || !policy.network.deny.is_empty()
}

/// Bounds the Network_Proxy's accept loop to the session lifetime.
///
/// Holding the guard keeps the proxy serving; dropping it (on any return path
/// from `run_in`, including the agent-failure and apply-failure exits) aborts
/// the background task so the proxy does not outlive the session.
struct ProxyGuard {
    handle: tokio::task::JoinHandle<()>,
}

impl Drop for ProxyGuard {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

/// Resolve the session [`Mode`]: `--mode` wins, else the profile/base mode, else
/// [`Mode::Enforce`]. An invalid `--mode` value is a usage error
/// (exit 1) that prevents the session from starting.
fn resolve_mode(flag: Option<&str>, policy_mode: Option<Mode>) -> CliResult<Mode> {
    match flag {
        Some(value) => parse_mode(value).ok_or_else(|| {
            CliError::usage(format!(
                "invalid --mode {value:?}: expected observe, enforce, or dry-run"
            ))
        }),
        None => Ok(policy_mode.unwrap_or(Mode::Enforce)),
    }
}

/// Parse a `--mode` value into a [`Mode`], or `None` if unrecognized.
fn parse_mode(value: &str) -> Option<Mode> {
    match value {
        "observe" => Some(Mode::Observe),
        "enforce" => Some(Mode::Enforce),
        "dry-run" => Some(Mode::DryRun),
        _ => None,
    }
}

/// The canonical kebab-case string for a [`Mode`] (matches `--mode` values).
fn mode_str(mode: Mode) -> &'static str {
    match mode {
        Mode::Observe => "observe",
        Mode::Enforce => "enforce",
        Mode::DryRun => "dry-run",
    }
}

/// Report the session header before the agent produces output: session id, policy path, profile, mode, agent command, and audit
/// path. Honors `--quiet` (suppressed) and `--json` (machine-readable).
fn print_header(
    ctx: &GlobalContext,
    id: &SessionId,
    source: &PolicySource,
    profile: Option<&str>,
    mode: Mode,
    command: &[String],
) {
    if ctx.is_quiet() {
        return;
    }

    let policy_path = source
        .path()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "(built-in default)".to_string());
    let audit_path = Path::new(FIDA_DIR)
        .join(SESSIONS_DIR)
        .join(id.as_str())
        .join(SESSION_EVENTS_FILE)
        .display()
        .to_string();
    let agent = command.join(" ");
    let mode_text = mode_str(mode);

    if ctx.json {
        let obj = serde_json::json!({
            "session": id.as_str(),
            "policy": policy_path,
            "profile": profile,
            "mode": mode_text,
            "agent": agent,
            "audit": audit_path,
        });
        println!("{obj}");
        return;
    }

    println!("Fida session started\n");
    println!("Session: {}", id.as_str());
    println!("Policy:  {policy_path}");
    println!("Profile: {}", profile.unwrap_or("(default)"));
    println!("Mode:    {mode_text}");
    println!("Agent:   {agent}");
    println!();
    println!("Audit:   {audit_path}\n");
}

/// Compute the session's changed set against `baseline` and apply it through the
/// File_Diff_Gate / broker chokepoint. Returns the gate's
/// [`ApplyReport`] (applied/rejected counts + worst exit code).
fn apply_changes(
    repo: &Path,
    work_dir: &Path,
    current_workspace: bool,
    policy: &CompiledPolicy,
    baseline: &DiffBaseline,
    interactive: bool,
    session_id: &str,
) -> CliResult<ApplyReport> {
    let gate = GitFileDiffGate::new(Broker::new(TerminalApprovalUi::new()), work_dir);
    let changes = gate
        .changed_files(work_dir, baseline)
        .map_err(|e| CliError::general(format!("failed to compute session diff: {e}")))?;

    let mut audit = JsonlAuditStore::new(fida_session::sessions_root(repo));
    let mut dispatcher = FileApplyDispatcher::new(work_dir, repo);
    let mut session = SessionHandle::new(session_id);
    let mut remembered = RememberedDecisions::new();

    let report = {
        let mut bctx = BrokerContext {
            policy,
            // The diff apply enforces file policy decisions (allow/deny/ask)
            // regardless of the agent's session mode; dry-run/never short-circuit
            // before reaching here.
            mode: Mode::Enforce,
            interactive,
            yes: false,
            session: &mut session,
            remembered: &mut remembered,
            audit: &mut audit,
            dispatcher: &mut dispatcher,
        };
        gate.apply(&mut bctx, &changes)
    };

    if current_workspace && !report.rejected_paths.is_empty() {
        restore_rejected_current_workspace(repo, baseline, &report.rejected_paths)?;
    }

    Ok(report)
}

fn restore_rejected_current_workspace(
    repo: &Path,
    baseline: &DiffBaseline,
    paths: &[PathBuf],
) -> CliResult {
    for path in paths {
        ensure_repo_relative(path)?;
        let checkout = Command::new("git")
            .current_dir(repo)
            .arg("checkout")
            .arg(&baseline.head_sha)
            .arg("--")
            .arg(path)
            .output()
            .map_err(|e| CliError::general(format!("failed to restore {}: {e}", path.display())))?;

        if checkout.status.success() {
            continue;
        }

        let full = repo.join(path);
        if full.is_dir() {
            std::fs::remove_dir_all(&full).map_err(|e| CliError::ApplyFailed {
                message: format!(
                    "failed to remove rejected directory {}: {e}",
                    path.display()
                ),
            })?;
        } else if full.exists() {
            std::fs::remove_file(&full).map_err(|e| CliError::ApplyFailed {
                message: format!("failed to remove rejected file {}: {e}", path.display()),
            })?;
        }
    }
    Ok(())
}

fn ensure_repo_relative(path: &Path) -> CliResult {
    if path.is_absolute()
        || path
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::Prefix(_)))
    {
        return Err(CliError::ApplyFailed {
            message: format!("refusing to restore unsafe path {}", path.display()),
        });
    }
    Ok(())
}

/// The [`ActionDispatcher`] the diff gate calls for a *permitted* file change.
///
/// It applies the change from the agent's workspace (`source_root`) into the
/// main repository (`dest_root`): `file.write` copies the file, `file.delete`
/// removes it. When the workspace is the repository itself (`current` mode) the
/// change is already in place and the copy is a no-op. A failed apply reports a
/// non-zero exit code so the gate records it as an apply failure (exit 7).
struct FileApplyDispatcher {
    source_root: PathBuf,
    dest_root: PathBuf,
    /// The first apply failure message, surfaced by the caller.
    error: Option<String>,
}

impl FileApplyDispatcher {
    fn new(source_root: impl Into<PathBuf>, dest_root: impl Into<PathBuf>) -> Self {
        FileApplyDispatcher {
            source_root: source_root.into(),
            dest_root: dest_root.into(),
            error: None,
        }
    }

    /// Record the first apply failure and return the apply-failed dispatch code.
    fn fail(&mut self, message: String) -> DispatchOutcome {
        if self.error.is_none() {
            self.error = Some(message);
        }
        DispatchOutcome {
            exit_code: fida_diff::EXIT_APPLY_FAILED,
        }
    }
}

impl ActionDispatcher for FileApplyDispatcher {
    fn dispatch(&mut self, action: &Action) -> DispatchOutcome {
        let rel = match &action.payload {
            ActionPayload::File { path } => path.clone(),
            _ => return self.fail("non-file action reached the file apply dispatcher".to_string()),
        };
        let dest = self.dest_root.join(&rel);

        match action.kind {
            ActionKind::FileWrite => {
                let src = self.source_root.join(&rel);
                // `current` workspace: the file is already at its destination.
                if src == dest {
                    return DispatchOutcome::success();
                }
                if let Some(parent) = dest.parent() {
                    if let Err(e) = std::fs::create_dir_all(parent) {
                        return self.fail(format!("create dir {}: {e}", parent.display()));
                    }
                }
                match std::fs::copy(&src, &dest) {
                    Ok(_) => DispatchOutcome::success(),
                    Err(e) => {
                        self.fail(format!("copy {} -> {}: {e}", src.display(), dest.display()))
                    }
                }
            }
            ActionKind::FileDelete => match std::fs::remove_file(&dest) {
                Ok(()) => DispatchOutcome::success(),
                // Already absent (e.g. `current` mode): the delete is satisfied.
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => DispatchOutcome::success(),
                Err(e) => self.fail(format!("delete {}: {e}", dest.display())),
            },
            other => self.fail(format!("unexpected action kind {other:?} in file apply")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    use crate::context::Verbosity;

    /// A quiet context (suppresses the header) with an explicit `--config`.
    fn quiet_ctx(policy_path: &Path) -> GlobalContext {
        GlobalContext {
            json: false,
            no_color: true,
            verbosity: Verbosity::Quiet,
            config: Some(policy_path.to_path_buf()),
        }
    }

    fn write_policy(name: &str, body: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "fida_run_test_{}_{}_{}.yaml",
            name,
            std::process::id(),
            now_nanos()
        ));
        let mut f = std::fs::File::create(&path).expect("create temp policy");
        f.write_all(body.as_bytes()).expect("write temp policy");
        path
    }

    fn now_nanos() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    }

    fn proxy_bind_permission_denied(result: &CliResult) -> bool {
        let rendered = format!("{result:?}");
        rendered.contains("failed to start network proxy")
            && rendered.contains("Operation not permitted")
    }

    fn run_args(
        mode: Option<&str>,
        workspace: Option<&str>,
        apply: Option<&str>,
        command: &[&str],
    ) -> RunArgs {
        RunArgs {
            profile: None,
            mode: mode.map(str::to_string),
            workspace: workspace.map(str::to_string),
            apply: apply.map(str::to_string),
            report: None,
            non_interactive: true,
            command: command.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn sessions_dir_exists(repo: &Path) -> bool {
        fida_session::sessions_root(repo).exists()
    }

    #[tokio::test]
    async fn invalid_mode_exits_1_without_starting_session() {
        let policy = write_policy("invalid_mode", "version: 1\ndefault_decision: allow\n");
        let repo = tempfile::tempdir().unwrap();
        let args = run_args(Some("yolo"), None, None, &["true"]);

        let err = run_in(repo.path(), &args, &quiet_ctx(&policy))
            .await
            .expect_err("must fail");
        assert_eq!(err.exit_code(), 1);
        assert!(
            !sessions_dir_exists(repo.path()),
            "no session should be created for an invalid mode"
        );
        let _ = std::fs::remove_file(&policy);
    }

    #[tokio::test]
    async fn invalid_workspace_exits_1_without_starting_session() {
        let policy = write_policy("invalid_ws", "version: 1\ndefault_decision: allow\n");
        let repo = tempfile::tempdir().unwrap();
        let args = run_args(None, Some("sandbox"), None, &["true"]);

        let err = run_in(repo.path(), &args, &quiet_ctx(&policy))
            .await
            .expect_err("must fail");
        assert_eq!(err.exit_code(), 1);
        assert!(!sessions_dir_exists(repo.path()));
        let _ = std::fs::remove_file(&policy);
    }

    #[tokio::test]
    async fn invalid_apply_exits_1_without_starting_session() {
        let policy = write_policy("invalid_apply", "version: 1\ndefault_decision: allow\n");
        let repo = tempfile::tempdir().unwrap();
        let args = run_args(None, None, Some("maybe"), &["true"]);

        let err = run_in(repo.path(), &args, &quiet_ctx(&policy))
            .await
            .expect_err("must fail");
        assert_eq!(err.exit_code(), 1);
        assert!(!sessions_dir_exists(repo.path()));
        let _ = std::fs::remove_file(&policy);
    }

    #[tokio::test]
    async fn baseline_failure_outside_git_prevents_session_start() {
        let policy = write_policy("baseline", "version: 1\ndefault_decision: allow\n");
        // A non-git temp dir: baseline capture must fail.
        let repo = tempfile::tempdir().unwrap();
        let args = run_args(None, None, Some("never"), &["true"]);

        let err = run_in(repo.path(), &args, &quiet_ctx(&policy))
            .await
            .expect_err("must fail");
        assert_eq!(err.exit_code(), 1);
        assert!(
            !sessions_dir_exists(repo.path()),
            "baseline failure must prevent session creation"
        );
        let _ = std::fs::remove_file(&policy);
    }

    #[test]
    fn mode_resolution_precedence() {
        // --mode wins.
        assert_eq!(
            resolve_mode(Some("observe"), Some(Mode::Enforce)).unwrap(),
            Mode::Observe
        );
        // profile/base mode when no --mode.
        assert_eq!(
            resolve_mode(None, Some(Mode::DryRun)).unwrap(),
            Mode::DryRun
        );
        // enforce default when neither is present.
        assert_eq!(resolve_mode(None, None).unwrap(), Mode::Enforce);
        // invalid --mode is a usage error.
        assert_eq!(resolve_mode(Some("nope"), None).unwrap_err().exit_code(), 1);
    }

    #[test]
    fn apply_mode_parsing() {
        assert_eq!(ApplyMode::parse("ask").unwrap(), ApplyMode::Ask);
        assert_eq!(ApplyMode::parse("never").unwrap(), ApplyMode::Never);
        assert_eq!(
            ApplyMode::parse("auto-if-allowed").unwrap(),
            ApplyMode::AutoIfAllowed
        );
        assert_eq!(ApplyMode::parse("bogus").unwrap_err().exit_code(), 1);
    }

    #[cfg(unix)]
    fn git(repo: &Path, args: &[&str]) {
        let out = std::process::Command::new("git")
            .args(args)
            .current_dir(repo)
            .output()
            .expect("git runs");
        assert!(
            out.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    #[cfg(unix)]
    fn init_repo() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path();
        git(p, &["init", "-q"]);
        git(p, &["config", "user.email", "test@example.com"]);
        git(p, &["config", "user.name", "Test"]);
        git(p, &["config", "commit.gpgsign", "false"]);
        std::fs::write(p.join("tracked.txt"), "original\n").unwrap();
        git(p, &["add", "-A"]);
        git(p, &["commit", "-q", "-m", "initial"]);
        dir
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn sh_agent_run_end_to_end_creates_a_session() {
        let policy = write_policy("e2e", "version: 1\ndefault_decision: allow\n");
        let repo = init_repo();
        // A trivial agent that writes a new file; workspace `current`, no apply.
        let args = run_args(
            Some("enforce"),
            Some("current"),
            Some("never"),
            &["sh", "-c", "echo created > newfile.txt"],
        );

        let result = run_in(repo.path(), &args, &quiet_ctx(&policy)).await;
        assert!(result.is_ok(), "expected a clean run, got {result:?}");

        // A session directory with metadata + result was produced.
        let root = fida_session::sessions_root(repo.path());
        assert!(root.exists(), "sessions root should exist");
        let entries: Vec<_> = std::fs::read_dir(&root)
            .unwrap()
            .filter_map(Result::ok)
            .collect();
        assert_eq!(entries.len(), 1, "exactly one session directory");
        let session = entries[0].path();
        assert!(session.join("session.json").is_file(), "metadata written");
        assert!(session.join("result.json").is_file(), "result written");
        let raw = std::fs::read_to_string(session.join("session.json")).unwrap();
        let metadata: fida_session::SessionMetadata = serde_json::from_str(&raw).unwrap();
        assert_eq!(metadata.workspace_mode, "current");

        let _ = std::fs::remove_file(&policy);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn default_run_workspace_is_isolated_copy() {
        let policy = write_policy("default_copy", "version: 1\ndefault_decision: allow\n");
        let repo = init_repo();
        let args = run_args(
            Some("enforce"),
            None,
            Some("auto-if-allowed"),
            &["sh", "-c", "printf 'changed\\n' > tracked.txt"],
        );

        let result = run_in(repo.path(), &args, &quiet_ctx(&policy)).await;
        assert!(result.is_ok(), "expected a clean run, got {result:?}");

        let root = fida_session::sessions_root(repo.path());
        let entries: Vec<_> = std::fs::read_dir(&root)
            .unwrap()
            .filter_map(Result::ok)
            .collect();
        let raw = std::fs::read_to_string(entries[0].path().join("session.json")).unwrap();
        let metadata: fida_session::SessionMetadata = serde_json::from_str(&raw).unwrap();
        assert_eq!(metadata.workspace_mode, "copy");
        assert_eq!(
            std::fs::read_to_string(repo.path().join("tracked.txt")).unwrap(),
            "changed\n"
        );
        let _ = std::fs::remove_file(&policy);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn dry_run_does_not_launch_agent_command() {
        let policy = write_policy("dry_run", "version: 1\ndefault_decision: allow\n");
        let repo = init_repo();
        let args = run_args(
            Some("dry-run"),
            Some("current"),
            Some("never"),
            &["sh", "-c", "printf side-effect > dryrun-side-effect.txt"],
        );

        let result = run_in(repo.path(), &args, &quiet_ctx(&policy)).await;
        assert!(result.is_ok(), "dry-run should succeed, got {result:?}");
        assert!(
            !repo.path().join("dryrun-side-effect.txt").exists(),
            "dry-run must not execute the agent command"
        );
        let _ = std::fs::remove_file(&policy);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn current_workspace_reverts_denied_file_changes() {
        let policy = write_policy(
            "current_reject",
            "version: 1\ndefault_decision: allow\nfiles:\n  write:\n    deny:\n      - secret/**\n",
        );
        let repo = init_repo();
        let args = run_args(
            Some("enforce"),
            Some("current"),
            Some("auto-if-allowed"),
            &[
                "sh",
                "-c",
                "mkdir -p secret && printf nope > secret/key.txt",
            ],
        );

        let result = run_in(repo.path(), &args, &quiet_ctx(&policy)).await;
        assert!(result.is_ok(), "deny apply reports counts, got {result:?}");
        assert!(
            !repo.path().join("secret/key.txt").exists(),
            "denied file writes must not remain in the main workspace"
        );
        let _ = std::fs::remove_file(&policy);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn agent_failure_exits_5_after_finalize() {
        let policy = write_policy("fail", "version: 1\ndefault_decision: allow\n");
        let repo = init_repo();
        let args = run_args(
            Some("enforce"),
            Some("current"),
            Some("never"),
            &["sh", "-c", "exit 3"],
        );

        let err = run_in(repo.path(), &args, &quiet_ctx(&policy))
            .await
            .expect_err("agent failed");
        assert_eq!(err.exit_code(), 5);
        assert!(matches!(err, CliError::AgentFailed { .. }));

        // The session was still finalized despite the agent failure.
        let root = fida_session::sessions_root(repo.path());
        let session = std::fs::read_dir(&root)
            .unwrap()
            .filter_map(Result::ok)
            .next()
            .unwrap()
            .path();
        assert!(session.join("result.json").is_file(), "result preserved");

        let _ = std::fs::remove_file(&policy);
    }

    #[test]
    fn network_gating_enabled_tracks_network_rules() {
        // No network section -> no proxy activation.
        let bare_path = write_policy("gating_bare", "version: 1\ndefault_decision: allow\n");
        let bare = fida_policy::load_source(&PolicySource::Config(bare_path.clone()), None)
            .expect("bare policy compiles");
        assert!(
            !network_gating_enabled(&bare),
            "a policy with no network rules must not activate the proxy"
        );

        // Any network rule -> proxy activation.
        let net_path = write_policy(
            "gating_net",
            "version: 1\ndefault_decision: allow\nnetwork:\n  allow:\n    - domain: github.com\n",
        );
        let with_net = fida_policy::load_source(&PolicySource::Config(net_path.clone()), None)
            .expect("network policy compiles");
        assert!(
            network_gating_enabled(&with_net),
            "a policy with a network rule must activate the proxy"
        );

        let _ = std::fs::remove_file(&bare_path);
        let _ = std::fs::remove_file(&net_path);
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn network_policy_injects_proxy_env_for_the_agent() {
        // A policy that expresses network intent activates the proxy and exports
        // FIDA_HTTP_PROXY / FIDA_HTTPS_PROXY into the agent env.
        let policy = write_policy(
            "net_env",
            "version: 1\ndefault_decision: allow\nnetwork:\n  allow:\n    - domain: github.com\n",
        );
        let repo = init_repo();
        // The agent records the injected proxy vars so we can assert on them.
        let args = run_args(
            Some("enforce"),
            Some("current"),
            Some("never"),
            &[
                "sh",
                "-c",
                "echo \"$FIDA_HTTP_PROXY|$FIDA_HTTPS_PROXY\" > proxy_env.txt",
            ],
        );

        let result = run_in(repo.path(), &args, &quiet_ctx(&policy)).await;
        if proxy_bind_permission_denied(&result) {
            let _ = std::fs::remove_file(&policy);
            return;
        }
        assert!(result.is_ok(), "expected a clean run, got {result:?}");

        let recorded = std::fs::read_to_string(repo.path().join("proxy_env.txt"))
            .expect("agent wrote proxy env file");
        let recorded = recorded.trim();
        let (http, https) = recorded
            .split_once('|')
            .expect("both proxy vars recorded, separated by |");
        assert!(
            http.starts_with("http://127.0.0.1:"),
            "FIDA_HTTP_PROXY should point at the loopback proxy, got {http:?}"
        );
        assert_eq!(http, https, "both proxy vars point at the same endpoint");

        let _ = std::fs::remove_file(&policy);
    }
}
