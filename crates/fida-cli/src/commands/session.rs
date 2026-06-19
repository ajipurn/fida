//! `fida session …` — manage sessions. **Owner: task 19.6.**
//!
//! Wires the `session` subcommand family to the Session_Manager
//! (`fida-session`), the Report_Generator (`fida-audit`), and the
//! File_Diff_Gate (`fida-diff`):
//!
//! - `session list` — every recorded session, newest-first; an empty repo
//!   reports "no sessions" and exits 0.
//! - `session show <ref>` — recorded metadata plus per-decision-state counts;
//!   an unresolved reference exits 1.
//! - `session diff <ref>` — the changed files and recorded patch
//! - `session export <ref> --format <fmt>` — render the session's audit events
//!   through the Report_Generator as `markdown`/`json`; an unsupported format
//!   exits 1.
//! - `session apply <ref>` — replay the session's changed set through the diff
//!   gate/broker, applying only `allow` paths, reporting applied vs rejected
//!   counts, and surfacing exit 6 (secret blocked) / 7 (apply failure)
//! - `session clean --older-than <dur>` — remove sessions older than the
//!   duration; an invalid duration removes nothing and exits 1
//!
//! Every `<ref>` accepts the literal `latest`, resolved to the most recently
//! started session.

use std::io::IsTerminal;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

use chrono::Utc;
use clap::{Args, Subcommand};

use fida_action::{Action, ActionKind, ActionPayload, Mode};
use fida_approval::TerminalApprovalUi;
use fida_audit::{
    AuditStore, DefaultReportGenerator, JsonlAuditStore, ReportFormat, ReportGenerator,
};
use fida_broker::{
    ActionDispatcher, Broker, BrokerContext, DispatchOutcome, EXIT_SECRET_BLOCKED,
    RememberedDecisions, SessionHandle,
};
use fida_diff::{Baseline, EXIT_APPLY_FAILED, FileDiffGate, GitFileDiffGate};
use fida_policy::{load_source, resolve_source_in};
use fida_session::{
    ExportFormat, SessionError, SessionId, SessionMetadata, clean_older_than, list_sessions,
    parse_duration, parse_export_format, resolve_session, session_diff, session_dir,
    session_summary, sessions_root,
};

use crate::context::GlobalContext;
use crate::error::{CliError, CliResult};

/// Arguments for the `fida session` command family.
#[derive(Debug, Args)]
pub struct SessionArgs {
    #[command(subcommand)]
    pub command: SessionCommand,
}

/// `fida session` subcommands.
#[derive(Debug, Subcommand)]
pub enum SessionCommand {
    /// List sessions.
    List,
    /// Show a session summary (`<id>` or `latest`).
    Show(SessionRef),
    /// Show changed files and patch for a session.
    Diff(SessionRef),
    /// Export a session report.
    Export(ExportArgs),
    /// Apply allowed changes to the main workspace.
    Apply(SessionRef),
    /// Remove old session data.
    Clean(CleanArgs),
}

/// A session selector accepting an id or the literal `latest`.
#[derive(Debug, Args)]
pub struct SessionRef {
    /// Session id, or `latest`.
    #[arg(default_value = "latest")]
    pub session: String,
}

/// `fida session export <id> --format <fmt>`.
#[derive(Debug, Args)]
pub struct ExportArgs {
    /// Session id, or `latest`.
    #[arg(default_value = "latest")]
    pub session: String,
    /// Report format: `markdown` or `json`.
    #[arg(long)]
    pub format: Option<String>,
}

/// `fida session clean --older-than <duration>`.
#[derive(Debug, Args)]
pub struct CleanArgs {
    /// Remove sessions older than this duration (e.g. `30d`).
    #[arg(long = "older-than")]
    pub older_than: Option<String>,
}

/// Dispatch the `session` subcommands against the current repository (`.`).
pub async fn run(args: &SessionArgs, ctx: &GlobalContext) -> CliResult {
    let repo = PathBuf::from(".");
    match &args.command {
        SessionCommand::List => list(&repo, ctx),
        SessionCommand::Show(r) => show(&repo, &r.session, ctx),
        SessionCommand::Diff(r) => diff(&repo, &r.session, ctx),
        SessionCommand::Export(a) => export(&repo, a, ctx),
        SessionCommand::Apply(r) => apply(&repo, &r.session, ctx),
        SessionCommand::Clean(a) => clean(&repo, a, ctx),
    }
}

// ---------------------------------------------------------------------------
// session list
// ---------------------------------------------------------------------------

/// List every recorded session, newest-first. An empty repo reports that no
/// sessions exist and completes successfully.
fn list(repo: &Path, ctx: &GlobalContext) -> CliResult {
    let sessions = list_sessions(repo).map_err(session_err_to_cli)?;

    if ctx.json {
        let entries: Vec<serde_json::Value> = sessions.iter().map(metadata_json).collect();
        println!("{}", serde_json::json!({ "sessions": entries }));
        return Ok(());
    }

    if sessions.is_empty() {
        if !ctx.is_quiet() {
            println!("No sessions recorded.");
        }
        return Ok(());
    }

    for m in &sessions {
        // id, start time, and active profile.
        println!(
            "{}\t{}\t{}",
            m.session_id,
            m.start_time.to_rfc3339(),
            m.profile.as_deref().unwrap_or("(default)"),
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// session show
// ---------------------------------------------------------------------------

/// Show a session's metadata and per-decision-state counts.
fn show(repo: &Path, reference: &str, ctx: &GlobalContext) -> CliResult {
    let id = resolve_session(repo, reference).map_err(session_err_to_cli)?;
    let summary = session_summary(repo, &id).map_err(session_err_to_cli)?;
    let m = &summary.metadata;
    let c = &summary.decision_counts;

    if ctx.json {
        let mut meta = metadata_json(m);
        meta["decision_counts"] = serde_json::json!({
            "allow": c.allow,
            "ask": c.ask,
            "deny": c.deny,
            "dry_run": c.dry_run,
            "total": c.total(),
        });
        println!("{meta}");
        return Ok(());
    }

    println!("Session:      {}", m.session_id);
    println!("Start time:   {}", m.start_time.to_rfc3339());
    if let Some(end) = m.end_time {
        println!("End time:     {}", end.to_rfc3339());
    }
    println!(
        "Profile:      {}",
        m.profile.as_deref().unwrap_or("(default)")
    );
    println!("Mode:         {}", mode_label(m.mode));
    println!("Workspace:    {}", m.workspace_mode);
    println!("Repo path:    {}", m.repo_path.display());
    println!("Git SHA:      {}", m.git_sha);
    println!("Agent command: {}", m.agent_command.join(" "));
    println!(
        "Decisions:    allow={}, ask={}, deny={}, dry_run={} (total {})",
        c.allow,
        c.ask,
        c.deny,
        c.dry_run,
        c.total(),
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// session diff
// ---------------------------------------------------------------------------

/// Show the changed files and recorded patch for a session.
fn diff(repo: &Path, reference: &str, ctx: &GlobalContext) -> CliResult {
    let id = resolve_session(repo, reference).map_err(session_err_to_cli)?;
    let patch = session_diff(repo, &id).map_err(session_err_to_cli)?;
    let files = changed_paths_from_patch(&patch);

    if ctx.json {
        println!(
            "{}",
            serde_json::json!({
                "session": id.as_str(),
                "changed_files": files,
                "patch": patch,
            })
        );
        return Ok(());
    }

    if patch.trim().is_empty() {
        if !ctx.is_quiet() {
            println!("No changes recorded for session {}.", id);
        }
        return Ok(());
    }

    if !ctx.is_quiet() {
        println!("Changed files:");
        if files.is_empty() {
            println!("  (none parsed)");
        } else {
            for f in &files {
                println!("  {f}");
            }
        }
        println!();
    }
    // The recorded patch is the primary result; print it even when quiet.
    print!("{patch}");
    if !patch.ends_with('\n') {
        println!();
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// session export
// ---------------------------------------------------------------------------

/// Render a session report from its audit events in `markdown` or `json`.
fn export(repo: &Path, args: &ExportArgs, _ctx: &GlobalContext) -> CliResult {
    let format = match &args.format {
        Some(f) => f.as_str(),
        None => {
            return Err(CliError::usage(
                "session export requires --format <markdown|json>",
            ));
        }
    };
    // Gate the format first so an unsupported value fails closed.
    let export_format = parse_export_format(format).map_err(session_err_to_cli)?;

    let id = resolve_session(repo, &args.session).map_err(session_err_to_cli)?;

    let store = JsonlAuditStore::new(sessions_root(repo));
    let events = store
        .read(id.as_str())
        .map_err(|e| CliError::general(format!("cannot read session events: {e}")))?;

    let rendered = DefaultReportGenerator::new()
        .render(&events, report_format(export_format))
        .map_err(|e| CliError::general(e.to_string()))?;

    // The rendered report is the primary result; print it even when quiet.
    println!("{rendered}");
    Ok(())
}

// ---------------------------------------------------------------------------
// session apply
// ---------------------------------------------------------------------------

/// Apply a session's allowed changes to the main workspace through the diff
/// gate/broker, reporting applied vs rejected counts and surfacing exit 6/7.
fn apply(repo: &Path, reference: &str, ctx: &GlobalContext) -> CliResult {
    let id = resolve_session(repo, reference).map_err(session_err_to_cli)?;
    let summary = session_summary(repo, &id).map_err(session_err_to_cli)?;
    let metadata = summary.metadata;

    // Resolve and compile the policy (profile from the session metadata), so
    // the same evaluator that gated the agent gates the apply.
    let source = resolve_source_in(repo, ctx.config.as_deref())?;
    let policy = load_source(&source, metadata.profile.as_deref())?;

    // The session's workspace (where the changed content lives) and the main
    // workspace the changes are applied into.
    if metadata.workspace_mode == "current" && metadata.baseline.dirty {
        return Err(CliError::general(
            "cannot apply a current-workspace session that started from a dirty tree",
        ));
    }

    let source_root = workspace_root(repo, &id, &metadata);
    let dest_root = repo.to_path_buf();
    let baseline = Baseline {
        head_sha: metadata.baseline.head_sha.clone(),
        dirty: metadata.baseline.dirty,
    };

    let broker = Broker::new(TerminalApprovalUi::new());
    let gate = GitFileDiffGate::new(broker, source_root.clone());

    // Replay the changed set recorded for the session.
    let changes = gate
        .changed_files(&source_root, &baseline)
        .map_err(|e| CliError::general(format!("cannot compute session changes: {e}")))?;

    // `apply` honors allow/deny/ask through the broker; non-interactive runs
    // fail closed on `ask`. A real tty on stdin permits prompts.
    let interactive = std::io::stdin().is_terminal();

    let mut session_handle = SessionHandle::new(id.as_str());
    let mut remembered = RememberedDecisions::new();
    let mut audit = JsonlAuditStore::new(sessions_root(repo));
    let mut dispatcher = FileApplyDispatcher::new(source_root, dest_root);

    let report = {
        let mut bctx = BrokerContext {
            policy: &policy,
            mode: Mode::Enforce,
            interactive,
            yes: false,
            session: &mut session_handle,
            remembered: &mut remembered,
            audit: &mut audit,
            dispatcher: &mut dispatcher,
        };
        gate.apply(&mut bctx, &changes)
    };

    if metadata.workspace_mode == "current" && !report.rejected_paths.is_empty() {
        restore_rejected_current_workspace(repo, &baseline, &report.rejected_paths)?;
    }

    if ctx.json {
        let failures: Vec<String> = report
            .failures
            .iter()
            .map(|p| p.display().to_string())
            .collect();
        println!(
            "{}",
            serde_json::json!({
                "session": id.as_str(),
                "applied": report.applied,
                "rejected": report.rejected,
                "failures": failures,
                "exit_code": report.exit_code,
            })
        );
    } else if !ctx.is_quiet() {
        // Applied vs rejected counts.
        println!(
            "Applied {} file(s), rejected {} file(s).",
            report.applied, report.rejected
        );
        for path in &report.failures {
            eprintln!("  could not apply: {}", path.display());
        }
    }

    // Surface secret-blocked (6) and apply-failure (7) outcomes.
    match report.exit_code {
        EXIT_SECRET_BLOCKED => Err(CliError::SecretBlocked {
            reason: format!("a changed file in session {id} contained a detected secret"),
        }),
        EXIT_APPLY_FAILED => Err(CliError::ApplyFailed {
            message: format!(
                "{} path(s) could not be applied to the main workspace",
                report.failures.len()
            ),
        }),
        _ => Ok(()),
    }
}

// ---------------------------------------------------------------------------
// session clean
// ---------------------------------------------------------------------------

/// Remove session directories older than `--older-than`. An invalid duration
/// removes nothing and exits 1.
fn clean(repo: &Path, args: &CleanArgs, ctx: &GlobalContext) -> CliResult {
    let raw = match &args.older_than {
        Some(d) => d.as_str(),
        None => {
            return Err(CliError::usage(
                "session clean requires --older-than <duration> (e.g. 30d)",
            ));
        }
    };
    // Parse + gate the duration before touching any directory.
    let duration = parse_duration(raw).map_err(session_err_to_cli)?;

    let removed = clean_older_than(repo, duration, Utc::now()).map_err(session_err_to_cli)?;

    if ctx.json {
        let ids: Vec<String> = removed.iter().map(|i| i.as_str().to_string()).collect();
        println!(
            "{}",
            serde_json::json!({ "removed": ids, "count": removed.len() })
        );
        return Ok(());
    }

    if !ctx.is_quiet() {
        if removed.is_empty() {
            println!("No sessions older than {raw}.");
        } else {
            println!("Removed {} session(s):", removed.len());
            for id in &removed {
                println!("  {id}");
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The apply dispatcher
// ---------------------------------------------------------------------------

/// The [`ActionDispatcher`] the broker calls for a *permitted* file change
/// during `session apply`. It materializes the recorded change into the main
/// workspace: a `file.write` copies the session's content over the destination
/// path; a `file.delete` removes the destination path.
///
/// When the session ran in the `current` workspace the source and destination
/// resolve to the same file, so the change is already present — the dispatcher
/// treats that as a successful (idempotent) apply rather than copying a file
/// onto itself. A real copy/delete failure reports a non-zero exit code, which
/// the diff gate records as an apply failure (exit 7).
struct FileApplyDispatcher {
    source_root: PathBuf,
    dest_root: PathBuf,
}

impl FileApplyDispatcher {
    fn new(source_root: PathBuf, dest_root: PathBuf) -> Self {
        FileApplyDispatcher {
            source_root,
            dest_root,
        }
    }
}

impl ActionDispatcher for FileApplyDispatcher {
    fn dispatch(&mut self, action: &Action) -> DispatchOutcome {
        let path = match &action.payload {
            ActionPayload::File { path } => path,
            // Only file actions flow through the diff gate; anything else is a
            // no-op success.
            _ => return DispatchOutcome::success(),
        };
        let dst = self.dest_root.join(path);

        match action.kind {
            ActionKind::FileWrite => {
                let src = self.source_root.join(path);
                // Already-present (current-workspace) change: nothing to copy.
                if same_file(&src, &dst) {
                    return DispatchOutcome::success();
                }
                if let Some(parent) = dst.parent() {
                    if let Err(_e) = std::fs::create_dir_all(parent) {
                        return DispatchOutcome {
                            exit_code: EXIT_APPLY_FAILED,
                        };
                    }
                }
                match std::fs::copy(&src, &dst) {
                    Ok(_) => DispatchOutcome::success(),
                    Err(_) => DispatchOutcome {
                        exit_code: EXIT_APPLY_FAILED,
                    },
                }
            }
            ActionKind::FileDelete => {
                // Already removed (current-workspace) change: nothing to do.
                if !dst.exists() {
                    return DispatchOutcome::success();
                }
                match std::fs::remove_file(&dst) {
                    Ok(()) => DispatchOutcome::success(),
                    Err(_) => DispatchOutcome {
                        exit_code: EXIT_APPLY_FAILED,
                    },
                }
            }
            _ => DispatchOutcome::success(),
        }
    }
}

/// Whether two paths resolve to the same file on disk (best-effort: falls back
/// to a literal comparison when canonicalization fails, e.g. a missing source).
fn same_file(a: &Path, b: &Path) -> bool {
    match (a.canonicalize(), b.canonicalize()) {
        (Ok(ca), Ok(cb)) => ca == cb,
        _ => a == b,
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// The workspace root the session's changed content lives in.
fn workspace_root(repo: &Path, id: &SessionId, metadata: &SessionMetadata) -> PathBuf {
    match metadata.workspace_mode.as_str() {
        "copy" | "git-worktree" => session_dir(repo, id).join("workspace"),
        _ => metadata.repo_path.clone(),
    }
}

fn restore_rejected_current_workspace(
    repo: &Path,
    baseline: &Baseline,
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

/// Map a [`SessionError`] to the CLI error bucket. Every session error the
/// `session` subcommands surface maps to the generic exit 1.
fn session_err_to_cli(err: SessionError) -> CliError {
    CliError::general(err.to_string())
}

/// Translate the gating [`ExportFormat`] into the Report_Generator's
/// [`ReportFormat`]; the two enums are isomorphic.
fn report_format(format: ExportFormat) -> ReportFormat {
    match format {
        ExportFormat::Markdown => ReportFormat::Markdown,
        ExportFormat::Json => ReportFormat::Json,
    }
}

/// The human-readable name of a session [`Mode`].
fn mode_label(mode: Mode) -> &'static str {
    match mode {
        Mode::Observe => "observe",
        Mode::Enforce => "enforce",
        Mode::DryRun => "dry-run",
    }
}

/// Build the redaction-safe JSON object for one session's metadata.
fn metadata_json(m: &SessionMetadata) -> serde_json::Value {
    serde_json::json!({
        "session_id": m.session_id.as_str(),
        "start_time": m.start_time.to_rfc3339(),
        "end_time": m.end_time.map(|t| t.to_rfc3339()),
        "profile": m.profile,
        "mode": mode_label(m.mode),
        "workspace_mode": m.workspace_mode.as_str(),
        "repo_path": m.repo_path.display().to_string(),
        "git_sha": m.git_sha,
        "agent_command": m.agent_command,
    })
}

/// Extract the set of changed paths from a unified-diff patch by reading its
/// `diff --git a/<path> b/<path>` headers. Used for the human-readable
/// changed-files listing in `session diff`.
fn changed_paths_from_patch(patch: &str) -> Vec<String> {
    let mut files = Vec::new();
    for line in patch.lines() {
        if let Some(rest) = line.strip_prefix("diff --git ") {
            // `a/<path> b/<path>`: take the `b/` side as the resulting path.
            if let Some(b_idx) = rest.find(" b/") {
                let b = &rest[b_idx + 3..];
                files.push(b.to_string());
                continue;
            }
            // Fall back to the `a/` side when only one path is present.
            if let Some(a) = rest.strip_prefix("a/") {
                let path = a.split_whitespace().next().unwrap_or(a);
                files.push(path.to_string());
            }
        }
    }
    files
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs;
    use std::path::Path;

    use chrono::{DateTime, TimeZone, Utc};
    use fida_session::{
        Baseline as SessionBaseline, CreateSessionParams, SESSION_DIFF_FILE, SESSION_EVENTS_FILE,
        SessionId, create_session, session_dir,
    };

    fn ctx(json: bool) -> GlobalContext {
        GlobalContext {
            json,
            no_color: true,
            verbosity: crate::context::Verbosity::Normal,
            config: None,
        }
    }

    fn ctx_with_config(path: &Path) -> GlobalContext {
        GlobalContext {
            json: false,
            no_color: true,
            verbosity: crate::context::Verbosity::Normal,
            config: Some(path.to_path_buf()),
        }
    }

    fn ts(y: i32, mo: u32, d: u32, h: u32, mi: u32, s: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(y, mo, d, h, mi, s).single().unwrap()
    }

    fn make_session(repo: &Path, start: DateTime<Utc>, profile: &str) -> SessionId {
        let params = CreateSessionParams {
            repo_path: repo.to_path_buf(),
            git_sha: "deadbeef".to_string(),
            profile: Some(profile.to_string()),
            mode: Mode::Enforce,
            workspace_mode: "current".to_string(),
            agent_command: vec!["codex".to_string()],
            start_time: start,
            baseline: SessionBaseline {
                head_sha: "deadbeef".to_string(),
                dirty: false,
            },
        };
        create_session(params).unwrap().id
    }

    // --- list ---

    #[test]
    fn list_empty_repo_is_ok() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(list(tmp.path(), &ctx(false)).is_ok());
        assert!(list(tmp.path(), &ctx(true)).is_ok());
    }

    #[test]
    fn list_with_sessions_is_ok() {
        let tmp = tempfile::tempdir().unwrap();
        make_session(tmp.path(), ts(2026, 6, 12, 7, 0, 0), "starter");
        make_session(tmp.path(), ts(2026, 6, 12, 8, 0, 0), "careful");
        assert!(list(tmp.path(), &ctx(false)).is_ok());
    }

    // --- show ---

    #[test]
    fn show_latest_resolves_and_succeeds() {
        let tmp = tempfile::tempdir().unwrap();
        make_session(tmp.path(), ts(2026, 6, 12, 7, 0, 0), "starter");
        assert!(show(tmp.path(), "latest", &ctx(false)).is_ok());
        assert!(show(tmp.path(), "latest", &ctx(true)).is_ok());
    }

    #[test]
    fn show_unknown_session_exits_1() {
        let tmp = tempfile::tempdir().unwrap();
        let err = show(tmp.path(), "does-not-exist", &ctx(false)).unwrap_err();
        assert_eq!(err.exit_code(), 1);
    }

    // --- diff ---

    #[test]
    fn diff_prints_recorded_patch() {
        let tmp = tempfile::tempdir().unwrap();
        let id = make_session(tmp.path(), ts(2026, 6, 12, 7, 0, 0), "starter");
        let patch = "diff --git a/src/x.rs b/src/x.rs\n--- a/src/x.rs\n+++ b/src/x.rs\n+added\n";
        fs::write(session_dir(tmp.path(), &id).join(SESSION_DIFF_FILE), patch).unwrap();
        assert!(diff(tmp.path(), id.as_str(), &ctx(false)).is_ok());
        assert!(diff(tmp.path(), "latest", &ctx(true)).is_ok());
    }

    #[test]
    fn diff_unknown_session_exits_1() {
        let tmp = tempfile::tempdir().unwrap();
        let err = diff(tmp.path(), "nope", &ctx(false)).unwrap_err();
        assert_eq!(err.exit_code(), 1);
    }

    #[test]
    fn changed_paths_parsed_from_patch_headers() {
        let patch = "diff --git a/src/x.rs b/src/x.rs\n+added\ndiff --git a/y b/y\n";
        assert_eq!(
            changed_paths_from_patch(patch),
            vec!["src/x.rs".to_string(), "y".to_string()]
        );
    }

    // --- export ---

    fn write_events(repo: &Path, id: &SessionId) {
        let line = format!(
            r#"{{"id":"evt_01","session_id":"{sid}","time":"2026-06-12T07:00:00Z","actor":"agent","action":{{"kind":"command.run","command":"echo hi"}},"decision":"allow","result":"allowed","matched_rule":"none","risk":"low","redacted":false}}"#,
            sid = id.as_str(),
        );
        fs::write(
            session_dir(repo, id).join(SESSION_EVENTS_FILE),
            format!("{line}\n"),
        )
        .unwrap();
    }

    #[test]
    fn export_markdown_renders_report() {
        let tmp = tempfile::tempdir().unwrap();
        let id = make_session(tmp.path(), ts(2026, 6, 12, 7, 0, 0), "starter");
        write_events(tmp.path(), &id);
        let args = ExportArgs {
            session: id.as_str().to_string(),
            format: Some("markdown".to_string()),
        };
        assert!(export(tmp.path(), &args, &ctx(false)).is_ok());
    }

    #[test]
    fn export_json_renders_report() {
        let tmp = tempfile::tempdir().unwrap();
        let id = make_session(tmp.path(), ts(2026, 6, 12, 7, 0, 0), "starter");
        write_events(tmp.path(), &id);
        let args = ExportArgs {
            session: "latest".to_string(),
            format: Some("json".to_string()),
        };
        assert!(export(tmp.path(), &args, &ctx(false)).is_ok());
    }

    #[test]
    fn export_unsupported_format_exits_1() {
        let tmp = tempfile::tempdir().unwrap();
        let id = make_session(tmp.path(), ts(2026, 6, 12, 7, 0, 0), "starter");
        write_events(tmp.path(), &id);
        let args = ExportArgs {
            session: id.as_str().to_string(),
            format: Some("yaml".to_string()),
        };
        let err = export(tmp.path(), &args, &ctx(false)).unwrap_err();
        assert_eq!(err.exit_code(), 1);
    }

    #[test]
    fn export_missing_format_exits_1() {
        let tmp = tempfile::tempdir().unwrap();
        make_session(tmp.path(), ts(2026, 6, 12, 7, 0, 0), "starter");
        let args = ExportArgs {
            session: "latest".to_string(),
            format: None,
        };
        let err = export(tmp.path(), &args, &ctx(false)).unwrap_err();
        assert_eq!(err.exit_code(), 1);
    }

    // --- clean ---

    #[test]
    fn clean_invalid_duration_exits_1_and_removes_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let id = make_session(tmp.path(), ts(2026, 6, 12, 7, 0, 0), "starter");
        let args = CleanArgs {
            older_than: Some("notaduration".to_string()),
        };
        let err = clean(tmp.path(), &args, &ctx(false)).unwrap_err();
        assert_eq!(err.exit_code(), 1);
        assert!(session_dir(tmp.path(), &id).exists(), "nothing removed");
    }

    #[test]
    fn clean_missing_duration_exits_1() {
        let tmp = tempfile::tempdir().unwrap();
        let args = CleanArgs { older_than: None };
        let err = clean(tmp.path(), &args, &ctx(false)).unwrap_err();
        assert_eq!(err.exit_code(), 1);
    }

    #[test]
    fn clean_removes_old_sessions() {
        let tmp = tempfile::tempdir().unwrap();
        // A very old session relative to now: 3650 days back.
        let old_start = Utc::now() - chrono::Duration::days(3650);
        let id = make_session(tmp.path(), old_start, "starter");
        let args = CleanArgs {
            older_than: Some("1d".to_string()),
        };
        assert!(clean(tmp.path(), &args, &ctx(false)).is_ok());
        assert!(!session_dir(tmp.path(), &id).exists());
    }

    // --- apply ---

    fn git(repo: &Path, args: &[&str]) {
        let out = std::process::Command::new("git")
            .args(args)
            .current_dir(repo)
            .output()
            .expect("git runs");
        assert!(
            out.status.success(),
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&out.stderr)
        );
    }

    fn init_git_repo(repo: &Path) -> String {
        git(repo, &["init", "-q"]);
        git(repo, &["config", "user.email", "test@example.com"]);
        git(repo, &["config", "user.name", "Test"]);
        git(repo, &["config", "commit.gpgsign", "false"]);
        fs::create_dir_all(repo.join("src")).unwrap();
        fs::write(repo.join("src/keep.txt"), "original\n").unwrap();
        git(repo, &["add", "-A"]);
        git(repo, &["commit", "-q", "-m", "initial"]);
        let out = std::process::Command::new("git")
            .args(["rev-parse", "HEAD"])
            .current_dir(repo)
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    #[test]
    fn apply_allows_changes_under_allow_policy() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path();
        let head = init_git_repo(repo);

        // Agent added a new untracked file after the baseline commit.
        fs::write(repo.join("src/new.txt"), "brand new\n").unwrap();

        // Allow-everything policy (written outside the repo to avoid being a
        // tracked change).
        let policy_dir = tempfile::tempdir().unwrap();
        let policy_path = policy_dir.path().join("fida.yaml");
        fs::write(&policy_path, "version: 1\ndefault_decision: allow\n").unwrap();

        // Session whose baseline is the initial commit; workspace == repo.
        let params = CreateSessionParams {
            repo_path: repo.to_path_buf(),
            git_sha: head.clone(),
            profile: None,
            mode: Mode::Enforce,
            workspace_mode: "current".to_string(),
            agent_command: vec!["agent".to_string()],
            start_time: Utc::now(),
            baseline: SessionBaseline {
                head_sha: head,
                dirty: false,
            },
        };
        let id = create_session(params).unwrap().id;

        let result = apply(repo, id.as_str(), &ctx_with_config(&policy_path));
        assert!(result.is_ok(), "allow apply should succeed: {result:?}");
        // The change was already present in the current workspace.
        assert!(repo.join("src/new.txt").exists());
    }

    #[test]
    fn apply_reads_changes_from_copy_workspace() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path();
        let head = init_git_repo(repo);

        let policy_dir = tempfile::tempdir().unwrap();
        let policy_path = policy_dir.path().join("fida.yaml");
        fs::write(&policy_path, "version: 1\ndefault_decision: allow\n").unwrap();

        let params = CreateSessionParams {
            repo_path: repo.to_path_buf(),
            git_sha: head.clone(),
            profile: None,
            mode: Mode::Enforce,
            workspace_mode: "copy".to_string(),
            agent_command: vec!["agent".to_string()],
            start_time: Utc::now(),
            baseline: SessionBaseline {
                head_sha: head,
                dirty: false,
            },
        };
        let id = create_session(params).unwrap().id;
        let workspace = session_dir(repo, &id).join("workspace");
        let clone = std::process::Command::new("git")
            .arg("clone")
            .arg(repo)
            .arg(&workspace)
            .output()
            .expect("git clone runs");
        assert!(
            clone.status.success(),
            "git clone failed: {}",
            String::from_utf8_lossy(&clone.stderr)
        );
        fs::write(
            workspace.join("src/from-copy.txt"),
            "from isolated workspace\n",
        )
        .unwrap();

        let result = apply(repo, id.as_str(), &ctx_with_config(&policy_path));
        assert!(
            result.is_ok(),
            "copy workspace apply should succeed: {result:?}"
        );
        assert_eq!(
            fs::read_to_string(repo.join("src/from-copy.txt")).unwrap(),
            "from isolated workspace\n"
        );
    }

    #[test]
    fn apply_rejects_changes_under_deny_policy() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path();
        let head = init_git_repo(repo);
        fs::write(repo.join("src/new.txt"), "brand new\n").unwrap();

        let policy_dir = tempfile::tempdir().unwrap();
        let policy_path = policy_dir.path().join("fida.yaml");
        // deny default -> file.write resolves deny -> rejected, workspace
        // unchanged, success exit (counts reported).
        fs::write(&policy_path, "version: 1\ndefault_decision: deny\n").unwrap();

        let params = CreateSessionParams {
            repo_path: repo.to_path_buf(),
            git_sha: head.clone(),
            profile: None,
            mode: Mode::Enforce,
            workspace_mode: "current".to_string(),
            agent_command: vec!["agent".to_string()],
            start_time: Utc::now(),
            baseline: SessionBaseline {
                head_sha: head,
                dirty: false,
            },
        };
        let id = create_session(params).unwrap().id;

        // A deny outcome is reported (applied 0 / rejected N) and exits 0; the
        // file remains untouched in the workspace regardless.
        let result = apply(repo, id.as_str(), &ctx_with_config(&policy_path));
        assert!(result.is_ok(), "deny apply reports counts, not an error");
    }

    #[test]
    fn apply_unknown_session_exits_1() {
        let tmp = tempfile::tempdir().unwrap();
        let err = apply(tmp.path(), "nope", &ctx(false)).unwrap_err();
        assert_eq!(err.exit_code(), 1);
    }
}
