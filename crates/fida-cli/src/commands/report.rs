//! `fida report <session>` — human-readable session report.
//! **Owner: task 19.7.**
//!
//! Resolves a session reference (`latest` or an explicit id), reads its audit
//! events, and renders them through the [`DefaultReportGenerator`] in the
//! requested format:
//!
//! * an unresolved session -> an error and no report;
//! * an unsupported `--format` -> an error and no report;
//! * a supported format (`markdown` | `json`) -> the rendered report, with every
//!   section rendered even when empty.
//!
//! The shared [`build_report`] entry point is reused by `fida audit export`
//! (task 19.7 owns both), so the two commands resolve, read, and render
//! identically.

use std::path::{Path, PathBuf};

use clap::Args;

use fida_audit::{
    AuditStore, DefaultReportGenerator, JsonlAuditStore, ReportFormat, ReportGenerator,
};
use fida_session::{resolve_session, sessions_root};

use crate::context::GlobalContext;
use crate::error::{CliError, CliResult};

/// Arguments for `fida report`.
#[derive(Debug, Args)]
pub struct ReportArgs {
    /// Session id, or `latest`.
    #[arg(default_value = "latest")]
    pub session: String,

    /// Report format: `markdown` or `json`.
    #[arg(long)]
    pub format: Option<String>,
}

/// Run `fida report <session>`.
pub async fn run(args: &ReportArgs, ctx: &GlobalContext) -> CliResult {
    let repo = PathBuf::from(".");
    let report = build_report(&repo, &args.session, args.format.as_deref(), ctx.json)?;
    // The report is the command's primary output; always print it.
    println!("{report}");
    Ok(())
}

/// Resolve `session_ref`, read its audit events, and render a session report in
/// the chosen format, returning the rendered document.
///
/// Shared by `fida report` and `fida audit export`. The format defaults to
/// `json` when no explicit format is supplied and `prefer_json` is set
/// (honoring the global `--json` flag), otherwise to `markdown`.
///
/// * An unresolved session maps to a generic error -> exit 1.
/// * An unsupported format maps to a generic error -> exit 1;
///   no report is produced in either case.
pub(crate) fn build_report(
    repo: &Path,
    session_ref: &str,
    format: Option<&str>,
    prefer_json: bool,
) -> CliResult<String> {
    // Resolve `latest`/<id>; an unresolved reference is exit 1.
    let session = resolve_session(repo, session_ref)
        .map_err(|e| CliError::general(format!("cannot resolve session: {e}")))?;

    // Choose and validate the format before reading anything; an unsupported
    // format produces no report.
    let format_name = format.unwrap_or(if prefer_json { "json" } else { "markdown" });
    let format = ReportFormat::parse(format_name).map_err(|e| CliError::general(e.to_string()))?;

    // Read every recorded event for the session in append order.
    let store = JsonlAuditStore::new(sessions_root(repo));
    let events = store
        .read(session.as_str())
        .map_err(|e| CliError::general(format!("failed to read audit events: {e}")))?;

    // Render; empty sections are emitted by the generator.
    DefaultReportGenerator::new()
        .render(&events, format)
        .map_err(|e| CliError::general(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};
    use fida_action::{Actor, Decision, MatchedRule, Mode, Risk};
    use fida_audit::{AuditAction, AuditEvent, AuditResult};
    use fida_session::{Baseline, CreateSessionParams, SessionId, create_session};

    fn make_session(repo: &Path) -> SessionId {
        let params = CreateSessionParams {
            repo_path: repo.to_path_buf(),
            git_sha: "deadbeef".to_string(),
            profile: Some("careful".to_string()),
            mode: Mode::Enforce,
            workspace_mode: "current".to_string(),
            agent_command: vec!["codex".to_string()],
            start_time: Utc.with_ymd_and_hms(2026, 6, 12, 7, 0, 0).unwrap(),
            baseline: Baseline {
                head_sha: "deadbeef".to_string(),
                dirty: false,
            },
        };
        create_session(params).unwrap().id
    }

    fn append_command(repo: &Path, session: &SessionId, id: &str, command: &str) {
        let mut store = JsonlAuditStore::new(sessions_root(repo));
        let event = AuditEvent {
            id: id.to_string(),
            session_id: session.as_str().to_string(),
            time: Utc.with_ymd_and_hms(2026, 6, 12, 7, 0, 0).unwrap(),
            actor: Actor::Agent,
            action: AuditAction::CommandRun {
                command: command.to_string(),
            },
            decision: Decision::Allow,
            result: AuditResult::Allowed,
            matched_rule: MatchedRule::NoExplicitRule,
            risk: Risk::Low,
            redacted: false,
            metrics: None,
        };
        store.append(&event).unwrap();
    }

    #[test]
    fn renders_markdown_for_existing_session() {
        let tmp = tempfile::tempdir().unwrap();
        let session = make_session(tmp.path());
        append_command(tmp.path(), &session, "evt_01", "pnpm install");

        let report = build_report(tmp.path(), session.as_str(), Some("markdown"), false).unwrap();
        assert!(report.contains("# Session Report"));
        assert!(report.contains("pnpm install"));
    }

    #[test]
    fn renders_json_when_requested() {
        let tmp = tempfile::tempdir().unwrap();
        let session = make_session(tmp.path());
        append_command(tmp.path(), &session, "evt_01", "pnpm install");

        let report = build_report(tmp.path(), session.as_str(), Some("json"), false).unwrap();
        let v: serde_json::Value = serde_json::from_str(&report).unwrap();
        assert_eq!(v["summary"]["total_events"], 1);
        assert_eq!(v["commands_run"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn latest_reference_resolves() {
        let tmp = tempfile::tempdir().unwrap();
        let session = make_session(tmp.path());
        append_command(tmp.path(), &session, "evt_01", "ls");

        let report = build_report(tmp.path(), "latest", None, false).unwrap();
        assert!(report.contains("# Session Report"));
    }

    #[test]
    fn empty_session_renders_all_sections() {
        let tmp = tempfile::tempdir().unwrap();
        let session = make_session(tmp.path());
        // No events appended (: empty sections still render).
        let report = build_report(tmp.path(), session.as_str(), Some("markdown"), false).unwrap();
        assert!(report.contains("## Commands Run"));
        assert!(report.contains("Total events: 0"));
    }

    #[test]
    fn unresolved_session_is_exit_1() {
        let tmp = tempfile::tempdir().unwrap();
        let err = build_report(tmp.path(), "no-such-session", Some("markdown"), false)
            .expect_err("must fail");
        assert_eq!(err.exit_code(), 1);
    }

    #[test]
    fn unsupported_format_is_exit_1() {
        let tmp = tempfile::tempdir().unwrap();
        let session = make_session(tmp.path());
        let err =
            build_report(tmp.path(), session.as_str(), Some("yaml"), false).expect_err("must fail");
        assert_eq!(err.exit_code(), 1);
    }

    #[test]
    fn prefer_json_defaults_format_to_json() {
        let tmp = tempfile::tempdir().unwrap();
        let session = make_session(tmp.path());
        append_command(tmp.path(), &session, "evt_01", "ls");
        // No explicit format + prefer_json -> JSON output.
        let report = build_report(tmp.path(), session.as_str(), None, true).unwrap();
        assert!(serde_json::from_str::<serde_json::Value>(&report).is_ok());
    }
}
