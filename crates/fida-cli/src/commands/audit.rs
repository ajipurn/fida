//! `fida audit …` — read audit events. **Owner: task 19.7.**
//!
//! Wires the four `audit` subcommands to the append-only Audit_Store:
//!
//! * `tail` — print the latest session's events in append order, then follow,
//!   surfacing each newly appended event well within the 2-second budget. The
//!   follow loop polls every 500 ms; it is the only unbounded
//!   path and is guarded so tests exercise the pure [`new_matching_events`]
//!   helper and the `FIDA_TAIL_ONCE` single-pass mode instead.
//! * `list` — print the latest session's events, optionally narrowed by
//!   `--kind`/`--decision`/`--risk`/`--since`; an unrecognized filter value is
//!   exit 1 with no events, and zero matches print nothing and
//!   succeed.
//! * `show <event-id>` — print every field of the identified event in the
//!   latest session, or exit 1 when no such event exists.
//! * `export <session> --format <fmt>` — render the session's events through
//!   the Report_Generator, reusing [`crate::commands::report::build_report`].

use std::path::{Path, PathBuf};
use std::time::Duration;

use chrono::{DateTime, Utc};
use clap::{Args, Subcommand};

use fida_action::{ActionKind, Actor, Decision, Protocol, Risk};
use fida_audit::{AuditAction, AuditEvent, AuditFilter, AuditStore, JsonlAuditStore};
use fida_session::{SessionId, parse_duration, resolve_session, sessions_root};

use crate::commands::report::build_report;
use crate::context::GlobalContext;
use crate::error::{CliError, CliResult};

/// Arguments for the `fida audit` command family.
#[derive(Debug, Args)]
pub struct AuditArgs {
    #[command(subcommand)]
    pub command: AuditCommand,
}

/// `fida audit` subcommands.
#[derive(Debug, Subcommand)]
pub enum AuditCommand {
    /// Follow latest session events.
    Tail(FilterArgs),
    /// List audit events with optional filters.
    List(FilterArgs),
    /// Show one event by id.
    Show(ShowArgs),
    /// Export events for a session.
    Export(ExportArgs),
}

/// Shared event filters.
#[derive(Debug, Args)]
pub struct FilterArgs {
    /// Filter by action kind, e.g. `command.run`.
    #[arg(long)]
    pub kind: Option<String>,
    /// Filter by decision, e.g. `deny`.
    #[arg(long)]
    pub decision: Option<String>,
    /// Filter by risk label, e.g. `high`.
    #[arg(long)]
    pub risk: Option<String>,
    /// Only events newer than this relative time, e.g. `1h`.
    #[arg(long)]
    pub since: Option<String>,
}

/// `fida audit show <event-id>`.
#[derive(Debug, Args)]
pub struct ShowArgs {
    /// The audit event id.
    pub event_id: String,
}

/// `fida audit export <session-id> --format <fmt>`.
#[derive(Debug, Args)]
pub struct ExportArgs {
    /// Session id, or `latest`.
    #[arg(default_value = "latest")]
    pub session: String,
    /// Output format, e.g. `json`.
    #[arg(long)]
    pub format: Option<String>,
}

/// Dispatch the `audit` subcommands (task 19.7).
pub async fn run(args: &AuditArgs, ctx: &GlobalContext) -> CliResult {
    let repo = PathBuf::from(".");
    match &args.command {
        AuditCommand::Tail(filter) => run_tail(&repo, filter, ctx).await,
        AuditCommand::List(filter) => run_list(&repo, filter, ctx),
        AuditCommand::Show(show) => run_show(&repo, show, ctx),
        AuditCommand::Export(export) => run_export(&repo, export, ctx),
    }
}

// ---------------------------------------------------------------------------
// list
// ---------------------------------------------------------------------------

fn run_list(repo: &Path, args: &FilterArgs, ctx: &GlobalContext) -> CliResult {
    let events = list_events(repo, args)?;
    emit_events(&events, ctx);
    Ok(())
}

/// Resolve the latest session, apply the (validated) filters, and return its
/// matching events in append order. An invalid filter value is exit 1 and
/// yields no events; zero matches is success with an empty vec.
fn list_events(repo: &Path, args: &FilterArgs) -> CliResult<Vec<AuditEvent>> {
    let session = resolve_latest(repo)?;
    let filter = build_filter(args)?;
    let store = store_for(repo);
    store.filter(session.as_str(), &filter).map_err(read_error)
}

// ---------------------------------------------------------------------------
// tail
// ---------------------------------------------------------------------------

async fn run_tail(repo: &Path, args: &FilterArgs, ctx: &GlobalContext) -> CliResult {
    let session = resolve_latest(repo)?;
    let filter = build_filter(args)?;
    let store = store_for(repo);
    let session_id = session.as_str().to_string();

    // Initial pass: print everything recorded so far, in append order.
    let mut all = store.read(&session_id).map_err(read_error)?;
    emit_events(&new_matching_events(&all, 0, &filter), ctx);
    let mut seen = all.len();

    // `FIDA_TAIL_ONCE` makes this a single bounded pass (the initial read
    // above) so the harness never blocks on the infinite follow loop.
    if std::env::var_os("FIDA_TAIL_ONCE").is_some() {
        return Ok(());
    }

    // Follow newly appended events. The 500 ms poll keeps display latency well
    // under the 2 s budget. This loop runs until the process is
    // interrupted, mirroring `tail -f`.
    loop {
        tokio::time::sleep(Duration::from_millis(500)).await;
        all = store.read(&session_id).map_err(read_error)?;
        if all.len() > seen {
            emit_events(&new_matching_events(&all, seen, &filter), ctx);
            seen = all.len();
        }
    }
}

/// Return the events at index `>= already_seen` that match `filter`, preserving
/// append order. Pure, so the follow loop's per-tick behavior is unit-testable
/// without the unbounded `tail` path.
fn new_matching_events(
    all: &[AuditEvent],
    already_seen: usize,
    filter: &AuditFilter,
) -> Vec<AuditEvent> {
    all.iter()
        .skip(already_seen)
        .filter(|e| filter.matches(e))
        .cloned()
        .collect()
}

// ---------------------------------------------------------------------------
// show
// ---------------------------------------------------------------------------

fn run_show(repo: &Path, args: &ShowArgs, ctx: &GlobalContext) -> CliResult {
    let event = find_event(repo, &args.event_id)?;
    emit_single_event(&event, ctx);
    Ok(())
}

/// Find an event by id in the latest session, or exit 1 when none matches.
fn find_event(repo: &Path, event_id: &str) -> CliResult<AuditEvent> {
    let session = resolve_latest(repo)?;
    let store = store_for(repo);
    let events = store.read(session.as_str()).map_err(read_error)?;
    events
        .into_iter()
        .find(|e| e.id == event_id)
        .ok_or_else(|| CliError::general(format!("audit event '{event_id}' not found")))
}

// ---------------------------------------------------------------------------
// export
// ---------------------------------------------------------------------------

fn run_export(repo: &Path, args: &ExportArgs, ctx: &GlobalContext) -> CliResult {
    // Reuse the shared report builder: resolve the session, read its events,
    // and render in the requested format (default markdown, or json under
    // `--json`). Unresolved session / unsupported format -> exit 1.
    let report = build_report(repo, &args.session, args.format.as_deref(), ctx.json)?;
    println!("{report}");
    Ok(())
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// The Audit_Store rooted at `repo`'s `.fida/sessions`.
fn store_for(repo: &Path) -> JsonlAuditStore {
    JsonlAuditStore::new(sessions_root(repo))
}

/// Resolve the most recently started session, mapping an unresolved reference
/// (e.g. no sessions yet) to exit 1.
fn resolve_latest(repo: &Path) -> CliResult<SessionId> {
    resolve_session(repo, "latest")
        .map_err(|e| CliError::general(format!("cannot resolve latest session: {e}")))
}

/// Map an Audit_Store read failure to a generic error (exit 1).
fn read_error(err: std::io::Error) -> CliError {
    CliError::general(format!("failed to read audit events: {err}"))
}

/// Build an [`AuditFilter`] from the CLI strings, rejecting any unrecognized
/// value with exit 1.
fn build_filter(args: &FilterArgs) -> CliResult<AuditFilter> {
    Ok(AuditFilter {
        kind: parse_opt(args.kind.as_deref(), parse_kind)?,
        decision: parse_opt(args.decision.as_deref(), parse_decision)?,
        risk: parse_opt(args.risk.as_deref(), parse_risk)?,
        since: parse_opt(args.since.as_deref(), parse_since)?,
    })
}

/// Apply `parse` to an optional string, threading the parse error outward.
fn parse_opt<T>(value: Option<&str>, parse: impl Fn(&str) -> CliResult<T>) -> CliResult<Option<T>> {
    value.map(parse).transpose()
}

/// Parse `--kind` against the dotted action-kind names (`command.run`, …).
fn parse_kind(s: &str) -> CliResult<ActionKind> {
    serde_json::from_value(serde_json::Value::String(s.to_string()))
        .map_err(|_| CliError::general(format!("invalid --kind value '{s}'")))
}

/// Parse `--decision` (`allow`/`ask`/`deny`/`dry_run`).
fn parse_decision(s: &str) -> CliResult<Decision> {
    serde_json::from_value(serde_json::Value::String(s.to_string()))
        .map_err(|_| CliError::general(format!("invalid --decision value '{s}'")))
}

/// Parse `--risk` (`low`/`medium`/`high`).
fn parse_risk(s: &str) -> CliResult<Risk> {
    serde_json::from_value(serde_json::Value::String(s.to_string()))
        .map_err(|_| CliError::general(format!("invalid --risk value '{s}'")))
}

/// Parse `--since` as either a relative duration (`1h`, `30m`, reusing the
/// session duration parser) subtracted from now, or an absolute RFC-3339
/// timestamp. Anything else is exit 1.
fn parse_since(s: &str) -> CliResult<DateTime<Utc>> {
    if let Ok(duration) = parse_duration(s) {
        return Ok(Utc::now() - duration);
    }
    DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|_| CliError::general(format!("invalid --since value '{s}'")))
}

// ---------------------------------------------------------------------------
// Output (honors --json / --quiet)
// ---------------------------------------------------------------------------

/// Print a list of events. JSON mode emits a single JSON array; text mode emits
/// one line per event in append order.
fn emit_events(events: &[AuditEvent], ctx: &GlobalContext) {
    if ctx.json {
        // A machine-readable array of the full event records.
        match serde_json::to_string_pretty(events) {
            Ok(json) => println!("{json}"),
            Err(e) => eprintln!("fida: failed to serialize events: {e}"),
        }
        return;
    }
    for event in events {
        println!("{}", event_line(event));
    }
}

/// Print every recorded field of a single event. JSON mode emits the
/// full record; text mode emits a labeled block.
fn emit_single_event(event: &AuditEvent, ctx: &GlobalContext) {
    if ctx.json {
        match serde_json::to_string_pretty(event) {
            Ok(json) => println!("{json}"),
            Err(e) => eprintln!("fida: failed to serialize event: {e}"),
        }
        return;
    }
    println!("id:           {}", event.id);
    println!("session_id:   {}", event.session_id);
    println!("time:         {}", event.time.to_rfc3339());
    println!("actor:        {}", actor_name(event.actor));
    println!("action:       {}", describe_action(&event.action));
    println!("decision:     {}", decision_name(event.decision));
    println!("result:       {}", result_name(event.result));
    println!("matched_rule: {}", event.matched_rule.as_str());
    println!("risk:         {}", risk_name(event.risk));
    println!("redacted:     {}", event.redacted);
}

/// A compact one-line summary of an event for `audit list` / `audit tail`.
fn event_line(event: &AuditEvent) -> String {
    format!(
        "{time}  {id}  {actor}  {action}  {decision}  {risk}  rule={rule}{redacted}",
        time = event.time.to_rfc3339(),
        id = event.id,
        actor = actor_name(event.actor),
        action = describe_action(&event.action),
        decision = decision_name(event.decision),
        risk = risk_name(event.risk),
        rule = event.matched_rule.as_str(),
        redacted = if event.redacted { "  [redacted]" } else { "" },
    )
}

/// A redaction-safe one-line description of an action, reusing only the fields
/// the event already persists.
fn describe_action(action: &AuditAction) -> String {
    match action {
        AuditAction::CommandRun { command } => format!("command.run: {command}"),
        AuditAction::CommandOutput { stream, .. } => format!("command.output(): {stream}"),
        AuditAction::CommandRedactionFailure { stream } => {
            format!("command.redaction_failure: {stream}")
        }
        AuditAction::FileRead { path } => format!("file.read: {path}"),
        AuditAction::FileWrite { path } => format!("file.write: {path}"),
        AuditAction::FileDelete { path } => format!("file.delete: {path}"),
        AuditAction::NetworkRequest {
            domain,
            host,
            protocol,
        } => {
            let dest = domain.as_deref().unwrap_or(host.as_str());
            format!("network.request: {} {dest}", protocol_name(*protocol))
        }
        AuditAction::McpToolCall { tool } => format!("mcp.tool_call: {tool}"),
        AuditAction::SecretDetected { pattern_id, reason } => {
            format!("secret.detected: {pattern_id} ({reason})")
        }
        AuditAction::SessionApplyChanges => "session.apply_changes".to_string(),
    }
}

fn actor_name(actor: Actor) -> &'static str {
    match actor {
        Actor::Agent => "agent",
        Actor::User => "user",
    }
}

fn decision_name(decision: Decision) -> &'static str {
    match decision {
        Decision::Allow => "allow",
        Decision::Ask => "ask",
        Decision::Deny => "deny",
        Decision::DryRun => "dry_run",
    }
}

fn risk_name(risk: Risk) -> &'static str {
    match risk {
        Risk::Low => "low",
        Risk::Medium => "medium",
        Risk::High => "high",
    }
}

fn protocol_name(protocol: Protocol) -> &'static str {
    match protocol {
        Protocol::Http => "http",
        Protocol::Https => "https",
    }
}

fn result_name(result: fida_audit::AuditResult) -> &'static str {
    use fida_audit::AuditResult::*;
    match result {
        Allowed => "allowed",
        AllowedOnce => "allowed_once",
        AllowedRemembered => "allowed_remembered",
        Denied => "denied",
        Blocked => "blocked",
        WouldRun => "would_run",
        TimedOut => "timed_out",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use fida_action::{MatchedRule, Mode};
    use fida_audit::AuditResult;
    use fida_session::{Baseline, CreateSessionParams, create_session};

    fn ts(h: u32, m: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 6, 12, h, m, 0).unwrap()
    }

    fn make_session(repo: &Path) -> SessionId {
        let params = CreateSessionParams {
            repo_path: repo.to_path_buf(),
            git_sha: "deadbeef".to_string(),
            profile: Some("careful".to_string()),
            mode: Mode::Enforce,
            workspace_mode: "current".to_string(),
            agent_command: vec!["codex".to_string()],
            start_time: ts(7, 0),
            baseline: Baseline {
                head_sha: "deadbeef".to_string(),
                dirty: false,
            },
        };
        create_session(params).unwrap().id
    }

    fn event(id: &str, session: &SessionId, time: DateTime<Utc>) -> AuditEvent {
        AuditEvent {
            id: id.to_string(),
            session_id: session.as_str().to_string(),
            time,
            actor: Actor::Agent,
            action: AuditAction::CommandRun {
                command: "echo hi".to_string(),
            },
            decision: Decision::Allow,
            result: AuditResult::Allowed,
            matched_rule: MatchedRule::NoExplicitRule,
            risk: Risk::Low,
            redacted: false,
            metrics: None,
        }
    }

    fn append(repo: &Path, e: &AuditEvent) {
        JsonlAuditStore::new(sessions_root(repo)).append(e).unwrap();
    }

    fn no_filter() -> FilterArgs {
        FilterArgs {
            kind: None,
            decision: None,
            risk: None,
            since: None,
        }
    }

    // --- filter parsing ---

    #[test]
    fn parses_valid_filter_values() {
        assert_eq!(parse_kind("command.run").unwrap(), ActionKind::CommandRun);
        assert_eq!(
            parse_kind("network.request").unwrap(),
            ActionKind::NetworkRequest
        );
        assert_eq!(parse_decision("deny").unwrap(), Decision::Deny);
        assert_eq!(parse_decision("dry_run").unwrap(), Decision::DryRun);
        assert_eq!(parse_risk("high").unwrap(), Risk::High);
    }

    #[test]
    fn rejects_invalid_filter_values_as_exit_1() {
        for err in [
            parse_kind("command.bogus").unwrap_err(),
            parse_decision("maybe").unwrap_err(),
            parse_risk("extreme").unwrap_err(),
            parse_since("not-a-time").unwrap_err(),
        ] {
            assert_eq!(err.exit_code(), 1);
        }
    }

    #[test]
    fn since_accepts_relative_and_iso() {
        // Relative: resolves to slightly before now.
        let rel = parse_since("1h").unwrap();
        assert!(rel < Utc::now());
        // Absolute RFC-3339.
        let abs = parse_since("2026-06-12T07:00:00Z").unwrap();
        assert_eq!(abs, ts(7, 0));
    }

    #[test]
    fn build_filter_rejects_one_bad_value() {
        let args = FilterArgs {
            kind: Some("command.run".to_string()),
            decision: Some("nope".to_string()),
            risk: None,
            since: None,
        };
        assert_eq!(build_filter(&args).unwrap_err().exit_code(), 1);
    }

    // --- list ---

    #[test]
    fn list_returns_latest_session_events_in_order() {
        let tmp = tempfile::tempdir().unwrap();
        let session = make_session(tmp.path());
        append(tmp.path(), &event("evt_01", &session, ts(7, 0)));
        append(tmp.path(), &event("evt_02", &session, ts(7, 1)));

        let events = list_events(tmp.path(), &no_filter()).unwrap();
        let ids: Vec<_> = events.iter().map(|e| e.id.as_str()).collect();
        assert_eq!(ids, vec!["evt_01", "evt_02"]);
    }

    #[test]
    fn list_applies_filters_and_semantics() {
        let tmp = tempfile::tempdir().unwrap();
        let session = make_session(tmp.path());
        let allow = event("evt_allow", &session, ts(7, 0));
        let mut deny = event("evt_deny", &session, ts(8, 0));
        deny.decision = Decision::Deny;
        deny.risk = Risk::High;
        append(tmp.path(), &allow);
        append(tmp.path(), &deny);

        let args = FilterArgs {
            kind: None,
            decision: Some("deny".to_string()),
            risk: Some("high".to_string()),
            since: None,
        };
        let events = list_events(tmp.path(), &args).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].id, "evt_deny");
    }

    #[test]
    fn list_zero_matches_is_success() {
        let tmp = tempfile::tempdir().unwrap();
        let session = make_session(tmp.path());
        append(tmp.path(), &event("evt_01", &session, ts(7, 0)));

        let args = FilterArgs {
            kind: None,
            decision: Some("deny".to_string()),
            risk: None,
            since: None,
        };
        let events = list_events(tmp.path(), &args).unwrap();
        assert!(events.is_empty());
    }

    #[test]
    fn list_invalid_filter_is_exit_1() {
        let tmp = tempfile::tempdir().unwrap();
        let session = make_session(tmp.path());
        append(tmp.path(), &event("evt_01", &session, ts(7, 0)));

        let args = FilterArgs {
            kind: Some("command.bogus".to_string()),
            decision: None,
            risk: None,
            since: None,
        };
        assert_eq!(list_events(tmp.path(), &args).unwrap_err().exit_code(), 1);
    }

    #[test]
    fn list_with_no_sessions_is_exit_1() {
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(
            list_events(tmp.path(), &no_filter())
                .unwrap_err()
                .exit_code(),
            1
        );
    }

    // --- show ---

    #[test]
    fn show_finds_event_by_id() {
        let tmp = tempfile::tempdir().unwrap();
        let session = make_session(tmp.path());
        append(tmp.path(), &event("evt_01", &session, ts(7, 0)));
        append(tmp.path(), &event("evt_02", &session, ts(7, 1)));

        let found = find_event(tmp.path(), "evt_02").unwrap();
        assert_eq!(found.id, "evt_02");
    }

    #[test]
    fn show_unknown_event_is_exit_1() {
        let tmp = tempfile::tempdir().unwrap();
        let session = make_session(tmp.path());
        append(tmp.path(), &event("evt_01", &session, ts(7, 0)));

        let err = find_event(tmp.path(), "evt_missing").unwrap_err();
        assert_eq!(err.exit_code(), 1);
    }

    // --- tail ---

    #[test]
    fn new_matching_events_returns_only_appended_tail() {
        let tmp = tempfile::tempdir().unwrap();
        let session = make_session(tmp.path());
        let all = vec![
            event("evt_01", &session, ts(7, 0)),
            event("evt_02", &session, ts(7, 1)),
            event("evt_03", &session, ts(7, 2)),
        ];
        let fresh = new_matching_events(&all, 1, &AuditFilter::default());
        let ids: Vec<_> = fresh.iter().map(|e| e.id.as_str()).collect();
        assert_eq!(ids, vec!["evt_02", "evt_03"]);
    }

    #[test]
    fn new_matching_events_honors_filter() {
        let session = SessionId::from_existing("s1");
        let mut deny = event("evt_deny", &session, ts(7, 1));
        deny.decision = Decision::Deny;
        let all = vec![event("evt_allow", &session, ts(7, 0)), deny];

        let filter = AuditFilter {
            decision: Some(Decision::Deny),
            ..Default::default()
        };
        let fresh = new_matching_events(&all, 0, &filter);
        assert_eq!(fresh.len(), 1);
        assert_eq!(fresh[0].id, "evt_deny");
    }

    #[test]
    fn tail_single_pass_with_guard_does_not_block() {
        // The `FIDA_TAIL_ONCE` guard makes the follow loop a single bounded
        // pass so the harness never hangs.
        // SAFETY: this test is the only code in the workspace that mutates
        // FIDA_TAIL_ONCE, and it restores the variable before returning.
        unsafe { std::env::set_var("FIDA_TAIL_ONCE", "1") };
        let tmp = tempfile::tempdir().unwrap();
        let session = make_session(tmp.path());
        append(tmp.path(), &event("evt_01", &session, ts(7, 0)));

        let ctx = GlobalContext {
            json: false,
            no_color: true,
            verbosity: crate::context::Verbosity::Normal,
            config: None,
        };
        let result = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(run_tail(tmp.path(), &no_filter(), &ctx));
        // SAFETY: paired with the unique test-only mutation above.
        unsafe { std::env::remove_var("FIDA_TAIL_ONCE") };
        assert!(result.is_ok());
    }

    // --- output formatting ---

    #[test]
    fn event_line_is_redaction_safe_and_compact() {
        let session = SessionId::from_existing("s1");
        let mut e = event("evt_01", &session, ts(7, 0));
        e.action = AuditAction::SecretDetected {
            pattern_id: "aws_key".to_string(),
            reason: "matched".to_string(),
        };
        e.redacted = true;
        let line = event_line(&e);
        assert!(line.contains("evt_01"));
        assert!(line.contains("secret.detected: aws_key"));
        assert!(line.contains("[redacted]"));
    }
}
