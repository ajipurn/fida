//! Session lifecycle, listing, and resolution helpers (spec task 8.2).
//!
//! Builds on the foundations from task 8.1 (ids, directory layout, metadata)
//! to provide the read-side and maintenance operations the `session`
//! subcommands wire up in task 19.6:
//!
//! - [`list_sessions`] — every recorded session, newest-first.
//! - [`latest`] / [`resolve_session`] — resolve `latest` (most recent start)
//!   and reject references that do not name an existing session.
//! - [`session_summary`] — recorded metadata plus per-decision-state counts
//!   read from `events.jsonl`.
//! - [`session_diff`] — the recorded patch for a session.
//! - [`parse_export_format`] — accept only `markdown`/`json`.
//! - [`parse_duration`] / [`clean_older_than`] — parse a `<n><s|m|h|d>`
//!   duration and remove session directories older than it.
//!
//! All on-disk reads are tolerant of unrelated entries in the sessions root:
//! directory entries that do not contain a readable `session.json` are not
//! treated as sessions, while a `session.json` that exists but fails to parse
//! surfaces as a [`SessionError::Serialize`] error.

use std::collections::BTreeMap;
use std::path::Path;

use chrono::{DateTime, Duration, Utc};
use fida_action::Decision;
use fida_audit::AuditEvent;

use crate::{
    SESSION_DIFF_FILE, SESSION_EVENTS_FILE, SessionError, SessionId, SessionMetadata, session_dir,
    session_metadata_path, sessions_root,
};

// ---------------------------------------------------------------------------
// Listing and resolution
// ---------------------------------------------------------------------------

/// Read and return the metadata of every recorded session under `repo`,
/// ordered from most recently started to least recently started.
///
/// When the sessions root does not exist or contains no sessions, an empty
/// vector is returned — this is a success, not an error.
/// Ordering is by start time descending; ties break on the (sortable) session
/// id descending so the result is deterministic.
pub fn list_sessions(repo: &Path) -> Result<Vec<SessionMetadata>, SessionError> {
    let root = sessions_root(repo);
    let entries = match std::fs::read_dir(&root) {
        Ok(entries) => entries,
        // A missing sessions root simply means no sessions exist yet.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(SessionError::Io(e)),
    };

    let mut sessions = Vec::new();
    for entry in entries {
        let entry = entry.map_err(SessionError::Io)?;
        if !entry.file_type().map_err(SessionError::Io)?.is_dir() {
            continue;
        }
        let id = SessionId::from_existing(entry.file_name().to_string_lossy().into_owned());
        let meta_path = session_metadata_path(repo, &id);
        // Skip directory entries that are not sessions (no metadata file).
        if !meta_path.is_file() {
            continue;
        }
        sessions.push(read_metadata(repo, &id)?);
    }

    sessions.sort_by(|a, b| {
        b.start_time
            .cmp(&a.start_time)
            .then_with(|| b.session_id.cmp(&a.session_id))
    });
    Ok(sessions)
}

/// Resolve `latest` to the session with the most recent start time, or `None`
/// when no sessions are recorded.
pub fn latest(repo: &Path) -> Result<Option<SessionId>, SessionError> {
    Ok(list_sessions(repo)?
        .into_iter()
        .next()
        .map(|m| m.session_id))
}

/// Resolve a user-supplied session reference to a concrete [`SessionId`].
///
/// The reference `"latest"` resolves to the most recently started session; any
/// other value is treated as a session id and must name an existing session. A
/// reference that cannot be resolved yields [`SessionError::SessionNotFound`].
pub fn resolve_session(repo: &Path, reference: &str) -> Result<SessionId, SessionError> {
    if reference == "latest" {
        return latest(repo)?.ok_or_else(|| SessionError::SessionNotFound(reference.to_string()));
    }

    let id = SessionId::from_existing(reference);
    if session_metadata_path(repo, &id).is_file() {
        Ok(id)
    } else {
        Err(SessionError::SessionNotFound(reference.to_string()))
    }
}

/// Read a single session's metadata, mapping a missing session to
/// [`SessionError::SessionNotFound`].
fn read_metadata(repo: &Path, id: &SessionId) -> Result<SessionMetadata, SessionError> {
    let path = session_metadata_path(repo, id);
    let raw = match std::fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(SessionError::SessionNotFound(id.as_str().to_string()));
        }
        Err(e) => return Err(SessionError::Io(e)),
    };
    serde_json::from_str(&raw).map_err(SessionError::Serialize)
}

// ---------------------------------------------------------------------------
// Summary (per-decision-state counts)
// ---------------------------------------------------------------------------

/// The count of resolved actions in a session grouped by decision state.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DecisionCounts {
    /// Actions resolved to `allow`.
    pub allow: usize,
    /// Actions resolved to `ask`.
    pub ask: usize,
    /// Actions resolved to `deny`.
    pub deny: usize,
    /// Actions resolved to `dry_run`.
    pub dry_run: usize,
}

impl DecisionCounts {
    /// Total number of recorded decisions across all states.
    pub fn total(&self) -> usize {
        self.allow + self.ask + self.deny + self.dry_run
    }

    fn record(&mut self, decision: Decision) {
        match decision {
            Decision::Allow => self.allow += 1,
            Decision::Ask => self.ask += 1,
            Decision::Deny => self.deny += 1,
            Decision::DryRun => self.dry_run += 1,
        }
    }
}

/// A session's recorded metadata together with its per-decision-state counts,
/// as displayed by `fida session show`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionSummary {
    /// The session's recorded metadata.
    pub metadata: SessionMetadata,
    /// Counts of resolved actions grouped by decision state.
    pub decision_counts: DecisionCounts,
}

/// Build the summary for `id`: its metadata plus a count of decisions per
/// decision state, computed from the session's `events.jsonl`.
///
/// An unresolved session yields [`SessionError::SessionNotFound`]. A session
/// with no audit log yet (no `events.jsonl`) reports all-zero counts.
pub fn session_summary(repo: &Path, id: &SessionId) -> Result<SessionSummary, SessionError> {
    let metadata = read_metadata(repo, id)?;
    let decision_counts = decision_counts(repo, id)?;
    Ok(SessionSummary {
        metadata,
        decision_counts,
    })
}

/// Count the resolved decisions recorded in a session's `events.jsonl`.
fn decision_counts(repo: &Path, id: &SessionId) -> Result<DecisionCounts, SessionError> {
    let path = session_dir(repo, id).join(SESSION_EVENTS_FILE);
    let raw = match std::fs::read_to_string(&path) {
        Ok(raw) => raw,
        // No audit log yet: zero decisions recorded.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(DecisionCounts::default()),
        Err(e) => return Err(SessionError::Io(e)),
    };

    let mut counts = DecisionCounts::default();
    for line in raw.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let event: AuditEvent = serde_json::from_str(line).map_err(SessionError::Serialize)?;
        counts.record(event.decision);
    }
    Ok(counts)
}

// ---------------------------------------------------------------------------
// Diff retrieval
// ---------------------------------------------------------------------------

/// Return the patch recorded for a session (`diff.patch`), as displayed by
/// `fida session diff`.
///
/// An unresolved session yields [`SessionError::SessionNotFound`]. A session
/// that recorded no diff returns an empty string.
pub fn session_diff(repo: &Path, id: &SessionId) -> Result<String, SessionError> {
    // Confirm the session exists before reporting on its diff.
    if !session_metadata_path(repo, id).is_file() {
        return Err(SessionError::SessionNotFound(id.as_str().to_string()));
    }

    let path = session_dir(repo, id).join(SESSION_DIFF_FILE);
    match std::fs::read_to_string(&path) {
        Ok(patch) => Ok(patch),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(e) => Err(SessionError::Io(e)),
    }
}

// ---------------------------------------------------------------------------
// Export format gating
// ---------------------------------------------------------------------------

/// A supported session export/report format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    /// Human-readable markdown.
    Markdown,
    /// Machine-readable JSON.
    Json,
}

impl ExportFormat {
    /// The canonical lowercase name of the format.
    pub fn as_str(&self) -> &'static str {
        match self {
            ExportFormat::Markdown => "markdown",
            ExportFormat::Json => "json",
        }
    }
}

/// Parse and gate an export format, accepting only `markdown` or `json` and
/// rejecting anything else with [`SessionError::UnsupportedFormat`].
pub fn parse_export_format(format: &str) -> Result<ExportFormat, SessionError> {
    match format {
        "markdown" => Ok(ExportFormat::Markdown),
        "json" => Ok(ExportFormat::Json),
        other => Err(SessionError::UnsupportedFormat(other.to_string())),
    }
}

// ---------------------------------------------------------------------------
// Duration parsing and cleanup
// ---------------------------------------------------------------------------

/// Parse a `--older-than` duration: a positive integer followed by one of the
/// unit suffixes `s` (seconds), `m` (minutes), `h` (hours), or `d` (days).
///
/// Any other shape — empty input, a non-positive or non-integer count, a
/// missing or unknown unit, or an overflowing value — yields
/// [`SessionError::InvalidDuration`].
pub fn parse_duration(input: &str) -> Result<Duration, SessionError> {
    let invalid = || SessionError::InvalidDuration(input.to_string());

    // Split into the leading digit run and the unit suffix. The string must be
    // exactly `<digits><unit>` with no surrounding whitespace or sign.
    let split = input
        .char_indices()
        .find(|(_, c)| !c.is_ascii_digit())
        .map(|(i, _)| i);
    let (digits, unit) = match split {
        Some(i) => input.split_at(i),
        // No non-digit char found: a unit suffix is required.
        None => return Err(invalid()),
    };

    if digits.is_empty() {
        return Err(invalid());
    }
    let value: i64 = digits.parse().map_err(|_| invalid())?;
    if value <= 0 {
        return Err(invalid());
    }

    match unit {
        "s" => Duration::try_seconds(value),
        "m" => Duration::try_minutes(value),
        "h" => Duration::try_hours(value),
        "d" => Duration::try_days(value),
        _ => return Err(invalid()),
    }
    .ok_or_else(invalid)
}

/// Remove every session directory whose start time is older than `duration`
/// before `now`, returning the ids of the removed sessions sorted ascending.
///
/// A session is removed when `start_time < now - duration`; sessions exactly at
/// or after the threshold are kept. On an invalid policy nothing is removed and
/// the error is returned before any deletion; [`parse_duration`] enforces this
/// at the call site.
pub fn clean_older_than(
    repo: &Path,
    duration: Duration,
    now: DateTime<Utc>,
) -> Result<Vec<SessionId>, SessionError> {
    let threshold = now - duration;

    // Resolve every session up front so a read failure aborts before any
    // directory is removed.
    let sessions = list_sessions(repo)?;
    let mut removed = BTreeMap::new();
    for metadata in sessions {
        if metadata.start_time < threshold {
            let id = metadata.session_id.clone();
            std::fs::remove_dir_all(session_dir(repo, &id)).map_err(SessionError::Io)?;
            removed.insert(id.as_str().to_string(), id);
        }
    }
    Ok(removed.into_values().collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Baseline, CreateSessionParams, SESSION_METADATA_FILE, create_session};
    use chrono::TimeZone;
    use fida_action::Mode;
    use std::path::Path;

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
            baseline: Baseline {
                head_sha: "deadbeef".to_string(),
                dirty: false,
            },
        };
        create_session(params).unwrap().id
    }

    fn write_events(repo: &Path, id: &SessionId, decisions: &[&str]) {
        let mut lines = String::new();
        for (i, decision) in decisions.iter().enumerate() {
            lines.push_str(&format!(
                r#"{{"id":"evt_{i}","session_id":"{sid}","time":"2026-06-12T07:00:0{i}Z","actor":"agent","action":{{"kind":"command.run","command":"echo hi"}},"decision":"{decision}","result":"allowed","matched_rule":"none","risk":"low","redacted":false}}"#,
                i = i,
                sid = id.as_str(),
                decision = decision,
            ));
            lines.push('\n');
        }
        std::fs::write(session_dir(repo, id).join(SESSION_EVENTS_FILE), lines).unwrap();
    }

    // --- listing & resolution ---

    #[test]
    fn listing_empty_repo_returns_ok_empty() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(list_sessions(tmp.path()).unwrap().is_empty());
        assert_eq!(latest(tmp.path()).unwrap(), None);
    }

    #[test]
    fn listing_orders_newest_first() {
        let tmp = tempfile::tempdir().unwrap();
        let older = make_session(tmp.path(), ts(2026, 6, 12, 7, 0, 0), "a");
        let newer = make_session(tmp.path(), ts(2026, 6, 12, 8, 0, 0), "b");
        let middle = make_session(tmp.path(), ts(2026, 6, 12, 7, 30, 0), "c");

        let ids: Vec<_> = list_sessions(tmp.path())
            .unwrap()
            .into_iter()
            .map(|m| m.session_id)
            .collect();
        assert_eq!(ids, vec![newer, middle, older]);
    }

    #[test]
    fn listing_skips_non_session_directories() {
        let tmp = tempfile::tempdir().unwrap();
        make_session(tmp.path(), ts(2026, 6, 12, 7, 0, 0), "a");
        // A stray directory without session.json must be ignored.
        std::fs::create_dir_all(sessions_root(tmp.path()).join("not-a-session")).unwrap();

        assert_eq!(list_sessions(tmp.path()).unwrap().len(), 1);
    }

    #[test]
    fn latest_resolves_to_most_recent_start() {
        let tmp = tempfile::tempdir().unwrap();
        make_session(tmp.path(), ts(2026, 6, 12, 7, 0, 0), "a");
        let newer = make_session(tmp.path(), ts(2026, 6, 12, 9, 0, 0), "b");

        assert_eq!(latest(tmp.path()).unwrap(), Some(newer.clone()));
        assert_eq!(resolve_session(tmp.path(), "latest").unwrap(), newer);
    }

    #[test]
    fn resolve_existing_id_succeeds() {
        let tmp = tempfile::tempdir().unwrap();
        let id = make_session(tmp.path(), ts(2026, 6, 12, 7, 0, 0), "a");
        assert_eq!(resolve_session(tmp.path(), id.as_str()).unwrap(), id);
    }

    #[test]
    fn resolve_unknown_session_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let err = resolve_session(tmp.path(), "does-not-exist").unwrap_err();
        assert!(matches!(err, SessionError::SessionNotFound(r) if r == "does-not-exist"));
    }

    #[test]
    fn resolve_latest_with_no_sessions_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let err = resolve_session(tmp.path(), "latest").unwrap_err();
        assert!(matches!(err, SessionError::SessionNotFound(_)));
    }

    // --- summary / decision counts ---

    #[test]
    fn summary_counts_decisions_per_state() {
        let tmp = tempfile::tempdir().unwrap();
        let id = make_session(tmp.path(), ts(2026, 6, 12, 7, 0, 0), "careful");
        write_events(
            tmp.path(),
            &id,
            &["allow", "allow", "ask", "deny", "dry_run", "deny"],
        );

        let summary = session_summary(tmp.path(), &id).unwrap();
        assert_eq!(summary.metadata.profile.as_deref(), Some("careful"));
        assert_eq!(
            summary.decision_counts,
            DecisionCounts {
                allow: 2,
                ask: 1,
                deny: 2,
                dry_run: 1,
            }
        );
        assert_eq!(summary.decision_counts.total(), 6);
    }

    #[test]
    fn summary_with_no_events_reports_zero_counts() {
        let tmp = tempfile::tempdir().unwrap();
        let id = make_session(tmp.path(), ts(2026, 6, 12, 7, 0, 0), "a");
        let summary = session_summary(tmp.path(), &id).unwrap();
        assert_eq!(summary.decision_counts, DecisionCounts::default());
    }

    #[test]
    fn summary_of_unknown_session_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let err = session_summary(tmp.path(), &SessionId::from_existing("nope")).unwrap_err();
        assert!(matches!(err, SessionError::SessionNotFound(_)));
    }

    // --- diff retrieval ---

    #[test]
    fn diff_returns_recorded_patch() {
        let tmp = tempfile::tempdir().unwrap();
        let id = make_session(tmp.path(), ts(2026, 6, 12, 7, 0, 0), "a");
        let patch = "diff --git a/x b/x\n+added\n";
        std::fs::write(session_dir(tmp.path(), &id).join(SESSION_DIFF_FILE), patch).unwrap();
        assert_eq!(session_diff(tmp.path(), &id).unwrap(), patch);
    }

    #[test]
    fn diff_with_no_patch_returns_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let id = make_session(tmp.path(), ts(2026, 6, 12, 7, 0, 0), "a");
        assert_eq!(session_diff(tmp.path(), &id).unwrap(), "");
    }

    #[test]
    fn diff_of_unknown_session_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let err = session_diff(tmp.path(), &SessionId::from_existing("nope")).unwrap_err();
        assert!(matches!(err, SessionError::SessionNotFound(_)));
    }

    // --- export format gating ---

    #[test]
    fn export_format_accepts_markdown_and_json() {
        assert_eq!(
            parse_export_format("markdown").unwrap(),
            ExportFormat::Markdown
        );
        assert_eq!(parse_export_format("json").unwrap(), ExportFormat::Json);
    }

    #[test]
    fn export_format_rejects_other_values() {
        for bad in ["yaml", "html", "MARKDOWN", "", "txt"] {
            let err = parse_export_format(bad).unwrap_err();
            assert!(matches!(err, SessionError::UnsupportedFormat(f) if f == bad));
        }
    }

    // --- duration parsing ---

    #[test]
    fn duration_parses_each_unit() {
        assert_eq!(parse_duration("30s").unwrap(), Duration::seconds(30));
        assert_eq!(parse_duration("15m").unwrap(), Duration::minutes(15));
        assert_eq!(parse_duration("2h").unwrap(), Duration::hours(2));
        assert_eq!(parse_duration("7d").unwrap(), Duration::days(7));
    }

    #[test]
    fn duration_rejects_invalid_inputs() {
        for bad in [
            "", "0s", "-1d", "10", "d", "10x", "1.5h", "10 s", " 10s", "abc", "10ss", "h10",
        ] {
            assert!(
                matches!(parse_duration(bad), Err(SessionError::InvalidDuration(_))),
                "expected {bad:?} to be rejected"
            );
        }
    }

    // --- cleanup ---

    #[test]
    fn clean_removes_only_sessions_older_than_duration() {
        let tmp = tempfile::tempdir().unwrap();
        let now = ts(2026, 6, 12, 12, 0, 0);
        // 3 days old -> removed by --older-than 2d
        let old = make_session(tmp.path(), ts(2026, 6, 9, 12, 0, 0), "old");
        // 1 day old -> kept
        let recent = make_session(tmp.path(), ts(2026, 6, 11, 12, 0, 0), "recent");

        let removed = clean_older_than(tmp.path(), parse_duration("2d").unwrap(), now).unwrap();
        assert_eq!(removed, vec![old.clone()]);
        assert!(!session_dir(tmp.path(), &old).exists());
        assert!(session_dir(tmp.path(), &recent).exists());
        // The kept session is still listed.
        assert_eq!(list_sessions(tmp.path()).unwrap().len(), 1);
    }

    #[test]
    fn clean_keeps_sessions_at_the_threshold() {
        let tmp = tempfile::tempdir().unwrap();
        let now = ts(2026, 6, 12, 12, 0, 0);
        // Exactly 1h old with --older-than 1h: not strictly older, so kept.
        let at_threshold = make_session(tmp.path(), ts(2026, 6, 12, 11, 0, 0), "edge");
        let removed = clean_older_than(tmp.path(), parse_duration("1h").unwrap(), now).unwrap();
        assert!(removed.is_empty());
        assert!(session_dir(tmp.path(), &at_threshold).exists());
    }

    #[test]
    fn clean_on_empty_repo_removes_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let removed =
            clean_older_than(tmp.path(), parse_duration("1d").unwrap(), Utc::now()).unwrap();
        assert!(removed.is_empty());
    }

    #[test]
    fn metadata_file_constant_is_referenced() {
        // Touch the imported constant so the test module documents the layout.
        assert_eq!(SESSION_METADATA_FILE, "session.json");
    }
}
