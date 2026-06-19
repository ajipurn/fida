//! `fida-session` — Session_Manager: ids, directories, metadata, lifecycle
//! (see spec tasks 8.x).
//!
//! This task (8.1) implements the foundations the rest of the Session_Manager
//! builds on:
//!
//! - [`SessionId`] generation as `<UTC-timestamp>-<short-random>`. The
//!   timestamp uses a colon-free, lexicographically sortable layout
//!   (`%Y-%m-%dT%H%M%SZ`) so ids sort by start time, and the random suffix
//!   guarantees uniqueness for sessions started in the same second.
//! - The session directory layout under `.fida/sessions/<id>/`.
//! - The [`SessionMetadata`] record written to `session.json` capturing the
//!   repository path, git SHA, profile, mode, agent command, start time, and
//!   the diff [`Baseline`] (design "Session Metadata and Directory Layout").
//!
//! Lifecycle, listing, and resolution helpers are implemented in
//! [`mod@lifecycle`] (task 8.2).

use std::error::Error;
use std::fmt;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use fida_action::Mode;
use rand::Rng;
use serde::{Deserialize, Serialize};

mod lifecycle;

pub use lifecycle::{
    DecisionCounts, ExportFormat, SessionSummary, clean_older_than, latest, list_sessions,
    parse_duration, parse_export_format, resolve_session, session_diff, session_summary,
};

/// The directory name Fida stores all session state under, relative to the
/// repository root.
pub const FIDA_DIR: &str = ".fida";

/// The sub-directory of [`FIDA_DIR`] holding per-session directories.
pub const SESSIONS_DIR: &str = "sessions";

/// The metadata file written into each session directory.
pub const SESSION_METADATA_FILE: &str = "session.json";

/// The append-only audit log written into each session directory.
pub const SESSION_EVENTS_FILE: &str = "events.jsonl";

/// The recorded session diff written into each session directory.
pub const SESSION_DIFF_FILE: &str = "diff.patch";

/// Number of hexadecimal characters in a [`SessionId`] random suffix.
const SUFFIX_HEX_LEN: usize = 6;

/// The `chrono` format string for the timestamp portion of a [`SessionId`].
///
/// Colon-free so the value is a safe path component on every platform
/// (notably Windows), and ordered most-significant-first so lexicographic
/// ordering matches chronological ordering.
const ID_TIMESTAMP_FORMAT: &str = "%Y-%m-%dT%H%M%SZ";

// ---------------------------------------------------------------------------
// Session id
// ---------------------------------------------------------------------------

/// A unique, sortable session identifier of the form
/// `<UTC-timestamp>-<short-random>`, e.g. `2026-06-12T070000Z-a1b2c3`.
///
/// The timestamp prefix makes ids lexicographically sortable by start time;
/// the random suffix keeps ids distinct when multiple sessions start within
/// the same second.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SessionId(String);

impl SessionId {
    /// Generate a new id for a session starting at `start_time`, drawing the
    /// random suffix from the thread-local RNG.
    pub fn generate(start_time: DateTime<Utc>) -> Self {
        let suffix: u32 = rand::thread_rng().gen_range(0..(1 << (4 * SUFFIX_HEX_LEN)));
        Self::from_parts(start_time, suffix)
    }

    /// Construct an id from an explicit timestamp and numeric suffix.
    ///
    /// Used internally by [`SessionId::generate`] and by tests that need
    /// deterministic ids. Only the low `SUFFIX_HEX_LEN * 4` bits of `suffix`
    /// are used.
    fn from_parts(start_time: DateTime<Utc>, suffix: u32) -> Self {
        let masked = suffix & ((1 << (4 * SUFFIX_HEX_LEN)) - 1);
        let id = format!(
            "{}-{:0width$x}",
            start_time.format(ID_TIMESTAMP_FORMAT),
            masked,
            width = SUFFIX_HEX_LEN,
        );
        SessionId(id)
    }

    /// Wrap an existing id string (e.g. an on-disk session directory name).
    pub fn from_existing(id: impl Into<String>) -> Self {
        SessionId(id.into())
    }

    /// The id as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for SessionId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

// ---------------------------------------------------------------------------
// Directory layout
// ---------------------------------------------------------------------------

/// The `.fida/sessions` root inside `repo`.
pub fn sessions_root(repo: &Path) -> PathBuf {
    repo.join(FIDA_DIR).join(SESSIONS_DIR)
}

/// The directory `.fida/sessions/<id>/` for a specific session inside `repo`.
pub fn session_dir(repo: &Path, id: &SessionId) -> PathBuf {
    sessions_root(repo).join(id.as_str())
}

/// The path to a session's `session.json` metadata file.
pub fn session_metadata_path(repo: &Path, id: &SessionId) -> PathBuf {
    session_dir(repo, id).join(SESSION_METADATA_FILE)
}

// ---------------------------------------------------------------------------
// Metadata
// ---------------------------------------------------------------------------

/// The recorded starting git state of the workspace, used as the diff baseline
/// (design "Session Metadata and Directory Layout").
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Baseline {
    /// The `HEAD` commit SHA at session start.
    pub head_sha: String,
    /// Whether the working tree had uncommitted changes at session start.
    pub dirty: bool,
}

/// The metadata persisted to `session.json`.
///
/// Field order and names mirror the design's "Session Metadata and Directory
/// Layout" example. `end_time` is always present, written as `null` at
/// creation and populated when the session finalizes (task 8.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionMetadata {
    pub session_id: SessionId,
    pub repo_path: PathBuf,
    pub git_sha: String,
    pub profile: Option<String>,
    pub mode: Mode,
    #[serde(default = "default_workspace_mode")]
    pub workspace_mode: String,
    pub agent_command: Vec<String>,
    pub start_time: DateTime<Utc>,
    #[serde(default)]
    pub end_time: Option<DateTime<Utc>>,
    pub baseline: Baseline,
}

/// Parameters describing a session to create.
///
/// `repo_path` is both where the `.fida/sessions/<id>/` directory is created
/// and the value recorded in the metadata's `repo_path` field.
#[derive(Debug, Clone)]
pub struct CreateSessionParams {
    pub repo_path: PathBuf,
    pub git_sha: String,
    pub profile: Option<String>,
    pub mode: Mode,
    pub workspace_mode: String,
    pub agent_command: Vec<String>,
    pub start_time: DateTime<Utc>,
    pub baseline: Baseline,
}

/// The result of creating a session: its id, on-disk directory, and the
/// metadata that was written.
#[derive(Debug, Clone)]
pub struct CreatedSession {
    pub id: SessionId,
    pub dir: PathBuf,
    pub metadata: SessionMetadata,
}

/// Errors that can occur while creating, resolving, or managing sessions.
#[derive(Debug)]
pub enum SessionError {
    /// Failed to create the session directory or write its metadata file.
    Io(std::io::Error),
    /// Failed to serialize or deserialize session metadata as JSON.
    Serialize(serde_json::Error),
    /// A referenced session could not be resolved to an existing session.
    /// Carries the unresolved reference.
    SessionNotFound(String),
    /// A `--older-than <duration>` value was not a positive integer followed
    /// by one of the unit suffixes `s|m|h|d`. Carries the offending input.
    InvalidDuration(String),
    /// An export format other than `markdown` or `json` was requested. Carries
    /// the offending format.
    UnsupportedFormat(String),
}

impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SessionError::Io(e) => write!(f, "session I/O error: {e}"),
            SessionError::Serialize(e) => write!(f, "session metadata serialization error: {e}"),
            SessionError::SessionNotFound(reference) => {
                write!(f, "session not found: {reference}")
            }
            SessionError::InvalidDuration(input) => write!(
                f,
                "invalid duration {input:?}: expected a positive integer followed by one of s, m, h, d"
            ),
            SessionError::UnsupportedFormat(format) => write!(
                f,
                "unsupported export format {format:?}: expected markdown or json"
            ),
        }
    }
}

impl Error for SessionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            SessionError::Io(e) => Some(e),
            SessionError::Serialize(e) => Some(e),
            SessionError::SessionNotFound(_)
            | SessionError::InvalidDuration(_)
            | SessionError::UnsupportedFormat(_) => None,
        }
    }
}

impl From<std::io::Error> for SessionError {
    fn from(e: std::io::Error) -> Self {
        SessionError::Io(e)
    }
}

impl From<serde_json::Error> for SessionError {
    fn from(e: serde_json::Error) -> Self {
        SessionError::Serialize(e)
    }
}

/// Create a new session: generate a [`SessionId`], create the
/// `.fida/sessions/<id>/` directory, and write `session.json`.
pub fn create_session(params: CreateSessionParams) -> Result<CreatedSession, SessionError> {
    let id = SessionId::generate(params.start_time);
    create_session_with_id(id, params)
}

/// Create a session using a caller-supplied id. Shared by [`create_session`]
/// and tests; lets task 8.2 reuse the same directory/metadata writing path.
fn create_session_with_id(
    id: SessionId,
    params: CreateSessionParams,
) -> Result<CreatedSession, SessionError> {
    let dir = session_dir(&params.repo_path, &id);
    std::fs::create_dir_all(&dir)?;

    let metadata = SessionMetadata {
        session_id: id.clone(),
        repo_path: params.repo_path,
        git_sha: params.git_sha,
        profile: params.profile,
        mode: params.mode,
        workspace_mode: params.workspace_mode,
        agent_command: params.agent_command,
        start_time: params.start_time,
        end_time: None,
        baseline: params.baseline,
    };

    let mut json = serde_json::to_string_pretty(&metadata)?;
    json.push('\n');
    std::fs::write(dir.join(SESSION_METADATA_FILE), json)?;

    Ok(CreatedSession { id, dir, metadata })
}

fn default_workspace_mode() -> String {
    "current".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn ts(y: i32, mo: u32, d: u32, h: u32, mi: u32, s: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(y, mo, d, h, mi, s).single().unwrap()
    }

    fn sample_params(repo: &Path, start: DateTime<Utc>) -> CreateSessionParams {
        CreateSessionParams {
            repo_path: repo.to_path_buf(),
            git_sha: "a1b2c3d4e5f6".to_string(),
            profile: Some("careful".to_string()),
            mode: Mode::Enforce,
            workspace_mode: "copy".to_string(),
            agent_command: vec!["codex".to_string()],
            start_time: start,
            baseline: Baseline {
                head_sha: "a1b2c3d4e5f6".to_string(),
                dirty: false,
            },
        }
    }

    #[test]
    fn id_has_timestamp_and_short_random_suffix() {
        let id = SessionId::from_parts(ts(2026, 6, 12, 7, 0, 0), 0xa1b2c3);
        assert_eq!(id.as_str(), "2026-06-12T070000Z-a1b2c3");
    }

    #[test]
    fn id_timestamp_is_colon_free_for_path_safety() {
        let id = SessionId::generate(ts(2026, 6, 12, 7, 0, 0));
        assert!(
            !id.as_str().contains(':'),
            "id must be a safe path component"
        );
    }

    #[test]
    fn id_suffix_is_zero_padded_to_six_hex_chars() {
        let id = SessionId::from_parts(ts(2026, 1, 2, 3, 4, 5), 0xf);
        assert_eq!(id.as_str(), "2026-01-02T030405Z-00000f");
        let (_, suffix) = id.as_str().rsplit_once('-').unwrap();
        assert_eq!(suffix.len(), SUFFIX_HEX_LEN);
    }

    #[test]
    fn ids_sort_lexicographically_by_start_time() {
        let earlier = SessionId::from_parts(ts(2026, 6, 12, 7, 0, 0), 0xffffff);
        let later = SessionId::from_parts(ts(2026, 6, 12, 7, 0, 1), 0x000000);
        // Even with a larger suffix, the earlier timestamp sorts first.
        assert!(earlier < later);
        assert!(earlier.as_str() < later.as_str());
    }

    #[test]
    fn generated_ids_are_distinct_within_the_same_second() {
        let start = ts(2026, 6, 12, 7, 0, 0);
        let mut seen = std::collections::HashSet::new();
        for _ in 0..1000 {
            let id = SessionId::generate(start);
            seen.insert(id.as_str().to_string());
        }
        // Collisions are possible but vanishingly unlikely over 1000 draws
        // from 16M values; require near-total uniqueness.
        assert!(
            seen.len() >= 995,
            "expected mostly-unique ids, got {}",
            seen.len()
        );
    }

    #[test]
    fn directory_layout_is_under_dot_fida_sessions() {
        let repo = Path::new("/repo");
        let id = SessionId::from_parts(ts(2026, 6, 12, 7, 0, 0), 0xa1b2c3);
        assert_eq!(
            session_dir(repo, &id),
            Path::new("/repo/.fida/sessions/2026-06-12T070000Z-a1b2c3")
        );
        assert_eq!(
            session_metadata_path(repo, &id),
            Path::new("/repo/.fida/sessions/2026-06-12T070000Z-a1b2c3/session.json")
        );
    }

    #[test]
    fn create_session_creates_directory_and_metadata_file() {
        let tmp = tempfile::tempdir().unwrap();
        let start = ts(2026, 6, 12, 7, 0, 0);
        let created = create_session(sample_params(tmp.path(), start)).unwrap();

        assert!(created.dir.is_dir());
        let meta_path = created.dir.join(SESSION_METADATA_FILE);
        assert!(meta_path.is_file());
        assert_eq!(meta_path, session_metadata_path(tmp.path(), &created.id));
    }

    #[test]
    fn written_metadata_round_trips_and_captures_all_fields() {
        let tmp = tempfile::tempdir().unwrap();
        let start = ts(2026, 6, 12, 7, 0, 0);
        let created = create_session(sample_params(tmp.path(), start)).unwrap();

        let raw = std::fs::read_to_string(created.dir.join(SESSION_METADATA_FILE)).unwrap();
        let parsed: SessionMetadata = serde_json::from_str(&raw).unwrap();
        assert_eq!(parsed, created.metadata);

        assert_eq!(parsed.session_id, created.id);
        assert_eq!(parsed.repo_path, tmp.path());
        assert_eq!(parsed.git_sha, "a1b2c3d4e5f6");
        assert_eq!(parsed.profile.as_deref(), Some("careful"));
        assert_eq!(parsed.mode, Mode::Enforce);
        assert_eq!(parsed.workspace_mode, "copy");
        assert_eq!(parsed.agent_command, vec!["codex".to_string()]);
        assert_eq!(parsed.start_time, start);
        assert_eq!(parsed.end_time, None);
        assert_eq!(parsed.baseline.head_sha, "a1b2c3d4e5f6");
        assert!(!parsed.baseline.dirty);
    }

    #[test]
    fn metadata_json_matches_design_schema_shape() {
        let tmp = tempfile::tempdir().unwrap();
        let start = ts(2026, 6, 12, 7, 0, 0);
        let created = create_session(sample_params(tmp.path(), start)).unwrap();

        let raw = std::fs::read_to_string(created.dir.join(SESSION_METADATA_FILE)).unwrap();
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();

        assert_eq!(v["session_id"], created.id.as_str());
        assert_eq!(v["start_time"], "2026-06-12T07:00:00Z");
        assert_eq!(v["mode"], "enforce");
        assert_eq!(v["workspace_mode"], "copy");
        assert_eq!(v["profile"], "careful");
        assert!(v["end_time"].is_null());
        assert_eq!(v["baseline"]["head_sha"], "a1b2c3d4e5f6");
        assert_eq!(v["baseline"]["dirty"], false);
        assert!(v["agent_command"].is_array());
    }

    #[test]
    fn create_session_uses_an_id_derived_from_start_time() {
        let tmp = tempfile::tempdir().unwrap();
        let start = ts(2026, 6, 12, 7, 0, 0);
        let created = create_session(sample_params(tmp.path(), start)).unwrap();
        assert!(created.id.as_str().starts_with("2026-06-12T070000Z-"));
    }
}
