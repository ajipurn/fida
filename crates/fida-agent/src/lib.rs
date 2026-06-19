//! `fida-agent` — Agent_Adapter: launch the agent command as a child
//! process within a session, stream its output live, prepare the working area
//! for the chosen `--workspace` mode, and finalize the session with a diff and
//! recorded result (design "Agent_Adapter", "File Diff Gate Design").
//!
//! The adapter is deliberately split into small, independently testable units:
//!
//! * [`WorkspaceMode`] prepares the directory the agent runs in,
//! * [`launch_agent`] spawns the agent child, streaming stdout/stderr live and
//!   reporting its exit code,
//! * [`changed_files`] / [`diff_patch`] compute the diff between the session
//!   start git state and the agent end state,
//! * [`finalize_session`] records `end_time`, the diff patch, and the session
//!   result into the session directory,
//! * [`exit_code`] maps the agent exit status and any post-exit apply failure
//!   to the documented exit codes.
//!
//! Diff computation shells out to `git` so the adapter stays usable while the
//! richer `fida-diff` File_Diff_Gate APIs land in parallel.

use std::error::Error;
use std::ffi::OsStr;
use std::fmt;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use fida_session::{SessionId, SessionMetadata, session_dir, session_metadata_path};

// ---------------------------------------------------------------------------
// Exit codes (design "Error Handling" table)
// ---------------------------------------------------------------------------

/// Normal completion: the agent exited zero and any apply step succeeded.
/// Re-exported from the broker so the whole CLI shares one success constant.
pub const EXIT_SUCCESS: u8 = fida_broker::EXIT_SUCCESS;

/// The agent child process exited with a non-zero status.
pub const EXIT_AGENT_FAILED: u8 = 5;

/// Applying session changes failed after the agent exited.
pub const EXIT_APPLY_FAILED: u8 = 7;

/// Map an agent exit status and post-exit apply result to a CLI exit code.
///
/// Precedence: a non-zero agent exit is reported as agent failure (5) and no
/// apply is attempted; only when the agent succeeded does an apply failure
/// surface as apply failure (7). A clean run is success.
pub fn exit_code(agent_exit_code: i32, apply_failed: bool) -> u8 {
    if agent_exit_code != 0 {
        EXIT_AGENT_FAILED
    } else if apply_failed {
        EXIT_APPLY_FAILED
    } else {
        EXIT_SUCCESS
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors raised while preparing the workspace, launching the agent, or
/// finalizing the session.
#[derive(Debug)]
pub enum AgentError {
    /// An I/O failure spawning the agent, preparing a workspace, or writing
    /// session artifacts.
    Io(io::Error),
    /// Failed to (de)serialize session metadata or the session result.
    Serialize(serde_json::Error),
    /// A `--workspace` value other than `current`, `copy`, or `git-worktree`
    /// Carries the offending input; the CLI maps this to exit 1.
    UnsupportedWorkspace(String),
    /// A shelled-out `git` invocation failed. Carries the command summary and
    /// captured stderr.
    Git { command: String, stderr: String },
}

impl fmt::Display for AgentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AgentError::Io(e) => write!(f, "agent I/O error: {e}"),
            AgentError::Serialize(e) => write!(f, "agent metadata serialization error: {e}"),
            AgentError::UnsupportedWorkspace(value) => write!(
                f,
                "unsupported workspace mode {value:?}: expected current, copy, or git-worktree"
            ),
            AgentError::Git { command, stderr } => {
                write!(f, "git command failed ({command}): {}", stderr.trim())
            }
        }
    }
}

impl Error for AgentError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            AgentError::Io(e) => Some(e),
            AgentError::Serialize(e) => Some(e),
            AgentError::UnsupportedWorkspace(_) | AgentError::Git { .. } => None,
        }
    }
}

impl From<io::Error> for AgentError {
    fn from(e: io::Error) -> Self {
        AgentError::Io(e)
    }
}

impl From<serde_json::Error> for AgentError {
    fn from(e: serde_json::Error) -> Self {
        AgentError::Serialize(e)
    }
}

// ---------------------------------------------------------------------------
// Workspace modes
// ---------------------------------------------------------------------------

/// The directory under a session that isolated workspace modes are prepared in.
const WORKSPACE_SUBDIR: &str = "workspace";

/// How the agent's working area relates to the repository.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WorkspaceMode {
    /// Operate in place on the repository working tree.
    Current,
    /// Copy the repository working tree into an isolated directory.
    Copy,
    /// Create a git worktree checked out at the current `HEAD`.
    GitWorktree,
}

impl WorkspaceMode {
    /// Parse a `--workspace` value, rejecting anything outside the exact set
    /// `current` | `copy` | `git-worktree`.
    pub fn parse(value: &str) -> Result<Self, AgentError> {
        match value {
            "current" => Ok(WorkspaceMode::Current),
            "copy" => Ok(WorkspaceMode::Copy),
            "git-worktree" => Ok(WorkspaceMode::GitWorktree),
            other => Err(AgentError::UnsupportedWorkspace(other.to_string())),
        }
    }

    /// The canonical string form, matching the accepted `--workspace` values.
    pub fn as_str(&self) -> &'static str {
        match self {
            WorkspaceMode::Current => "current",
            WorkspaceMode::Copy => "copy",
            WorkspaceMode::GitWorktree => "git-worktree",
        }
    }

    /// Prepare the working area and return the path the agent should run in.
    ///
    /// * `current` returns `repo` unchanged.
    /// * `copy` recursively copies the repository tree into the session's
    ///   `workspace/` directory so agent edits never touch the main tree.
    /// * `git-worktree` shells out to `git worktree add` to check `HEAD` out
    ///   into the session's `workspace/` directory.
    pub fn prepare(&self, repo: &Path, session_dir: &Path) -> Result<PathBuf, AgentError> {
        match self {
            WorkspaceMode::Current => Ok(repo.to_path_buf()),
            WorkspaceMode::Copy => {
                let dest = session_dir.join(WORKSPACE_SUBDIR);
                if dest.exists() {
                    std::fs::remove_dir_all(&dest)?;
                }
                copy_tree(repo, &dest)?;
                Ok(dest)
            }
            WorkspaceMode::GitWorktree => {
                let dest = session_dir.join(WORKSPACE_SUBDIR);
                if dest.exists() {
                    std::fs::remove_dir_all(&dest)?;
                }
                run_git(
                    repo,
                    &[
                        "worktree",
                        "add",
                        "--detach",
                        &dest.to_string_lossy(),
                        "HEAD",
                    ],
                )?;
                Ok(dest)
            }
        }
    }
}

/// Recursively copy `src` into `dest`, creating `dest` and intermediate
/// directories. Symlinks are copied as their target contents (best-effort).
///
/// The session directory lives under `.fida/sessions/<id>/workspace` inside
/// the repository. Skipping the top-level `.fida` directory prevents the copy
/// workspace from recursively copying its own destination back into itself.
fn copy_tree(src: &Path, dest: &Path) -> io::Result<()> {
    std::fs::create_dir_all(dest)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let from = entry.path();
        if entry.file_name() == ".fida" {
            continue;
        }
        let to = dest.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_tree(&from, &to)?;
        } else {
            std::fs::copy(&from, &to)?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Agent launch and streaming
// ---------------------------------------------------------------------------

/// What command to launch, where, and with which extra environment variables.
#[derive(Debug, Clone)]
pub struct AgentSpec {
    /// The agent command as an argv vector; `argv[0]` is the program.
    pub argv: Vec<String>,
    /// The working directory the agent runs in (from [`WorkspaceMode::prepare`]).
    pub cwd: PathBuf,
    /// Extra environment variables to inject (e.g. proxy vars from fida-net).
    pub env: Vec<(String, String)>,
}

impl AgentSpec {
    /// Construct a spec for `argv` running in `cwd` with no extra environment.
    pub fn new(argv: Vec<String>, cwd: impl Into<PathBuf>) -> Self {
        AgentSpec {
            argv,
            cwd: cwd.into(),
            env: Vec::new(),
        }
    }
}

/// The result of running the agent child to completion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgentExit {
    /// The process exit code, or `-1` for a process terminated by a signal.
    pub code: i32,
}

impl AgentExit {
    /// Whether the agent exited successfully (`code == 0`).
    pub fn is_success(&self) -> bool {
        self.code == 0
    }
}

/// Launch the agent command as a child process, streaming its stdout and
/// stderr live to the parent's stdout/stderr, and return its exit code.
///
/// Each output stream is pumped on its own thread (mirroring `fida-exec`) so
/// neither pipe can stall the other. An empty `argv` is rejected before spawn.
pub fn launch_agent(spec: &AgentSpec) -> Result<AgentExit, AgentError> {
    let program = spec.argv.first().ok_or_else(|| {
        AgentError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "agent command is empty",
        ))
    })?;

    let mut cmd = Command::new(program);
    cmd.args(&spec.argv[1..])
        .current_dir(&spec.cwd)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (key, value) in &spec.env {
        cmd.env(key, value);
    }

    let mut child = cmd.spawn()?;

    let stdout = child.stdout.take().expect("stdout was piped");
    let stderr = child.stderr.take().expect("stderr was piped");
    let out_handle = pump_stream(stdout, Stream::Stdout);
    let err_handle = pump_stream(stderr, Stream::Stderr);

    let status = child.wait()?;

    // Reader threads finish once the pipes close (child exited).
    let _ = out_handle.join();
    let _ = err_handle.join();

    // A signal-terminated process has no numeric code; report -1.
    Ok(AgentExit {
        code: status.code().unwrap_or(-1),
    })
}

/// Which parent stream a pump thread mirrors to.
#[derive(Debug, Clone, Copy)]
enum Stream {
    Stdout,
    Stderr,
}

/// Spawn a thread that streams `reader` live to the corresponding parent
/// stream until the pipe closes.
fn pump_stream<R>(mut reader: R, stream: Stream) -> thread::JoinHandle<()>
where
    R: Read + Send + 'static,
{
    thread::spawn(move || {
        let mut buf = [0u8; 8192];
        loop {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    let chunk = &buf[..n];
                    match stream {
                        Stream::Stdout => {
                            let mut out = io::stdout();
                            let _ = out.write_all(chunk);
                            let _ = out.flush();
                        }
                        Stream::Stderr => {
                            let mut err = io::stderr();
                            let _ = err.write_all(chunk);
                            let _ = err.flush();
                        }
                    }
                }
                Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
    })
}

// ---------------------------------------------------------------------------
// Diff between session start and agent end state
// ---------------------------------------------------------------------------

/// How a path changed between the session baseline and the agent end state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChangeStatus {
    /// The path did not exist at baseline and exists now.
    Added,
    /// The path existed at baseline and its contents changed.
    Modified,
    /// The path existed at baseline and no longer exists.
    Deleted,
}

/// A single changed path in the session's end-state diff.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangedFile {
    /// The repository-relative path that changed.
    pub path: PathBuf,
    /// How it changed.
    pub status: ChangeStatus,
}

/// Compute the changed-file set in `work_dir` relative to the session start git
/// state (design "File Diff Gate Design" step 3).
///
/// Shells out to `git status --porcelain` so staged, unstaged, and untracked
/// changes are all captured as added/modified/deleted entries.
pub fn changed_files(work_dir: &Path) -> Result<Vec<ChangedFile>, AgentError> {
    let out = run_git(
        work_dir,
        &["status", "--porcelain", "--untracked-files=all"],
    )?;
    Ok(parse_porcelain(&out))
}

/// Capture a unified diff of the working tree against `HEAD` (best-effort).
///
/// Untracked files are not shown by `git diff`; the authoritative changed-set
/// is [`changed_files`]. This patch is recorded for human review.
pub fn diff_patch(work_dir: &Path) -> Result<String, AgentError> {
    run_git(work_dir, &["diff", "HEAD"])
}

/// Parse `git status --porcelain` output into [`ChangedFile`] entries.
///
/// Porcelain v1 lines are `XY <path>` where `X`/`Y` are staged/worktree status
/// codes. `??` is an untracked (added) file; a `D` in either column is a
/// deletion; anything else is treated as a modification. Rename entries
/// (` -> `) record the destination path as modified.
fn parse_porcelain(output: &str) -> Vec<ChangedFile> {
    let mut changes = Vec::new();
    for line in output.lines() {
        if line.len() < 3 {
            continue;
        }
        let code = &line[..2];
        let rest = line[3..].trim();
        // For renames/copies, take the destination path after " -> ".
        let path_str = rest.rsplit(" -> ").next().unwrap_or(rest);
        let path = PathBuf::from(unquote_path(path_str));
        let status = if code == "??" || code.starts_with('A') || code.contains('A') {
            ChangeStatus::Added
        } else if code.contains('D') {
            ChangeStatus::Deleted
        } else {
            ChangeStatus::Modified
        };
        changes.push(ChangedFile { path, status });
    }
    changes
}

/// Strip the surrounding quotes git adds to paths containing unusual bytes.
fn unquote_path(path: &str) -> String {
    if path.len() >= 2 && path.starts_with('"') && path.ends_with('"') {
        path[1..path.len() - 1].to_string()
    } else {
        path.to_string()
    }
}

/// Run `git <args>` in `dir`, returning stdout on success or an
/// [`AgentError::Git`] carrying the captured stderr on failure.
fn run_git<S: AsRef<OsStr>>(dir: &Path, args: &[S]) -> Result<String, AgentError> {
    let output = Command::new("git").current_dir(dir).args(args).output()?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    } else {
        let rendered: Vec<String> = args
            .iter()
            .map(|a| a.as_ref().to_string_lossy().into_owned())
            .collect();
        Err(AgentError::Git {
            command: format!("git {}", rendered.join(" ")),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }
}

// ---------------------------------------------------------------------------
// Finalization
// ---------------------------------------------------------------------------

/// The file recording the finalized session outcome inside the session dir.
pub const SESSION_RESULT_FILE: &str = "result.json";

/// The recorded outcome of an agent session, persisted to `result.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionResult {
    /// The agent child's exit code (`-1` if signal-terminated).
    pub agent_exit_code: i32,
    /// The changed-file set computed at finalization.
    pub changed_files: Vec<ChangedFile>,
    /// When the session was finalized.
    pub finalized_at: DateTime<Utc>,
}

/// Finalize the session after the agent exits.
///
/// Computes the changed-file set and diff patch from `work_dir`, records the
/// session result and diff into the session directory, and stamps `end_time`
/// into `session.json`. Returns the recorded [`SessionResult`].
///
/// Finalization always runs, whether the agent succeeded or failed, so the
/// session result and diff are preserved for a later apply.
pub fn finalize_session(
    repo: &Path,
    id: &SessionId,
    work_dir: &Path,
    agent_exit_code: i32,
) -> Result<SessionResult, AgentError> {
    finalize_session_at(repo, id, work_dir, agent_exit_code, Utc::now())
}

/// [`finalize_session`] with an injectable finalization timestamp (for tests).
pub fn finalize_session_at(
    repo: &Path,
    id: &SessionId,
    work_dir: &Path,
    agent_exit_code: i32,
    finalized_at: DateTime<Utc>,
) -> Result<SessionResult, AgentError> {
    let changed = changed_files(work_dir)?;
    let patch = diff_patch(work_dir).unwrap_or_default();

    let dir = session_dir(repo, id);
    std::fs::create_dir_all(&dir)?;

    // Record the diff patch using the session crate's diff.patch convention.
    std::fs::write(dir.join(fida_session::SESSION_DIFF_FILE), patch)?;

    // Record the session result.
    let result = SessionResult {
        agent_exit_code,
        changed_files: changed,
        finalized_at,
    };
    let mut json = serde_json::to_string_pretty(&result)?;
    json.push('\n');
    std::fs::write(dir.join(SESSION_RESULT_FILE), json)?;

    // Stamp end_time into session.json if present (best-effort metadata update).
    let meta_path = session_metadata_path(repo, id);
    if meta_path.exists() {
        let raw = std::fs::read_to_string(&meta_path)?;
        let mut metadata: SessionMetadata = serde_json::from_str(&raw)?;
        metadata.end_time = Some(finalized_at);
        let mut meta_json = serde_json::to_string_pretty(&metadata)?;
        meta_json.push('\n');
        std::fs::write(&meta_path, meta_json)?;
    }

    Ok(result)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use std::process::Command;

    use chrono::TimeZone;
    use fida_action::Mode;
    use fida_session::{
        Baseline, CreateSessionParams, SESSION_DIFF_FILE, SessionId, create_session,
    };
    use tempfile::TempDir;

    fn fixed_time() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 6, 12, 7, 0, 0).single().unwrap()
    }

    /// A `sh -c <script>` agent spec running in `cwd`.
    fn sh_agent(script: &str, cwd: &Path) -> AgentSpec {
        AgentSpec::new(
            vec!["sh".to_string(), "-c".to_string(), script.to_string()],
            cwd,
        )
    }

    /// Initialize a git repo with one committed file, returning the repo path.
    fn init_repo() -> TempDir {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path();
        for args in [
            vec!["init", "-q"],
            vec!["config", "user.email", "test@example.com"],
            vec!["config", "user.name", "Test"],
        ] {
            let status = Command::new("git")
                .current_dir(path)
                .args(&args)
                .status()
                .unwrap();
            assert!(status.success(), "git {args:?} failed");
        }
        std::fs::write(path.join("tracked.txt"), "original\n").unwrap();
        for args in [vec!["add", "."], vec!["commit", "-q", "-m", "init"]] {
            let status = Command::new("git")
                .current_dir(path)
                .args(&args)
                .status()
                .unwrap();
            assert!(status.success(), "git {args:?} failed");
        }
        dir
    }

    // -- exit-code mapping --------------------------------------------------

    #[test]
    fn exit_code_success_when_agent_zero_and_apply_ok() {
        assert_eq!(exit_code(0, false), EXIT_SUCCESS);
    }

    #[test]
    fn exit_code_agent_failure_is_five() {
        assert_eq!(exit_code(1, false), EXIT_AGENT_FAILED);
        assert_eq!(EXIT_AGENT_FAILED, 5);
    }

    #[test]
    fn exit_code_apply_failure_is_seven_only_after_clean_agent_exit() {
        assert_eq!(exit_code(0, true), EXIT_APPLY_FAILED);
        assert_eq!(EXIT_APPLY_FAILED, 7);
        // Agent failure dominates: a non-zero agent exit reports 5 even if an
        // apply would also have failed (no apply is attempted).
        assert_eq!(exit_code(2, true), EXIT_AGENT_FAILED);
    }

    // -- launch + streaming -------------------------------------------------

    #[test]
    fn launch_trivial_command_reports_success() {
        let cwd = tempfile::tempdir().unwrap();
        let exit = launch_agent(&sh_agent("echo hello", cwd.path())).unwrap();
        assert!(exit.is_success());
        assert_eq!(exit.code, 0);
    }

    #[test]
    fn launch_nonzero_command_propagates_exit_code_mapped_to_five() {
        let cwd = tempfile::tempdir().unwrap();
        let exit = launch_agent(&sh_agent("exit 3", cwd.path())).unwrap();
        assert_eq!(exit.code, 3);
        assert!(!exit.is_success());
        assert_eq!(exit_code(exit.code, false), EXIT_AGENT_FAILED);
    }

    #[test]
    fn launch_empty_argv_is_rejected() {
        let cwd = tempfile::tempdir().unwrap();
        let spec = AgentSpec::new(vec![], cwd.path());
        assert!(matches!(launch_agent(&spec), Err(AgentError::Io(_))));
    }

    // -- workspace modes ----------------------------------------------------

    #[test]
    fn workspace_parse_roundtrips_supported_modes() {
        for mode in [
            WorkspaceMode::Current,
            WorkspaceMode::Copy,
            WorkspaceMode::GitWorktree,
        ] {
            assert_eq!(WorkspaceMode::parse(mode.as_str()).unwrap(), mode);
        }
    }

    #[test]
    fn workspace_parse_rejects_unknown_mode() {
        match WorkspaceMode::parse("sandbox") {
            Err(AgentError::UnsupportedWorkspace(v)) => assert_eq!(v, "sandbox"),
            other => panic!("expected UnsupportedWorkspace, got {other:?}"),
        }
    }

    #[test]
    fn workspace_current_returns_repo_path() {
        let repo = tempfile::tempdir().unwrap();
        let session = tempfile::tempdir().unwrap();
        let path = WorkspaceMode::Current
            .prepare(repo.path(), session.path())
            .unwrap();
        assert_eq!(path, repo.path());
    }

    #[test]
    fn workspace_copy_isolates_the_tree() {
        let repo = init_repo();
        let session = tempfile::tempdir().unwrap();
        let work = WorkspaceMode::Copy
            .prepare(repo.path(), session.path())
            .unwrap();
        assert_ne!(work, repo.path());
        assert!(work.join("tracked.txt").exists());

        // Editing the copy must not touch the original tree.
        std::fs::write(work.join("tracked.txt"), "changed in copy\n").unwrap();
        let original = std::fs::read_to_string(repo.path().join("tracked.txt")).unwrap();
        assert_eq!(original, "original\n");
    }

    #[test]
    fn workspace_copy_skips_fida_session_artifacts() {
        let repo = init_repo();
        let session = repo.path().join(".fida/sessions/test-session");
        std::fs::create_dir_all(&session).unwrap();
        std::fs::write(repo.path().join(".fida/old-session.json"), "{}\n").unwrap();

        let work = WorkspaceMode::Copy.prepare(repo.path(), &session).unwrap();

        assert!(work.join("tracked.txt").exists());
        assert!(
            !work.join(".fida").exists(),
            "copy workspace must not recursively include session state"
        );
    }

    // -- diff computation ---------------------------------------------------

    #[test]
    fn changed_files_detects_add_modify_delete() {
        let repo = init_repo();
        let path = repo.path();
        std::fs::write(path.join("tracked.txt"), "modified\n").unwrap();
        std::fs::write(path.join("added.txt"), "new\n").unwrap();
        std::fs::remove_file(path.join("tracked.txt")).ok();
        // Re-add a modified tracked file separately so we exercise all three.
        std::fs::write(path.join("tracked.txt"), "modified\n").unwrap();
        std::fs::write(path.join("todelete.txt"), "x\n").unwrap();
        Command::new("git")
            .current_dir(path)
            .args(["add", "todelete.txt"])
            .status()
            .unwrap();
        Command::new("git")
            .current_dir(path)
            .args(["commit", "-q", "-m", "second"])
            .status()
            .unwrap();
        std::fs::remove_file(path.join("todelete.txt")).unwrap();

        let changes = changed_files(path).unwrap();
        let added = changes
            .iter()
            .any(|c| c.path == Path::new("added.txt") && c.status == ChangeStatus::Added);
        let modified = changes
            .iter()
            .any(|c| c.path == Path::new("tracked.txt") && c.status == ChangeStatus::Modified);
        let deleted = changes
            .iter()
            .any(|c| c.path == Path::new("todelete.txt") && c.status == ChangeStatus::Deleted);
        assert!(added, "expected added.txt: {changes:?}");
        assert!(modified, "expected modified tracked.txt: {changes:?}");
        assert!(deleted, "expected deleted todelete.txt: {changes:?}");
    }

    #[test]
    fn parse_porcelain_classifies_status_codes() {
        let out = "?? new.rs\n M edited.rs\n D gone.rs\nR  old.rs -> renamed.rs\n";
        let changes = parse_porcelain(out);
        assert_eq!(
            changes,
            vec![
                ChangedFile {
                    path: PathBuf::from("new.rs"),
                    status: ChangeStatus::Added
                },
                ChangedFile {
                    path: PathBuf::from("edited.rs"),
                    status: ChangeStatus::Modified
                },
                ChangedFile {
                    path: PathBuf::from("gone.rs"),
                    status: ChangeStatus::Deleted
                },
                // A rename's destination is reported as a content change;
                // both Added and Modified map to file.write at the gate.
                ChangedFile {
                    path: PathBuf::from("renamed.rs"),
                    status: ChangeStatus::Modified
                },
            ]
        );
    }

    // -- finalization -------------------------------------------------------

    #[test]
    fn finalize_records_result_diff_and_end_time() {
        let repo = init_repo();
        let start = fixed_time();
        let created = create_session(CreateSessionParams {
            repo_path: repo.path().to_path_buf(),
            git_sha: "deadbeef".to_string(),
            profile: None,
            mode: Mode::Enforce,
            workspace_mode: "current".to_string(),
            agent_command: vec!["sh".to_string(), "-c".to_string(), "true".to_string()],
            start_time: start,
            baseline: Baseline {
                head_sha: "deadbeef".to_string(),
                dirty: false,
            },
        })
        .unwrap();

        // Agent made a change in the repo working tree.
        std::fs::write(repo.path().join("tracked.txt"), "edited\n").unwrap();

        let end = Utc.with_ymd_and_hms(2026, 6, 12, 7, 5, 0).single().unwrap();
        let result = finalize_session_at(repo.path(), &created.id, repo.path(), 0, end).unwrap();

        assert_eq!(result.agent_exit_code, 0);
        assert_eq!(result.finalized_at, end);
        assert!(
            result
                .changed_files
                .iter()
                .any(|c| c.path == Path::new("tracked.txt"))
        );

        // Artifacts on disk.
        assert!(created.dir.join(SESSION_RESULT_FILE).exists());
        assert!(created.dir.join(SESSION_DIFF_FILE).exists());

        // session.json end_time stamped.
        let meta_raw =
            std::fs::read_to_string(session_metadata_path(repo.path(), &created.id)).unwrap();
        let meta: SessionMetadata = serde_json::from_str(&meta_raw).unwrap();
        assert_eq!(meta.end_time, Some(end));
    }

    #[test]
    fn finalize_preserves_result_on_agent_failure() {
        // Even when the agent failed (non-zero), finalization records the
        // result and diff so they survive for a later apply.
        let repo = init_repo();
        let id = SessionId::from_existing("2026-06-12T070000Z-abc123");
        std::fs::create_dir_all(session_dir(repo.path(), &id)).unwrap();
        std::fs::write(repo.path().join("tracked.txt"), "partial\n").unwrap();

        let result = finalize_session_at(repo.path(), &id, repo.path(), 5, fixed_time()).unwrap();
        assert_eq!(result.agent_exit_code, 5);
        assert!(
            session_dir(repo.path(), &id)
                .join(SESSION_RESULT_FILE)
                .exists()
        );
        assert_eq!(exit_code(result.agent_exit_code, false), EXIT_AGENT_FAILED);
    }
}
