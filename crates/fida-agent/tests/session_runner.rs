//! Integration test for the session runner against a stub agent (task 17.2).
//!
//! These tests exercise the `fida-agent` Agent_Adapter end to end against a
//! real temporary git repository and trivial `sh -c` stub agents, covering:
//!
//! 1. Session creation + baseline capture,
//! 2. Stub agent launch + diff computation,
//! 3. Finalization / report artifacts,
//! 4. Agent-failure exit code 5.
//!
//! Process-launch and git-shelling tests are gated with `#[cfg(unix)]` (matching
//! the crate's inline tests), since the stub agents use `sh -c`.

use std::path::Path;
use std::process::Command;

use chrono::{TimeZone, Utc};

use fida_action::Mode;
use fida_agent::{
    AgentSpec, ChangeStatus, EXIT_AGENT_FAILED, SESSION_RESULT_FILE, SessionResult, changed_files,
    diff_patch, exit_code, finalize_session_at, launch_agent,
};
use fida_session::{
    Baseline, CreateSessionParams, SESSION_DIFF_FILE, SessionMetadata, create_session,
    session_metadata_path,
};
use tempfile::TempDir;

/// Whether a `git` executable is available on PATH. Git is expected, but we
/// gate so the suite degrades gracefully on minimal CI images.
fn git_available() -> bool {
    Command::new("git")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Run `git <args>` in `dir`, asserting success.
fn git(dir: &Path, args: &[&str]) {
    let status = Command::new("git")
        .current_dir(dir)
        .args(args)
        .status()
        .unwrap_or_else(|e| panic!("failed to spawn git {args:?}: {e}"));
    assert!(status.success(), "git {args:?} failed");
}

/// Initialize a temp git repo with a single committed file (`tracked.txt`).
fn init_repo() -> TempDir {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path();
    git(path, &["init", "-q"]);
    git(path, &["config", "user.email", "test@example.com"]);
    git(path, &["config", "user.name", "Test"]);
    std::fs::write(path.join("tracked.txt"), "original\n").unwrap();
    git(path, &["add", "."]);
    git(path, &["commit", "-q", "-m", "init"]);
    dir
}

/// The current `HEAD` SHA of the repo at `path`.
fn head_sha(path: &Path) -> String {
    let out = Command::new("git")
        .current_dir(path)
        .args(["rev-parse", "HEAD"])
        .output()
        .unwrap();
    assert!(out.status.success(), "git rev-parse HEAD failed");
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// A `sh -c <script>` stub-agent spec running in `cwd`.
#[cfg(unix)]
fn sh_agent(script: &str, cwd: &Path) -> AgentSpec {
    AgentSpec::new(
        vec!["sh".to_string(), "-c".to_string(), script.to_string()],
        cwd,
    )
}

/// Build session-creation params capturing the repo's real HEAD as the
/// baseline.
fn params_for(repo: &Path) -> CreateSessionParams {
    let sha = head_sha(repo);
    CreateSessionParams {
        repo_path: repo.to_path_buf(),
        git_sha: sha.clone(),
        profile: Some("careful".to_string()),
        mode: Mode::Enforce,
        workspace_mode: "current".to_string(),
        agent_command: vec!["sh".to_string(), "-c".to_string(), "true".to_string()],
        start_time: Utc.with_ymd_and_hms(2026, 6, 12, 7, 0, 0).single().unwrap(),
        baseline: Baseline {
            head_sha: sha,
            dirty: false,
        },
    }
}

// ---------------------------------------------------------------------------
// 1. Session creation + baseline capture
// ---------------------------------------------------------------------------

#[test]
fn session_creation_captures_baseline_at_head() {
    if !git_available() {
        eprintln!("skipping: git not available");
        return;
    }
    let repo = init_repo();
    let expected_head = head_sha(repo.path());

    let created = create_session(params_for(repo.path())).unwrap();

    // Session directory and session.json exist.
    assert!(created.dir.is_dir(), "session dir should exist");
    let meta_path = session_metadata_path(repo.path(), &created.id);
    assert!(meta_path.is_file(), "session.json should exist");

    // The captured baseline head_sha is the repo HEAD, and it is not dirty.
    assert_eq!(created.metadata.baseline.head_sha, expected_head);
    assert!(!created.metadata.baseline.dirty);

    // session.json round-trips with the same baseline.
    let raw = std::fs::read_to_string(&meta_path).unwrap();
    let parsed: SessionMetadata = serde_json::from_str(&raw).unwrap();
    assert_eq!(parsed.baseline.head_sha, expected_head);
    assert_eq!(parsed.session_id, created.id);
    assert!(parsed.end_time.is_none(), "end_time unset before finalize");
}

// ---------------------------------------------------------------------------
// 2. Stub agent launch + diff computation
// ---------------------------------------------------------------------------

#[cfg(unix)]
#[test]
fn stub_agent_modifies_workspace_and_diff_is_detected() {
    if !git_available() {
        eprintln!("skipping: git not available");
        return;
    }
    let repo = init_repo();

    // Launch a stub agent that modifies a tracked file and adds a new one.
    let exit = launch_agent(&sh_agent(
        "echo changed > tracked.txt && echo new > added.txt",
        repo.path(),
    ))
    .unwrap();
    assert!(exit.is_success(), "stub agent should exit 0");
    assert_eq!(exit.code, 0);

    // The modification and addition are detected by the diff computation.
    let changes = changed_files(repo.path()).unwrap();
    let modified = changes
        .iter()
        .any(|c| c.path == Path::new("tracked.txt") && c.status == ChangeStatus::Modified);
    let added = changes
        .iter()
        .any(|c| c.path == Path::new("added.txt") && c.status == ChangeStatus::Added);
    assert!(modified, "expected tracked.txt modified: {changes:?}");
    assert!(added, "expected added.txt added: {changes:?}");

    // The unified patch reflects the tracked-file modification.
    let patch = diff_patch(repo.path()).unwrap();
    assert!(
        patch.contains("tracked.txt"),
        "diff patch should mention tracked.txt: {patch}"
    );
}

// ---------------------------------------------------------------------------
// 3. Finalization / report artifacts
// ---------------------------------------------------------------------------

#[cfg(unix)]
#[test]
fn finalization_writes_diff_result_and_stamps_end_time() {
    if !git_available() {
        eprintln!("skipping: git not available");
        return;
    }
    let repo = init_repo();
    let created = create_session(params_for(repo.path())).unwrap();

    // Stub agent makes a change in the repo working tree.
    let exit = launch_agent(&sh_agent("echo edited > tracked.txt", repo.path())).unwrap();
    assert!(exit.is_success());

    let end = Utc.with_ymd_and_hms(2026, 6, 12, 7, 5, 0).single().unwrap();
    let result: SessionResult =
        finalize_session_at(repo.path(), &created.id, repo.path(), exit.code, end).unwrap();

    // Report artifacts written into the session directory.
    assert!(
        created.dir.join(SESSION_RESULT_FILE).exists(),
        "result.json should be written"
    );
    assert!(
        created.dir.join(SESSION_DIFF_FILE).exists(),
        "diff.patch should be written"
    );

    // The recorded result captures the agent exit code and changed file.
    assert_eq!(result.agent_exit_code, 0);
    assert_eq!(result.finalized_at, end);
    assert!(
        result
            .changed_files
            .iter()
            .any(|c| c.path == Path::new("tracked.txt"))
    );

    // result.json round-trips.
    let raw = std::fs::read_to_string(created.dir.join(SESSION_RESULT_FILE)).unwrap();
    let parsed: SessionResult = serde_json::from_str(&raw).unwrap();
    assert_eq!(parsed, result);

    // end_time is stamped into session.json.
    let meta_raw =
        std::fs::read_to_string(session_metadata_path(repo.path(), &created.id)).unwrap();
    let meta: SessionMetadata = serde_json::from_str(&meta_raw).unwrap();
    assert_eq!(meta.end_time, Some(end));
}

// ---------------------------------------------------------------------------
// 4. Agent-failure exit code 5
// ---------------------------------------------------------------------------

#[cfg(unix)]
#[test]
fn failing_stub_agent_maps_to_exit_code_five() {
    if !git_available() {
        eprintln!("skipping: git not available");
        return;
    }
    let repo = init_repo();
    let created = create_session(params_for(repo.path())).unwrap();

    // Stub agent exits non-zero.
    let exit = launch_agent(&sh_agent("exit 1", repo.path())).unwrap();
    assert!(!exit.is_success());
    assert_ne!(exit.code, 0);

    // The non-zero agent exit maps to EXIT_AGENT_FAILED (5).
    assert_eq!(exit_code(exit.code, false), EXIT_AGENT_FAILED);
    assert_eq!(EXIT_AGENT_FAILED, 5);

    // Finalization still runs after a failed agent so the result is preserved
    // for a later apply: result.json is recorded with the failure.
    let end = Utc.with_ymd_and_hms(2026, 6, 12, 7, 5, 0).single().unwrap();
    let result =
        finalize_session_at(repo.path(), &created.id, repo.path(), exit.code, end).unwrap();
    assert_eq!(result.agent_exit_code, exit.code);
    assert!(created.dir.join(SESSION_RESULT_FILE).exists());
    assert_eq!(exit_code(result.agent_exit_code, false), EXIT_AGENT_FAILED);
}
