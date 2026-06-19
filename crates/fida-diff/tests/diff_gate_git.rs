//! Integration tests for the File_Diff_Gate against a real temporary git
//! repository (design "File Diff Gate Design", task 14.3).
//!
//! Unlike the unit tests inside `fida-diff`, these exercise the gate end to
//! end through its public API: a temp `git` repo is created with the `git` CLI,
//! a baseline is captured, real working-tree edits are made, the changed set is
//! computed, and changes are applied through a broker wired with the public
//! testing helpers. Every test that shells out to `git` is gated on `git` being
//! available so the suite degrades gracefully where it is not installed.
//!
//! Coverage:
//! * baseline capture and dirty flag,
//! * changed-set computation for add/modify/delete,
//! * selective apply honoring allow/deny,
//! * exit code 7 when an approved change fails to apply.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use fida_action::Mode;
use fida_broker::testing::{MemoryAuditStore, RecordingDispatcher, ScriptedApprovalUi};
use fida_broker::{
    ActionBroker, Broker, BrokerContext, EXIT_SUCCESS, RememberedDecisions, SessionHandle,
};
use fida_diff::{ChangeKind, ChangedFile, EXIT_APPLY_FAILED, FileDiffGate, GitFileDiffGate};
use fida_policy::{CompiledPolicy, PolicySource, load_source};

const SESSION: &str = "2026-06-12T070000Z-diffit";

/// Allows writes under `src/**`, denies `secret/**`; anything else falls
/// through to the global `ask` default. `block_in_diffs` is on so the secret
/// gate is wired, but these tests use non-secret content so it never trips.
const TEST_POLICY: &str = r#"
version: 1
default_decision: ask

commands: {}

files:
  read:
    allow: ["**/*"]
  write:
    allow: ["src/**"]
    deny: ["secret/**"]

network: {}
mcp: {}
secrets:
  redact: true
  block_in_diffs: true
  patterns: []
audit:
  path: .fida/sessions
  format: jsonl
  redact_stdout: true
  redact_stderr: true
"#;

// --- git availability gate --------------------------------------------------

/// Whether a usable `git` CLI is on PATH. Tests that build a real repo skip
/// themselves (returning early) when it is not, rather than failing.
fn git_available() -> bool {
    Command::new("git")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Run a `git` subcommand in `repo`, asserting success.
fn git(repo: &Path, args: &[&str]) {
    let out = Command::new("git")
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

/// Initialize a repo with two committed files under `src/` and return the temp
/// dir (kept alive by the caller).
fn init_repo() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path();
    git(p, &["init", "-q"]);
    git(p, &["config", "user.email", "test@example.com"]);
    git(p, &["config", "user.name", "Test"]);
    git(p, &["config", "commit.gpgsign", "false"]);
    fs::create_dir_all(p.join("src")).unwrap();
    fs::write(p.join("src/keep.txt"), "original\n").unwrap();
    fs::write(p.join("src/gone.txt"), "remove me\n").unwrap();
    git(p, &["add", "-A"]);
    git(p, &["commit", "-q", "-m", "initial"]);
    dir
}

// --- policy + apply harness --------------------------------------------------

/// Compile [`TEST_POLICY`] from a temp YAML via the real policy loader.
fn compile_policy() -> CompiledPolicy {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("fida.yaml");
    fs::write(&path, TEST_POLICY).unwrap();
    let policy = load_source(&PolicySource::Config(path), None).expect("policy compiles");
    drop(dir);
    policy
}

/// Owns the broker-context dependencies so an apply can borrow them mutably.
struct ApplyHarness {
    policy: CompiledPolicy,
    session: SessionHandle,
    remembered: RememberedDecisions,
    audit: MemoryAuditStore,
    dispatcher: RecordingDispatcher,
}

impl ApplyHarness {
    fn new(dispatcher: RecordingDispatcher) -> Self {
        ApplyHarness {
            policy: compile_policy(),
            session: SessionHandle::new(SESSION),
            remembered: RememberedDecisions::new(),
            audit: MemoryAuditStore::new(),
            dispatcher,
        }
    }

    fn apply<B: ActionBroker>(
        &mut self,
        gate: &GitFileDiffGate<B>,
        mode: Mode,
        interactive: bool,
        changes: &[ChangedFile],
    ) -> fida_diff::ApplyReport {
        let mut ctx = BrokerContext {
            policy: &self.policy,
            mode,
            interactive,
            yes: false,
            session: &mut self.session,
            remembered: &mut self.remembered,
            audit: &mut self.audit,
            dispatcher: &mut self.dispatcher,
        };
        gate.apply(&mut ctx, changes)
    }
}

/// A gate routing through a broker with an always-denying approval UI (so any
/// stray `ask` is deterministically rejected) reading content from `source_root`.
fn gate(source_root: &Path) -> GitFileDiffGate<Broker<ScriptedApprovalUi>> {
    GitFileDiffGate::new(
        Broker::new(ScriptedApprovalUi::always_denying()),
        source_root,
    )
}

// --- 1. baseline capture ----------------------------------------------------

#[test]
fn baseline_captures_real_head_sha_and_clean_flag() {
    if !git_available() {
        eprintln!("skipping: git not available");
        return;
    }
    let repo = init_repo();
    let g = gate(repo.path());

    let base = g.record_baseline(repo.path()).expect("baseline captured");

    // The recorded sha is the real 40-char HEAD of the temp repo.
    let head = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(repo.path())
        .output()
        .expect("rev-parse");
    let expected = String::from_utf8_lossy(&head.stdout).trim().to_string();
    assert_eq!(base.head_sha.len(), 40, "full HEAD sha recorded");
    assert_eq!(base.head_sha, expected, "recorded sha matches real HEAD");
    assert!(!base.dirty, "freshly committed tree is clean");
}

#[test]
fn baseline_reports_dirty_after_worktree_edit() {
    if !git_available() {
        eprintln!("skipping: git not available");
        return;
    }
    let repo = init_repo();
    fs::write(repo.path().join("src/keep.txt"), "changed\n").unwrap();
    let g = gate(repo.path());

    let base = g.record_baseline(repo.path()).expect("baseline captured");

    assert!(base.dirty, "modified working tree is dirty");
}

// --- 2. changed-set computation --------------------------------------------

#[test]
fn changed_files_reports_added_modified_deleted() {
    if !git_available() {
        eprintln!("skipping: git not available");
        return;
    }
    let repo = init_repo();
    let g = gate(repo.path());
    let base = g.record_baseline(repo.path()).unwrap();

    // Modify a tracked file, add an untracked file, delete a tracked file.
    fs::write(repo.path().join("src/keep.txt"), "modified\n").unwrap();
    fs::write(repo.path().join("src/new.txt"), "brand new\n").unwrap();
    fs::remove_file(repo.path().join("src/gone.txt")).unwrap();

    let changes = g.changed_files(repo.path(), &base).unwrap();

    let kind_of = |p: &str| {
        changes
            .iter()
            .find(|c| c.path == Path::new(p))
            .map(|c| c.kind)
    };
    assert_eq!(kind_of("src/keep.txt"), Some(ChangeKind::Modified));
    assert_eq!(kind_of("src/new.txt"), Some(ChangeKind::Added));
    assert_eq!(kind_of("src/gone.txt"), Some(ChangeKind::Deleted));
    assert_eq!(changes.len(), 3, "exactly the three edits are reported");
}

// --- 3. selective apply -----------------------------------------------------

#[test]
fn apply_is_selective_allow_applied_deny_rejected() {
    if !git_available() {
        eprintln!("skipping: git not available");
        return;
    }
    // Build a real repo, then make edits under both an allowed and a denied
    // path. The changed set is computed from git, not hand-built.
    let repo = init_repo();
    git(repo.path(), &["config", "user.email", "test@example.com"]);
    let g = gate(repo.path());
    let base = g.record_baseline(repo.path()).unwrap();

    fs::create_dir_all(repo.path().join("secret")).unwrap();
    fs::write(repo.path().join("src/ok.txt"), "fine\n").unwrap(); // allow → add
    fs::write(repo.path().join("secret/key.txt"), "nope\n").unwrap(); // deny → add

    let mut changes = g.changed_files(repo.path(), &base).unwrap();
    changes.sort_by(|a, b| a.path.cmp(&b.path));
    assert_eq!(changes.len(), 2, "two untracked additions");

    let mut h = ApplyHarness::new(RecordingDispatcher::succeeding());
    let report = h.apply(&g, Mode::Enforce, true, &changes);

    assert_eq!(report.applied, 1, "only the src/** allow path applies");
    assert_eq!(report.rejected, 1, "the secret/** deny path is rejected");
    assert!(report.failures.is_empty(), "no apply failures");
    assert_eq!(report.exit_code, EXIT_SUCCESS);
    // The denied change never reaches the dispatcher → workspace unchanged.
    assert_eq!(
        h.dispatcher.count(),
        1,
        "only the allowed change dispatched"
    );
}

// --- 4. exit code 7 on apply failure ---------------------------------------

#[test]
fn apply_failure_yields_exit_code_7_with_failing_path() {
    if !git_available() {
        eprintln!("skipping: git not available");
        return;
    }
    let repo = init_repo();
    let g = gate(repo.path());
    let base = g.record_baseline(repo.path()).unwrap();

    fs::write(repo.path().join("src/ok.txt"), "fine\n").unwrap(); // allow → add

    let changes = g.changed_files(repo.path(), &base).unwrap();
    assert_eq!(changes.len(), 1);

    // The permitted change's dispatch reports a non-zero (apply) failure.
    let mut h = ApplyHarness::new(RecordingDispatcher::new(EXIT_APPLY_FAILED));
    let report = h.apply(&g, Mode::Enforce, true, &changes);

    assert_eq!(
        report.applied, 0,
        "the failed apply is not counted as applied"
    );
    assert_eq!(report.failures, vec![PathBuf::from("src/ok.txt")]);
    assert_eq!(report.exit_code, EXIT_APPLY_FAILED, "exit code 7 surfaced");
}
