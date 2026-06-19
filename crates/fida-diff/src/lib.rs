//! `fida-diff` — the File_Diff_Gate: capture a git baseline at session
//! start, compute the changed set at session end, map each change to a file
//! [`Action`], and apply changes through the [`ActionBroker`] chokepoint
//! (design "File Diff Gate Design").
//!
//! The gate never decides policy itself. It produces normalized [`Action`]s —
//! added/modified paths become `file.write`, deleted paths become
//! `file.delete` — and routes each one through the broker so the same
//! evaluate → mode → approval → dispatch → audit pipeline that gates commands
//! also gates file changes. The broker's injected [`ActionDispatcher`] performs
//! the concrete copy/delete into the main workspace; the gate only orchestrates
//! and tallies the result.
//!
//! # Baseline and changed set
//!
//! [`GitFileDiffGate::record_baseline`] records `HEAD` and the working-tree
//! dirty flag via the `git` CLI. A capture failure is a
//! [`DiffError::BaselineCapture`], which the caller treats as preventing the
//! session from starting. [`GitFileDiffGate::changed_files`] diffs the
//! working tree against the baseline commit and folds in untracked files,
//! yielding added/modified/deleted [`ChangedFile`]s.
//!
//! # Apply semantics
//!
//! [`GitFileDiffGate::apply`] walks the changed set and, for each change:
//!
//! * when `block_in_diffs` is enabled and a content-bearing change contains a
//!   detected secret, blocks the file, leaves the workspace unmodified, and
//!   raises exit code 6;
//! * otherwise routes the file [`Action`] through the broker — `allow` is
//!   applied, `deny` leaves the path unchanged, an `ask` is applied only after
//!   interactive approval and skipped non-interactively;
//! * a permitted change whose dispatch reports a non-zero code is an apply
//!   failure recorded in [`ApplyReport::failures`] and raises exit code 7
//!
//! The returned [`ApplyReport`] carries applied/rejected counts plus
//! the worst exit code observed so the CLI can surface 6/7 as required.

use std::path::{Path, PathBuf};
use std::process::Command;

use fida_action::{Action, ActionKind, ActionPayload, Actor};
use fida_broker::{ActionBroker, ActionResult, BrokerContext, EXIT_SECRET_BLOCKED, EXIT_SUCCESS};
use fida_secrets::{Scanner, SecretScanner};

/// Exit code surfaced when the diff gate cannot apply one or more approved
/// changes to the main workspace.
pub const EXIT_APPLY_FAILED: u8 = 7;

// ---------------------------------------------------------------------------
// Baseline and changed-set model
// ---------------------------------------------------------------------------

/// The git state captured at session start.
///
/// Mirrors `fida_session::Baseline`; defined locally because `fida-diff`
/// does not depend on `fida-session`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Baseline {
    /// The `HEAD` commit SHA at session start.
    pub head_sha: String,
    /// Whether the working tree had uncommitted changes at session start.
    pub dirty: bool,
}

/// How a path changed relative to the baseline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeKind {
    /// The path did not exist at baseline and now exists.
    Added,
    /// The path existed at baseline and its contents changed.
    Modified,
    /// The path existed at baseline and was removed.
    Deleted,
}

/// A single path that changed during the session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangedFile {
    /// The repo-relative path that changed.
    pub path: PathBuf,
    /// How it changed.
    pub kind: ChangeKind,
}

/// The tally produced by an apply operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyReport {
    /// Number of changes successfully applied to the main workspace.
    pub applied: usize,
    /// Number of changes rejected without an error: `deny` decisions,
    /// unapproved `ask` decisions, and secret-blocked diffs.
    pub rejected: usize,
    /// Paths that were permitted but could not be applied (drives exit 7).
    pub failures: Vec<PathBuf>,
    /// Paths rejected by policy, missing approval, dry-run, or secret blocking.
    pub rejected_paths: Vec<PathBuf>,
    /// The worst exit code observed across the operation: `0` normally,
    /// [`EXIT_SECRET_BLOCKED`] (6) when a secret-bearing diff was blocked, or
    /// [`EXIT_APPLY_FAILED`] (7) when an approved change failed to apply.
    pub exit_code: u8,
}

impl ApplyReport {
    /// An empty report with a success exit code.
    fn new() -> Self {
        ApplyReport {
            applied: 0,
            rejected: 0,
            failures: Vec::new(),
            rejected_paths: Vec::new(),
            exit_code: EXIT_SUCCESS,
        }
    }

    /// Raise the report's exit code to `code` if it is more severe (larger).
    /// Apply failure (7) dominates a secret block (6), which dominates success.
    fn raise(&mut self, code: u8) {
        if code > self.exit_code {
            self.exit_code = code;
        }
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Failures surfaced by the diff gate.
#[derive(Debug)]
pub enum DiffError {
    /// The starting git state could not be captured; the session must not start
    BaselineCapture(String),
    /// A `git` invocation failed.
    Git(String),
    /// An underlying I/O error (e.g. `git` could not be spawned).
    Io(std::io::Error),
}

impl std::fmt::Display for DiffError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DiffError::BaselineCapture(msg) => {
                write!(f, "could not capture workspace git state: {msg}")
            }
            DiffError::Git(msg) => write!(f, "git command failed: {msg}"),
            DiffError::Io(err) => write!(f, "git could not be run: {err}"),
        }
    }
}

impl std::error::Error for DiffError {}

impl From<std::io::Error> for DiffError {
    fn from(err: std::io::Error) -> Self {
        DiffError::Io(err)
    }
}

// ---------------------------------------------------------------------------
// File_Diff_Gate contract
// ---------------------------------------------------------------------------

/// The File_Diff_Gate contract (design "File Diff Gate Design").
pub trait FileDiffGate {
    /// Record the starting git state as the session baseline.
    fn record_baseline(&self, repo: &Path) -> Result<Baseline, DiffError>;

    /// Compute the set of files changed relative to `base`.
    fn changed_files(&self, repo: &Path, base: &Baseline) -> Result<Vec<ChangedFile>, DiffError>;

    /// Apply the changed set through the broker, honoring allow/deny/ask and
    /// `block_in_diffs`.
    fn apply(&self, ctx: &mut BrokerContext, changes: &[ChangedFile]) -> ApplyReport;
}

/// Map a single changed path to the file [`Action`] the broker evaluates:
/// added/modified → `file.write`, deleted → `file.delete`.
///
/// This is the pure mapping exercised by the file-change-action property
/// (task 14.2 / Property 9).
pub fn action_for_change(change: &ChangedFile) -> Action {
    let kind = match change.kind {
        ChangeKind::Added | ChangeKind::Modified => ActionKind::FileWrite,
        ChangeKind::Deleted => ActionKind::FileDelete,
    };
    Action {
        kind,
        actor: Actor::Agent,
        payload: ActionPayload::File {
            path: change.path.clone(),
        },
    }
}

// ---------------------------------------------------------------------------
// git-backed implementation
// ---------------------------------------------------------------------------

/// The concrete File_Diff_Gate, backed by the `git` CLI and an
/// [`ActionBroker`].
///
/// `source_root` is the workspace the session's changes live in (the `current`
/// tree, a `copy`, or a `git-worktree`); the gate reads file content from there
/// when scanning a diff for secrets.
#[derive(Debug, Clone)]
pub struct GitFileDiffGate<B: ActionBroker> {
    broker: B,
    source_root: PathBuf,
}

impl<B: ActionBroker> GitFileDiffGate<B> {
    /// Construct a gate that routes file actions through `broker` and reads
    /// changed-file content (for secret scanning) from `source_root`.
    pub fn new(broker: B, source_root: impl Into<PathBuf>) -> Self {
        GitFileDiffGate {
            broker,
            source_root: source_root.into(),
        }
    }
}

/// Run `git` in `repo` and return its stdout, mapping non-zero exit and spawn
/// failure to a [`DiffError`].
fn run_git(repo: &Path, args: &[&str]) -> Result<String, DiffError> {
    let output = Command::new("git")
        .args(args)
        .current_dir(repo)
        .output()
        .map_err(DiffError::Io)?;
    if !output.status.success() {
        return Err(DiffError::Git(format!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

impl<B: ActionBroker> FileDiffGate for GitFileDiffGate<B> {
    fn record_baseline(&self, repo: &Path) -> Result<Baseline, DiffError> {
        // A capture failure must prevent session start, so both probes map to
        // BaselineCapture.
        let head = run_git(repo, &["rev-parse", "HEAD"])
            .map_err(|e| DiffError::BaselineCapture(e.to_string()))?;
        let status = run_git(repo, &["status", "--porcelain"])
            .map_err(|e| DiffError::BaselineCapture(e.to_string()))?;
        Ok(Baseline {
            head_sha: head.trim().to_string(),
            dirty: !status.trim().is_empty(),
        })
    }

    fn changed_files(&self, repo: &Path, base: &Baseline) -> Result<Vec<ChangedFile>, DiffError> {
        let mut changes = Vec::new();

        // Tracked changes: working tree vs the baseline commit.
        let diff = run_git(repo, &["diff", "--name-status", &base.head_sha])?;
        for line in diff.lines() {
            if line.is_empty() {
                continue;
            }
            let mut parts = line.split('\t');
            let status = parts.next().unwrap_or("");
            match status.chars().next() {
                Some('A') => push(&mut changes, parts.next(), ChangeKind::Added),
                Some('M') => push(&mut changes, parts.next(), ChangeKind::Modified),
                Some('D') => push(&mut changes, parts.next(), ChangeKind::Deleted),
                // Rename/copy carry `old\tnew`: model as delete-old + add-new.
                Some('R') | Some('C') => {
                    push(&mut changes, parts.next(), ChangeKind::Deleted);
                    push(&mut changes, parts.next(), ChangeKind::Added);
                }
                _ => {}
            }
        }

        // Untracked files are additions `git diff` does not report.
        let untracked = run_git(repo, &["ls-files", "--others", "--exclude-standard"])?;
        for line in untracked.lines() {
            if !line.is_empty() {
                changes.push(ChangedFile {
                    path: PathBuf::from(line),
                    kind: ChangeKind::Added,
                });
            }
        }

        Ok(changes)
    }

    fn apply(&self, ctx: &mut BrokerContext, changes: &[ChangedFile]) -> ApplyReport {
        let mut report = ApplyReport::new();
        let block_secrets = ctx.policy.secrets.block_in_diffs;
        let scanner = Scanner::new(&ctx.policy.secrets);

        for change in changes {
            // Secret gate: a content-bearing diff with a detected secret is
            // blocked before reaching the broker; the workspace stays unchanged
            // and the apply surfaces exit 6.
            if block_secrets && content_bearing(change.kind) {
                let full = self.source_root.join(&change.path);
                if let Ok(content) = std::fs::read_to_string(&full) {
                    if let Some(finding) = scanner.scan(&content).into_iter().next() {
                        let secret_action = Action {
                            kind: ActionKind::SecretDetected,
                            actor: Actor::Agent,
                            payload: ActionPayload::Secret { finding },
                        };
                        let _ = self.broker.handle(ctx, secret_action);
                        report.rejected += 1;
                        report.rejected_paths.push(change.path.clone());
                        report.raise(EXIT_SECRET_BLOCKED);
                        continue;
                    }
                }
            }

            let action = action_for_change(change);
            let outcome = self.broker.handle(ctx, action);
            match outcome.result {
                // allow / approved ask / remembered: the dispatcher performed
                // the apply. A non-zero dispatch code means the write/delete
                // failed → exit 7.
                ActionResult::Permitted => {
                    if outcome.exit_code == EXIT_SUCCESS {
                        report.applied += 1;
                    } else {
                        report.failures.push(change.path.clone());
                        report.raise(EXIT_APPLY_FAILED);
                    }
                }
                // deny, unapproved ask, or dry-run: nothing
                // applied, workspace unchanged.
                ActionResult::Denied | ActionResult::Blocked | ActionResult::WouldRun => {
                    report.rejected += 1;
                    report.rejected_paths.push(change.path.clone());
                }
            }
        }

        report
    }
}

/// Whether a change kind carries file content that can be scanned for secrets.
fn content_bearing(kind: ChangeKind) -> bool {
    matches!(kind, ChangeKind::Added | ChangeKind::Modified)
}

/// Push a [`ChangedFile`] for `path` (when present) with the given kind.
fn push(changes: &mut Vec<ChangedFile>, path: Option<&str>, kind: ChangeKind) {
    if let Some(p) = path {
        if !p.is_empty() {
            changes.push(ChangedFile {
                path: PathBuf::from(p),
                kind,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs;
    use std::path::Path;

    use fida_action::Mode;
    use fida_audit::AuditStore;
    use fida_broker::testing::{MemoryAuditStore, RecordingDispatcher, ScriptedApprovalUi};
    use fida_broker::{Broker, RememberedDecisions, SessionHandle};
    use fida_policy::{CompiledPolicy, PolicySource, load_source};

    const SESSION: &str = "2026-06-12T070000Z-diff01";

    /// Allows writes under `src/**`, denies `secret/**`; everything else falls
    /// through to the global `ask` default. `block_in_diffs` is on so the
    /// secret gate is exercised.
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

    // --- git fixture helpers ------------------------------------------------

    fn git(repo: &Path, args: &[&str]) {
        let status = std::process::Command::new("git")
            .args(args)
            .current_dir(repo)
            .output()
            .expect("git runs");
        assert!(
            status.status.success(),
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&status.stderr)
        );
    }

    /// Initialize a repo with one committed file and return its temp dir.
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

    fn compile() -> CompiledPolicy {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fida.yaml");
        fs::write(&path, TEST_POLICY).unwrap();
        // Keep dir alive for the load call.
        let policy = load_source(&PolicySource::Config(path), None).expect("policy compiles");
        drop(dir);
        policy
    }

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
                policy: compile(),
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
        ) -> ApplyReport {
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

    fn gate(source_root: &Path) -> GitFileDiffGate<Broker<ScriptedApprovalUi>> {
        GitFileDiffGate::new(
            Broker::new(ScriptedApprovalUi::always_denying()),
            source_root,
        )
    }

    // --- baseline -----------------------------------------------------------

    #[test]
    fn record_baseline_captures_head_and_clean_flag() {
        let repo = init_repo();
        let g = gate(repo.path());
        let base = g.record_baseline(repo.path()).expect("baseline");
        assert_eq!(base.head_sha.len(), 40, "full HEAD sha recorded");
        assert!(!base.dirty, "freshly committed tree is clean");
    }

    #[test]
    fn record_baseline_reports_dirty_when_worktree_modified() {
        let repo = init_repo();
        fs::write(repo.path().join("src/keep.txt"), "changed\n").unwrap();
        let g = gate(repo.path());
        let base = g.record_baseline(repo.path()).expect("baseline");
        assert!(base.dirty, "modified working tree is dirty");
    }

    #[test]
    fn record_baseline_fails_outside_git_repo() {
        let dir = tempfile::tempdir().unwrap();
        let g = gate(dir.path());
        let err = g.record_baseline(dir.path()).unwrap_err();
        assert!(
            matches!(err, DiffError::BaselineCapture(_)),
            "non-repo capture must prevent session start, got {err:?}"
        );
    }

    // --- changed set --------------------------------------------------------

    #[test]
    fn changed_files_detects_add_modify_delete() {
        let repo = init_repo();
        let g = gate(repo.path());
        let base = g.record_baseline(repo.path()).unwrap();

        // modify tracked, delete tracked, add untracked.
        fs::write(repo.path().join("src/keep.txt"), "modified\n").unwrap();
        fs::write(repo.path().join("src/new.txt"), "brand new\n").unwrap();
        fs::remove_file(repo.path().join("src/gone.txt")).unwrap();

        let mut changes = g.changed_files(repo.path(), &base).unwrap();
        changes.sort_by(|a, b| a.path.cmp(&b.path));

        let find = |p: &str| {
            changes
                .iter()
                .find(|c| c.path == Path::new(p))
                .map(|c| c.kind)
        };
        assert_eq!(find("src/keep.txt"), Some(ChangeKind::Modified));
        assert_eq!(find("src/new.txt"), Some(ChangeKind::Added));
        assert_eq!(find("src/gone.txt"), Some(ChangeKind::Deleted));
    }

    // --- action mapping -----------------------------------------------------

    #[test]
    fn action_for_change_maps_kinds() {
        let added = action_for_change(&ChangedFile {
            path: PathBuf::from("src/a"),
            kind: ChangeKind::Added,
        });
        let modified = action_for_change(&ChangedFile {
            path: PathBuf::from("src/b"),
            kind: ChangeKind::Modified,
        });
        let deleted = action_for_change(&ChangedFile {
            path: PathBuf::from("src/c"),
            kind: ChangeKind::Deleted,
        });
        assert_eq!(added.kind, ActionKind::FileWrite);
        assert_eq!(modified.kind, ActionKind::FileWrite);
        assert_eq!(deleted.kind, ActionKind::FileDelete);
    }

    // --- apply --------------------------------------------------------------

    #[test]
    fn apply_applies_allow_and_rejects_deny() {
        let src = tempfile::tempdir().unwrap();
        fs::create_dir_all(src.path().join("src")).unwrap();
        fs::create_dir_all(src.path().join("secret")).unwrap();
        fs::write(src.path().join("src/ok.txt"), "fine\n").unwrap();
        fs::write(src.path().join("secret/key.txt"), "nope\n").unwrap();

        let g = gate(src.path());
        let mut h = ApplyHarness::new(RecordingDispatcher::succeeding());
        let changes = vec![
            ChangedFile {
                path: PathBuf::from("src/ok.txt"),
                kind: ChangeKind::Added,
            },
            ChangedFile {
                path: PathBuf::from("secret/key.txt"),
                kind: ChangeKind::Modified,
            },
        ];
        let report = h.apply(&g, Mode::Enforce, true, &changes);

        assert_eq!(report.applied, 1, "only the allow path applies");
        assert_eq!(report.rejected, 1, "deny path is rejected");
        assert!(report.failures.is_empty());
        assert_eq!(report.exit_code, EXIT_SUCCESS);
        assert_eq!(h.dispatcher.count(), 1, "deny never reaches dispatch");
    }

    #[test]
    fn apply_blocks_secret_diff_with_exit_6() {
        let src = tempfile::tempdir().unwrap();
        fs::create_dir_all(src.path().join("src")).unwrap();
        fs::write(
            src.path().join("src/leak.txt"),
            "-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----\n",
        )
        .unwrap();

        let g = gate(src.path());
        let mut h = ApplyHarness::new(RecordingDispatcher::succeeding());
        let changes = vec![ChangedFile {
            path: PathBuf::from("src/leak.txt"),
            kind: ChangeKind::Added,
        }];
        let report = h.apply(&g, Mode::Enforce, true, &changes);

        assert_eq!(report.applied, 0, "secret-bearing diff not applied");
        assert_eq!(report.rejected, 1);
        assert_eq!(report.exit_code, EXIT_SECRET_BLOCKED);
        assert_eq!(
            h.dispatcher.count(),
            0,
            "blocked diff never reaches dispatch; workspace unchanged"
        );
        let events = h.audit.read(SESSION).unwrap();
        assert!(events.iter().any(|event| matches!(
            &event.action,
            fida_audit::AuditAction::SecretDetected { .. }
        )));
    }

    #[test]
    fn apply_failed_dispatch_yields_exit_7() {
        let src = tempfile::tempdir().unwrap();
        fs::create_dir_all(src.path().join("src")).unwrap();
        fs::write(src.path().join("src/ok.txt"), "fine\n").unwrap();

        let g = gate(src.path());
        // Permitted action whose dispatch reports a non-zero (apply) failure.
        let mut h = ApplyHarness::new(RecordingDispatcher::new(EXIT_APPLY_FAILED));
        let changes = vec![ChangedFile {
            path: PathBuf::from("src/ok.txt"),
            kind: ChangeKind::Added,
        }];
        let report = h.apply(&g, Mode::Enforce, true, &changes);

        assert_eq!(report.applied, 0);
        assert_eq!(report.failures, vec![PathBuf::from("src/ok.txt")]);
        assert_eq!(report.exit_code, EXIT_APPLY_FAILED);
    }

    #[test]
    fn apply_skips_ask_when_non_interactive() {
        let src = tempfile::tempdir().unwrap();
        fs::create_dir_all(src.path().join("docs")).unwrap();
        fs::write(src.path().join("docs/readme.md"), "hi\n").unwrap();

        let g = gate(src.path());
        let mut h = ApplyHarness::new(RecordingDispatcher::succeeding());
        // `docs/**` matches no allow/deny → global default ask → non-interactive
        // blocks it.
        let changes = vec![ChangedFile {
            path: PathBuf::from("docs/readme.md"),
            kind: ChangeKind::Added,
        }];
        let report = h.apply(&g, Mode::Enforce, false, &changes);

        assert_eq!(report.applied, 0);
        assert_eq!(report.rejected, 1);
        assert_eq!(h.dispatcher.count(), 0, "unapproved ask is not applied");
    }
}
