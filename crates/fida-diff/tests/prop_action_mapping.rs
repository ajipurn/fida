//! Property test for the File_Diff_Gate's file-change action mapping and
//! allow-vs-deny apply semantics (spec task 14.2 / design "File Diff Gate
//! Design").
//!
//! Feature: fida-mvp, Property 9: File-change action mapping
//!
//!
//! The property has two parts:
//!
//! 1. *Action mapping*: for an arbitrary [`ChangedFile`],
//!    `action_for_change` yields an `ActionKind::FileWrite` for an added or
//!    modified path and an `ActionKind::FileDelete` for a deleted path, and the
//!    resulting action's `File` payload carries exactly the change's path.
//!
//! 2. *Apply allow vs deny*: with a policy that allows writes
//!    under `src/**` and denies `secret/**`, applying an arbitrary mix of
//!    changed files under those two trees applies every `allow` path (counted
//!    and dispatched) and never applies a `deny` path — the deny path is
//!    rejected, never reaches the dispatcher, and leaves the workspace
//!    unchanged.

use std::fs;
use std::path::PathBuf;

use proptest::prelude::*;

use fida_action::{ActionKind, ActionPayload, Mode};
use fida_broker::testing::{MemoryAuditStore, RecordingDispatcher, ScriptedApprovalUi};
use fida_broker::{Broker, BrokerContext, EXIT_SUCCESS, RememberedDecisions, SessionHandle};
use fida_diff::{ChangeKind, ChangedFile, FileDiffGate, GitFileDiffGate, action_for_change};
use fida_policy::{CompiledPolicy, PolicySource, load_source};

const SESSION: &str = "2026-06-12T070000Z-prop09";

/// Allows writes under `src/**`, denies `secret/**`; everything else falls
/// through to the global `ask` default. `block_in_diffs` is on so the secret
/// gate participates (the generated files carry no secrets, so it never fires).
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

/// Compile [`TEST_POLICY`] into a [`CompiledPolicy`].
fn compile() -> CompiledPolicy {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("fida.yaml");
    fs::write(&path, TEST_POLICY).unwrap();
    let policy = load_source(&PolicySource::Config(path), None).expect("policy compiles");
    drop(dir);
    policy
}

/// Whether a change kind carries content (mirrors the gate's internal rule).
fn content_bearing(kind: ChangeKind) -> bool {
    matches!(kind, ChangeKind::Added | ChangeKind::Modified)
}

/// Strategy over the three change kinds.
fn change_kind() -> impl Strategy<Value = ChangeKind> {
    prop_oneof![
        Just(ChangeKind::Added),
        Just(ChangeKind::Modified),
        Just(ChangeKind::Deleted),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 100, ..ProptestConfig::default() })]

    /// Part 1 — `action_for_change` maps kinds and preserves the path.
    #[test]
    fn action_mapping_kind_and_path(
        path in "[a-zA-Z0-9_./-]{1,24}",
        kind in change_kind(),
    ) {
        let change = ChangedFile { path: PathBuf::from(&path), kind };
        let action = action_for_change(&change);

        match kind {
            ChangeKind::Added | ChangeKind::Modified => {
                prop_assert_eq!(action.kind, ActionKind::FileWrite);
            }
            ChangeKind::Deleted => {
                prop_assert_eq!(action.kind, ActionKind::FileDelete);
            }
        }

        match &action.payload {
            ActionPayload::File { path: p } => prop_assert_eq!(p, &change.path),
            other => prop_assert!(false, "expected a File payload, got {:?}", other),
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 100, ..ProptestConfig::default() })]

    /// Part 2 — applying a mix of `src/**` (allow) and `secret/**` (deny)
    /// changes applies only allow paths and leaves deny paths unchanged
    #[test]
    fn apply_applies_allow_and_leaves_deny_unchanged(
        allow_kinds in prop::collection::vec(change_kind(), 0..5),
        deny_kinds in prop::collection::vec(change_kind(), 0..5),
    ) {
        let src = tempfile::tempdir().unwrap();
        fs::create_dir_all(src.path().join("src")).unwrap();
        fs::create_dir_all(src.path().join("secret")).unwrap();

        let mut changes = Vec::new();

        // Allow tree: writes under src/** resolve to allow.
        for (i, &kind) in allow_kinds.iter().enumerate() {
            let rel = format!("src/f{i}.txt");
            if content_bearing(kind) {
                fs::write(src.path().join(&rel), "ordinary content\n").unwrap();
            }
            changes.push(ChangedFile { path: PathBuf::from(rel), kind });
        }

        // Deny tree: writes under secret/** resolve to deny.
        for (i, &kind) in deny_kinds.iter().enumerate() {
            let rel = format!("secret/f{i}.txt");
            if content_bearing(kind) {
                fs::write(src.path().join(&rel), "ordinary content\n").unwrap();
            }
            changes.push(ChangedFile { path: PathBuf::from(rel), kind });
        }

        let policy = compile();
        let mut session = SessionHandle::new(SESSION);
        let mut remembered = RememberedDecisions::new();
        let mut audit = MemoryAuditStore::new();
        let mut dispatcher = RecordingDispatcher::succeeding();
        // Interactive so an `ask` would prompt rather than fail closed; the
        // always-denying UI guards against any unexpected `ask` slipping
        // through (all generated paths resolve to allow or deny, never ask).
        let gate = GitFileDiffGate::new(
            Broker::new(ScriptedApprovalUi::always_denying()),
            src.path(),
        );

        let report = {
            let mut ctx = BrokerContext {
                policy: &policy,
                mode: Mode::Enforce,
                interactive: true,
                yes: false,
                session: &mut session,
                remembered: &mut remembered,
                audit: &mut audit,
                dispatcher: &mut dispatcher,
            };
            gate.apply(&mut ctx, &changes)
        };

        let allow_count = allow_kinds.len();
        let deny_count = deny_kinds.len();

        // Allow paths are applied; deny paths are rejected; nothing fails.
        prop_assert_eq!(report.applied, allow_count);
        prop_assert_eq!(report.rejected, deny_count);
        prop_assert!(report.failures.is_empty());
        prop_assert_eq!(report.exit_code, EXIT_SUCCESS);

        // Only allow paths reach the dispatcher; deny paths never do, so the
        // workspace is left unchanged for every deny path.
        prop_assert_eq!(dispatcher.count(), allow_count);
        for action in &dispatcher.dispatched {
            if let ActionPayload::File { path } = &action.payload {
                prop_assert!(
                    path.starts_with("src"),
                    "only allow (src/**) paths may be dispatched, got {:?}",
                    path
                );
            } else {
                prop_assert!(false, "diff gate must dispatch File actions only");
            }
        }
    }
}
