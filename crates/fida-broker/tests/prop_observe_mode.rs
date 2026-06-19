//! Property test for observe-mode semantics (design "Session Modes",
//! Property 19.
//!
//! Feature: fida-mvp, Property 19: Observe mode never blocks
//!
//! *For any* action evaluated while the session is in `observe` mode, the
//! broker records exactly one audit event and permits the action regardless
//! of the decision the evaluator would have reached in `enforce` mode — it
//! never blocks and never prompts.

use std::path::PathBuf;

use proptest::prelude::*;

use fida_action::{Action, ActionKind, ActionPayload, Actor, Finding, Mode};
use fida_audit::{AuditResult, AuditStore};
use fida_broker::testing::{MemoryAuditStore, RecordingDispatcher, ScriptedApprovalUi};
use fida_broker::{
    ActionBroker, ActionResult, Broker, BrokerContext, EXIT_SUCCESS, RememberedDecisions,
    SessionHandle,
};
use fida_policy::{CompiledPolicy, PolicySource, load_source};

const SESSION: &str = "2026-06-12T070000Z-observe";

/// A mixed policy: one allow rule, one plain `ask` rule, one auto-approval
/// `ask` rule, a destructive `deny` rule, and a global `ask` default. In
/// `enforce` mode these would resolve to allow / ask / deny respectively; in
/// `observe` mode every one of them must be permitted.
const MIXED_POLICY: &str = r#"
version: 1
default_decision: ask

commands:
  allow:
    - exact: git status
  ask:
    - prefix: pnpm install
      reason: installs can run lifecycle scripts
    - prefix: cargo fmt
      reason: formatting is low risk
      auto_approve: true
  deny:
    - regex: "rm\\s+-rf\\s+(/|~|\\.)"
      reason: destructive remove

files:
  read:
    allow: ["**/*"]
  write:
    allow: ["src/**"]

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

fn compile(raw: &str) -> CompiledPolicy {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("fida.yaml");
    std::fs::write(&path, raw).unwrap();
    load_source(&PolicySource::Config(path), None).expect("policy compiles")
}

fn command(argv: Vec<String>) -> Action {
    Action {
        kind: ActionKind::CommandRun,
        actor: Actor::Agent,
        payload: ActionPayload::Command {
            argv,
            cwd: PathBuf::from("/repo"),
        },
    }
}

fn command_str(cmd: &str) -> Action {
    command(cmd.split_whitespace().map(str::to_string).collect())
}

fn secret_action() -> Action {
    Action {
        kind: ActionKind::SecretDetected,
        actor: Actor::Agent,
        payload: ActionPayload::Secret {
            finding: Finding {
                pattern_id: "private_key".to_string(),
                reason: "PEM header".to_string(),
            },
        },
    }
}

/// Generate a diverse spread of actions covering every `enforce`-mode decision
/// branch: hard `deny` (`rm -rf …`, secret), `allow` (`git status`), plain
/// `ask` (`pnpm install …`), auto-approve `ask` (`cargo fmt …`), and arbitrary
/// benign commands that fall through to the global `ask` default.
fn action_strategy() -> impl Strategy<Value = Action> {
    prop_oneof![
        // Would hard-deny in enforce.
        Just(command_str("rm -rf /")),
        Just(command_str("rm -rf ~")),
        Just(command_str("rm -rf .")),
        Just(secret_action()),
        // Would allow in enforce.
        Just(command_str("git status")),
        // Would ask in enforce (plain rule).
        Just(command_str("pnpm install lodash")),
        // Would ask in enforce (auto-approve rule).
        Just(command_str("cargo fmt --all")),
        // Arbitrary benign commands → fall through to the global `ask` default.
        proptest::collection::vec("[a-z][a-z0-9_-]{0,7}", 1..4).prop_map(command),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 100, ..ProptestConfig::default() })]

    /// Property 19: in observe mode, any action — including ones that would
    /// `deny`, `ask`, or `allow` in enforce mode — is permitted, dispatched,
    /// never prompted, and audited exactly once as `Allowed`.
    #[test]
    fn observe_mode_permits_audits_and_never_prompts(action in action_strategy()) {
        let policy = compile(MIXED_POLICY);
        let ui = ScriptedApprovalUi::always_denying();
        let mut session = SessionHandle::new(SESSION);
        let mut remembered = RememberedDecisions::new();
        let mut audit = MemoryAuditStore::new();
        let mut dispatcher = RecordingDispatcher::succeeding();

        let broker = Broker::new(&ui);
        let out = {
            let mut ctx = BrokerContext {
                policy: &policy,
                mode: Mode::Observe,
                interactive: false,
                yes: false,
                session: &mut session,
                remembered: &mut remembered,
                audit: &mut audit,
                dispatcher: &mut dispatcher,
            };
            broker.handle(&mut ctx, action)
        };

        // Permitted regardless of the underlying decision, with success exit.
        prop_assert_eq!(out.result, ActionResult::Permitted);
        prop_assert_eq!(out.exit_code, EXIT_SUCCESS);

        // Observe permits and dispatches the action exactly once.
        prop_assert_eq!(dispatcher.count(), 1);

        // Observe never blocks via the approval UI.
        prop_assert_eq!(ui.prompt_count(), 0);

        // Exactly one audit event, recorded as Allowed (never blocked/denied).
        let events = audit.read(SESSION).unwrap();
        prop_assert_eq!(events.len(), 1);
        prop_assert_eq!(events[0].result, AuditResult::Allowed);
    }
}
