// Feature: fida-mvp, Property 6: Non-interactive ask fails closed
//
// Property 6: Non-interactive ask fails closed — any `ask` while
// non-interactive with no remembered match blocks without executing and
// records a blocked-needs-approval event.
//
//
// Strategy: build a policy whose global `default_decision` is `ask` with empty
// rule sections, so any benign command that hits no hard deny falls through to
// the global `ask` default. Drive each generated command through the broker in
// `enforce` mode with `interactive=false`, `yes=false`, and an EMPTY
// `RememberedDecisions`. For every case the broker must fail closed: block the
// action, surface EXIT_APPROVAL_REQUIRED, dispatch nothing, never prompt, and
// record exactly one blocked-needs-approval audit event.

use std::path::PathBuf;

use proptest::prelude::*;

use fida_action::{Action, ActionKind, ActionPayload, Actor, Mode};
use fida_audit::{AuditResult, AuditStore};
use fida_broker::testing::{MemoryAuditStore, RecordingDispatcher, ScriptedApprovalUi};
use fida_broker::{
    ActionBroker, ActionResult, Broker, BrokerContext, EXIT_APPROVAL_REQUIRED, RememberedDecisions,
    SessionHandle,
};
use fida_policy::{CompiledPolicy, PolicySource, load_source};

const SESSION: &str = "2026-06-12T070000Z-prop06";

/// A policy with empty rule sections and a global `ask` default, so any benign
/// command that matches no rule and trips no hard deny resolves to `ask`.
const ASK_DEFAULT_POLICY: &str = r#"
version: 1
default_decision: ask

commands: {}

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

/// Generate a benign command (binary + 0..=3 args) drawn from a clearly safe
/// charset so it never trips a built-in hard deny (no `rm -rf`, no `curl | sh`)
/// and matches no explicit rule — every such command falls through to the
/// global `ask` default.
fn benign_command() -> impl Strategy<Value = Vec<String>> {
    let binary = prop::sample::select(vec![
        "ls", "echo", "cat", "pwd", "date", "whoami", "head", "wc", "grep", "find",
    ])
    .prop_map(str::to_string);

    let arg = "[a-z0-9_][a-z0-9_-]{0,7}";
    let args = prop::collection::vec(arg, 0..=3);

    (binary, args).prop_map(|(bin, args)| {
        let mut argv = vec![bin];
        argv.extend(args);
        argv
    })
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 100, ..ProptestConfig::default() })]

    #[test]
    fn non_interactive_ask_fails_closed(argv in benign_command()) {
        let policy = compile(ASK_DEFAULT_POLICY);
        let mut session = SessionHandle::new(SESSION);
        let mut remembered = RememberedDecisions::new();
        let mut audit = MemoryAuditStore::new();
        let mut dispatcher = RecordingDispatcher::succeeding();
        let ui = ScriptedApprovalUi::always_denying();

        let action = command(argv);

        let outcome = {
            let broker = Broker::new(&ui);
            let mut ctx = BrokerContext {
                policy: &policy,
                mode: Mode::Enforce,
                interactive: false,
                yes: false,
                session: &mut session,
                remembered: &mut remembered,
                audit: &mut audit,
                dispatcher: &mut dispatcher,
            };
            broker.handle(&mut ctx, action)
        };

        // The generated command must actually resolve to `ask`; otherwise the
        // generator is broken (it produced something matching a rule or a hard
        // deny) and this property is no longer exercising fail-closed.
        prop_assert_eq!(
            outcome.decision.decision,
            fida_action::Decision::Ask,
            "generated command did not resolve to ask"
        );

        // Fail closed: blocked, EXIT_APPROVAL_REQUIRED, nothing executed.
        prop_assert_eq!(outcome.result, ActionResult::Blocked);
        prop_assert_eq!(outcome.exit_code, EXIT_APPROVAL_REQUIRED);
        prop_assert_eq!(dispatcher.count(), 0, "fail-closed must not execute");

        // Never prompted (non-interactive).
        prop_assert_eq!(ui.prompt_count(), 0, "non-interactive never prompts");

        // Exactly one blocked-needs-approval audit event recorded.
        let events = audit.read(SESSION).unwrap();
        prop_assert_eq!(events.len(), 1, "exactly one audit event per action");
        prop_assert_eq!(events[0].result, AuditResult::Blocked);
    }
}
