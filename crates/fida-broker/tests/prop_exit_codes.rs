// Feature: fida-mvp, Property 17: Decision-to-exit-code mapping
//
// Property 17: Decision-to-exit-code mapping — allow -> the command's own exit
// code (0 on success), deny -> 2, non-interactive ask -> 3, denied secret -> 6.
//
//
// Strategy: a single policy with a `prefix: echo` allow rule, a destructive
// `rm -rf` regex deny rule, and a global `ask` default. Each generated case
// belongs to one of the four decision classes and is driven through the broker
// in `enforce` mode, non-interactive (`interactive=false`, `yes=false`, empty
// remembered set):
//
// * allow — `echo <random tokens>` with a dispatcher reporting a RANDOM
// exit code N; the broker must propagate it verbatim
// (`exit_code == N`), so a succeeding dispatch yields 0
// and any other N yields N.
// * deny — `rm -rf {/|~|.}` (non-secret) must surface EXIT_DENY = 2
// and never dispatch.
// * ask — a benign command that matches no rule falls through to the
// global `ask` default; non-interactively it fails closed with
// EXIT_APPROVAL_REQUIRED = 3 and never dispatches.
// * secret — a `SecretDetected` action denied at the secret-detection stage
// must surface EXIT_SECRET_BLOCKED = 6 and never
// dispatch.

use std::path::PathBuf;

use proptest::prelude::*;

use fida_action::{Action, ActionKind, ActionPayload, Actor, Decision, EvalStage, Finding, Mode};
use fida_audit::AuditStore;
use fida_broker::testing::{MemoryAuditStore, RecordingDispatcher, ScriptedApprovalUi};
use fida_broker::{
    ActionBroker, ActionResult, Broker, BrokerContext, EXIT_APPROVAL_REQUIRED, EXIT_DENY,
    EXIT_SECRET_BLOCKED, RememberedDecisions, SessionHandle,
};
use fida_policy::{CompiledPolicy, PolicySource, load_source};

const SESSION: &str = "2026-06-12T070000Z-prop17";

/// A policy that exercises every decision class: a `prefix: echo` allow rule, a
/// destructive `rm -rf` regex deny rule, and a global `ask` default for
/// everything else.
const MIXED_POLICY: &str = r#"
version: 1
default_decision: ask

commands:
  allow:
    - prefix: echo
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

fn secret_action(pattern_id: String, reason: String) -> Action {
    Action {
        kind: ActionKind::SecretDetected,
        actor: Actor::Agent,
        payload: ActionPayload::Secret {
            finding: Finding { pattern_id, reason },
        },
    }
}

/// One generated case, tagged with the decision class it should exercise.
#[derive(Debug, Clone)]
enum Scenario {
    /// `echo <args>` matching the allow rule; the dispatcher reports
    /// `dispatch_code`, which the broker must propagate verbatim.
    Allow {
        argv: Vec<String>,
        dispatch_code: u8,
    },
    /// `rm -rf <target>` matching the destructive deny rule.
    Deny { argv: Vec<String> },
    /// A benign command that matches no rule and falls through to `ask`.
    Ask { argv: Vec<String> },
    /// A secret-detected action denied at the secret-detection stage.
    Secret { pattern_id: String, reason: String },
}

/// Safe token charset for command arguments — never trips a hard deny.
const ARG: &str = "[a-z0-9_][a-z0-9_-]{0,7}";

fn allow_scenario() -> impl Strategy<Value = Scenario> {
    let args = prop::collection::vec(ARG, 0..=3);
    (args, any::<u8>()).prop_map(|(args, dispatch_code)| {
        let mut argv = vec!["echo".to_string()];
        argv.extend(args);
        Scenario::Allow {
            argv,
            dispatch_code,
        }
    })
}

fn deny_scenario() -> impl Strategy<Value = Scenario> {
    prop::sample::select(vec!["/", "~", "."]).prop_map(|target| Scenario::Deny {
        argv: vec!["rm".to_string(), "-rf".to_string(), target.to_string()],
    })
}

fn ask_scenario() -> impl Strategy<Value = Scenario> {
    // Binaries that match neither the `echo` allow rule nor any hard deny, so
    // they fall through to the global `ask` default.
    let binary = prop::sample::select(vec![
        "ls", "pwd", "date", "whoami", "head", "wc", "grep", "find", "cat",
    ])
    .prop_map(str::to_string);
    let args = prop::collection::vec(ARG, 0..=3);
    (binary, args).prop_map(|(bin, args)| {
        let mut argv = vec![bin];
        argv.extend(args);
        Scenario::Ask { argv }
    })
}

fn secret_scenario() -> impl Strategy<Value = Scenario> {
    ("[a-z_][a-z0-9_]{0,15}", "[A-Za-z ]{1,20}")
        .prop_map(|(pattern_id, reason)| Scenario::Secret { pattern_id, reason })
}

fn scenario() -> impl Strategy<Value = Scenario> {
    prop_oneof![
        allow_scenario(),
        deny_scenario(),
        ask_scenario(),
        secret_scenario(),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 100,..ProptestConfig::default() })]

    #[test]
    fn decision_maps_to_expected_exit_code(scenario in scenario()) {
        let policy = compile(MIXED_POLICY);
        let mut session = SessionHandle::new(SESSION);
        let mut remembered = RememberedDecisions::new();
        let mut audit = MemoryAuditStore::new();
        let ui = ScriptedApprovalUi::always_denying();

        // Per-scenario expectations: the action, the dispatcher (carrying the
        // exit code an allow propagates), and the asserted broker verdict.
        let (action, mut dispatcher, expected_exit, expected_result, expected_decision) =
            match scenario.clone() {
                Scenario::Allow { argv, dispatch_code } => (
                    command(argv),
                    RecordingDispatcher::new(dispatch_code),
                    dispatch_code,
                    ActionResult::Permitted,
                    Decision::Allow,
                ),
                Scenario::Deny { argv } => (
                    command(argv),
                    RecordingDispatcher::succeeding(),
                    EXIT_DENY,
                    ActionResult::Denied,
                    Decision::Deny,
                ),
                Scenario::Ask { argv } => (
                    command(argv),
                    RecordingDispatcher::succeeding(),
                    EXIT_APPROVAL_REQUIRED,
                    ActionResult::Blocked,
                    Decision::Ask,
                ),
                Scenario::Secret { pattern_id, reason } => (
                    secret_action(pattern_id, reason),
                    RecordingDispatcher::succeeding(),
                    EXIT_SECRET_BLOCKED,
                    ActionResult::Denied,
                    Decision::Deny,
                ),
            };

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

        // The case must actually exercise its intended decision class; if not,
        // the generator is broken and the property is no longer meaningful.
        prop_assert_eq!(
            outcome.decision.decision,
            expected_decision,
            "scenario did not resolve to its intended decision: {:?}",
            scenario
        );

        // Core property: the decision maps to the expected exit code.
        prop_assert_eq!(
            outcome.exit_code,
            expected_exit,
            "wrong exit code for {:?}",
            scenario
        );
        prop_assert_eq!(outcome.result, expected_result);

        // A denied secret must originate from the secret-detection stage
        // (the source of EXIT_SECRET_BLOCKED).
        if let Scenario::Secret {.. } = scenario {
            prop_assert_eq!(outcome.decision.stage, EvalStage::SecretDetection);
        }

        // Dispatch happens only for the permitted (allow) class; deny, ask, and
        // secret never execute.
        match scenario {
            Scenario::Allow {.. } => {
                prop_assert_eq!(dispatcher.count(), 1, "allow must dispatch exactly once");
            }
            _ => prop_assert_eq!(dispatcher.count(), 0, "non-allow must not dispatch"),
        }

        // Every resolved action records exactly one audit event.
        let events = audit.read(SESSION).unwrap();
        prop_assert_eq!(events.len(), 1, "exactly one audit event per action");
        prop_assert_eq!(events[0].decision, outcome.decision.decision);
    }
}
