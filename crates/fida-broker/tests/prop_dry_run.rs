// Feature: fida-mvp, Property 20: Dry-run executes nothing
//
// Property 20: in dry-run mode (session `Mode::DryRun`, the `exec --dry-run`
// equivalent) the broker records the decision but performs NO command, file,
// network, or MCP tool action — nothing is executed.
//
//
// Strategy: generate a diverse population of actions spanning every
// `ActionKind` and every decision class (allow / deny / ask / secret), then
// drive each one through the broker with `mode = Mode::DryRun`. The session
// `Mode` short-circuits before any dispatch regardless of what the evaluator
// would have decided, so for EVERY generated case the property must hold:
//
// * the injected dispatcher is never invoked (`count == 0`) — no
// command/file/network/tool action is performed,
// * the broker verdict is `ActionResult::WouldRun` with `EXIT_SUCCESS`,
// * exactly one audit event is recorded with
// `AuditResult::WouldRun`,
// * the decision is still recorded on the outcome and mirrored on the event
// (the decision is observed even though nothing runs), and
// * the approval UI is never prompted (dry-run neither blocks nor asks).

use std::path::PathBuf;

use proptest::prelude::*;

use fida_action::{Action, ActionKind, ActionPayload, Actor, Finding, Mode, NetTarget, Protocol};
use fida_audit::{AuditResult, AuditStore};
use fida_broker::testing::{MemoryAuditStore, RecordingDispatcher, ScriptedApprovalUi};
use fida_broker::{
    ActionBroker, ActionResult, Broker, BrokerContext, EXIT_SUCCESS, RememberedDecisions,
    SessionHandle,
};
use fida_policy::{CompiledPolicy, PolicySource, load_source};

const SESSION: &str = "2026-06-12T070000Z-prop20";

/// A policy that exercises every decision class so the generated actions span
/// allow / deny / ask: a `prefix: echo` command allow, a destructive `rm -rf`
/// command deny, a global `ask` default, plus file/network/mcp sections.
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

network:
  allow:
    - domain: example.com
  deny:
    - host: 169.254.169.254
      reason: cloud metadata service

mcp:
  tools:
    allow:
      - pattern: "safe.*"
    deny:
      - pattern: "shell.*"
        reason: shell tools must go through fida exec

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

/// Safe token charset for command arguments / path segments — never trips a
/// hard deny or path-traversal guard.
const TOKEN: &str = "[a-z0-9_][a-z0-9_-]{0,7}";

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

fn file_action(kind: ActionKind, path: String) -> Action {
    Action {
        kind,
        actor: Actor::Agent,
        payload: ActionPayload::File {
            path: PathBuf::from(path),
        },
    }
}

fn network_action(host: String, domain: Option<String>, protocol: Protocol) -> Action {
    Action {
        kind: ActionKind::NetworkRequest,
        actor: Actor::Agent,
        payload: ActionPayload::Network {
            target: NetTarget {
                domain,
                host,
                protocol,
            },
        },
    }
}

fn mcp_action(tool_name: String) -> Action {
    Action {
        kind: ActionKind::McpToolCall,
        actor: Actor::Agent,
        payload: ActionPayload::Mcp { tool_name },
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

/// A command that matches the `echo` allow rule (allow decision).
fn allow_command() -> impl Strategy<Value = Action> {
    prop::collection::vec(TOKEN, 0..=3).prop_map(|args| {
        let mut argv = vec!["echo".to_string()];
        argv.extend(args);
        command(argv)
    })
}

/// A destructive `rm -rf` command matching the deny rule (deny decision).
fn deny_command() -> impl Strategy<Value = Action> {
    prop::sample::select(vec!["/", "~", "."]).prop_map(|target| {
        command(vec![
            "rm".to_string(),
            "-rf".to_string(),
            target.to_string(),
        ])
    })
}

/// A benign command matching no rule — falls through to the global `ask`.
fn ask_command() -> impl Strategy<Value = Action> {
    let binary = prop::sample::select(vec![
        "ls", "pwd", "date", "whoami", "head", "wc", "grep", "find", "cat",
    ])
    .prop_map(str::to_string);
    (binary, prop::collection::vec(TOKEN, 0..=3)).prop_map(|(bin, args)| {
        let mut argv = vec![bin];
        argv.extend(args);
        command(argv)
    })
}

/// File actions across read / write / delete kinds.
fn file_kinds() -> impl Strategy<Value = Action> {
    let kind = prop::sample::select(vec![
        ActionKind::FileRead,
        ActionKind::FileWrite,
        ActionKind::FileDelete,
    ]);
    let dir = prop::sample::select(vec!["src", "tests", "docs", "tmp"]);
    (kind, dir, TOKEN).prop_map(|(kind, dir, name)| file_action(kind, format!("{dir}/{name}.rs")))
}

/// Network actions across protocols, with and without a known domain.
fn network_kinds() -> impl Strategy<Value = Action> {
    let protocol = prop::sample::select(vec![Protocol::Http, Protocol::Https]);
    let host = prop::sample::select(vec![
        "example.com",
        "evil.test",
        "169.254.169.254",
        "localhost",
    ])
    .prop_map(str::to_string);
    let domain = prop::option::of(
        prop::sample::select(vec!["example.com", "evil.test"]).prop_map(str::to_string),
    );
    (host, domain, protocol)
        .prop_map(|(host, domain, protocol)| network_action(host, domain, protocol))
}

/// MCP tool-call actions across allowed and unknown tools.
fn mcp_kinds() -> impl Strategy<Value = Action> {
    prop::sample::select(vec!["safe.tool", "browser.navigate", "shell.run"])
        .prop_map(|tool| mcp_action(tool.to_string()))
}

/// Secret-detected actions (denied at the secret-detection stage).
fn secret_kinds() -> impl Strategy<Value = Action> {
    ("[a-z_][a-z0-9_]{0,15}", "[A-Za-z ]{1,20}")
        .prop_map(|(pattern_id, reason)| secret_action(pattern_id, reason))
}

/// A diverse action spanning every kind and decision class.
fn any_action() -> impl Strategy<Value = Action> {
    prop_oneof![
        allow_command(),
        deny_command(),
        ask_command(),
        file_kinds(),
        network_kinds(),
        mcp_kinds(),
        secret_kinds(),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 100,..ProptestConfig::default() })]

    #[test]
    fn dry_run_executes_nothing(action in any_action()) {
        let policy = compile(MIXED_POLICY);
        let mut session = SessionHandle::new(SESSION);
        let mut remembered = RememberedDecisions::new();
        let mut audit = MemoryAuditStore::new();
        // A dispatcher that would succeed if ever called — it must NOT be.
        let mut dispatcher = RecordingDispatcher::succeeding();
        // An always-allowing UI would still let actions through if prompted;
        // dry-run must never prompt it.
        let ui = ScriptedApprovalUi::always_denying();

        let outcome = {
            let broker = Broker::new(&ui);
            let mut ctx = BrokerContext {
                policy: &policy,
                mode: Mode::DryRun,
                interactive: true,
                yes: false,
                session: &mut session,
                remembered: &mut remembered,
                audit: &mut audit,
                dispatcher: &mut dispatcher,
            };
            broker.handle(&mut ctx, action.clone())
        };

        // Core property: nothing was executed — no command/file/network/tool
        // action performed.
        prop_assert_eq!(
            dispatcher.count(),
            0,
            "dry-run must execute nothing, but dispatched: {:?}",
            action
        );

        // The broker reports "would run" with a success exit code.
        prop_assert_eq!(outcome.result, ActionResult::WouldRun);
        prop_assert_eq!(outcome.exit_code, EXIT_SUCCESS);

        // The decision is still recorded on the outcome (observed, not run).
        // DecisionResult carries a populated decision/reason for every action.
        prop_assert!(
            !outcome.decision.reason.is_empty(),
            "decision must still be recorded in dry-run"
        );

        // Exactly one audit event, recorded as WouldRun, mirroring the
        // observed decision.
        let events = audit.read(SESSION).unwrap();
        prop_assert_eq!(events.len(), 1, "exactly one audit event per action");
        prop_assert_eq!(events[0].result, AuditResult::WouldRun);
        prop_assert_eq!(events[0].decision, outcome.decision.decision);

        // The approval UI is never prompted in dry-run.
        prop_assert_eq!(ui.prompt_count(), 0, "dry-run must never prompt for approval");
    }
}
