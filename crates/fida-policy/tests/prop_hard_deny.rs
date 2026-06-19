// Feature: fida-mvp, Property 3: Hard-deny dominance and disable semantics
//
// Property 3: For any action that matches a built-in hard-deny rule, when hard
// denies are enabled the evaluator returns `deny` from the hard-deny stage; and
// for any such action when hard denies are disabled, the evaluator returns
// whatever decision stages 2–7 produce — the hard-deny stage is skipped, never
// silently denied.
//
//
// Strategy: generate an action that is guaranteed to hit one of the three
// built-in hard-deny categories (destructive command, sensitive file, or the
// cloud-metadata host / a private-CIDR network target). The policy is built
// with NO explicit rules of any kind via the serialize-to-YAML + `load_source`
// pattern (mirroring `prop_round_trip.rs`'s `load_via_yaml`), so nothing but the
// hard-deny stage and the global default can fire.
//
//   * With `hard_denies_disabled: false` (and no explicit allow), the action
//     resolves to `Deny` at `EvalStage::HardDeny`.
//   * With `hard_denies_disabled: true`, the hard-deny stage is skipped and the
//     action falls through to the global default (stage 7). The decision then
//     equals the policy's `default_decision` — proving the formerly hard-denied
//     action is NOT silently denied (e.g. `default_decision: allow` ⇒ `Allow`).
//
// Both `default_decision` and the hard-deny category are varied across cases.

use std::io::Write;
use std::path::PathBuf;

use fida_action::{
    Action, ActionKind, ActionPayload, Actor, Decision, EvalStage, NetTarget, Protocol,
};
use fida_policy::compiled::CompiledPolicy;
use fida_policy::evaluator::evaluate;
use fida_policy::loader::{PolicySource, load_source};
use proptest::prelude::*;

/// Build a minimal compiled policy with no explicit rules, the given global
/// `default_decision`, and the given hard-deny toggle — via the
/// serialize-to-YAML + `load_source(&PolicySource::Config(path), None)` pattern.
fn load_minimal_policy(default_decision: Decision, hard_denies_disabled: bool) -> CompiledPolicy {
    let decision = match default_decision {
        Decision::Allow => "allow",
        Decision::Ask => "ask",
        Decision::Deny => "deny",
        // `dry_run` is not a valid global default; never generated here.
        Decision::DryRun => unreachable!("dry_run is not a valid default_decision"),
    };
    let yaml = format!(
        "version: 1\ndefault_decision: {decision}\nhard_denies_disabled: {hard_denies_disabled}\n"
    );
    let mut file = tempfile::Builder::new()
        .suffix(".yaml")
        .tempfile()
        .expect("create temp policy file");
    file.write_all(yaml.as_bytes()).expect("write temp policy");
    file.flush().expect("flush temp policy");
    let source = PolicySource::Config(file.path().to_path_buf());
    load_source(&source, None)
        .unwrap_or_else(|e| panic!("minimal policy failed to load: {e}\n--- yaml ---\n{yaml}"))
}

// Generators — each produces an Action guaranteed to hit a built-in hard deny.

/// A short, glob/regex-safe token.
fn word() -> impl Strategy<Value = String> {
    "[a-z][a-z0-9]{0,5}".prop_map(|s| s)
}

/// A `default_decision`-valid decision (never `DryRun`).
fn gate_decision() -> impl Strategy<Value = Decision> {
    prop_oneof![
        Just(Decision::Allow),
        Just(Decision::Ask),
        Just(Decision::Deny),
    ]
}

/// An action whose argv joins to a string matching a built-in destructive
/// command pattern (`rm -rf <root|home|cwd>`, `curl ... | sh`, `wget ... | sh`).
fn destructive_command_action() -> impl Strategy<Value = Action> {
    let rm = (
        prop_oneof![Just("-r"), Just("-rf")],
        prop_oneof![Just("/"), Just("~"), Just(".")],
    )
        .prop_map(|(flag, target)| vec!["rm".to_string(), flag.to_string(), target.to_string()]);

    let pipe_shell = (
        prop_oneof![Just("curl"), Just("wget")],
        word(),
        prop_oneof![Just("sh"), Just("bash"), Just("zsh")],
    )
        .prop_map(|(tool, host, shell)| {
            vec![
                tool.to_string(),
                format!("https://{host}.test/install.sh"),
                "|".to_string(),
                shell.to_string(),
            ]
        });

    prop_oneof![rm, pipe_shell].prop_map(|argv| Action {
        kind: ActionKind::CommandRun,
        actor: Actor::Agent,
        payload: ActionPayload::Command {
            argv,
            cwd: PathBuf::from("/repo"),
        },
    })
}

/// Optional leading directory segments for a sensitive-file path.
fn optional_dir() -> impl Strategy<Value = Option<Vec<String>>> {
    prop::option::of(prop::collection::vec(word(), 1..=2))
}

/// An action whose path matches a built-in sensitive-file glob (`.env`,
/// `.env.*`, `**/*.pem`, `**/*.key`, `**/id_rsa`, `**/id_ed25519`).
fn sensitive_file_action() -> impl Strategy<Value = Action> {
    let path = prop_oneof![
        Just(".env".to_string()),
        word().prop_map(|w| format!(".env.{w}")),
        (optional_dir(), word()).prop_map(|(dir, name)| with_dir(dir, format!("{name}.pem"))),
        (optional_dir(), word()).prop_map(|(dir, name)| with_dir(dir, format!("{name}.key"))),
        optional_dir().prop_map(|dir| with_dir(dir, "id_rsa".to_string())),
        optional_dir().prop_map(|dir| with_dir(dir, "id_ed25519".to_string())),
    ];

    path.prop_map(|p| Action {
        kind: ActionKind::FileWrite,
        actor: Actor::Agent,
        payload: ActionPayload::File {
            path: PathBuf::from(p),
        },
    })
}

/// Join optional directory segments and a filename into a repo-relative path.
fn with_dir(dir: Option<Vec<String>>, name: String) -> String {
    match dir {
        Some(segments) if !segments.is_empty() => format!("{}/{name}", segments.join("/")),
        _ => name,
    }
}

/// An action targeting the cloud-metadata host or an address inside a built-in
/// private CIDR (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`).
fn network_hard_deny_action() -> impl Strategy<Value = Action> {
    let host = prop_oneof![
        Just("169.254.169.254".to_string()),
        (any::<u8>(), any::<u8>(), any::<u8>()).prop_map(|(b, c, d)| format!("10.{b}.{c}.{d}")),
        (16u8..=31, any::<u8>(), any::<u8>()).prop_map(|(b, c, d)| format!("172.{b}.{c}.{d}")),
        (any::<u8>(), any::<u8>()).prop_map(|(c, d)| format!("192.168.{c}.{d}")),
    ];

    host.prop_map(|host| Action {
        kind: ActionKind::NetworkRequest,
        actor: Actor::Agent,
        payload: ActionPayload::Network {
            target: NetTarget {
                domain: None,
                host,
                protocol: Protocol::Https,
            },
        },
    })
}

/// Any action that hits one of the three built-in hard-deny categories.
fn hard_denied_action() -> impl Strategy<Value = Action> {
    prop_oneof![
        destructive_command_action(),
        sensitive_file_action(),
        network_hard_deny_action(),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 100, ..ProptestConfig::default() })]

    // Feature: fida-mvp, Property 3: Hard-deny dominance and disable semantics
    #[test]
    fn hard_deny_dominates_when_enabled_and_is_skipped_when_disabled(
        action in hard_denied_action(),
        default_decision in gate_decision(),
    ) {
        // Enabled: a hard-deny match dominates — `deny` from
        // the hard-deny stage, regardless of the global default.
        let enabled = load_minimal_policy(default_decision, false);
        let r_enabled = evaluate(&enabled, &action);
        prop_assert_eq!(
            r_enabled.decision,
            Decision::Deny,
            "hard-denied action must resolve to deny when hard denies are enabled (action: {:?})",
            action
        );
        prop_assert_eq!(
            r_enabled.stage,
            EvalStage::HardDeny,
            "decision must originate from the hard-deny stage when enabled (action: {:?})",
            action
        );

        // Disabled: the hard-deny stage is skipped entirely.
        // With no explicit rules and no secret, the action falls through to the
        // global default (stage 7) — never silently denied by the hard-deny
        // stage. The resolved decision equals `default_decision`, so a policy
        // with `default_decision: allow` actually ALLOWS the formerly
        // hard-denied action.
        let disabled = load_minimal_policy(default_decision, true);
        let r_disabled = evaluate(&disabled, &action);
        prop_assert_ne!(
            r_disabled.stage,
            EvalStage::HardDeny,
            "hard-deny stage must be skipped when disabled (action: {:?})",
            action
        );
        prop_assert_eq!(
            r_disabled.stage,
            EvalStage::GlobalDefault,
            "with no explicit rules the disabled-hard-deny action must resolve at the global default (action: {:?})",
            action
        );
        prop_assert_eq!(
            r_disabled.decision,
            default_decision,
            "disabled hard-deny action must take the global default decision, not a silent deny (action: {:?})",
            action
        );
    }
}
