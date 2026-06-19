// Feature: fida-mvp, Property 2: First-match stage ordering is honored
//
// Property 2: the returned decision originates from the earliest matching
// stage; no later stage overrides an earlier match.
//
//
// The evaluator runs a fixed 7-stage pipeline and stops at the first stage
// that matches:
//   1 HardDeny, 2 SecretDetection, 3 ExplicitDeny, 4 ExplicitAllow,
//   5 ExplicitAsk, 6 ProfileDefault, 7 GlobalDefault.
//
// This file exercises ordering two ways:
//   * the explicit command tiers (deny < allow < ask < global default): when
//     the *same* command is placed into a random subset of tiers, the result
//     must originate from the earliest occupied tier — never a later one.
//   * the documented hard-deny exception: a built-in hard-deny match yields to
//     an explicit allow for the same action (stage 1 falls through to stage 4),
//     and otherwise denies at stage 1.
//
// Policies are built by serializing a `PolicyFile` to YAML and loading it back
// through the real loader pipeline, mirroring `prop_round_trip.rs`.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::PathBuf;

use fida_action::{
    Action, ActionKind, ActionPayload, Actor, Decision, EvalStage, NetTarget, Protocol,
};
use fida_policy::compiled::CompiledPolicy;
use fida_policy::loader::{PolicySource, load_source};
use fida_policy::schema::{
    AuditSection, CommandMatcher, CommandRule, CommandSection, FileSection, McpSection, NetRule,
    NetTargetMatcher, NetworkSection, PolicyFile, SecretSection,
};
use proptest::prelude::*;

// Helpers

/// Serialize a `PolicyFile` to YAML, write it to a temp file, and load it back
/// through the real loader pipeline (parse → validate → compile).
fn load_via_yaml(policy: &PolicyFile) -> CompiledPolicy {
    let yaml = serde_yaml::to_string(policy).expect("serialize policy to YAML");
    let mut file = tempfile::Builder::new()
        .suffix(".yaml")
        .tempfile()
        .expect("create temp policy file");
    file.write_all(yaml.as_bytes()).expect("write temp policy");
    file.flush().expect("flush temp policy");
    let source = PolicySource::Config(file.path().to_path_buf());
    load_source(&source, None).unwrap_or_else(|e| {
        panic!("valid version-1 policy failed to load: {e}\n--- yaml ---\n{yaml}")
    })
}

/// A minimal version-1 policy with empty sections and the given global default.
fn base_policy(default_decision: Decision) -> PolicyFile {
    PolicyFile {
        version: 1,
        default_decision,
        profiles: BTreeMap::new(),
        commands: CommandSection::default(),
        files: FileSection::default(),
        network: NetworkSection::default(),
        mcp: McpSection::default(),
        secrets: SecretSection::default(),
        audit: AuditSection::default(),
        hard_denies_disabled: false,
        agents: Vec::new(),
    }
}

fn command_action(command: &str) -> Action {
    Action {
        kind: ActionKind::CommandRun,
        actor: Actor::Agent,
        payload: ActionPayload::Command {
            argv: command.split(' ').map(|s| s.to_string()).collect(),
            cwd: PathBuf::from("/repo"),
        },
    }
}

fn network_action(host: &str) -> Action {
    Action {
        kind: ActionKind::NetworkRequest,
        actor: Actor::Agent,
        payload: ActionPayload::Network {
            target: NetTarget {
                domain: None,
                host: host.to_string(),
                protocol: Protocol::Https,
            },
        },
    }
}

// Generators

/// A safe command string: 1–3 lowercase words joined by single spaces. These
/// never collide with built-in hard-deny command patterns (`rm -rf /`,
/// `curl ... | sh`, ...), so the only stages that can match are the explicit
/// command tiers and the global default.
fn command_string() -> impl Strategy<Value = String> {
    prop::collection::vec("[a-z][a-z0-9]{0,5}", 1..=3).prop_map(|ws| ws.join(" "))
}

/// A global default decision (never `DryRun`).
fn gate_decision() -> impl Strategy<Value = Decision> {
    prop_oneof![
        Just(Decision::Allow),
        Just(Decision::Ask),
        Just(Decision::Deny),
    ]
}

/// A host that is always a built-in hard deny: the cloud metadata IP or an
/// address inside one of the default private CIDRs (10/8, 172.16/12,
/// 192.168/16).
fn hard_denied_host() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("169.254.169.254".to_string()),
        Just("10.0.0.1".to_string()),
        Just("172.16.0.1".to_string()),
        Just("192.168.1.1".to_string()),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 100, ..ProptestConfig::default() })]

    // Feature: fida-mvp, Property 2: First-match stage ordering is honored
    //
    // The same command is placed (as an exact matcher) into a random subset of
    // the deny/allow/ask tiers. The result must originate from the earliest
    // occupied tier (deny < allow < ask), or the global default when no tier
    // is occupied — a later tier never overrides an earlier match.
    #[test]
    fn explicit_tier_first_match_is_honored(
        command in command_string(),
        in_deny in any::<bool>(),
        in_allow in any::<bool>(),
        in_ask in any::<bool>(),
        default_decision in gate_decision(),
    ) {
        let rule = |cmd: &str| CommandRule {
            matcher: CommandMatcher::Exact(cmd.to_string()),
            working_dir: None,
            reason: None,
            auto_approve: false,
        };

        let mut policy = base_policy(default_decision);
        if in_deny {
            policy.commands.deny.push(rule(&command));
        }
        if in_allow {
            policy.commands.allow.push(rule(&command));
        }
        if in_ask {
            policy.commands.ask.push(rule(&command));
        }

        let compiled = load_via_yaml(&policy);
        let result = fida_policy::evaluate(&compiled, &command_action(&command));

        // Earliest occupied tier wins; otherwise the global default.
        let (expected_stage, expected_decision) = if in_deny {
            (EvalStage::ExplicitDeny, Decision::Deny)
        } else if in_allow {
            (EvalStage::ExplicitAllow, Decision::Allow)
        } else if in_ask {
            (EvalStage::ExplicitAsk, Decision::Ask)
        } else {
            (EvalStage::GlobalDefault, default_decision)
        };

        prop_assert_eq!(
            result.stage, expected_stage,
            "stage must originate from the earliest matching tier (deny={}, allow={}, ask={})",
            in_deny, in_allow, in_ask
        );
        prop_assert_eq!(result.decision, expected_decision);
        prop_assert!(!result.reason.is_empty(), "every result carries a non-empty reason");
    }

    // Feature: fida-mvp, Property 2: First-match stage ordering is honored
    //
    // The documented hard-deny exception: a built-in hard-deny match (stage 1)
    // is overridden only by an explicit allow for the same action (stage 4).
    // With an allow rule present the result originates from ExplicitAllow;
    // without it, from HardDeny — and never a later/earlier stage in between.
    #[test]
    fn hard_deny_yields_only_to_explicit_allow(
        host in hard_denied_host(),
        add_allow in any::<bool>(),
        default_decision in gate_decision(),
    ) {
        let mut policy = base_policy(default_decision);
        if add_allow {
            policy.network.allow.push(NetRule {
                target: NetTargetMatcher::Host(host.clone()),
                reason: None,
            });
        }

        let compiled = load_via_yaml(&policy);
        let result = fida_policy::evaluate(&compiled, &network_action(&host));

        let (expected_stage, expected_decision) = if add_allow {
            (EvalStage::ExplicitAllow, Decision::Allow)
        } else {
            (EvalStage::HardDeny, Decision::Deny)
        };

        prop_assert_eq!(result.stage, expected_stage, "host={}", host);
        prop_assert_eq!(result.decision, expected_decision);
        prop_assert!(!result.reason.is_empty());
    }
}
