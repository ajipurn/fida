// Feature: fida-mvp, Property 10: Network default denies hold without explicit rules
//
// Property 10: any network request to the cloud metadata IP `169.254.169.254`
// or to an address inside a private CIDR range (10.0.0.0/8, 172.16.0.0/12,
// 192.168.0.0/16) with NO explicit network allow rule for that host resolves to
// `Decision::Deny` at stage `EvalStage::HardDeny`.
//
//
// Built-in hard denies are always materialized when a policy is loaded
// (loader::builtin_hard_denies), independent of which sections the author wrote.
// Stage 1 of the evaluator applies them and is overridable only by an explicit
// allow rule for the same action (design "Network Matching"). The core property
// asserts the deny holds *without* such a rule; a control case confirms the
// "without explicit rules" qualifier by flipping the outcome to an explicit
// allow when a matching host rule is present.

use std::io::Write;

use fida_action::{
    Action, ActionKind, ActionPayload, Actor, Decision, EvalStage, NetTarget, Protocol,
};
use fida_policy::compiled::CompiledPolicy;
use fida_policy::evaluator::evaluate;
use fida_policy::loader::{PolicySource, load_source};
use fida_policy::schema::{
    AuditFormat, AuditSection, CommandSection, FileSection, McpSection, NetRule, NetTargetMatcher,
    NetworkSection, PathRules, PolicyFile, SecretSection, ToolRules,
};
use proptest::prelude::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Serialize a `PolicyFile` to YAML and load it back through the real loader
/// pipeline (parse → validate → compile). Mirrors `load_via_yaml` from
/// `prop_round_trip.rs`.
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

/// A version-1 policy with all sections empty except `network`, whose allow
/// tier contains the supplied rules. The global default decision is varied to
/// prove the hard deny dominates regardless of the fall-through default.
fn policy_with_net_allow(default_decision: Decision, allow: Vec<NetRule>) -> PolicyFile {
    PolicyFile {
        version: 1,
        default_decision,
        profiles: Default::default(),
        commands: CommandSection {
            allow: vec![],
            ask: vec![],
            deny: vec![],
        },
        files: FileSection {
            read: PathRules {
                allow: vec![],
                ask: vec![],
                deny: vec![],
            },
            write: PathRules {
                allow: vec![],
                ask: vec![],
                deny: vec![],
            },
        },
        network: NetworkSection {
            allow,
            ask: vec![],
            deny: vec![],
        },
        mcp: McpSection {
            tools: ToolRules {
                allow: vec![],
                ask: vec![],
                deny: vec![],
            },
        },
        secrets: SecretSection {
            redact: true,
            block_in_diffs: true,
            patterns: vec![],
        },
        audit: AuditSection {
            path: "audit.jsonl".into(),
            format: AuditFormat::Jsonl,
            redact_stdout: true,
            redact_stderr: true,
        },
        hard_denies_disabled: false,
        agents: vec![],
    }
}

/// A network request action for `host` with no registered domain.
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

// ---------------------------------------------------------------------------
// Generators — addresses guaranteed to be inside a built-in hard-deny range
// ---------------------------------------------------------------------------

/// A `default_decision`-valid decision (never `DryRun`).
fn gate_decision() -> impl Strategy<Value = Decision> {
    prop_oneof![
        Just(Decision::Allow),
        Just(Decision::Ask),
        Just(Decision::Deny),
    ]
}

/// An address string that is always hard-denied by the built-in set:
/// the cloud metadata IP, or an IPv4 inside 10/8, 172.16/12, or 192.168/16.
fn denied_host() -> impl Strategy<Value = String> {
    prop_oneof![
        // Cloud metadata IP.
        Just("169.254.169.254".to_string()),
        // 10.0.0.0/8.
        (0u8..=255, 0u8..=255, 0u8..=255).prop_map(|(b, c, d)| format!("10.{b}.{c}.{d}")),
        // 172.16.0.0/12 -> second octet 16..=31.
        (16u8..=31, 0u8..=255, 0u8..=255).prop_map(|(a, c, d)| format!("172.{a}.{c}.{d}")),
        // 192.168.0.0/16.
        (0u8..=255, 0u8..=255).prop_map(|(c, d)| format!("192.168.{c}.{d}")),
    ]
}

// ---------------------------------------------------------------------------
// Property 10
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig { cases: 100, ..ProptestConfig::default() })]

    // Feature: fida-mvp, Property 10: Network default denies hold without explicit rules
    #[test]
    fn network_default_denies_without_explicit_rule(
        host in denied_host(),
        default_decision in gate_decision(),
    ) {
        // No explicit network allow rule → the built-in hard deny must dominate,
        // regardless of the global default decision.
        let policy = load_via_yaml(&policy_with_net_allow(default_decision, vec![]));
        let result = evaluate(&policy, &network_action(&host));

        prop_assert_eq!(
            result.decision,
            Decision::Deny,
            "expected Deny for `{}` with no allow rule (default `{:?}`)",
            host,
            default_decision
        );
        prop_assert_eq!(
            result.stage,
            EvalStage::HardDeny,
            "expected HardDeny stage for `{}`",
            host
        );

        // Control: an explicit allow rule for the *same* host flips the outcome
        // to an explicit allow, confirming the "without explicit rules"
        // qualifier of the property (design "Network Matching").
        let allowed = load_via_yaml(&policy_with_net_allow(
            default_decision,
            vec![NetRule {
                target: NetTargetMatcher::Host(host.clone()),
                reason: None,
            }],
        ));
        let allowed_result = evaluate(&allowed, &network_action(&host));
        prop_assert_eq!(
            allowed_result.decision,
            Decision::Allow,
            "explicit allow rule should override the hard deny for `{}`",
            host
        );
        prop_assert_eq!(
            allowed_result.stage,
            EvalStage::ExplicitAllow,
            "explicit allow should resolve at ExplicitAllow for `{}`",
            host
        );
    }
}
