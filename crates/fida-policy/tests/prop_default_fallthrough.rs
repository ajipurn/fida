// Feature: fida-mvp, Property 5: Default fallthrough
//
// Property 5: when no hard-deny / secret / explicit rule matches, `evaluate`
// returns the active profile's default decision if the profile defines one,
// otherwise it falls through to the global `default_decision`.
//
//
// Strategy: build a policy whose command/file/network/mcp/secret rule sections
// are all EMPTY, so stages 1-5 cannot match for a benign action. We then
// evaluate a benign command (`echo hi`) that trips no built-in hard deny and
// no explicit rule. We vary (a) the global `default_decision` and (b) whether
// the active profile declares its own `default_decision`, and assert the
// evaluator resolves at exactly the right default stage with the right value:
//   * profile default present  -> stage == ProfileDefault, decision == profile's
//   * profile default absent    -> stage == GlobalDefault,  decision == global's
//
// `load_source` materializes the built-in hard denies for every loaded policy
// (hard_denies_disabled stays false), so this exercises the real stage-6/7
// fallthrough rather than a degenerate empty policy.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::PathBuf;

use fida_action::{Action, ActionKind, ActionPayload, Actor, Decision, EvalStage};
use fida_policy::compiled::CompiledPolicy;
use fida_policy::loader::{PolicySource, load_source};
use fida_policy::schema::{PolicyFile, Profile};
use proptest::prelude::*;

/// Name of the profile we activate in every generated case.
const PROFILE: &str = "active";

/// Serialize a `PolicyFile` to YAML, write it to a temp file, and load it back
/// through the real loader pipeline with `profile` active. Mirrors
/// `load_via_yaml` from `prop_round_trip.rs`, extended to pass a profile name.
fn load_via_yaml(policy: &PolicyFile, profile: Option<&str>) -> CompiledPolicy {
    let yaml = serde_yaml::to_string(policy).expect("serialize policy to YAML");
    let mut file = tempfile::Builder::new()
        .suffix(".yaml")
        .tempfile()
        .expect("create temp policy file");
    file.write_all(yaml.as_bytes()).expect("write temp policy");
    file.flush().expect("flush temp policy");
    let source = PolicySource::Config(file.path().to_path_buf());
    load_source(&source, profile).unwrap_or_else(|e| {
        panic!("valid version-1 policy failed to load: {e}\n--- yaml ---\n{yaml}")
    })
}

/// A benign command action that matches no built-in hard deny and (given empty
/// rule sections) no explicit rule, so evaluation must reach the default stage.
fn benign_action() -> Action {
    Action {
        kind: ActionKind::CommandRun,
        actor: Actor::Agent,
        payload: ActionPayload::Command {
            argv: vec!["echo".to_string(), "hi".to_string()],
            cwd: PathBuf::from("/repo"),
        },
    }
}

/// Build a policy with EMPTY rule sections, the given global default, and an
/// `active` profile that optionally declares its own default decision. All
/// other profile fields stay `None`/empty so nothing else can match.
fn make_policy(global_default: Decision, profile_default: Option<Decision>) -> PolicyFile {
    let mut profiles = BTreeMap::new();
    profiles.insert(
        PROFILE.to_string(),
        Profile {
            default_decision: profile_default,
            ..Profile::default()
        },
    );

    PolicyFile {
        version: 1,
        default_decision: global_default,
        profiles,
        commands: Default::default(),
        files: Default::default(),
        network: Default::default(),
        mcp: Default::default(),
        secrets: Default::default(),
        audit: Default::default(),
        hard_denies_disabled: false,
        agents: Vec::new(),
    }
}

/// A `default_decision`-valid decision (never `DryRun`).
fn gate_decision() -> impl Strategy<Value = Decision> {
    prop_oneof![
        Just(Decision::Allow),
        Just(Decision::Ask),
        Just(Decision::Deny),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 100, ..ProptestConfig::default() })]

    // Feature: fida-mvp, Property 5: Default fallthrough
    #[test]
    fn default_fallthrough_resolves_profile_then_global(
        global_default in gate_decision(),
        profile_default in proptest::option::of(gate_decision()),
    ) {
        let policy_file = make_policy(global_default, profile_default);
        let compiled = load_via_yaml(&policy_file, Some(PROFILE));
        let result = fida_policy::evaluate(&compiled, &benign_action());

        match profile_default {
            Some(expected) => {
                prop_assert_eq!(
                    result.stage,
                    EvalStage::ProfileDefault,
                    "profile declares a default; evaluator must resolve at the profile-default stage"
                );
                prop_assert_eq!(
                    result.decision,
                    expected,
                    "profile-default decision must equal the profile's declared default"
                );
            }
            None => {
                prop_assert_eq!(
                    result.stage,
                    EvalStage::GlobalDefault,
                    "no profile default; evaluator must fall through to the global default stage"
                );
                prop_assert_eq!(
                    result.decision,
                    global_default,
                    "global-default decision must equal the policy's default_decision"
                );
            }
        }
    }
}
