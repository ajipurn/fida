// Feature: fida-mvp, Property 4: Decision result completeness
//
// Property 4: every `DecisionResult` returned by `evaluate(policy, action)` is
// fully populated — a decision in {allow, ask, deny, dry_run}, a non-empty
// `reason`, a risk in {low, medium, high}, and either a concrete (non-empty)
// rule id or the `NoExplicitRule` sentinel.
//
//
// The `Decision`, `Risk`, and `MatchedRule` enums make some facets trivially
// true by type (a `DecisionResult` cannot exist with an out-of-band decision or
// risk). The meaningful, non-trivial assertions are therefore:
//   * `reason` is never empty;
//   * an explicit-stage result (ExplicitDeny / ExplicitAllow / ExplicitAsk),
//     plus the materialized hard-deny and secret stages, carries
//     `MatchedRule::Rule(id)` with a non-empty `id`;
//   * a default-stage result (ProfileDefault / GlobalDefault) carries
//     `MatchedRule::NoExplicitRule`.
//
// Generators (PolicyFile + Action) and `load_via_yaml` are copied from
// prop_round_trip.rs / prop_eval_deterministic.rs so this file is
// self-contained (no shared test module to clash with sibling prop_*.rs files).

use std::collections::BTreeMap;
use std::io::Write;
use std::path::PathBuf;

use fida_action::{
    Action, ActionKind, ActionPayload, Actor, Decision, EvalStage, Finding, MatchedRule, Mode,
    NetTarget, Protocol, Risk,
};
use fida_policy::compiled::CompiledPolicy;
use fida_policy::evaluate;
use fida_policy::loader::{PolicySource, load_source};
use fida_policy::schema::{
    AuditFormat, AuditSection, CommandMatcher, CommandRule, CommandSection, FileSection,
    McpSection, NetRule, NetTargetMatcher, NetworkSection, PathRules, PolicyFile, Profile,
    SecretPattern, SecretSection, ToolPattern, ToolRules,
};
use proptest::prelude::*;

// ---------------------------------------------------------------------------
// PolicyFile generators — constrained to the valid version-1 input space.
// ---------------------------------------------------------------------------

/// A short identifier-ish token that round-trips through YAML without quoting
/// surprises and is safe to embed in regex/glob/domain patterns.
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

fn mode() -> impl Strategy<Value = Mode> {
    prop_oneof![Just(Mode::Observe), Just(Mode::Enforce), Just(Mode::DryRun),]
}

fn command_string() -> impl Strategy<Value = String> {
    prop::collection::vec(word(), 1..=3).prop_map(|ws| ws.join(" "))
}

fn command_matcher() -> impl Strategy<Value = CommandMatcher> {
    prop_oneof![
        command_string().prop_map(CommandMatcher::Exact),
        command_string().prop_map(CommandMatcher::Prefix),
        word().prop_map(CommandMatcher::Regex),
        word().prop_map(CommandMatcher::Binary),
    ]
}

fn opt_reason() -> impl Strategy<Value = Option<String>> {
    prop::option::of(prop::collection::vec(word(), 1..=3).prop_map(|ws| ws.join(" ")))
}

fn opt_working_dir() -> impl Strategy<Value = Option<PathBuf>> {
    prop::option::of(
        prop::collection::vec(word(), 1..=3).prop_map(|ws| PathBuf::from(ws.join("/"))),
    )
}

fn command_rule() -> impl Strategy<Value = CommandRule> {
    (
        command_matcher(),
        opt_working_dir(),
        opt_reason(),
        any::<bool>(),
    )
        .prop_map(|(matcher, working_dir, reason, auto_approve)| CommandRule {
            matcher,
            working_dir,
            reason,
            auto_approve,
        })
}

fn command_section() -> impl Strategy<Value = CommandSection> {
    (
        prop::collection::vec(command_rule(), 0..=3),
        prop::collection::vec(command_rule(), 0..=3),
        prop::collection::vec(command_rule(), 0..=3),
    )
        .prop_map(|(allow, ask, deny)| CommandSection { allow, ask, deny })
}

fn glob_pattern() -> impl Strategy<Value = String> {
    prop_oneof![
        word(),
        word().prop_map(|w| format!("{w}/**")),
        word().prop_map(|w| format!("{w}/*")),
        word().prop_map(|w| format!("**/*.{w}")),
        (word(), word()).prop_map(|(a, b)| format!("{a}/{b}")),
    ]
}

fn path_rules() -> impl Strategy<Value = PathRules> {
    (
        prop::collection::vec(glob_pattern(), 0..=3),
        prop::collection::vec(glob_pattern(), 0..=3),
        prop::collection::vec(glob_pattern(), 0..=3),
    )
        .prop_map(|(allow, ask, deny)| PathRules { allow, ask, deny })
}

fn file_section() -> impl Strategy<Value = FileSection> {
    (path_rules(), path_rules()).prop_map(|(read, write)| FileSection { read, write })
}

fn cidr() -> impl Strategy<Value = String> {
    (0u8..=255, 0u8..=255, 0u8..=255, 0u8..=255, 0u8..=32)
        .prop_map(|(a, b, c, d, p)| format!("{a}.{b}.{c}.{d}/{p}"))
}

fn net_target_matcher() -> impl Strategy<Value = NetTargetMatcher> {
    prop_oneof![
        prop_oneof![
            word().prop_map(|w| format!("{w}.com")),
            word().prop_map(|w| format!("*.{w}.com")),
        ]
        .prop_map(NetTargetMatcher::Domain),
        word().prop_map(NetTargetMatcher::Host),
        cidr().prop_map(NetTargetMatcher::Cidr),
    ]
}

fn net_rule() -> impl Strategy<Value = NetRule> {
    (net_target_matcher(), opt_reason()).prop_map(|(target, reason)| NetRule { target, reason })
}

fn network_section() -> impl Strategy<Value = NetworkSection> {
    (
        prop::collection::vec(net_rule(), 0..=3),
        prop::collection::vec(net_rule(), 0..=3),
        prop::collection::vec(net_rule(), 0..=3),
    )
        .prop_map(|(allow, ask, deny)| NetworkSection { allow, ask, deny })
}

fn tool_pattern() -> impl Strategy<Value = ToolPattern> {
    let pat = prop_oneof![
        word(),
        word().prop_map(|w| format!("{w}.*")),
        (word(), word()).prop_map(|(a, b)| format!("{a}.{b}")),
    ];
    (pat, opt_reason()).prop_map(|(pattern, reason)| ToolPattern { pattern, reason })
}

fn mcp_section() -> impl Strategy<Value = McpSection> {
    (
        prop::collection::vec(tool_pattern(), 0..=3),
        prop::collection::vec(tool_pattern(), 0..=3),
        prop::collection::vec(tool_pattern(), 0..=3),
    )
        .prop_map(|(allow, ask, deny)| McpSection {
            tools: ToolRules { allow, ask, deny },
        })
}

fn secret_pattern() -> impl Strategy<Value = SecretPattern> {
    (word(), word()).prop_map(|(name, regex)| SecretPattern { name, regex })
}

fn secret_section() -> impl Strategy<Value = SecretSection> {
    (
        any::<bool>(),
        any::<bool>(),
        prop::collection::vec(secret_pattern(), 0..=3),
    )
        .prop_map(|(redact, block_in_diffs, patterns)| SecretSection {
            redact,
            block_in_diffs,
            patterns,
        })
}

fn audit_section() -> impl Strategy<Value = AuditSection> {
    (
        prop::collection::vec(word(), 1..=3).prop_map(|ws| PathBuf::from(ws.join("/"))),
        any::<bool>(),
        any::<bool>(),
    )
        .prop_map(|(path, redact_stdout, redact_stderr)| AuditSection {
            path,
            format: AuditFormat::Jsonl,
            redact_stdout,
            redact_stderr,
        })
}

fn profile() -> impl Strategy<Value = Profile> {
    (
        prop::option::of(gate_decision()),
        prop::option::of(mode()),
        prop::option::of(command_section()),
        prop::option::of(file_section()),
        prop::option::of(any::<bool>()),
        prop::option::of(prop::collection::vec(word(), 0..=2)),
    )
        .prop_map(
            |(default_decision, mode, commands, files, hard_denies_disabled, agents)| Profile {
                parent: None,
                default_decision,
                mode,
                commands,
                files,
                network: None,
                mcp: None,
                secrets: None,
                audit: None,
                hard_denies_disabled,
                agents,
            },
        )
}

fn profiles() -> impl Strategy<Value = BTreeMap<String, Profile>> {
    prop::collection::btree_map(word(), profile(), 0..=2)
}

fn policy_file() -> impl Strategy<Value = PolicyFile> {
    (
        gate_decision(),
        profiles(),
        command_section(),
        file_section(),
        network_section(),
        mcp_section(),
        secret_section(),
        audit_section(),
        any::<bool>(),
        prop::collection::vec(word(), 0..=3),
    )
        .prop_map(
            |(
                default_decision,
                profiles,
                commands,
                files,
                network,
                mcp,
                secrets,
                audit,
                hard_denies_disabled,
                agents,
            )| PolicyFile {
                version: 1,
                default_decision,
                profiles,
                commands,
                files,
                network,
                mcp,
                secrets,
                audit,
                hard_denies_disabled,
                agents,
            },
        )
}

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

// ---------------------------------------------------------------------------
// Action generators — every action kind, with deliberately weird payloads to
// exercise the evaluator broadly across all stages.
// ---------------------------------------------------------------------------

fn actor() -> impl Strategy<Value = Actor> {
    prop_oneof![Just(Actor::Agent), Just(Actor::User)]
}

fn protocol() -> impl Strategy<Value = Protocol> {
    prop_oneof![Just(Protocol::Http), Just(Protocol::Https)]
}

fn argv_token() -> impl Strategy<Value = String> {
    prop_oneof![
        word(),
        Just("rm".to_string()),
        Just("-rf".to_string()),
        Just("/".to_string()),
        Just("git".to_string()),
        Just("--force".to_string()),
        "[a-z./*-]{1,8}",
    ]
}

fn weird_path() -> impl Strategy<Value = PathBuf> {
    prop_oneof![
        Just(PathBuf::new()),
        Just(PathBuf::from("/")),
        Just(PathBuf::from(".env")),
        Just(PathBuf::from("/etc/shadow")),
        prop::collection::vec(word(), 1..=4).prop_map(|ws| PathBuf::from(ws.join("/"))),
        prop::collection::vec(word(), 1..=4)
            .prop_map(|ws| PathBuf::from(format!("/{}", ws.join("/")))),
        "[a-zA-Z0-9._/*-]{0,16}".prop_map(PathBuf::from),
    ]
}

fn weird_host() -> impl Strategy<Value = String> {
    prop_oneof![
        Just(String::new()),
        Just("localhost".to_string()),
        Just("127.0.0.1".to_string()),
        Just("169.254.169.254".to_string()),
        Just("example.com".to_string()),
        word().prop_map(|w| format!("{w}.com")),
        (0u8..=255, 0u8..=255, 0u8..=255, 0u8..=255)
            .prop_map(|(a, b, c, d)| format!("{a}.{b}.{c}.{d}")),
        "[a-zA-Z0-9.-]{0,20}",
    ]
}

fn opt_domain() -> impl Strategy<Value = Option<String>> {
    prop::option::of(prop_oneof![
        word().prop_map(|w| format!("{w}.com")),
        Just("example.com".to_string()),
        "[a-z.-]{1,16}",
    ])
}

fn net_target_value() -> impl Strategy<Value = NetTarget> {
    (opt_domain(), weird_host(), protocol()).prop_map(|(domain, host, protocol)| NetTarget {
        domain,
        host,
        protocol,
    })
}

fn tool_name() -> impl Strategy<Value = String> {
    prop_oneof![
        Just(String::new()),
        word(),
        (word(), word()).prop_map(|(a, b)| format!("{a}.{b}")),
        "[a-zA-Z0-9._-]{0,24}",
    ]
}

fn finding() -> impl Strategy<Value = Finding> {
    (
        tool_name(),
        opt_reason().prop_map(|r| r.unwrap_or_default()),
    )
        .prop_map(|(pattern_id, reason)| Finding { pattern_id, reason })
}

fn action() -> impl Strategy<Value = Action> {
    let command = (
        prop::collection::vec(argv_token(), 1..=4),
        weird_path(),
        actor(),
    )
        .prop_map(|(argv, cwd, actor)| Action {
            kind: ActionKind::CommandRun,
            actor,
            payload: ActionPayload::Command { argv, cwd },
        });

    let file = (
        prop_oneof![
            Just(ActionKind::FileRead),
            Just(ActionKind::FileWrite),
            Just(ActionKind::FileDelete),
        ],
        weird_path(),
        actor(),
    )
        .prop_map(|(kind, path, actor)| Action {
            kind,
            actor,
            payload: ActionPayload::File { path },
        });

    let network = (net_target_value(), actor()).prop_map(|(target, actor)| Action {
        kind: ActionKind::NetworkRequest,
        actor,
        payload: ActionPayload::Network { target },
    });

    let mcp = (tool_name(), actor()).prop_map(|(tool_name, actor)| Action {
        kind: ActionKind::McpToolCall,
        actor,
        payload: ActionPayload::Mcp { tool_name },
    });

    let secret = (finding(), actor()).prop_map(|(finding, actor)| Action {
        kind: ActionKind::SecretDetected,
        actor,
        payload: ActionPayload::Secret { finding },
    });

    prop_oneof![command, file, network, mcp, secret]
}

// ---------------------------------------------------------------------------
// Property 4
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig { cases: 100, ..ProptestConfig::default() })]

    // Feature: fida-mvp, Property 4: Decision result completeness
    #[test]
    fn decision_result_is_complete(policy in policy_file(), action in action()) {
        let compiled = load_via_yaml(&policy);
        let result = evaluate(&compiled, &action);

        // (a) decision is one of the four defined variants. The enum makes this
        //     true by type; assert the exhaustive match to document the invariant.
        prop_assert!(matches!(
            result.decision,
            Decision::Allow | Decision::Ask | Decision::Deny | Decision::DryRun
        ));

        // (b) risk is one of the three defined variants (true by type).
        prop_assert!(matches!(
            result.risk,
            Risk::Low | Risk::Medium | Risk::High
        ));

        // (c) reason is never empty.
        prop_assert!(
            !result.reason.is_empty(),
            "DecisionResult.reason was empty for stage {:?}",
            result.stage
        );

        // (d) matched_rule is well-formed: a Rule must carry a non-empty id.
        if let MatchedRule::Rule(ref id) = result.matched_rule {
            prop_assert!(
                !id.is_empty(),
                "MatchedRule::Rule carried an empty id at stage {:?}",
                result.stage
            );
        }

        // (e) explicit and materialized stages carry a concrete rule id;
        //     default stages carry NoExplicitRule.
        match result.stage {
            EvalStage::HardDeny
            | EvalStage::SecretDetection
            | EvalStage::ExplicitDeny
            | EvalStage::ExplicitAllow
            | EvalStage::ExplicitAsk => {
                match result.matched_rule {
                    MatchedRule::Rule(ref id) => prop_assert!(
                        !id.is_empty(),
                        "explicit/materialized stage {:?} carried an empty rule id",
                        result.stage
                    ),
                    MatchedRule::NoExplicitRule => prop_assert!(
                        false,
                        "explicit/materialized stage {:?} carried NoExplicitRule",
                        result.stage
                    ),
                }
            }
            EvalStage::ProfileDefault | EvalStage::GlobalDefault => {
                prop_assert_eq!(
                    &result.matched_rule,
                    &MatchedRule::NoExplicitRule,
                    "default stage {:?} did not carry NoExplicitRule",
                    result.stage
                );
            }
        }
    }
}
