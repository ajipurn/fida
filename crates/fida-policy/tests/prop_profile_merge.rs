// Feature: fida-mvp, Property 8: Profile merge precedence
//
// Property 8: for any base policy and a single profile overriding a random
// subset of fields, the compiled policy reflects the profile's value for every
// overridden field and retains the base value for every non-overridden field.
//
//
// `CompiledPolicy` derives neither `PartialEq` nor `Serialize` (compiled
// regex/glob engines have no meaningful structural equality), so we assert
// equivalence through a comparable structural `Summary` (mirroring the sibling
// `prop_round_trip.rs`). The merge is exercised through the real public path:
// serialize a generated `PolicyFile` to a temp YAML file and call
// `load_source(&PolicySource::Config(path), Some("prof"))`.
//
// Merge semantics under test (see loader `apply_profile`):
//   * Section-valued overrides (`commands`, `files`, `network`, `mcp`,
//     `secrets`, `audit`, `hard_denies_disabled`, `agents`) replace the base
//     section wholesale when present, otherwise the base value is retained.
//   * `mode` populates the compiled `mode` slot (the base PolicyFile has no
//     top-level mode), so it is `Some(profile.mode)` when overridden and `None`
//     otherwise.
//   * The global `default_decision` is NEVER replaced: a profile's
//     `default_decision` lands in the separate `profile_default_decision` slot
//     (`Some(value)` when the profile sets it, `None` when it does not), while
//     the compiled `default_decision` always equals the base global.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::PathBuf;

use fida_action::{Decision, Mode};
use fida_policy::compiled::{CompiledCommandMatcher, CompiledNetTarget, CompiledPolicy};
use fida_policy::loader::{PolicySource, load_source};
use fida_policy::schema::{
    AuditFormat, AuditSection, CommandMatcher, CommandRule, CommandSection, FileSection,
    McpSection, NetRule, NetTargetMatcher, NetworkSection, PathRules, PolicyFile, Profile,
    SecretPattern, SecretSection, ToolPattern, ToolRules,
};
use proptest::prelude::*;

// Comparable structural views of the section-valued parts of a CompiledPolicy.

#[derive(Debug, PartialEq)]
struct GlobSummary {
    rule_id: String,
    source: String,
}

#[derive(Debug, PartialEq)]
struct CmdSummary {
    rule_id: String,
    matcher: String,
    working_dir: Option<PathBuf>,
    reason: Option<String>,
    auto_approve: bool,
}

#[derive(Debug, PartialEq)]
struct NetSummary {
    rule_id: String,
    target: String,
    reason: Option<String>,
}

#[derive(Debug, PartialEq)]
struct ToolSummary {
    rule_id: String,
    source: String,
    reason: Option<String>,
}

#[derive(Debug, PartialEq)]
struct SecretSummary {
    name: String,
    regex: String,
}

/// The merge-relevant projection of a `CompiledPolicy`. Excludes the built-in
/// hard denies (constant across loads) and the `version` (never profiled).
#[derive(Debug, PartialEq)]
struct Summary {
    default_decision: Decision,
    mode: Option<Mode>,
    profile_default_decision: Option<Decision>,

    cmd_allow: Vec<CmdSummary>,
    cmd_ask: Vec<CmdSummary>,
    cmd_deny: Vec<CmdSummary>,

    file_read_allow: Vec<GlobSummary>,
    file_read_ask: Vec<GlobSummary>,
    file_read_deny: Vec<GlobSummary>,
    file_write_allow: Vec<GlobSummary>,
    file_write_ask: Vec<GlobSummary>,
    file_write_deny: Vec<GlobSummary>,

    net_allow: Vec<NetSummary>,
    net_ask: Vec<NetSummary>,
    net_deny: Vec<NetSummary>,

    tool_allow: Vec<ToolSummary>,
    tool_ask: Vec<ToolSummary>,
    tool_deny: Vec<ToolSummary>,

    secret_redact: bool,
    secret_block_in_diffs: bool,
    secret_patterns: Vec<SecretSummary>,

    audit_path: PathBuf,
    audit_format: AuditFormat,
    audit_redact_stdout: bool,
    audit_redact_stderr: bool,

    hard_denies_disabled: bool,
    agents: Vec<String>,
}

fn matcher_repr(m: &CompiledCommandMatcher) -> String {
    match m {
        CompiledCommandMatcher::Exact(s) => format!("exact:{s}"),
        CompiledCommandMatcher::Prefix(s) => format!("prefix:{s}"),
        CompiledCommandMatcher::Binary(s) => format!("binary:{s}"),
        CompiledCommandMatcher::Regex(re) => format!("regex:{}", re.as_str()),
    }
}

fn net_repr(t: &CompiledNetTarget) -> String {
    match t {
        CompiledNetTarget::Domain { pattern, .. } => format!("domain:{pattern}"),
        CompiledNetTarget::Host(h) => format!("host:{h}"),
        CompiledNetTarget::Cidr(n) => format!("cidr:{n}"),
    }
}

fn cmd_tier(rules: &[fida_policy::compiled::CompiledCommandRule]) -> Vec<CmdSummary> {
    rules
        .iter()
        .map(|r| CmdSummary {
            rule_id: r.rule_id.clone(),
            matcher: matcher_repr(&r.matcher),
            working_dir: r.working_dir.clone(),
            reason: r.reason.clone(),
            auto_approve: r.auto_approve,
        })
        .collect()
}

fn glob_tier(rules: &[fida_policy::compiled::CompiledGlobRule]) -> Vec<GlobSummary> {
    rules
        .iter()
        .map(|r| GlobSummary {
            rule_id: r.rule_id.clone(),
            source: r.source.clone(),
        })
        .collect()
}

fn net_tier(rules: &[fida_policy::compiled::CompiledNetRule]) -> Vec<NetSummary> {
    rules
        .iter()
        .map(|r| NetSummary {
            rule_id: r.rule_id.clone(),
            target: net_repr(&r.target),
            reason: r.reason.clone(),
        })
        .collect()
}

fn tool_tier(rules: &[fida_policy::compiled::CompiledToolPattern]) -> Vec<ToolSummary> {
    rules
        .iter()
        .map(|r| ToolSummary {
            rule_id: r.rule_id.clone(),
            source: r.source.clone(),
            reason: r.reason.clone(),
        })
        .collect()
}

fn summarize(p: &CompiledPolicy) -> Summary {
    Summary {
        default_decision: p.default_decision,
        mode: p.mode,
        profile_default_decision: p.profile_default_decision,

        cmd_allow: cmd_tier(&p.commands.allow),
        cmd_ask: cmd_tier(&p.commands.ask),
        cmd_deny: cmd_tier(&p.commands.deny),

        file_read_allow: glob_tier(&p.files.read.allow),
        file_read_ask: glob_tier(&p.files.read.ask),
        file_read_deny: glob_tier(&p.files.read.deny),
        file_write_allow: glob_tier(&p.files.write.allow),
        file_write_ask: glob_tier(&p.files.write.ask),
        file_write_deny: glob_tier(&p.files.write.deny),

        net_allow: net_tier(&p.network.allow),
        net_ask: net_tier(&p.network.ask),
        net_deny: net_tier(&p.network.deny),

        tool_allow: tool_tier(&p.mcp.tools.allow),
        tool_ask: tool_tier(&p.mcp.tools.ask),
        tool_deny: tool_tier(&p.mcp.tools.deny),

        secret_redact: p.secrets.redact,
        secret_block_in_diffs: p.secrets.block_in_diffs,
        secret_patterns: p
            .secrets
            .patterns
            .iter()
            .map(|s| SecretSummary {
                name: s.name.clone(),
                regex: s.regex.as_str().to_string(),
            })
            .collect(),

        audit_path: p.audit.path.clone(),
        audit_format: p.audit.format,
        audit_redact_stdout: p.audit.redact_stdout,
        audit_redact_stderr: p.audit.redact_stderr,

        hard_denies_disabled: p.hard_denies_disabled,
        agents: p.agents.clone(),
    }
}

/// Serialize a `PolicyFile` to a temp YAML file and load it back through the
/// real loader pipeline, merging the optional named profile.
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

/// Apply the profile's section-valued overrides onto a clone of `base` at the
/// schema level, mirroring the loader's wholesale-replacement semantics. The
/// result has no profiles, so loading it with no `--profile` produces the
/// "expected merged" section values: profile value where overridden, base
/// value otherwise. Note: `default_decision`/`mode` are deliberately NOT
/// applied here — they have dedicated compiled slots asserted separately.
fn expected_section_base(base: &PolicyFile, profile: &Profile) -> PolicyFile {
    let mut p = base.clone();
    if let Some(c) = &profile.commands {
        p.commands = c.clone();
    }
    if let Some(f) = &profile.files {
        p.files = f.clone();
    }
    if let Some(n) = &profile.network {
        p.network = n.clone();
    }
    if let Some(m) = &profile.mcp {
        p.mcp = m.clone();
    }
    if let Some(s) = &profile.secrets {
        p.secrets = s.clone();
    }
    if let Some(a) = &profile.audit {
        p.audit = a.clone();
    }
    if let Some(b) = profile.hard_denies_disabled {
        p.hard_denies_disabled = b;
    }
    if let Some(ag) = &profile.agents {
        p.agents = ag.clone();
    }
    p.profiles = BTreeMap::new();
    p
}

// Generators — constrained to the valid version-1 input space.

fn word() -> impl Strategy<Value = String> {
    "[a-z][a-z0-9]{0,5}".prop_map(|s| s)
}

fn gate_decision() -> impl Strategy<Value = Decision> {
    prop_oneof![
        Just(Decision::Allow),
        Just(Decision::Ask),
        Just(Decision::Deny),
    ]
}

fn mode() -> impl Strategy<Value = Mode> {
    prop_oneof![Just(Mode::Observe), Just(Mode::Enforce), Just(Mode::DryRun)]
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

fn net_target() -> impl Strategy<Value = NetTargetMatcher> {
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
    (net_target(), opt_reason()).prop_map(|(target, reason)| NetRule { target, reason })
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

/// A base policy with NO profiles (the single test profile is added by the
/// test body). This is the unprofiled baseline whose values must be retained
/// wherever the profile does not override.
fn base_policy() -> impl Strategy<Value = PolicyFile> {
    (
        gate_decision(),
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
                profiles: BTreeMap::new(),
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

/// A parentless profile that overrides a random subset of fields. Each `None`
/// leaves the corresponding base value untouched; each `Some` overrides it.
fn overriding_profile() -> impl Strategy<Value = Profile> {
    (
        prop::option::of(gate_decision()),
        prop::option::of(mode()),
        prop::option::of(command_section()),
        prop::option::of(file_section()),
        prop::option::of(network_section()),
        prop::option::of(mcp_section()),
        prop::option::of(secret_section()),
        prop::option::of(audit_section()),
        prop::option::of(any::<bool>()),
        prop::option::of(prop::collection::vec(word(), 0..=2)),
    )
        .prop_map(
            |(
                default_decision,
                mode,
                commands,
                files,
                network,
                mcp,
                secrets,
                audit,
                hard_denies_disabled,
                agents,
            )| Profile {
                parent: None,
                default_decision,
                mode,
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

// Property 8

proptest! {
    #![proptest_config(ProptestConfig { cases: 100, ..ProptestConfig::default() })]

    // Feature: fida-mvp, Property 8: Profile merge precedence
    #[test]
    fn profile_merge_takes_overrides_and_retains_base(
        base in base_policy(),
        profile in overriding_profile(),
    ) {
        // Build the policy containing the single named profile.
        let mut with_profile = base.clone();
        with_profile
            .profiles
            .insert("prof".to_string(), profile.clone());

        // Load with the profile active — the artifact under test.
        let merged = summarize(&load_via_yaml(&with_profile, Some("prof")));

        // The unprofiled baseline (every field at its base value).
        let base_compiled = summarize(&load_via_yaml(&base, None));

        // Section-valued fields: build the expected merged sections by applying
        // only the profile's section overrides onto the base, then loading with
        // no profile. This encodes "profile value where overridden, base value
        // otherwise" for every wholesale-replaced section.
        let expected_sections =
            summarize(&load_via_yaml(&expected_section_base(&base, &profile), None));

        // --- Wholesale section precedence ---
        prop_assert_eq!(&merged.cmd_allow, &expected_sections.cmd_allow);
        prop_assert_eq!(&merged.cmd_ask, &expected_sections.cmd_ask);
        prop_assert_eq!(&merged.cmd_deny, &expected_sections.cmd_deny);

        prop_assert_eq!(&merged.file_read_allow, &expected_sections.file_read_allow);
        prop_assert_eq!(&merged.file_read_ask, &expected_sections.file_read_ask);
        prop_assert_eq!(&merged.file_read_deny, &expected_sections.file_read_deny);
        prop_assert_eq!(&merged.file_write_allow, &expected_sections.file_write_allow);
        prop_assert_eq!(&merged.file_write_ask, &expected_sections.file_write_ask);
        prop_assert_eq!(&merged.file_write_deny, &expected_sections.file_write_deny);

        prop_assert_eq!(&merged.net_allow, &expected_sections.net_allow);
        prop_assert_eq!(&merged.net_ask, &expected_sections.net_ask);
        prop_assert_eq!(&merged.net_deny, &expected_sections.net_deny);

        prop_assert_eq!(&merged.tool_allow, &expected_sections.tool_allow);
        prop_assert_eq!(&merged.tool_ask, &expected_sections.tool_ask);
        prop_assert_eq!(&merged.tool_deny, &expected_sections.tool_deny);

        prop_assert_eq!(merged.secret_redact, expected_sections.secret_redact);
        prop_assert_eq!(
            merged.secret_block_in_diffs,
            expected_sections.secret_block_in_diffs
        );
        prop_assert_eq!(&merged.secret_patterns, &expected_sections.secret_patterns);

        prop_assert_eq!(&merged.audit_path, &expected_sections.audit_path);
        prop_assert_eq!(merged.audit_format, expected_sections.audit_format);
        prop_assert_eq!(
            merged.audit_redact_stdout,
            expected_sections.audit_redact_stdout
        );
        prop_assert_eq!(
            merged.audit_redact_stderr,
            expected_sections.audit_redact_stderr
        );

        prop_assert_eq!(
            merged.hard_denies_disabled,
            expected_sections.hard_denies_disabled
        );
        prop_assert_eq!(&merged.agents, &expected_sections.agents);

        // --- Per-field override-vs-retain checks for non-section slots ---

        // Global default_decision is NEVER replaced by a profile: the compiled
        // default always equals the base global, regardless of the profile.
        prop_assert_eq!(merged.default_decision, base.default_decision);
        prop_assert_eq!(merged.default_decision, base_compiled.default_decision);

        // A profile's default_decision lands in the dedicated profile slot:
        // Some(value) when set, None when the profile does not set it.
        prop_assert_eq!(merged.profile_default_decision, profile.default_decision);

        // mode has no top-level base value, so the compiled slot is exactly the
        // profile's mode (Some when overridden, None otherwise).
        prop_assert_eq!(merged.mode, profile.mode);
    }
}
