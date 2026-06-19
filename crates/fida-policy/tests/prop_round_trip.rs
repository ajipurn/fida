// Feature: fida-mvp, Property 16: Policy round-trip
//
// Property 16: serializing any valid version-1 policy to YAML and loading it
// back yields an equivalent `CompiledPolicy`.
//
//
// `CompiledPolicy` intentionally derives neither `PartialEq` nor `Serialize`
// (compiled regex/glob engines have no meaningful structural equality), so we
// assert equivalence two ways:
//   1. Exact round-trip at the `PolicyFile` level (it derives `PartialEq`):
//      `parse(serialize(p)) == p`.
//   2. Structural equivalence of the resulting `CompiledPolicy`: both the
//      original-serialized YAML and the reparsed-then-reserialized YAML must
//      load successfully and produce the same rule ids, counts, decision
//      values, and pattern/source strings (captured by `summarize`).

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

// ---------------------------------------------------------------------------
// Structural summary of a CompiledPolicy (a comparable, equality-able view)
// ---------------------------------------------------------------------------

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

#[derive(Debug, PartialEq)]
struct Summary {
    version: u32,
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

    // The materialized built-in hard denies must be stable across loads.
    hard_deny_command_ids: Vec<String>,
    hard_deny_file_ids: Vec<String>,
    hard_deny_hosts: Vec<String>,
    hard_deny_cidrs: Vec<String>,
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
        version: p.version,
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

        hard_deny_command_ids: p
            .hard_denies
            .command_patterns
            .iter()
            .map(|h| h.rule_id.clone())
            .collect(),
        hard_deny_file_ids: p
            .hard_denies
            .file_globs
            .iter()
            .map(|h| h.rule_id.clone())
            .collect(),
        hard_deny_hosts: p.hard_denies.network_hosts.clone(),
        hard_deny_cidrs: p
            .hard_denies
            .network_cidrs
            .iter()
            .map(|c| c.to_string())
            .collect(),
    }
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
// Generators — constrained to the valid version-1 input space
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

/// A command string: 1–3 safe words joined by single spaces.
fn command_string() -> impl Strategy<Value = String> {
    prop::collection::vec(word(), 1..=3).prop_map(|ws| ws.join(" "))
}

/// A command matcher. Regex patterns are kept to valid literal words so
/// compilation always succeeds (the property is about round-trip, not the
/// matcher language).
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

/// A glob pattern that compiles cleanly under `globset`.
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

/// A valid IPv4 CIDR string. Host bits are tolerated by `ipnetwork::FromStr`.
fn cidr() -> impl Strategy<Value = String> {
    (0u8..=255, 0u8..=255, 0u8..=255, 0u8..=255, 0u8..=32)
        .prop_map(|(a, b, c, d, p)| format!("{a}.{b}.{c}.{d}/{p}"))
}

fn net_target() -> impl Strategy<Value = NetTargetMatcher> {
    prop_oneof![
        // Domains are compiled as globs, so keep them glob-valid.
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
    // Regex kept to a literal word so compilation always succeeds.
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

/// A profile with no `parent` (cycle/parent resolution is exercised by
/// Property 8, task 3.4). Round-trip only needs valid serializable overrides.
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

// ---------------------------------------------------------------------------
// Property 16
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig { cases: 100, ..ProptestConfig::default() })]

    // Feature: fida-mvp, Property 16: Policy round-trip
    #[test]
    fn policy_round_trip_yields_equivalent_compiled_policy(policy in policy_file()) {
        // 1. Exact round-trip at the PolicyFile level.
        let yaml = serde_yaml::to_string(&policy).expect("serialize");
        let reparsed: PolicyFile = serde_yaml::from_str(&yaml).expect("reparse");
        prop_assert_eq!(&policy, &reparsed, "PolicyFile did not round-trip through YAML");

        // 2. Both the original and the reparsed policy compile to structurally
        //    equivalent CompiledPolicy values.
        let compiled_original = load_via_yaml(&policy);
        let compiled_reparsed = load_via_yaml(&reparsed);
        prop_assert_eq!(
            summarize(&compiled_original),
            summarize(&compiled_reparsed),
            "CompiledPolicy summaries diverged after round-trip"
        );
    }
}
