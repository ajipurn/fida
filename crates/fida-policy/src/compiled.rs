//! The **compiled** (post-load) policy form — the *only* form the evaluator
//! sees (design "Data Models": `CompiledPolicy`).
//!
//! Where [`crate::schema`] holds raw strings, this module holds the artifacts
//! the loader (task 3.2) produces: command regexes compiled into
//! [`regex::Regex`], file/tool globs compiled into [`globset::GlobMatcher`],
//! network CIDRs parsed into [`ipnetwork::IpNetwork`], the selected profile
//! already merged over the base, and the built-in hard denies materialized.
//!
//! These types are runtime artifacts, not wire types: they derive `Debug` and
//! `Clone` but deliberately not `Serialize`/`Deserialize` or `PartialEq`
//! (compiled regex/glob engines have no meaningful structural equality).

use std::path::PathBuf;

use fida_action::{Decision, Mode};
use globset::GlobMatcher;
use ipnetwork::IpNetwork;
use regex::Regex;

use crate::schema::AuditSection;

/// A fully evaluatable policy: validated, globs expanded, regexes compiled,
/// the active profile merged in, and hard denies materialized.
///
/// Produced by the loader from a [`crate::schema::PolicyFile`]; consumed by the
/// evaluator as a pure input (`evaluate(&CompiledPolicy, &Action)`).
#[derive(Debug, Clone)]
pub struct CompiledPolicy {
    /// Always `1` for this schema version.
    pub version: u32,
    /// Effective global default after profile merge.
    pub default_decision: Decision,
    /// Effective session mode after profile merge, if the active profile (or
    /// base) declared one.
    pub mode: Option<Mode>,
    /// Effective profile default decision, applied at stage 6 before the
    /// global default at stage 7. `None` when the active
    /// profile declares no default of its own.
    pub profile_default_decision: Option<Decision>,

    pub commands: CompiledCommandSection,
    pub files: CompiledFileSection,
    pub network: CompiledNetworkSection,
    pub mcp: CompiledMcpSection,
    pub secrets: CompiledSecretSection,
    /// Audit config carries no compiled artifacts, so the schema type is reused.
    pub audit: AuditSection,

    /// When `true`, the evaluator skips the hard-deny stage.
    pub hard_denies_disabled: bool,
    pub agents: Vec<String>,

    /// Built-in hard-deny rules materialized at load time.
    pub hard_denies: HardDenies,
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

/// Compiled command rules grouped by decision tier, evaluated in document
/// order within each tier (deny → allow → ask at the evaluator level).
#[derive(Debug, Clone, Default)]
pub struct CompiledCommandSection {
    pub allow: Vec<CompiledCommandRule>,
    pub ask: Vec<CompiledCommandRule>,
    pub deny: Vec<CompiledCommandRule>,
}

/// A command rule with its matcher compiled and its identity/metadata retained.
#[derive(Debug, Clone)]
pub struct CompiledCommandRule {
    /// Stable identifier for audit / explain output, e.g. `commands.ask[1]`
    pub rule_id: String,
    pub matcher: CompiledCommandMatcher,
    /// Working-directory condition.
    pub working_dir: Option<PathBuf>,
    pub reason: Option<String>,
    /// Eligibility for `--yes` auto-approval.
    pub auto_approve: bool,
}

/// A command matcher with any regex already compiled.
#[derive(Debug, Clone)]
pub enum CompiledCommandMatcher {
    Exact(String),
    Prefix(String),
    Regex(Regex),
    Binary(String),
}

// ---------------------------------------------------------------------------
// Files
// ---------------------------------------------------------------------------

/// Compiled file policy for read and write paths.
#[derive(Debug, Clone, Default)]
pub struct CompiledFileSection {
    pub read: CompiledPathRules,
    pub write: CompiledPathRules,
}

/// Compiled glob path rules grouped by decision tier.
#[derive(Debug, Clone, Default)]
pub struct CompiledPathRules {
    pub allow: Vec<CompiledGlobRule>,
    pub ask: Vec<CompiledGlobRule>,
    pub deny: Vec<CompiledGlobRule>,
}

/// A compiled glob with its source pattern and rule identity retained so the
/// evaluator can report the matched rule.
#[derive(Debug, Clone)]
pub struct CompiledGlobRule {
    pub rule_id: String,
    /// The original glob text, kept for explain output and debugging.
    pub source: String,
    pub matcher: GlobMatcher,
}

// ---------------------------------------------------------------------------
// Network
// ---------------------------------------------------------------------------

/// Compiled network rules grouped by decision tier.
#[derive(Debug, Clone, Default)]
pub struct CompiledNetworkSection {
    pub allow: Vec<CompiledNetRule>,
    pub ask: Vec<CompiledNetRule>,
    pub deny: Vec<CompiledNetRule>,
}

/// A compiled network rule with its target matcher and identity retained.
#[derive(Debug, Clone)]
pub struct CompiledNetRule {
    pub rule_id: String,
    pub target: CompiledNetTarget,
    pub reason: Option<String>,
}

/// A compiled network target. Domain/host stay as
/// strings; CIDR is parsed into an [`IpNetwork`] for membership tests.
#[derive(Debug, Clone)]
pub enum CompiledNetTarget {
    /// Domain match; the optional compiled glob supports wildcard `*`.
    Domain {
        pattern: String,
        matcher: GlobMatcher,
    },
    Host(String),
    Cidr(IpNetwork),
}

// ---------------------------------------------------------------------------
// MCP
// ---------------------------------------------------------------------------

/// Compiled MCP policy.
#[derive(Debug, Clone, Default)]
pub struct CompiledMcpSection {
    pub tools: CompiledToolRules,
}

/// Compiled tool-name patterns grouped by decision tier.
#[derive(Debug, Clone, Default)]
pub struct CompiledToolRules {
    pub allow: Vec<CompiledToolPattern>,
    pub ask: Vec<CompiledToolPattern>,
    pub deny: Vec<CompiledToolPattern>,
}

/// A compiled glob/prefix pattern over dotted tool names (e.g. `browser.*`).
#[derive(Debug, Clone)]
pub struct CompiledToolPattern {
    pub rule_id: String,
    pub source: String,
    pub matcher: GlobMatcher,
    pub reason: Option<String>,
}

// ---------------------------------------------------------------------------
// Secrets
// ---------------------------------------------------------------------------

/// Compiled secret detection configuration.
#[derive(Debug, Clone, Default)]
pub struct CompiledSecretSection {
    pub redact: bool,
    pub block_in_diffs: bool,
    pub patterns: Vec<CompiledSecretPattern>,
}

/// A compiled named secret pattern. `name` is the `pattern_id` surfaced in
/// findings — never the secret value.
#[derive(Debug, Clone)]
pub struct CompiledSecretPattern {
    pub name: String,
    pub regex: Regex,
}

// ---------------------------------------------------------------------------
// Hard denies (materialized built-ins)
// ---------------------------------------------------------------------------

/// The built-in hard-deny rules materialized at load time.
///
/// Populated by the loader (task 3.2) / matcher materialization (task 4.3):
/// destructive command patterns, sensitive file paths, and the network
/// metadata IP + private CIDRs. Evaluated at stage 1 unless
/// [`CompiledPolicy::hard_denies_disabled`] is set.
#[derive(Debug, Clone, Default)]
pub struct HardDenies {
    /// Destructive command regexes, e.g. `rm -rf /|~|.`, `curl ... | sh`.
    pub command_patterns: Vec<HardDenyPattern>,
    /// Sensitive file write/delete globs, e.g. `.env`, `**/*.pem`, key files.
    pub file_globs: Vec<CompiledGlobRule>,
    /// Built-in denied hosts, e.g. the cloud metadata IP `169.254.169.254`.
    pub network_hosts: Vec<String>,
    /// Built-in denied CIDRs, e.g. `10.0.0.0/8`, `172.16.0.0/12`,
    /// `192.168.0.0/16`.
    pub network_cidrs: Vec<IpNetwork>,
}

/// A materialized hard-deny regex with its identity and human-readable reason.
#[derive(Debug, Clone)]
pub struct HardDenyPattern {
    /// Stable id, e.g. `builtin.hard_deny.destructive_rm`.
    pub rule_id: String,
    pub regex: Regex,
    pub reason: String,
}
