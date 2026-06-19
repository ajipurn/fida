//! Version-1 policy **schema** types — the raw form parsed directly from a
//! `fida.yaml` / `.fida/policy.yaml` document.
//!
//! These types mirror `examples/fida.yaml` and the design's
//! "Policy Schema (version 1)" section. They are intentionally *pure data*:
//! command matchers carry regex/glob/cidr patterns as plain strings, no
//! compilation happens here. Loading, validation, glob expansion, regex
//! compilation, and profile merge are the loader's job (task 3.2); the
//! evaluator never sees these types — it only sees [`crate::CompiledPolicy`].
//!
//! Every type derives `serde` so a parsed policy can be round-tripped
//! (design Property 16) and so `fida policy schema` can describe the shape.

use std::collections::BTreeMap;
use std::path::PathBuf;

use fida_action::{Decision, Mode};
use serde::{Deserialize, Serialize};

/// `skip_serializing_if` helper for `bool` fields that default to `false`.
fn is_false(b: &bool) -> bool {
    !*b
}

/// A complete version-1 policy document as parsed from YAML.
///
/// Matches the top-level shape of `examples/fida.yaml`. Optional sections
/// default to empty so a minimal policy (only `version` + `default_decision`)
/// deserializes; the loader (task 3.2) enforces which fields are required for
/// schema validity.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyFile {
    /// Declared schema version. Only `1` is supported; the loader rejects any
    /// other value.
    pub version: u32,

    /// Global default decision applied when no rule matches.
    /// Must be one of `allow`/`ask`/`deny` — validated by the loader.
    pub default_decision: Decision,

    /// Named profiles selectable with `--profile`. Ordered
    /// for deterministic iteration during merge and cycle detection.
    #[serde(default)]
    pub profiles: BTreeMap<String, Profile>,

    #[serde(default)]
    pub commands: CommandSection,
    #[serde(default)]
    pub files: FileSection,
    #[serde(default)]
    pub network: NetworkSection,
    #[serde(default)]
    pub mcp: McpSection,
    #[serde(default)]
    pub secrets: SecretSection,
    #[serde(default)]
    pub audit: AuditSection,

    /// When `true`, the built-in hard-deny stage is skipped.
    /// Defaults to `false` (hard denies enabled).
    #[serde(default, skip_serializing_if = "is_false")]
    pub hard_denies_disabled: bool,

    /// Configured agent binaries Fida knows how to launch.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub agents: Vec<String>,
}

/// A named set of overrides layered over the base policy.
///
/// Every field is optional: a present field overrides the base value, an
/// absent field inherits it. `parent` enables single-inheritance chains that
/// the loader resolves with cycle detection.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Profile {
    /// Parent profile to inherit from before applying this profile's overrides.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_decision: Option<Decision>,
    /// Session enforcement mode override.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<Mode>,

    // Any section may be overridden; profile values win on overlap.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commands: Option<CommandSection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub files: Option<FileSection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<NetworkSection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp: Option<McpSection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secrets: Option<SecretSection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit: Option<AuditSection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hard_denies_disabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agents: Option<Vec<String>>,
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

/// Command rules grouped by decision tier.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct CommandSection {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<CommandRule>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ask: Vec<CommandRule>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny: Vec<CommandRule>,
}

/// A single command rule: one matcher plus optional conditions/metadata.
///
/// The matcher is flattened so the YAML reads `- exact: git status` or
/// `- prefix: pnpm install` with sibling `reason`/`working_dir`/`auto_approve`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CommandRule {
    #[serde(flatten)]
    pub matcher: CommandMatcher,
    /// Working-directory condition: the rule applies only when the action's
    /// cwd equals or nests under this path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub working_dir: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Eligibility for `--yes` auto-approval. Default false.
    #[serde(default, skip_serializing_if = "is_false")]
    pub auto_approve: bool,
}

/// How a command rule matches a `command.run` action.
///
/// In the raw schema the regex matcher carries the pattern as a string; the
/// loader compiles it into [`crate::compiled::CompiledCommandMatcher`].
/// Externally tagged so each YAML entry names exactly one matcher key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CommandMatcher {
    /// Full command string equals this value.
    Exact(String),
    /// Command string starts with this value on a token boundary.
    Prefix(String),
    /// Compiled regex matches the command string (pattern as written).
    Regex(String),
    /// First argv token's basename equals this binary name.
    Binary(String),
}

// ---------------------------------------------------------------------------
// Files
// ---------------------------------------------------------------------------

/// File policy split into read and write path rules.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct FileSection {
    #[serde(default)]
    pub read: PathRules,
    #[serde(default)]
    pub write: PathRules,
}

/// Glob path rules grouped by decision tier. Patterns are raw glob strings
/// (e.g. `src/**`, `**/*.pem`); the loader expands/compiles them.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct PathRules {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ask: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny: Vec<String>,
}

// ---------------------------------------------------------------------------
// Network
// ---------------------------------------------------------------------------

/// Network rules grouped by decision tier.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct NetworkSection {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<NetRule>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ask: Vec<NetRule>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny: Vec<NetRule>,
}

/// A single network rule: a domain/host/cidr target plus an optional reason.
///
/// The target is flattened so the YAML reads `- domain: github.com` or
/// `- cidr: 10.0.0.0/8` with a sibling `reason`. The cidr is kept as a string
/// here; the loader parses it into an [`ipnetwork::IpNetwork`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetRule {
    #[serde(flatten)]
    pub target: NetTargetMatcher,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// The kind of network target a [`NetRule`] matches.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetTargetMatcher {
    /// Domain match, wildcard `*` supported.
    Domain(String),
    /// Exact host (hostname or IP literal).
    Host(String),
    /// CIDR membership (pattern as written, e.g. `192.168.0.0/16`).
    Cidr(String),
}

// ---------------------------------------------------------------------------
// MCP
// ---------------------------------------------------------------------------

/// MCP policy. Currently scopes `tools/call` gating.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct McpSection {
    #[serde(default)]
    pub tools: ToolRules,
}

/// MCP tool-name rules grouped by decision tier.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ToolRules {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<ToolPattern>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ask: Vec<ToolPattern>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny: Vec<ToolPattern>,
}

/// A glob/prefix pattern over dotted MCP tool names (e.g. `browser.*`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolPattern {
    pub pattern: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

// ---------------------------------------------------------------------------
// Secrets
// ---------------------------------------------------------------------------

/// Secret detection / redaction configuration.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SecretSection {
    /// Deprecated compatibility flag. Model-bound content is always redacted;
    /// setting this to false no longer disables the safety invariant.
    #[serde(default)]
    pub redact: bool,
    /// Block applying a diff file that contains a detected secret.
    #[serde(default)]
    pub block_in_diffs: bool,
    /// Named secret patterns (regex as written); compiled by the loader.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub patterns: Vec<SecretPattern>,
}

/// A named secret pattern: an identifier plus the regex used to detect it.
/// `name` is the `pattern_id` recorded in findings (never the value).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretPattern {
    pub name: String,
    pub regex: String,
}

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

/// Audit store configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditSection {
    /// Directory under which session audit trails are written.
    pub path: PathBuf,
    pub format: AuditFormat,
    #[serde(default = "default_true")]
    pub redact_stdout: bool,
    #[serde(default = "default_true")]
    pub redact_stderr: bool,
}

fn default_true() -> bool {
    true
}

impl Default for AuditSection {
    fn default() -> Self {
        AuditSection {
            path: PathBuf::from(".fida/sessions"),
            format: AuditFormat::Jsonl,
            redact_stdout: true,
            redact_stderr: true,
        }
    }
}

/// On-disk audit format. JSONL is the only supported format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuditFormat {
    #[default]
    Jsonl,
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE: &str = include_str!("../../../examples/fida.yaml");

    #[test]
    fn deserializes_the_example_policy() {
        let policy: PolicyFile = serde_yaml::from_str(EXAMPLE).expect("parse example");
        assert_eq!(policy.version, 1);
        assert_eq!(policy.default_decision, Decision::Ask);

        // Profiles: careful / observe / ci-readonly.
        assert!(policy.profiles.contains_key("careful"));
        assert_eq!(policy.profiles["observe"].mode, Some(Mode::Observe));
        assert_eq!(
            policy.profiles["ci-readonly"].default_decision,
            Some(Decision::Deny)
        );

        // Command matchers flatten correctly.
        assert_eq!(
            policy.commands.allow[0].matcher,
            CommandMatcher::Exact("git status".to_string())
        );
        let install = policy
            .commands
            .ask
            .iter()
            .find(|r| matches!(&r.matcher, CommandMatcher::Prefix(p) if p == "pnpm install"))
            .expect("pnpm install ask rule");
        assert_eq!(
            install.reason.as_deref(),
            Some("package manager installs can run lifecycle scripts")
        );
        assert!(matches!(
            policy.commands.deny[0].matcher,
            CommandMatcher::Regex(_)
        ));

        // File globs land in the right tiers.
        assert!(policy.files.write.allow.contains(&"src/**".to_string()));
        assert!(policy.files.write.deny.contains(&".env".to_string()));

        // Network rules flatten domain/host/cidr.
        assert_eq!(
            policy.network.allow[0].target,
            NetTargetMatcher::Domain("github.com".to_string())
        );
        assert!(
            policy
                .network
                .deny
                .iter()
                .any(|r| r.target == NetTargetMatcher::Host("169.254.169.254".to_string()))
        );
        assert!(
            policy
                .network
                .deny
                .iter()
                .any(|r| matches!(&r.target, NetTargetMatcher::Cidr(c) if c == "10.0.0.0/8"))
        );

        // MCP tool patterns.
        assert_eq!(policy.mcp.tools.allow[0].pattern, "docs.*");
        assert!(policy.mcp.tools.deny.iter().any(|p| p.pattern == "shell.*"));

        // Secrets + audit.
        assert!(policy.secrets.redact);
        assert!(policy.secrets.block_in_diffs);
        assert_eq!(policy.secrets.patterns[0].name, "private_key");
        assert_eq!(policy.audit.format, AuditFormat::Jsonl);
        assert!(policy.audit.redact_stdout);

        // Omitted top-level fields fall back to defaults.
        assert!(!policy.hard_denies_disabled);
        assert!(policy.agents.is_empty());
    }

    #[test]
    fn minimal_policy_uses_section_defaults() {
        let yaml = "version: 1\ndefault_decision: deny\n";
        let policy: PolicyFile = serde_yaml::from_str(yaml).expect("parse minimal");
        assert_eq!(policy.version, 1);
        assert_eq!(policy.default_decision, Decision::Deny);
        assert!(policy.profiles.is_empty());
        assert!(policy.commands.allow.is_empty());
        assert_eq!(policy.audit, AuditSection::default());
        assert!(!policy.secrets.redact);
    }

    #[test]
    fn command_rule_round_trips_through_yaml() {
        let rule = CommandRule {
            matcher: CommandMatcher::Prefix("cargo build".to_string()),
            working_dir: Some(PathBuf::from("crates/fida-cli")),
            reason: Some("scoped build".to_string()),
            auto_approve: true,
        };
        let yaml = serde_yaml::to_string(&rule).expect("serialize");
        let back: CommandRule = serde_yaml::from_str(&yaml).expect("deserialize");
        assert_eq!(rule, back);
    }

    #[test]
    fn policy_file_round_trips_through_yaml() {
        let policy: PolicyFile = serde_yaml::from_str(EXAMPLE).expect("parse");
        let yaml = serde_yaml::to_string(&policy).expect("serialize");
        let back: PolicyFile = serde_yaml::from_str(&yaml).expect("reparse");
        assert_eq!(policy, back);
    }
}
