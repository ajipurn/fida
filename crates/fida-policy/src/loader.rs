//! Policy_Loader — source resolution, reading, parsing, schema validation,
//! compilation, and profile merge (spec task 3.2; design "Policy_Loader").
//!
//! This module transforms a raw `fida.yaml` / `.fida/policy.yaml` document
//! (the [`crate::schema`] form) into a fully evaluatable [`CompiledPolicy`]:
//! globs expanded, regexes/CIDRs compiled, the selected profile merged over the
//! base, and the built-in hard denies materialized.
//!
//! Source resolution follows the precedence `--config` \> `.fida/policy.yaml`
//! \> `fida.yaml` \> built-in default. A missing `--config` path is a hard
//! error, never a fallthrough. Every loader failure is a [`LoadError`], which
//! the CLI surfaces as exit code 4.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use fida_action::{Decision, Mode};
use globset::{Glob, GlobMatcher};
use ipnetwork::IpNetwork;
use regex::Regex;

use crate::compiled::{
    CompiledCommandMatcher, CompiledCommandRule, CompiledCommandSection, CompiledFileSection,
    CompiledGlobRule, CompiledMcpSection, CompiledNetRule, CompiledNetTarget,
    CompiledNetworkSection, CompiledPathRules, CompiledPolicy, CompiledSecretPattern,
    CompiledSecretSection, CompiledToolPattern, CompiledToolRules, HardDenies, HardDenyPattern,
};
use crate::schema::{
    CommandMatcher, CommandRule, CommandSection, FileSection, McpSection, NetRule,
    NetTargetMatcher, NetworkSection, PathRules, PolicyFile, Profile, SecretSection,
};

/// Maximum accepted Policy_File size: 1 MB.
pub const MAX_POLICY_BYTES: usize = 1_048_576;

/// Repo-relative path checked second in the resolution order.
pub const DOT_FIDA_PATH: &str = ".fida/policy.yaml";
/// Repo-relative path checked third in the resolution order.
pub const FIDA_YAML_PATH: &str = "fida.yaml";

// ---------------------------------------------------------------------------
// PolicySource
// ---------------------------------------------------------------------------

/// The resolved origin of a policy (design "Policy_Loader").
///
/// Selected by [`resolve_source`] using the precedence `--config` >
/// `.fida/policy.yaml` > `fida.yaml` > built-in default.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicySource {
    /// Explicit `--config <path>` with no fallthrough.
    Config(PathBuf),
    /// Repo-local `.fida/policy.yaml`.
    DotFida(PathBuf),
    /// Repo-local `fida.yaml`.
    FidaYaml(PathBuf),
    /// No file found and no `--config` given.
    BuiltinDefault,
}

impl PolicySource {
    /// The on-disk path backing this source, if any. `BuiltinDefault` has none.
    pub fn path(&self) -> Option<&Path> {
        match self {
            PolicySource::Config(p) | PolicySource::DotFida(p) | PolicySource::FidaYaml(p) => {
                Some(p)
            }
            PolicySource::BuiltinDefault => None,
        }
    }

    /// Whether this source is the built-in default (drives the
    /// "using built-in default policy" notice.
    pub fn is_builtin_default(&self) -> bool {
        matches!(self, PolicySource::BuiltinDefault)
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// A single schema validation failure with the offending field path
/// (design `SchemaViolation`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaViolation {
    /// Dotted field path, e.g. `version`, `default_decision`,
    /// `profiles.careful.default_decision`.
    pub field_path: String,
    pub message: String,
}

impl SchemaViolation {
    fn new(field_path: impl Into<String>, message: impl Into<String>) -> Self {
        SchemaViolation {
            field_path: field_path.into(),
            message: message.into(),
        }
    }
}

impl std::fmt::Display for SchemaViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.field_path, self.message)
    }
}

/// A profile resolution failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfileError {
    /// `--profile <name>` names a profile not present in the policy.
    Unknown(String),
    /// A profile's `parent` references a profile that does not exist.
    UndefinedParent { profile: String, parent: String },
    /// Profile inheritance forms a cycle; the vec lists the names involved in
    /// resolution order.
    Cycle(Vec<String>),
}

impl std::fmt::Display for ProfileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProfileError::Unknown(name) => write!(f, "profile `{name}` is not defined"),
            ProfileError::UndefinedParent { profile, parent } => write!(
                f,
                "profile `{profile}` inherits from undefined parent `{parent}`"
            ),
            ProfileError::Cycle(chain) => {
                write!(f, "profile inheritance cycle: {}", chain.join(" -> "))
            }
        }
    }
}

/// Every way loading a policy can fail. All variants map to CLI exit code 4
/// (design "Policy_Loader").
#[derive(Debug)]
pub enum LoadError {
    /// `--config` path missing/unreadable, or a resolved file became unreadable.
    /// No fallthrough occurs.
    Io { path: PathBuf, message: String },
    /// Resolved Policy_File exceeds [`MAX_POLICY_BYTES`].
    Size {
        path: PathBuf,
        size: usize,
        max: usize,
    },
    /// YAML could not be parsed; carries 1-based line/column when available
    Parse {
        path: Option<PathBuf>,
        line: Option<usize>,
        column: Option<usize>,
        message: String,
    },
    /// One or more schema violations, each with a field path.
    Schema { violations: Vec<SchemaViolation> },
    /// A glob, command matcher, secret regex, or CIDR failed to compile
    Compile {
        field_path: String,
        pattern: String,
        message: String,
    },
    /// Profile resolution failed.
    Profile(ProfileError),
}

impl LoadError {
    /// The CLI exit code for any load failure — always 4 (design "Policy_Loader").
    pub fn exit_code(&self) -> i32 {
        4
    }
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadError::Io { path, message } => {
                write!(f, "cannot read policy `{}`: {message}", path.display())
            }
            LoadError::Size { path, size, max } => write!(
                f,
                "policy `{}` is {size} bytes, exceeding the {max} byte limit",
                path.display()
            ),
            LoadError::Parse {
                path,
                line,
                column,
                message,
            } => {
                let loc = match (line, column) {
                    (Some(l), Some(c)) => format!(" at line {l}, column {c}"),
                    (Some(l), None) => format!(" at line {l}"),
                    _ => String::new(),
                };
                match path {
                    Some(p) => write!(f, "failed to parse `{}`{loc}: {message}", p.display()),
                    None => write!(f, "failed to parse policy{loc}: {message}"),
                }
            }
            LoadError::Schema { violations } => {
                write!(f, "policy schema validation failed:")?;
                for v in violations {
                    write!(f, "\n  - {v}")?;
                }
                Ok(())
            }
            LoadError::Compile {
                field_path,
                pattern,
                message,
            } => write!(
                f,
                "failed to compile pattern `{pattern}` at `{field_path}`: {message}"
            ),
            LoadError::Profile(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for LoadError {}

// ---------------------------------------------------------------------------
// PolicyLoader trait + filesystem implementation
// ---------------------------------------------------------------------------

/// The loader interface (design "Policy_Loader").
pub trait PolicyLoader {
    /// Resolve the policy source by precedence.
    fn resolve_source(&self, config: Option<&Path>) -> Result<PolicySource, LoadError>;

    /// Read, parse, validate, compile, and profile-merge a policy.
    fn load(
        &self,
        source: &PolicySource,
        profile: Option<&str>,
    ) -> Result<CompiledPolicy, LoadError>;

    /// Schema-only validation used by `policy check` and `init` self-check. A
    /// basic implementation; task 3.6 extends it.
    fn validate(&self, raw: &str) -> Result<(), Vec<SchemaViolation>>;
}

/// Filesystem-backed [`PolicyLoader`] rooted at a repository directory.
///
/// `resolve_source` checks `.fida/policy.yaml` and `fida.yaml` relative to
/// `root`; an explicit `--config` path is used as given.
#[derive(Debug, Clone)]
pub struct FsPolicyLoader {
    root: PathBuf,
}

impl FsPolicyLoader {
    /// Create a loader rooted at `root` (typically the repo / current dir).
    pub fn new(root: impl Into<PathBuf>) -> Self {
        FsPolicyLoader { root: root.into() }
    }
}

impl Default for FsPolicyLoader {
    fn default() -> Self {
        FsPolicyLoader::new(PathBuf::from("."))
    }
}

impl PolicyLoader for FsPolicyLoader {
    fn resolve_source(&self, config: Option<&Path>) -> Result<PolicySource, LoadError> {
        resolve_source_in(&self.root, config)
    }

    fn load(
        &self,
        source: &PolicySource,
        profile: Option<&str>,
    ) -> Result<CompiledPolicy, LoadError> {
        load_source(source, profile)
    }

    fn validate(&self, raw: &str) -> Result<(), Vec<SchemaViolation>> {
        validate_raw(raw)
    }
}

// ---------------------------------------------------------------------------
// Source resolution
// ---------------------------------------------------------------------------

/// Resolve a [`PolicySource`] under `root` using the documented precedence.
///
/// * `--config` wins outright; if the path does not exist or is not a file it
///   is a hard error with **no** fallthrough.
/// * Otherwise `.fida/policy.yaml`, then `fida.yaml` under `root`.
/// * Otherwise [`PolicySource::BuiltinDefault`].
pub fn resolve_source_in(root: &Path, config: Option<&Path>) -> Result<PolicySource, LoadError> {
    if let Some(cfg) = config {
        if cfg.is_file() {
            return Ok(PolicySource::Config(cfg.to_path_buf()));
        }
        return Err(LoadError::Io {
            path: cfg.to_path_buf(),
            message: if cfg.exists() {
                "path exists but is not a readable file".to_string()
            } else {
                "no file exists at the --config path".to_string()
            },
        });
    }

    let dot_fida = root.join(DOT_FIDA_PATH);
    if dot_fida.is_file() {
        return Ok(PolicySource::DotFida(dot_fida));
    }

    let fida_yaml = root.join(FIDA_YAML_PATH);
    if fida_yaml.is_file() {
        return Ok(PolicySource::FidaYaml(fida_yaml));
    }

    Ok(PolicySource::BuiltinDefault)
}

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

/// Load and compile a resolved [`PolicySource`], merging the named profile.
pub fn load_source(
    source: &PolicySource,
    profile: Option<&str>,
) -> Result<CompiledPolicy, LoadError> {
    let (raw, path) = match source {
        PolicySource::BuiltinDefault => (BUILTIN_DEFAULT_POLICY.to_string(), None),
        other => {
            let path = other
                .path()
                .expect("non-builtin source has a path")
                .to_path_buf();
            (read_capped(&path)?, Some(path))
        }
    };

    let policy = parse_and_validate(&raw, path.as_deref())?;
    let merged = merge_profile(&policy, profile)?;
    compile(merged)
}

/// Read a file enforcing the 1 MB cap.
fn read_capped(path: &Path) -> Result<String, LoadError> {
    let bytes = fs::read(path).map_err(|e| LoadError::Io {
        path: path.to_path_buf(),
        message: e.to_string(),
    })?;
    if bytes.len() > MAX_POLICY_BYTES {
        return Err(LoadError::Size {
            path: path.to_path_buf(),
            size: bytes.len(),
            max: MAX_POLICY_BYTES,
        });
    }
    String::from_utf8(bytes).map_err(|e| LoadError::Parse {
        path: Some(path.to_path_buf()),
        line: None,
        column: None,
        message: format!("file is not valid UTF-8: {e}"),
    })
}

/// Parse YAML, then validate against the v1 schema.
fn parse_and_validate(raw: &str, path: Option<&Path>) -> Result<PolicyFile, LoadError> {
    // Step 1: pure YAML syntax. Catches structural parse errors with location.
    let value: serde_yaml::Value = serde_yaml::from_str(raw).map_err(|e| {
        let loc = e.location();
        LoadError::Parse {
            path: path.map(Path::to_path_buf),
            line: loc.as_ref().map(|l| l.line()),
            column: loc.as_ref().map(|l| l.column()),
            message: e.to_string(),
        }
    })?;

    // Step 2: shape into typed schema. Missing/ill-typed fields are schema
    // violations rather than raw parse errors.
    let policy: PolicyFile = serde_yaml::from_value(value).map_err(|e| LoadError::Schema {
        violations: vec![SchemaViolation::new("<document>", e.to_string())],
    })?;

    let violations = validate_policy(&policy);
    if !violations.is_empty() {
        return Err(LoadError::Schema { violations });
    }
    Ok(policy)
}

/// Schema-only validation entry point used by `policy check` and the `init`
/// self-check (design `validate`).
///
/// Reports **per-field** [`SchemaViolation`]s rather than collapsing the whole
/// document into one error: missing required top-level fields, an unsupported
/// `version`, and out-of-domain `default_decision`/`mode` values are each
/// attributed to their field path so `policy check` can list them as separate
/// entries. Validation collects all violations it can find
/// in one pass instead of stopping at the first.
pub fn validate_raw(raw: &str) -> Result<(), Vec<SchemaViolation>> {
    // Step 1: YAML syntax. A structural parse failure is a single document-level
    // violation — there is no field to attribute it to yet.
    let value: serde_yaml::Value = match serde_yaml::from_str(raw) {
        Ok(v) => v,
        Err(e) => {
            return Err(vec![SchemaViolation::new(
                "<document>",
                format!("invalid YAML: {e}"),
            )]);
        }
    };

    // Step 2: structural, per-field checks straight off the YAML value. These
    // give precise field paths even for required fields that serde would
    // otherwise reject with a single opaque message.
    let mut violations = validate_value(&value);

    // Step 3: only when the structural checks pass do we attempt the typed
    // deserialization. It surfaces any remaining shape problems (wrong types in
    // nested sections) that the targeted checks above don't enumerate, plus the
    // domain checks in `validate_policy`.
    if violations.is_empty() {
        match serde_yaml::from_value::<PolicyFile>(value) {
            Ok(policy) => violations.extend(validate_policy(&policy)),
            Err(e) => violations.push(violation_from_serde_error(&e)),
        }
    }

    if violations.is_empty() {
        Ok(())
    } else {
        Err(violations)
    }
}

/// Per-field structural validation over the raw YAML value. Checks presence
/// and domain of the required/enum-valued fields
/// that a plain typed deserialization cannot attribute to a field path.
fn validate_value(value: &serde_yaml::Value) -> Vec<SchemaViolation> {
    let mut violations = Vec::new();

    let Some(map) = value.as_mapping() else {
        violations.push(SchemaViolation::new(
            "<document>",
            "policy document must be a YAML mapping with at least `version` and `default_decision`",
        ));
        return violations;
    };

    // `version` — required, must be the integer 1.
    match map.get("version") {
        None => violations.push(SchemaViolation::new(
            "version",
            "required field is missing; version-1 policies must declare `version: 1`",
        )),
        Some(v) => match v.as_u64() {
            Some(1) => {}
            Some(other) => violations.push(SchemaViolation::new(
                "version",
                format!("unsupported policy version `{other}`; only `1` is supported"),
            )),
            None => violations.push(SchemaViolation::new("version", "must be the integer `1`")),
        },
    }

    // `default_decision` — required, must be one of allow/ask/deny.
    match map.get("default_decision") {
        None => violations.push(SchemaViolation::new(
            "default_decision",
            "required field is missing; must be one of `allow`, `ask`, or `deny`",
        )),
        Some(v) => check_decision_value(v, "default_decision", &mut violations),
    }

    // `profiles.<name>.default_decision` / `.mode` domain checks.
    if let Some(profiles) = map.get("profiles") {
        match profiles.as_mapping() {
            None => violations.push(SchemaViolation::new(
                "profiles",
                "must be a mapping of profile name to profile overrides",
            )),
            Some(profiles) => {
                for (name, profile) in profiles {
                    let name = name.as_str().unwrap_or("<non-string-key>");
                    let Some(pmap) = profile.as_mapping() else {
                        violations.push(SchemaViolation::new(
                            format!("profiles.{name}"),
                            "must be a mapping of override fields",
                        ));
                        continue;
                    };
                    if let Some(d) = pmap.get("default_decision") {
                        check_decision_value(
                            d,
                            &format!("profiles.{name}.default_decision"),
                            &mut violations,
                        );
                    }
                    if let Some(m) = pmap.get("mode") {
                        check_mode_value(m, &format!("profiles.{name}.mode"), &mut violations);
                    }
                }
            }
        }
    }

    violations
}

/// Push a violation unless `value` is a string naming an allow/ask/deny gate.
fn check_decision_value(
    value: &serde_yaml::Value,
    field_path: &str,
    violations: &mut Vec<SchemaViolation>,
) {
    match value.as_str() {
        Some(s) if crate::schema_json::DEFAULT_DECISIONS.contains(&s) => {}
        _ => violations.push(SchemaViolation::new(
            field_path,
            "must be one of `allow`, `ask`, or `deny`",
        )),
    }
}

/// Push a violation unless `value` is a string naming a supported session mode.
fn check_mode_value(
    value: &serde_yaml::Value,
    field_path: &str,
    violations: &mut Vec<SchemaViolation>,
) {
    match value.as_str() {
        Some(s) if crate::schema_json::MODES.contains(&s) => {}
        _ => violations.push(SchemaViolation::new(
            field_path,
            "must be one of `observe`, `enforce`, or `dry-run`",
        )),
    }
}

/// Best-effort mapping of a serde deserialization error to a [`SchemaViolation`].
/// serde_yaml does not expose a structured field path, so we attribute the
/// error to the document while preserving serde's descriptive message.
fn violation_from_serde_error(err: &serde_yaml::Error) -> SchemaViolation {
    SchemaViolation::new("<document>", err.to_string())
}

/// Validate a parsed policy against the version-1 rules:
/// supported version and `default_decision` ∈ {allow, ask, deny}.
fn validate_policy(policy: &PolicyFile) -> Vec<SchemaViolation> {
    let mut violations = Vec::new();

    if policy.version != 1 {
        violations.push(SchemaViolation::new(
            "version",
            format!(
                "unsupported policy version `{}`; only `1` is supported",
                policy.version
            ),
        ));
    }

    // The global default_decision must be a concrete gate (not `dry_run`).
    if !is_valid_default(policy.default_decision) {
        violations.push(SchemaViolation::new(
            "default_decision",
            "must be one of `allow`, `ask`, or `deny`",
        ));
    }

    for (name, profile) in &policy.profiles {
        if let Some(d) = profile.default_decision {
            if !is_valid_default(d) {
                violations.push(SchemaViolation::new(
                    format!("profiles.{name}.default_decision"),
                    "must be one of `allow`, `ask`, or `deny`",
                ));
            }
        }
    }

    violations
}

/// A `default_decision` value is valid iff it is allow/ask/deny.
fn is_valid_default(d: Decision) -> bool {
    matches!(d, Decision::Allow | Decision::Ask | Decision::Deny)
}

// ---------------------------------------------------------------------------
// Profile merge
// ---------------------------------------------------------------------------

/// The effective policy values after the active profile is merged over the base.
#[derive(Debug)]
struct MergedPolicy {
    version: u32,
    default_decision: Decision,
    profile_default_decision: Option<Decision>,
    mode: Option<Mode>,
    commands: CommandSection,
    files: FileSection,
    network: NetworkSection,
    mcp: McpSection,
    secrets: SecretSection,
    audit: crate::schema::AuditSection,
    hard_denies_disabled: bool,
    agents: Vec<String>,
}

/// Resolve and apply the named profile (if any) over the base policy.
///
/// Profile values win on overlap. Section-valued overrides
/// replace the base section wholesale; `default_decision`/`mode` populate the
/// profile-default slots consumed at evaluation stages 6/7. Inheritance is
/// resolved leaf-last with cycle and undefined-parent detection.
fn merge_profile(policy: &PolicyFile, profile: Option<&str>) -> Result<MergedPolicy, LoadError> {
    let mut merged = MergedPolicy {
        version: policy.version,
        default_decision: policy.default_decision,
        profile_default_decision: None,
        mode: None,
        commands: policy.commands.clone(),
        files: policy.files.clone(),
        network: policy.network.clone(),
        mcp: policy.mcp.clone(),
        secrets: policy.secrets.clone(),
        audit: policy.audit.clone(),
        hard_denies_disabled: policy.hard_denies_disabled,
        agents: policy.agents.clone(),
    };

    let Some(name) = profile else {
        return Ok(merged);
    };

    let chain = resolve_profile_chain(policy, name)?;
    for p in chain {
        apply_profile(&mut merged, p);
    }
    Ok(merged)
}

/// Build the inheritance chain for `name` in apply order (root parent first,
/// the named profile last), detecting unknown names and cycles.
fn resolve_profile_chain<'a>(
    policy: &'a PolicyFile,
    name: &str,
) -> Result<Vec<&'a Profile>, LoadError> {
    if !policy.profiles.contains_key(name) {
        return Err(LoadError::Profile(ProfileError::Unknown(name.to_string())));
    }

    // Walk leaf -> root, recording the visit order for cycle reporting.
    let mut order: Vec<String> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut current = name.to_string();

    loop {
        if !seen.insert(current.clone()) {
            order.push(current.clone());
            return Err(LoadError::Profile(ProfileError::Cycle(order)));
        }
        order.push(current.clone());

        let profile = policy
            .profiles
            .get(&current)
            .expect("profile presence checked before descent");

        match &profile.parent {
            Some(parent) => {
                if !policy.profiles.contains_key(parent) {
                    return Err(LoadError::Profile(ProfileError::UndefinedParent {
                        profile: current.clone(),
                        parent: parent.clone(),
                    }));
                }
                current = parent.clone();
            }
            None => break,
        }
    }

    // `order` is leaf -> root; apply root first so the leaf wins on overlap.
    Ok(order
        .into_iter()
        .rev()
        .map(|n| policy.profiles.get(&n).expect("name from order map"))
        .collect())
}

/// Overlay one profile's present fields onto the working merged policy.
fn apply_profile(merged: &mut MergedPolicy, profile: &Profile) {
    if let Some(d) = profile.default_decision {
        merged.profile_default_decision = Some(d);
    }
    if let Some(m) = profile.mode {
        merged.mode = Some(m);
    }
    if let Some(c) = &profile.commands {
        merged.commands = c.clone();
    }
    if let Some(fsec) = &profile.files {
        merged.files = fsec.clone();
    }
    if let Some(n) = &profile.network {
        merged.network = n.clone();
    }
    if let Some(m) = &profile.mcp {
        merged.mcp = m.clone();
    }
    if let Some(s) = &profile.secrets {
        merged.secrets = s.clone();
    }
    if let Some(a) = &profile.audit {
        merged.audit = a.clone();
    }
    if let Some(b) = profile.hard_denies_disabled {
        merged.hard_denies_disabled = b;
    }
    if let Some(a) = &profile.agents {
        merged.agents = a.clone();
    }
}

// ---------------------------------------------------------------------------
// Compilation
// ---------------------------------------------------------------------------

/// Compile a merged policy into the evaluatable [`CompiledPolicy`].
fn compile(m: MergedPolicy) -> Result<CompiledPolicy, LoadError> {
    Ok(CompiledPolicy {
        version: m.version,
        default_decision: m.default_decision,
        mode: m.mode,
        profile_default_decision: m.profile_default_decision,
        commands: compile_commands(&m.commands)?,
        files: compile_files(&m.files)?,
        network: compile_network(&m.network)?,
        mcp: compile_mcp(&m.mcp)?,
        secrets: compile_secrets(&m.secrets)?,
        audit: m.audit,
        hard_denies_disabled: m.hard_denies_disabled,
        agents: m.agents,
        hard_denies: builtin_hard_denies(),
    })
}

fn compile_commands(section: &CommandSection) -> Result<CompiledCommandSection, LoadError> {
    Ok(CompiledCommandSection {
        allow: compile_command_tier(&section.allow, "commands.allow")?,
        ask: compile_command_tier(&section.ask, "commands.ask")?,
        deny: compile_command_tier(&section.deny, "commands.deny")?,
    })
}

fn compile_command_tier(
    rules: &[CommandRule],
    tier_path: &str,
) -> Result<Vec<CompiledCommandRule>, LoadError> {
    rules
        .iter()
        .enumerate()
        .map(|(i, rule)| {
            let rule_id = format!("{tier_path}[{i}]");
            let matcher = match &rule.matcher {
                CommandMatcher::Exact(s) => CompiledCommandMatcher::Exact(s.clone()),
                CommandMatcher::Prefix(s) => CompiledCommandMatcher::Prefix(s.clone()),
                CommandMatcher::Binary(s) => CompiledCommandMatcher::Binary(s.clone()),
                CommandMatcher::Regex(pattern) => {
                    let re = Regex::new(pattern).map_err(|e| LoadError::Compile {
                        field_path: format!("{rule_id}.regex"),
                        pattern: pattern.clone(),
                        message: e.to_string(),
                    })?;
                    CompiledCommandMatcher::Regex(re)
                }
            };
            Ok(CompiledCommandRule {
                rule_id,
                matcher,
                working_dir: rule.working_dir.clone(),
                reason: rule.reason.clone(),
                auto_approve: rule.auto_approve,
            })
        })
        .collect()
}

fn compile_files(section: &FileSection) -> Result<CompiledFileSection, LoadError> {
    Ok(CompiledFileSection {
        read: compile_path_rules(&section.read, "files.read")?,
        write: compile_path_rules(&section.write, "files.write")?,
    })
}

fn compile_path_rules(rules: &PathRules, base: &str) -> Result<CompiledPathRules, LoadError> {
    Ok(CompiledPathRules {
        allow: compile_glob_tier(&rules.allow, &format!("{base}.allow"))?,
        ask: compile_glob_tier(&rules.ask, &format!("{base}.ask"))?,
        deny: compile_glob_tier(&rules.deny, &format!("{base}.deny"))?,
    })
}

fn compile_glob_tier(
    patterns: &[String],
    tier_path: &str,
) -> Result<Vec<CompiledGlobRule>, LoadError> {
    patterns
        .iter()
        .enumerate()
        .map(|(i, pattern)| {
            let rule_id = format!("{tier_path}[{i}]");
            let matcher = compile_glob(pattern, &rule_id)?;
            Ok(CompiledGlobRule {
                rule_id,
                source: pattern.clone(),
                matcher,
            })
        })
        .collect()
}

fn compile_network(section: &NetworkSection) -> Result<CompiledNetworkSection, LoadError> {
    Ok(CompiledNetworkSection {
        allow: compile_net_tier(&section.allow, "network.allow")?,
        ask: compile_net_tier(&section.ask, "network.ask")?,
        deny: compile_net_tier(&section.deny, "network.deny")?,
    })
}

fn compile_net_tier(rules: &[NetRule], tier_path: &str) -> Result<Vec<CompiledNetRule>, LoadError> {
    rules
        .iter()
        .enumerate()
        .map(|(i, rule)| {
            let rule_id = format!("{tier_path}[{i}]");
            let target = match &rule.target {
                NetTargetMatcher::Domain(pattern) => CompiledNetTarget::Domain {
                    pattern: pattern.clone(),
                    matcher: compile_glob(pattern, &format!("{rule_id}.domain"))?,
                },
                NetTargetMatcher::Host(h) => CompiledNetTarget::Host(h.clone()),
                NetTargetMatcher::Cidr(cidr) => {
                    let net = cidr.parse::<IpNetwork>().map_err(|e| LoadError::Compile {
                        field_path: format!("{rule_id}.cidr"),
                        pattern: cidr.clone(),
                        message: e.to_string(),
                    })?;
                    CompiledNetTarget::Cidr(net)
                }
            };
            Ok(CompiledNetRule {
                rule_id,
                target,
                reason: rule.reason.clone(),
            })
        })
        .collect()
}

fn compile_mcp(section: &McpSection) -> Result<CompiledMcpSection, LoadError> {
    Ok(CompiledMcpSection {
        tools: CompiledToolRules {
            allow: compile_tool_tier(&section.tools.allow, "mcp.tools.allow")?,
            ask: compile_tool_tier(&section.tools.ask, "mcp.tools.ask")?,
            deny: compile_tool_tier(&section.tools.deny, "mcp.tools.deny")?,
        },
    })
}

fn compile_tool_tier(
    patterns: &[crate::schema::ToolPattern],
    tier_path: &str,
) -> Result<Vec<CompiledToolPattern>, LoadError> {
    patterns
        .iter()
        .enumerate()
        .map(|(i, tp)| {
            let rule_id = format!("{tier_path}[{i}]");
            let matcher = compile_glob(&tp.pattern, &rule_id)?;
            Ok(CompiledToolPattern {
                rule_id,
                source: tp.pattern.clone(),
                matcher,
                reason: tp.reason.clone(),
            })
        })
        .collect()
}

fn compile_secrets(section: &SecretSection) -> Result<CompiledSecretSection, LoadError> {
    let patterns = section
        .patterns
        .iter()
        .enumerate()
        .map(|(i, p)| {
            let regex = Regex::new(&p.regex).map_err(|e| LoadError::Compile {
                field_path: format!("secrets.patterns[{i}].regex"),
                pattern: p.regex.clone(),
                message: e.to_string(),
            })?;
            Ok(CompiledSecretPattern {
                name: p.name.clone(),
                regex,
            })
        })
        .collect::<Result<Vec<_>, LoadError>>()?;

    Ok(CompiledSecretSection {
        redact: section.redact,
        block_in_diffs: section.block_in_diffs,
        patterns,
    })
}

/// Compile a single glob pattern, surfacing failures as [`LoadError::Compile`].
fn compile_glob(pattern: &str, field_path: &str) -> Result<GlobMatcher, LoadError> {
    Glob::new(pattern)
        .map(|g| g.compile_matcher())
        .map_err(|e| LoadError::Compile {
            field_path: field_path.to_string(),
            pattern: pattern.to_string(),
            message: e.to_string(),
        })
}

// ---------------------------------------------------------------------------
// Built-in hard denies (shared seam with task 4.3)
// ---------------------------------------------------------------------------

/// Materialize the built-in hard-deny rules: destructive command patterns,
/// sensitive file write/delete paths, and the cloud metadata IP + private
/// CIDRs. These are always materialized; whether the evaluator
/// applies them is governed by [`CompiledPolicy::hard_denies_disabled`].
pub fn builtin_hard_denies() -> HardDenies {
    let command_patterns = BUILTIN_DESTRUCTIVE_COMMANDS
        .iter()
        .map(|(id, pat, reason)| HardDenyPattern {
            rule_id: (*id).to_string(),
            regex: Regex::new(pat).expect("built-in destructive command regex is valid"),
            reason: (*reason).to_string(),
        })
        .collect();

    let file_globs = BUILTIN_SENSITIVE_PATHS
        .iter()
        .map(|(id, pat)| CompiledGlobRule {
            rule_id: (*id).to_string(),
            source: (*pat).to_string(),
            matcher: Glob::new(pat)
                .expect("built-in sensitive-path glob is valid")
                .compile_matcher(),
        })
        .collect();

    let network_hosts = BUILTIN_DENIED_HOSTS.iter().map(|h| h.to_string()).collect();

    let network_cidrs = BUILTIN_DENIED_CIDRS
        .iter()
        .map(|c| c.parse::<IpNetwork>().expect("built-in CIDR is valid"))
        .collect();

    HardDenies {
        command_patterns,
        file_globs,
        network_hosts,
        network_cidrs,
    }
}

/// Built-in destructive command patterns: (rule_id, regex, reason).
const BUILTIN_DESTRUCTIVE_COMMANDS: &[(&str, &str, &str)] = &[
    (
        "builtin.hard_deny.destructive_rm",
        r"rm\s+-rf?\s+(/|~|\.)(\s|$)",
        "recursive force-remove of root, home, or the current directory",
    ),
    (
        "builtin.hard_deny.curl_pipe_shell",
        r"curl\s+.*\|\s*(sh|bash|zsh)",
        "piping a remote script straight into a shell",
    ),
    (
        "builtin.hard_deny.wget_pipe_shell",
        r"wget\s+.*\|\s*(sh|bash|zsh)",
        "piping a remote script straight into a shell",
    ),
];

/// Built-in sensitive file write/delete globs: (rule_id, glob).
const BUILTIN_SENSITIVE_PATHS: &[(&str, &str)] = &[
    ("builtin.hard_deny.dotenv", ".env"),
    ("builtin.hard_deny.dotenv_variant", ".env.*"),
    ("builtin.hard_deny.pem", "**/*.pem"),
    ("builtin.hard_deny.key", "**/*.key"),
    ("builtin.hard_deny.id_rsa", "**/id_rsa"),
    ("builtin.hard_deny.id_ed25519", "**/id_ed25519"),
];

/// Built-in denied network hosts (cloud metadata service).
const BUILTIN_DENIED_HOSTS: &[&str] = &["169.254.169.254"];

/// Built-in denied private network CIDRs.
const BUILTIN_DENIED_CIDRS: &[&str] = &["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"];

// ---------------------------------------------------------------------------
// Built-in default policy
// ---------------------------------------------------------------------------

/// The built-in default policy used when no file is found and no `--config` is
/// given. Balanced: allow the everyday low-risk dev loop
/// outright (so agents are not nagged for routine work), read broadly, gate
/// writes, ask before arbitrary network access, deny writes to sensitive
/// targets, and stop unambiguously destructive commands. Read and command
/// output is
/// secret-redacted and network egress is gated separately, so a permissive
/// command surface does not by itself leak secrets or allow exfiltration.
pub const BUILTIN_DEFAULT_POLICY: &str = r#"version: 1
default_decision: ask

commands:
  # Allow the everyday, low-risk dev loop outright. Anything not listed here
  # still falls through to `ask`; genuinely dangerous commands are denied below
  # (deny is evaluated before allow, so it wins even with a broad allow list).
  allow:
    # Read-only inspection.
    - binary: ls
    - binary: pwd
    - binary: echo
    - binary: cat
    - binary: head
    - binary: tail
    - binary: wc
    - binary: sort
    - binary: uniq
    - binary: cut
    - binary: diff
    - binary: which
    - binary: tree
    - binary: stat
    - binary: file
    - binary: basename
    - binary: dirname
    - binary: realpath
    - binary: find
    - binary: grep
    - binary: rg
    - binary: fd
    - prefix: rg --files
    # Git: status, history, and local working-tree changes. Publishing
    # (`git push`) and force-push are intentionally NOT allowed here.
    - prefix: git status
    - prefix: git diff
    - prefix: git log
    - prefix: git show
    - prefix: git branch
    - prefix: git ls-files
    - prefix: git blame
    - prefix: git add
    - prefix: git restore
    - prefix: git switch
    - prefix: git checkout
    - prefix: git stash
    - prefix: git fetch
    # Build / test / lint / format for the common toolchains.
    - prefix: cargo build
    - prefix: cargo check
    - prefix: cargo test
    - prefix: cargo fmt
    - prefix: cargo clippy
    - prefix: cargo doc
    - prefix: cargo run
    - prefix: cargo metadata
    - prefix: cargo tree
    - binary: rustc
    - binary: rustfmt
    - prefix: npm test
    - prefix: npm run
    - prefix: pnpm test
    - prefix: pnpm run
    - prefix: yarn test
    - prefix: yarn run
    - prefix: go build
    - prefix: go test
    - prefix: go vet
    - prefix: go run
    - binary: gofmt
    - binary: make
    - binary: pytest
    - binary: ruff
    - binary: eslint
    - binary: prettier
    - binary: tsc
  # Hard-stop the unambiguously destructive or trust-breaking commands.
  # Best-effort: a determined agent can evade string matching (shell tricks,
  # absolute paths). This is a guardrail, not a sandbox — pair with
  # FIDA_SANDBOX=1 for OS-level containment.
  deny:
    - regex: "rm\\s+-rf\\s+(/|~|\\.)"
      reason: destructive recursive delete of root, home, or cwd
    - binary: sudo
      reason: privilege escalation runs outside the policy trust boundary
    - binary: shutdown
      reason: host power control
    - binary: reboot
      reason: host power control
    - binary: mkfs
      reason: formatting a filesystem destroys data
    - binary: dd
      reason: raw block writes can destroy data
    - regex: "\\bgit\\s+push\\b.*--force"
      reason: force-push can clobber published history
    - regex: "curl\\s+.*\\|\\s*(sh|bash)"
      reason: piping a remote script straight into a shell is unsafe
    - regex: "wget\\s+.*\\|\\s*(sh|bash)"
      reason: piping a remote script straight into a shell is unsafe
    - regex: "chmod\\s+.*777"
      reason: world-writable permissions

files:
  read:
    allow:
      - "**/*"
  write:
    allow:
      - src/**
      - tests/**
      - docs/**
      - README.md
    deny:
      - .env
      - .env.*
      - "**/*.pem"
      - "**/*.key"

network:
  ask:
    - domain: "*"
      reason: arbitrary network access can transmit code or local data
  deny:
    - host: 169.254.169.254
      reason: cloud metadata service

secrets:
  redact: true
  block_in_diffs: true

audit:
  path: .fida/sessions
  format: jsonl
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use fida_action::{Action, ActionKind, ActionPayload, Actor, EvalStage};
    use std::fs;
    use tempfile::tempdir;

    fn command_action(command: &str) -> Action {
        Action {
            kind: ActionKind::CommandRun,
            actor: Actor::Agent,
            payload: ActionPayload::Command {
                argv: command
                    .split_whitespace()
                    .map(ToString::to_string)
                    .collect(),
                cwd: PathBuf::from("/repo"),
            },
        }
    }

    fn write(dir: &Path, rel: &str, contents: &str) -> PathBuf {
        let path = dir.join(rel);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&path, contents).unwrap();
        path
    }

    #[test]
    fn resolves_config_first() {
        let dir = tempdir().unwrap();
        let cfg = write(dir.path(), "custom.yaml", BUILTIN_DEFAULT_POLICY);
        write(dir.path(), ".fida/policy.yaml", BUILTIN_DEFAULT_POLICY);
        let src = resolve_source_in(dir.path(), Some(&cfg)).unwrap();
        assert_eq!(src, PolicySource::Config(cfg));
    }

    #[test]
    fn missing_config_is_hard_error_no_fallthrough() {
        let dir = tempdir().unwrap();
        // A repo file exists, but --config must NOT fall through to it.
        write(dir.path(), "fida.yaml", BUILTIN_DEFAULT_POLICY);
        let missing = dir.path().join("does-not-exist.yaml");
        let err = resolve_source_in(dir.path(), Some(&missing)).unwrap_err();
        assert!(matches!(err, LoadError::Io { .. }));
        assert_eq!(err.exit_code(), 4);
    }

    #[test]
    fn resolution_precedence_dot_fida_over_fida_yaml() {
        let dir = tempdir().unwrap();
        let dot = write(dir.path(), ".fida/policy.yaml", BUILTIN_DEFAULT_POLICY);
        write(dir.path(), "fida.yaml", BUILTIN_DEFAULT_POLICY);
        let src = resolve_source_in(dir.path(), None).unwrap();
        assert_eq!(src, PolicySource::DotFida(dot));
    }

    #[test]
    fn falls_back_to_builtin_default() {
        let dir = tempdir().unwrap();
        let src = resolve_source_in(dir.path(), None).unwrap();
        assert_eq!(src, PolicySource::BuiltinDefault);
        assert!(src.is_builtin_default());
    }

    #[test]
    fn builtin_default_loads_and_compiles() {
        let policy = load_source(&PolicySource::BuiltinDefault, None).unwrap();
        assert_eq!(policy.version, 1);
        assert_eq!(policy.default_decision, Decision::Ask);
        assert!(!policy.commands.allow.is_empty());
        // Hard denies always materialized.
        assert!(!policy.hard_denies.command_patterns.is_empty());
        assert_eq!(policy.hard_denies.network_cidrs.len(), 3);
        assert_eq!(policy.hard_denies.network_hosts, vec!["169.254.169.254"]);
    }

    #[test]
    fn builtin_default_allows_common_local_dev_commands() {
        let policy = load_source(&PolicySource::BuiltinDefault, None).unwrap();
        let allowed = [
            "cargo build",
            "cargo check",
            "cargo metadata",
            "cargo test",
            "git log",
            "git ls-files",
            "rg --files",
        ];

        for expected in allowed {
            assert!(
                policy
                    .commands
                    .allow
                    .iter()
                    .any(|rule| match &rule.matcher {
                        CompiledCommandMatcher::Exact(command)
                        | CompiledCommandMatcher::Prefix(command) => command == expected,
                        CompiledCommandMatcher::Binary(_) | CompiledCommandMatcher::Regex(_) =>
                            false,
                    }),
                "`{expected}` should be explicitly allowed by the built-in default policy"
            );
        }
    }

    #[test]
    fn builtin_default_resolves_common_local_dev_commands_as_explicit_allow() {
        let policy = load_source(&PolicySource::BuiltinDefault, None).unwrap();
        let commands = [
            "cargo build --workspace",
            "cargo check --workspace",
            "cargo metadata --format-version 1",
            "git log --oneline -15",
            "git ls-files",
            "rg --files crates",
        ];

        for command in commands {
            let result = crate::evaluator::evaluate(&policy, &command_action(command));
            assert_eq!(
                result.decision,
                Decision::Allow,
                "`{command}` should be allowed by the built-in default policy"
            );
            assert_eq!(
                result.stage,
                EvalStage::ExplicitAllow,
                "`{command}` should match an explicit allow rule"
            );
        }
    }

    #[test]
    fn loads_example_policy_with_rule_ids() {
        let example = include_str!("../../../examples/fida.yaml");
        let policy = parse_and_validate(example, None).and_then(|p| {
            let merged = merge_profile(&p, None)?;
            compile(merged)
        });
        let policy = policy.unwrap();
        assert_eq!(policy.commands.allow[0].rule_id, "commands.allow[0]");
        assert_eq!(policy.commands.deny[0].rule_id, "commands.deny[0]");
        assert_eq!(policy.files.write.allow[0].rule_id, "files.write.allow[0]");
        assert_eq!(policy.network.deny[0].rule_id, "network.deny[0]");
    }

    #[test]
    fn oversize_file_rejected() {
        let dir = tempdir().unwrap();
        let mut big = String::from("version: 1\ndefault_decision: ask\n# ");
        big.push_str(&"x".repeat(MAX_POLICY_BYTES));
        let path = write(dir.path(), "big.yaml", &big);
        let err = read_capped(&path).unwrap_err();
        assert!(matches!(err, LoadError::Size { .. }));
    }

    #[test]
    fn unparseable_yaml_reports_location() {
        let err = parse_and_validate("version: 1\n  : : bad", None).unwrap_err();
        match err {
            LoadError::Parse { line, .. } => assert!(line.is_some()),
            other => panic!("expected parse error, got {other:?}"),
        }
    }

    #[test]
    fn unsupported_version_is_schema_violation() {
        let err = parse_and_validate("version: 2\ndefault_decision: ask\n", None).unwrap_err();
        match err {
            LoadError::Schema { violations } => {
                assert!(violations.iter().any(|v| v.field_path == "version"));
            }
            other => panic!("expected schema error, got {other:?}"),
        }
    }

    #[test]
    fn dry_run_default_decision_is_invalid() {
        let yaml = "version: 1\ndefault_decision: dry_run\n";
        let err = parse_and_validate(yaml, None).unwrap_err();
        match err {
            LoadError::Schema { violations } => {
                assert!(
                    violations
                        .iter()
                        .any(|v| v.field_path == "default_decision")
                );
            }
            other => panic!("expected schema error, got {other:?}"),
        }
    }

    #[test]
    fn bad_command_regex_is_compile_error() {
        let yaml = "version: 1\ndefault_decision: ask\ncommands:\n  deny:\n    - regex: \"([\"\n";
        let err = parse_and_validate(yaml, None)
            .and_then(|p| compile(merge_profile(&p, None)?))
            .unwrap_err();
        match err {
            LoadError::Compile { field_path, .. } => {
                assert_eq!(field_path, "commands.deny[0].regex");
            }
            other => panic!("expected compile error, got {other:?}"),
        }
    }

    #[test]
    fn unknown_profile_errors() {
        let yaml = "version: 1\ndefault_decision: ask\n";
        let policy = parse_and_validate(yaml, None).unwrap();
        let err = merge_profile(&policy, Some("ghost")).unwrap_err();
        assert!(matches!(
            err,
            LoadError::Profile(ProfileError::Unknown(ref n)) if n == "ghost"
        ));
    }

    #[test]
    fn undefined_parent_errors() {
        let yaml = "version: 1\ndefault_decision: ask\nprofiles:\n  child:\n    parent: missing\n";
        let policy = parse_and_validate(yaml, None).unwrap();
        let err = merge_profile(&policy, Some("child")).unwrap_err();
        assert!(matches!(
            err,
            LoadError::Profile(ProfileError::UndefinedParent { .. })
        ));
    }

    #[test]
    fn cyclic_parent_errors() {
        let yaml = "version: 1\ndefault_decision: ask\nprofiles:\n  a:\n    parent: b\n  b:\n    parent: a\n";
        let policy = parse_and_validate(yaml, None).unwrap();
        let err = merge_profile(&policy, Some("a")).unwrap_err();
        assert!(matches!(err, LoadError::Profile(ProfileError::Cycle(_))));
    }

    #[test]
    fn profile_wins_on_overlap_and_inherits_otherwise() {
        let yaml = "\
version: 1
default_decision: ask
commands:
  allow:
    - exact: base only
profiles:
  base:
    default_decision: allow
    commands:
      allow:
        - exact: from base profile
  leaf:
    parent: base
    default_decision: deny
";
        let policy = parse_and_validate(yaml, None).unwrap();
        let merged = merge_profile(&policy, Some("leaf")).unwrap();
        // Leaf default wins over base profile default.
        assert_eq!(merged.profile_default_decision, Some(Decision::Deny));
        // Global default is never replaced (stage 7).
        assert_eq!(merged.default_decision, Decision::Ask);
        // Commands section inherited from `base` (leaf did not override it).
        assert_eq!(
            merged.commands.allow[0].matcher,
            CommandMatcher::Exact("from base profile".to_string())
        );
    }

    #[test]
    fn validate_raw_accepts_builtin_and_rejects_bad_version() {
        assert!(validate_raw(BUILTIN_DEFAULT_POLICY).is_ok());
        let violations = validate_raw("version: 9\ndefault_decision: ask\n").unwrap_err();
        assert!(violations.iter().any(|v| v.field_path == "version"));
    }

    #[test]
    fn validate_raw_reports_missing_required_fields_by_path() {
        // Empty mapping: both required fields missing, each its own violation.
        let violations = validate_raw("{}\n").unwrap_err();
        assert!(violations.iter().any(|v| v.field_path == "version"));
        assert!(
            violations
                .iter()
                .any(|v| v.field_path == "default_decision")
        );
    }

    #[test]
    fn validate_raw_reports_invalid_default_decision_by_path() {
        let violations = validate_raw("version: 1\ndefault_decision: maybe\n").unwrap_err();
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].field_path, "default_decision");
    }

    #[test]
    fn validate_raw_rejects_dry_run_default_with_field_path() {
        let violations = validate_raw("version: 1\ndefault_decision: dry_run\n").unwrap_err();
        assert!(
            violations
                .iter()
                .any(|v| v.field_path == "default_decision")
        );
    }

    #[test]
    fn validate_raw_reports_profile_field_paths() {
        let yaml = "\
version: 1
default_decision: ask
profiles:
  bad:
    default_decision: nope
    mode: turbo
";
        let violations = validate_raw(yaml).unwrap_err();
        assert!(
            violations
                .iter()
                .any(|v| v.field_path == "profiles.bad.default_decision")
        );
        assert!(
            violations
                .iter()
                .any(|v| v.field_path == "profiles.bad.mode")
        );
    }

    #[test]
    fn validate_raw_reports_non_mapping_document() {
        let violations = validate_raw("- just\n- a list\n").unwrap_err();
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].field_path, "<document>");
    }

    #[test]
    fn validate_raw_accepts_example_policy() {
        let example = include_str!("../../../examples/fida.yaml");
        assert!(validate_raw(example).is_ok());
    }
}
