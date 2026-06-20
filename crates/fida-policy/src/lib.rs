//! `fida-policy` — Policy_Loader and Policy_Evaluator.
//!
//! Dependency sink: depends only on `fida-action` within the workspace.
//! Keeps the evaluator a pure function `evaluate(policy, action) -> DecisionResult`
//! with no filesystem, clock, or network coupling (see spec tasks 3.x, 4.x).
//!
//! This crate hosts two policy representations:
//!
//! * [`mod@schema`] — the raw version-1 policy as parsed from YAML
//!   (`PolicyFile` and friends). Pure data; patterns are unvalidated strings.
//! * [`mod@compiled`] — [`CompiledPolicy`], the post-load form (regexes
//!   compiled, globs expanded, profile merged, hard denies materialized). The
//!   evaluator only ever sees this form.
//!
//! The loader logic that transforms `schema` → `compiled` (parsing, validation,
//! compilation, profile merge) lands in task 3.2. The deterministic 7-stage
//! [`mod@evaluator`] consumes the compiled form (tasks 4.1–4.3).

pub mod compiled;
pub mod evaluator;
pub mod loader;
pub mod matchers;
pub mod schema;
pub mod schema_json;

pub use compiled::{
    CompiledCommandMatcher, CompiledCommandRule, CompiledCommandSection, CompiledFileSection,
    CompiledGlobRule, CompiledMcpSection, CompiledNetRule, CompiledNetTarget,
    CompiledNetworkSection, CompiledPathRules, CompiledPolicy, CompiledSecretPattern,
    CompiledSecretSection, CompiledToolPattern, CompiledToolRules, HardDenies, HardDenyPattern,
};
pub use schema::{
    AuditFormat, AuditSection, CommandMatcher, CommandRule, CommandSection, FileSection,
    McpSection, NetRule, NetTargetMatcher, NetworkSection, PathRules, PolicyFile, Profile,
    SecretPattern, SecretSection, ToolPattern, ToolRules,
};

pub use schema_json::policy_json_schema;

pub use loader::{
    BUILTIN_DEFAULT_POLICY, BUILTIN_SECRET_GUARD_POLICY, FsPolicyLoader, LoadError,
    MAX_POLICY_BYTES, PolicyLoader, PolicySource, ProfileError, SchemaViolation,
    builtin_hard_denies, load_secret_guard_policy, load_source, resolve_source_in, validate_raw,
};

pub use evaluator::{PolicyEvaluator, StagedEvaluator, evaluate};
