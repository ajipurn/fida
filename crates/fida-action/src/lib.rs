//! `fida-action` — shared domain types for Fida.
//!
//! This crate is a dependency sink: it depends on nothing else in the
//! workspace. It hosts the normalized [`Action`] model and the
//! [`DecisionResult`] every other crate consumes.
//!
//! All public types derive `serde` because they are serialized to the
//! append-only audit JSONL store. Serde rename attributes are pinned to the
//! audit event schema (see design "Audit Event (JSONL line schema)"):
//! action kinds use dotted names (`"command.run"`), decisions use snake_case
//! (`"dry_run"`), and [`Mode`] uses kebab-case (`"dry-run"`).

use std::path::PathBuf;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

// ---------------------------------------------------------------------------
// Normalized Action model
// ---------------------------------------------------------------------------

/// The kind of a normalized [`Action`].
///
/// Serde names match the audit event `action.kind` field exactly
/// (glossary: `command.run`, `file.read`, ...).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ActionKind {
    #[serde(rename = "command.run")]
    CommandRun,
    #[serde(rename = "file.read")]
    FileRead,
    #[serde(rename = "file.write")]
    FileWrite,
    #[serde(rename = "file.delete")]
    FileDelete,
    #[serde(rename = "network.request")]
    NetworkRequest,
    #[serde(rename = "mcp.tool_call")]
    McpToolCall,
    #[serde(rename = "secret.detected")]
    SecretDetected,
    #[serde(rename = "session.apply_changes")]
    SessionApplyChanges,
}

/// Who originated an [`Action`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Actor {
    Agent,
    User,
}

/// The network protocol of a [`NetTarget`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Http,
    Https,
}

/// A normalized network destination.
///
/// Carries only redaction-safe routing fields — `domain`, `host`, and
/// `protocol` — never request payloads.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NetTarget {
    /// Registered domain when known (e.g. `example.com`), if resolvable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    /// Concrete host the request targets: an IP literal or hostname.
    pub host: String,
    pub protocol: Protocol,
}

/// A secret-scanner finding.
///
/// Records only the matched pattern identifier and a human-readable reason —
/// never the secret value, a substring of it, or its length.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Finding {
    pub pattern_id: String,
    pub reason: String,
}

/// Kind-specific details for an [`Action`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionPayload {
    Command { argv: Vec<String>, cwd: PathBuf },
    File { path: PathBuf },
    Network { target: NetTarget },
    Mcp { tool_name: String },
    Secret { finding: Finding },
}

/// A normalized agent or user operation submitted to the evaluator/broker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Action {
    pub kind: ActionKind,
    pub actor: Actor,
    pub payload: ActionPayload,
}

// ---------------------------------------------------------------------------
// Decision result
// ---------------------------------------------------------------------------

/// How an action is handled.
///
/// Serde names match the audit `decision`/`result` schema: note `DryRun`
/// serializes to `"dry_run"` (snake_case), distinct from [`Mode::DryRun`]
/// which serializes to `"dry-run"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Allow,
    Ask,
    Deny,
    DryRun,
}

/// The risk level attached to a decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Risk {
    Low,
    Medium,
    High,
}

/// How strongly an installed agent integration prevents raw secret values from
/// reaching the model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtectionLevel {
    /// Native reads/commands have a hard-blocking hook in addition to Fida's
    /// redacting gateway.
    Enforced,
    /// The gateway and instructions are installed, but native tools can bypass
    /// them when the agent does not provide a hard-block hook.
    BestEffort,
    /// Fida was selected for the agent, but required integration artifacts are
    /// missing or the redaction self-test failed.
    Incomplete,
    /// No active Fida integration is recorded.
    Inactive,
}

impl ProtectionLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            ProtectionLevel::Enforced => "enforced",
            ProtectionLevel::BestEffort => "best_effort",
            ProtectionLevel::Incomplete => "incomplete",
            ProtectionLevel::Inactive => "inactive",
        }
    }

    /// Whether native agent tools can still expose a raw secret to the model.
    pub fn raw_secret_exposure_possible(self) -> bool {
        !matches!(self, ProtectionLevel::Enforced)
    }
}

/// Which of the fixed seven evaluation stages produced a [`DecisionResult`].
///
/// Stage order is fixed; the evaluator stops at the first
/// matching stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvalStage {
    /// (1) Built-in hard denies.
    HardDeny,
    /// (2) Secret detection.
    SecretDetection,
    /// (3) Explicit deny rules.
    ExplicitDeny,
    /// (4) Explicit allow rules.
    ExplicitAllow,
    /// (5) Explicit ask rules.
    ExplicitAsk,
    /// (6) Profile default decision.
    ProfileDefault,
    /// (7) Global default decision.
    GlobalDefault,
}

/// The rule that produced a decision, or a sentinel when none matched.
///
/// Serializes as a plain string to match the audit `matched_rule` field:
/// [`MatchedRule::Rule`] becomes its inner identifier (e.g. `"commands.ask[0]"`)
/// and [`MatchedRule::NoExplicitRule`] becomes the sentinel `"none"`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum MatchedRule {
    Rule(String),
    NoExplicitRule,
}

/// Sentinel string used on the wire for [`MatchedRule::NoExplicitRule`].
const NO_EXPLICIT_RULE_SENTINEL: &str = "none";

impl MatchedRule {
    /// The wire/string form of this matched rule.
    pub fn as_str(&self) -> &str {
        match self {
            MatchedRule::Rule(id) => id.as_str(),
            MatchedRule::NoExplicitRule => NO_EXPLICIT_RULE_SENTINEL,
        }
    }
}

impl Serialize for MatchedRule {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for MatchedRule {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Ok(if s == NO_EXPLICIT_RULE_SENTINEL {
            MatchedRule::NoExplicitRule
        } else {
            MatchedRule::Rule(s)
        })
    }
}

/// The complete, self-describing outcome of evaluating an [`Action`].
///
/// Every field is always populated: a decision, a non-empty
/// `reason`, the matched rule (or [`MatchedRule::NoExplicitRule`]), a risk
/// level, and the originating [`EvalStage`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionResult {
    pub decision: Decision,
    pub reason: String,
    pub matched_rule: MatchedRule,
    pub risk: Risk,
    pub stage: EvalStage,
}

// ---------------------------------------------------------------------------
// Session mode
// ---------------------------------------------------------------------------

/// The session enforcement mode.
///
/// Serde names match the CLI `--mode` values; `DryRun` serializes to the
/// kebab-case `"dry-run"`, distinct from [`Decision::DryRun`] (`"dry_run"`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Mode {
    /// Evaluate and audit every action but never block or prompt.
    Observe,
    /// Apply each decision in real time.
    Enforce,
    /// Evaluate and record decisions but execute nothing.
    DryRun,
}

// ---------------------------------------------------------------------------
// Session handle
// ---------------------------------------------------------------------------

/// Per-session state used to attribute and order audit events.
///
/// Holds the owning session id and a monotonic counter used to mint unique,
/// append-ordered event ids (`evt_01`, `evt_02`, …) so the one-event-per-action
/// guarantee yields stable identifiers.
#[derive(Debug, Clone)]
pub struct SessionHandle {
    session_id: String,
    event_counter: u32,
}

impl SessionHandle {
    /// Create a handle for `session_id` with the event counter at zero.
    pub fn new(session_id: impl Into<String>) -> Self {
        SessionHandle {
            session_id: session_id.into(),
            event_counter: 0,
        }
    }

    /// The owning session id.
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Mint the next unique, append-ordered event id for this session.
    pub fn next_event_id(&mut self) -> String {
        self.event_counter += 1;
        format!("evt_{:02}", self.event_counter)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn json(value: &impl Serialize) -> String {
        serde_json::to_string(value).expect("serialize")
    }

    #[test]
    fn action_kind_uses_dotted_audit_names() {
        assert_eq!(json(&ActionKind::CommandRun), "\"command.run\"");
        assert_eq!(json(&ActionKind::FileRead), "\"file.read\"");
        assert_eq!(json(&ActionKind::FileWrite), "\"file.write\"");
        assert_eq!(json(&ActionKind::FileDelete), "\"file.delete\"");
        assert_eq!(json(&ActionKind::NetworkRequest), "\"network.request\"");
        assert_eq!(json(&ActionKind::McpToolCall), "\"mcp.tool_call\"");
        assert_eq!(json(&ActionKind::SecretDetected), "\"secret.detected\"");
        assert_eq!(
            json(&ActionKind::SessionApplyChanges),
            "\"session.apply_changes\""
        );
    }

    #[test]
    fn actor_serializes_lowercase() {
        assert_eq!(json(&Actor::Agent), "\"agent\"");
        assert_eq!(json(&Actor::User), "\"user\"");
    }

    #[test]
    fn decision_uses_snake_case_dry_run() {
        assert_eq!(json(&Decision::Allow), "\"allow\"");
        assert_eq!(json(&Decision::Ask), "\"ask\"");
        assert_eq!(json(&Decision::Deny), "\"deny\"");
        assert_eq!(json(&Decision::DryRun), "\"dry_run\"");
    }

    #[test]
    fn mode_uses_kebab_case_dry_run() {
        assert_eq!(json(&Mode::Observe), "\"observe\"");
        assert_eq!(json(&Mode::Enforce), "\"enforce\"");
        // Distinct from Decision::DryRun ("dry_run").
        assert_eq!(json(&Mode::DryRun), "\"dry-run\"");
    }

    #[test]
    fn risk_serializes_lowercase() {
        assert_eq!(json(&Risk::Low), "\"low\"");
        assert_eq!(json(&Risk::Medium), "\"medium\"");
        assert_eq!(json(&Risk::High), "\"high\"");
    }

    #[test]
    fn protection_level_has_stable_wire_names() {
        assert_eq!(json(&ProtectionLevel::Enforced), "\"enforced\"");
        assert_eq!(json(&ProtectionLevel::BestEffort), "\"best_effort\"");
        assert!(ProtectionLevel::BestEffort.raw_secret_exposure_possible());
        assert!(!ProtectionLevel::Enforced.raw_secret_exposure_possible());
    }

    #[test]
    fn protocol_serializes_lowercase() {
        assert_eq!(json(&Protocol::Http), "\"http\"");
        assert_eq!(json(&Protocol::Https), "\"https\"");
    }

    #[test]
    fn matched_rule_serializes_as_plain_string_with_sentinel() {
        assert_eq!(
            json(&MatchedRule::Rule("commands.ask[0]".to_string())),
            "\"commands.ask[0]\""
        );
        assert_eq!(json(&MatchedRule::NoExplicitRule), "\"none\"");
        assert_eq!(MatchedRule::NoExplicitRule.as_str(), "none");
    }

    #[test]
    fn matched_rule_round_trips() {
        for rule in [
            MatchedRule::Rule("builtin.hard_deny.destructive_rm".to_string()),
            MatchedRule::NoExplicitRule,
        ] {
            let s = json(&rule);
            let back: MatchedRule = serde_json::from_str(&s).expect("deserialize");
            assert_eq!(rule, back);
        }
    }

    #[test]
    fn finding_records_only_pattern_and_reason() {
        let finding = Finding {
            pattern_id: "aws_access_key".to_string(),
            reason: "matched AWS access key pattern".to_string(),
        };
        let v: serde_json::Value = serde_json::to_value(&finding).unwrap();
        let obj = v.as_object().unwrap();
        assert_eq!(obj.len(), 2);
        assert!(obj.contains_key("pattern_id"));
        assert!(obj.contains_key("reason"));
    }

    #[test]
    fn net_target_omits_absent_domain() {
        let target = NetTarget {
            domain: None,
            host: "169.254.169.254".to_string(),
            protocol: Protocol::Http,
        };
        let v: serde_json::Value = serde_json::to_value(&target).unwrap();
        assert!(!v.as_object().unwrap().contains_key("domain"));
        assert_eq!(v["host"], "169.254.169.254");
        assert_eq!(v["protocol"], "http");
    }

    #[test]
    fn action_round_trips_for_each_payload() {
        let actions = vec![
            Action {
                kind: ActionKind::CommandRun,
                actor: Actor::Agent,
                payload: ActionPayload::Command {
                    argv: vec!["pnpm".to_string(), "install".to_string()],
                    cwd: PathBuf::from("/repo"),
                },
            },
            Action {
                kind: ActionKind::FileWrite,
                actor: Actor::User,
                payload: ActionPayload::File {
                    path: PathBuf::from("src/app.ts"),
                },
            },
            Action {
                kind: ActionKind::NetworkRequest,
                actor: Actor::Agent,
                payload: ActionPayload::Network {
                    target: NetTarget {
                        domain: Some("example.com".to_string()),
                        host: "93.184.216.34".to_string(),
                        protocol: Protocol::Https,
                    },
                },
            },
            Action {
                kind: ActionKind::McpToolCall,
                actor: Actor::Agent,
                payload: ActionPayload::Mcp {
                    tool_name: "browser.navigate".to_string(),
                },
            },
            Action {
                kind: ActionKind::SecretDetected,
                actor: Actor::Agent,
                payload: ActionPayload::Secret {
                    finding: Finding {
                        pattern_id: "private_key".to_string(),
                        reason: "PEM private key header".to_string(),
                    },
                },
            },
        ];
        for action in actions {
            let s = json(&action);
            let back: Action = serde_json::from_str(&s).expect("deserialize");
            assert_eq!(action, back);
        }
    }

    #[test]
    fn decision_result_round_trips_and_keeps_all_fields() {
        let result = DecisionResult {
            decision: Decision::Ask,
            reason: "matches an ask rule".to_string(),
            matched_rule: MatchedRule::Rule("commands.ask[1]".to_string()),
            risk: Risk::Medium,
            stage: EvalStage::ExplicitAsk,
        };
        let s = json(&result);
        let back: DecisionResult = serde_json::from_str(&s).expect("deserialize");
        assert_eq!(result, back);

        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["decision"], "ask");
        assert_eq!(v["matched_rule"], "commands.ask[1]");
        assert_eq!(v["risk"], "medium");
        assert_eq!(v["stage"], "explicit_ask");
    }
}
