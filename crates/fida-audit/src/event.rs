//! The redaction-safe audit event schema (spec task 7.2).
//!
//! One [`AuditEvent`] serializes to exactly one JSON object per line in
//! `events.jsonl`. The on-the-wire shape mirrors the
//! design "Audit Event (JSONL line schema)" example:
//!
//! ```jsonc
//! {
//!   "id": "evt_01",
//!   "session_id": "2026-06-12T070000Z-a1b2c3",
//!   "time": "2026-06-12T07:00:00Z",
//!   "actor": "agent",
//!   "action": { "kind": "command.run", "command": "pnpm install" },
//!   "decision": "ask",
//!   "result": "allowed_once",
//!   "matched_rule": "commands.ask[0]",
//!   "risk": "medium",
//!   "redacted": false
//! }
//! ```
//!
//! Every `action` payload carries only redaction-safe fields: network events
//! record domain/host/protocol but never request bodies, and secret events
//! record `pattern_id`/`reason` but never the value.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use fida_action::{
    Action, ActionKind, ActionPayload, Actor, Decision, MatchedRule, Protocol, Risk,
};

/// The maximum integer representable in JSON without loss (R5.1). Every numeric
/// [`AuditMetrics`] subfield must fall within `0..=MAX_SAFE_INT`.
pub const MAX_SAFE_INT: u64 = 9_007_199_254_740_991;

/// Optional measured metrics attached to an audit event (R5).
///
/// The field is present-or-absent *as a whole*: a present object requires all
/// five subfields. Construct via [`AuditMetrics::validated`] so out-of-bounds
/// values are rejected (returned as `None`) rather than persisted. `model` is
/// the only free-text subfield and is run through the Secret_Scanner on write
/// (see `store`), so the metrics never carry secret material (R5.5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditMetrics {
    /// Wall-clock duration of the measured action, in milliseconds.
    pub duration_ms: u64,
    /// Bytes of input associated with the action.
    pub input_bytes: u64,
    /// Bytes of output associated with the action.
    pub output_bytes: u64,
    /// A token-count estimate, always an estimate.
    pub estimated_tokens: u64,
    /// The model name the action used (1–200 chars, non-whitespace).
    pub model: String,
}

impl AuditMetrics {
    /// Smart constructor: returns `Some` only when every numeric subfield is in
    /// `0..=MAX_SAFE_INT` and `model` is 1–200 characters with at least one
    /// non-whitespace character (R5.1). Otherwise `None`, so a caller drops the
    /// whole field rather than persist an invalid metric (R5.7).
    pub fn validated(
        duration_ms: u64,
        input_bytes: u64,
        output_bytes: u64,
        estimated_tokens: u64,
        model: String,
    ) -> Option<Self> {
        let bounds_ok = [duration_ms, input_bytes, output_bytes, estimated_tokens]
            .iter()
            .all(|&v| v <= MAX_SAFE_INT);
        let model_len = model.chars().count();
        let model_ok = (1..=200).contains(&model_len) && model.chars().any(|c| !c.is_whitespace());
        if bounds_ok && model_ok {
            Some(AuditMetrics {
                duration_ms,
                input_bytes,
                output_bytes,
                estimated_tokens,
                model,
            })
        } else {
            None
        }
    }
}

/// A single append-only audit record.
///
/// Field order matches the JSONL schema example so serialized lines read
/// id → session → time → actor → action → decision → result → rule → risk →
/// redacted. All fields are always populated; `metrics` is optional and
/// omitted from the line entirely when absent (R5.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Identifier unique within the owning session (e.g. `"evt_01"`).
    pub id: String,
    /// The session this event belongs to (`<UTC-timestamp>-<short-random>`).
    pub session_id: String,
    /// When the action resolved, as a UTC ISO-8601 timestamp.
    pub time: DateTime<Utc>,
    /// Who originated the action.
    pub actor: Actor,
    /// The redaction-safe description of the action.
    pub action: AuditAction,
    /// The decision the evaluator produced.
    pub decision: Decision,
    /// How the action ultimately resolved.
    pub result: AuditResult,
    /// The rule that produced the decision, or the `none` sentinel.
    pub matched_rule: MatchedRule,
    /// The risk level attached to the decision.
    pub risk: Risk,
    /// Whether any field of this event had secret material redacted.
    pub redacted: bool,
    /// Optional measured metrics (R5). Absent on pre-metrics lines and omitted
    /// from serialization when `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metrics: Option<AuditMetrics>,
}

/// How a resolved action ultimately ended up (the audit `result` field).
///
/// Serde names are snake_case to match the schema (`allowed_once`,
/// `would_run`, `timed_out`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditResult {
    /// Permitted without prompting (e.g. observe mode or an allow rule).
    Allowed,
    /// Permitted once via an interactive "allow once" approval.
    AllowedOnce,
    /// Permitted via a remembered-for-session decision.
    AllowedRemembered,
    /// Denied by policy.
    Denied,
    /// Blocked because approval was required but unavailable (fail-closed).
    Blocked,
    /// Recorded only; nothing executed (dry-run).
    WouldRun,
    /// Terminated after exceeding its timeout.
    TimedOut,
}

/// The redaction-safe action payload embedded in an [`AuditEvent`].
///
/// Internally tagged on `kind` using the dotted action names so a line reads
/// `{ "kind": "command.run", "command": "..." }`. Unlike
/// [`fida_action::ActionPayload`], every variant here is guaranteed to hold
/// only fields that are safe to persist to disk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum AuditAction {
    /// A command invocation, recorded as a single redaction-safe string.
    #[serde(rename = "command.run")]
    CommandRun { command: String },
    /// Redacted command output captured from stdout or stderr.
    #[serde(rename = "command.output")]
    CommandOutput { stream: String, content: String },
    /// Redaction failed for a command stream, so no stream content was stored.
    #[serde(rename = "command.redaction_failure")]
    CommandRedactionFailure { stream: String },
    /// A file read, recorded by path only.
    #[serde(rename = "file.read")]
    FileRead { path: String },
    /// A file write, recorded by path only.
    #[serde(rename = "file.write")]
    FileWrite { path: String },
    /// A file delete, recorded by path only.
    #[serde(rename = "file.delete")]
    FileDelete { path: String },
    /// A network request, recorded by destination routing only — never the
    /// request body.
    #[serde(rename = "network.request")]
    NetworkRequest {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        domain: Option<String>,
        host: String,
        protocol: Protocol,
    },
    /// An MCP tool call, recorded by tool name only.
    #[serde(rename = "mcp.tool_call")]
    McpToolCall { tool: String },
    /// A secret detection, recorded by pattern id and reason only — never the
    /// matched value or its length.
    #[serde(rename = "secret.detected")]
    SecretDetected { pattern_id: String, reason: String },
    /// Applying recorded session changes to the workspace.
    #[serde(rename = "session.apply_changes")]
    SessionApplyChanges,
}

impl AuditAction {
    /// Build a redaction-safe [`AuditAction`] from a normalized [`Action`].
    ///
    /// Command argv is collapsed to a single space-joined string and file
    /// paths are rendered lossily; no field that could contain secret bytes is
    /// ever copied across.
    pub fn from_action(action: &Action) -> Self {
        match &action.payload {
            ActionPayload::Command { argv, .. } => AuditAction::CommandRun {
                command: argv.join(" "),
            },
            ActionPayload::File { path } => {
                let path = path.to_string_lossy().into_owned();
                match action.kind {
                    ActionKind::FileRead => AuditAction::FileRead { path },
                    ActionKind::FileDelete => AuditAction::FileDelete { path },
                    // Any other file kind is treated as a write.
                    _ => AuditAction::FileWrite { path },
                }
            }
            ActionPayload::Network { target } => AuditAction::NetworkRequest {
                domain: target.domain.clone(),
                host: target.host.clone(),
                protocol: target.protocol,
            },
            ActionPayload::Mcp { tool_name } => AuditAction::McpToolCall {
                tool: tool_name.clone(),
            },
            ActionPayload::Secret { finding } => AuditAction::SecretDetected {
                pattern_id: finding.pattern_id.clone(),
                reason: finding.reason.clone(),
            },
        }
    }
}

impl From<&Action> for AuditAction {
    fn from(action: &Action) -> Self {
        AuditAction::from_action(action)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use fida_action::{Finding, NetTarget};
    use serde_json::{Value, json};

    fn fixed_time() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 6, 12, 7, 0, 0).unwrap()
    }

    fn sample_event() -> AuditEvent {
        AuditEvent {
            id: "evt_01".to_string(),
            session_id: "2026-06-12T070000Z-a1b2c3".to_string(),
            time: fixed_time(),
            actor: Actor::Agent,
            action: AuditAction::CommandRun {
                command: "pnpm install".to_string(),
            },
            decision: Decision::Ask,
            result: AuditResult::AllowedOnce,
            matched_rule: MatchedRule::Rule("commands.ask[0]".to_string()),
            risk: Risk::Medium,
            redacted: false,
            metrics: None,
        }
    }

    #[test]
    fn event_matches_design_jsonl_schema() {
        let v: Value = serde_json::to_value(sample_event()).unwrap();
        assert_eq!(
            v,
            json!({
                "id": "evt_01",
                "session_id": "2026-06-12T070000Z-a1b2c3",
                "time": "2026-06-12T07:00:00Z",
                "actor": "agent",
                "action": { "kind": "command.run", "command": "pnpm install" },
                "decision": "ask",
                "result": "allowed_once",
                "matched_rule": "commands.ask[0]",
                "risk": "medium",
                "redacted": false
            })
        );
    }

    #[test]
    fn event_round_trips() {
        let event = sample_event();
        let line = serde_json::to_string(&event).unwrap();
        // One JSONL line: no embedded newlines.
        assert!(!line.contains('\n'));
        let back: AuditEvent = serde_json::from_str(&line).unwrap();
        assert_eq!(event, back);
    }

    #[test]
    fn result_uses_snake_case_names() {
        let cases = [
            (AuditResult::Allowed, "\"allowed\""),
            (AuditResult::AllowedOnce, "\"allowed_once\""),
            (AuditResult::AllowedRemembered, "\"allowed_remembered\""),
            (AuditResult::Denied, "\"denied\""),
            (AuditResult::Blocked, "\"blocked\""),
            (AuditResult::WouldRun, "\"would_run\""),
            (AuditResult::TimedOut, "\"timed_out\""),
        ];
        for (result, expected) in cases {
            assert_eq!(serde_json::to_string(&result).unwrap(), expected);
        }
    }

    #[test]
    fn network_action_records_only_routing_fields() {
        let action = AuditAction::NetworkRequest {
            domain: Some("example.com".to_string()),
            host: "93.184.216.34".to_string(),
            protocol: Protocol::Https,
        };
        let v: Value = serde_json::to_value(&action).unwrap();
        assert_eq!(
            v,
            json!({
                "kind": "network.request",
                "domain": "example.com",
                "host": "93.184.216.34",
                "protocol": "https"
            })
        );
    }

    #[test]
    fn network_action_omits_absent_domain() {
        let action = AuditAction::NetworkRequest {
            domain: None,
            host: "169.254.169.254".to_string(),
            protocol: Protocol::Http,
        };
        let v: Value = serde_json::to_value(&action).unwrap();
        assert!(!v.as_object().unwrap().contains_key("domain"));
    }

    #[test]
    fn secret_action_records_only_pattern_and_reason() {
        let action = AuditAction::SecretDetected {
            pattern_id: "aws_access_key".to_string(),
            reason: "matched AWS access key pattern".to_string(),
        };
        let v: Value = serde_json::to_value(&action).unwrap();
        assert_eq!(
            v,
            json!({
                "kind": "secret.detected",
                "pattern_id": "aws_access_key",
                "reason": "matched AWS access key pattern"
            })
        );
    }

    #[test]
    fn from_action_collapses_command_argv() {
        let action = Action {
            kind: ActionKind::CommandRun,
            actor: Actor::Agent,
            payload: ActionPayload::Command {
                argv: vec!["pnpm".to_string(), "install".to_string()],
                cwd: "/repo".into(),
            },
        };
        assert_eq!(
            AuditAction::from(&action),
            AuditAction::CommandRun {
                command: "pnpm install".to_string()
            }
        );
    }

    #[test]
    fn from_action_maps_file_kinds() {
        let path = std::path::PathBuf::from("src/app.ts");
        let read = Action {
            kind: ActionKind::FileRead,
            actor: Actor::Agent,
            payload: ActionPayload::File { path: path.clone() },
        };
        let write = Action {
            kind: ActionKind::FileWrite,
            actor: Actor::Agent,
            payload: ActionPayload::File { path: path.clone() },
        };
        let delete = Action {
            kind: ActionKind::FileDelete,
            actor: Actor::Agent,
            payload: ActionPayload::File { path },
        };
        assert_eq!(
            AuditAction::from(&read),
            AuditAction::FileRead {
                path: "src/app.ts".to_string()
            }
        );
        assert_eq!(
            AuditAction::from(&write),
            AuditAction::FileWrite {
                path: "src/app.ts".to_string()
            }
        );
        assert_eq!(
            AuditAction::from(&delete),
            AuditAction::FileDelete {
                path: "src/app.ts".to_string()
            }
        );
    }

    #[test]
    fn from_action_preserves_network_routing() {
        let action = Action {
            kind: ActionKind::NetworkRequest,
            actor: Actor::Agent,
            payload: ActionPayload::Network {
                target: NetTarget {
                    domain: Some("example.com".to_string()),
                    host: "93.184.216.34".to_string(),
                    protocol: Protocol::Https,
                },
            },
        };
        assert_eq!(
            AuditAction::from(&action),
            AuditAction::NetworkRequest {
                domain: Some("example.com".to_string()),
                host: "93.184.216.34".to_string(),
                protocol: Protocol::Https,
            }
        );
    }

    #[test]
    fn from_action_keeps_only_secret_pattern_and_reason() {
        let action = Action {
            kind: ActionKind::SecretDetected,
            actor: Actor::Agent,
            payload: ActionPayload::Secret {
                finding: Finding {
                    pattern_id: "private_key".to_string(),
                    reason: "PEM private key header".to_string(),
                },
            },
        };
        assert_eq!(
            AuditAction::from(&action),
            AuditAction::SecretDetected {
                pattern_id: "private_key".to_string(),
                reason: "PEM private key header".to_string(),
            }
        );
    }

    #[test]
    fn from_action_maps_mcp_tool() {
        let action = Action {
            kind: ActionKind::McpToolCall,
            actor: Actor::Agent,
            payload: ActionPayload::Mcp {
                tool_name: "browser.navigate".to_string(),
            },
        };
        assert_eq!(
            AuditAction::from(&action),
            AuditAction::McpToolCall {
                tool: "browser.navigate".to_string()
            }
        );
    }

    #[test]
    fn apply_changes_action_serializes_with_kind_only() {
        let v: Value = serde_json::to_value(AuditAction::SessionApplyChanges).unwrap();
        assert_eq!(v, json!({ "kind": "session.apply_changes" }));
    }

    #[test]
    fn metrics_validated_enforces_bounds_and_model() {
        // All in bounds + a real model -> Some.
        assert!(AuditMetrics::validated(1, 2, 3, 4, "claude-3-5".to_string()).is_some());
        assert!(AuditMetrics::validated(0, 0, 0, 0, "m".to_string()).is_some());
        assert!(AuditMetrics::validated(MAX_SAFE_INT, 0, 0, 0, "m".to_string()).is_some());
        // Just beyond the safe integer -> None.
        assert!(AuditMetrics::validated(MAX_SAFE_INT + 1, 0, 0, 0, "m".to_string()).is_none());
        // Empty / whitespace-only / over-length model -> None.
        assert!(AuditMetrics::validated(0, 0, 0, 0, String::new()).is_none());
        assert!(AuditMetrics::validated(0, 0, 0, 0, "   ".to_string()).is_none());
        assert!(AuditMetrics::validated(0, 0, 0, 0, "x".repeat(201)).is_none());
    }

    #[test]
    fn event_with_metrics_round_trips_and_absent_metrics_is_omitted() {
        // Present metrics survive a round trip with every subfield preserved.
        let mut event = sample_event();
        event.metrics = AuditMetrics::validated(1200, 4096, 8192, 2048, "model-x".to_string());
        assert!(event.metrics.is_some());
        let line = serde_json::to_string(&event).unwrap();
        let back: AuditEvent = serde_json::from_str(&line).unwrap();
        assert_eq!(event, back);

        // Absent metrics is omitted from the serialized line and parses back absent.
        let absent = sample_event();
        assert!(absent.metrics.is_none());
        let line = serde_json::to_string(&absent).unwrap();
        assert!(!line.contains("metrics"));
        let back: AuditEvent = serde_json::from_str(&line).unwrap();
        assert!(back.metrics.is_none());
    }
}
