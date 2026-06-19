//! The Report_Generator (spec task 7.5).
//!
//! Renders a human- or machine-readable session report from a slice of
//! [`AuditEvent`]s in either `markdown` or `json`. Every report carries the
//! same seven sections — session summary, commands run, denied actions, human
//! approvals, changed files, secret redactions, and MCP calls — and any section
//! with no corresponding events is rendered empty rather than omitted.
//! Unsupported formats are rejected with a [`ReportError::UnsupportedFormat`]
//! and produce no report; because [`render`] takes a typed
//! [`ReportFormat`], the string entry point [`ReportFormat::parse`] is the only
//! place an unsupported format name can arrive, and it fails closed there.
//!
//! The Audit_Store feeds [`render`] only pre-redacted events, so the report
//! repeats the same redaction-safe fields the events
//! already carry and never reconstructs secret material.
//!
//! [`render`]: ReportGenerator::render

use serde::Serialize;

use fida_action::{Decision, MatchedRule, Risk};

use crate::event::{AuditAction, AuditEvent, AuditResult};

/// The output formats the Report_Generator can produce. These are the only
/// supported formats; any other request is an
/// [`ReportError::UnsupportedFormat`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReportFormat {
    /// A human-readable Markdown document.
    Markdown,
    /// A machine-readable JSON document.
    Json,
}

impl ReportFormat {
    /// The canonical lowercase name of this format (`"markdown"` / `"json"`).
    pub fn as_str(self) -> &'static str {
        match self {
            ReportFormat::Markdown => "markdown",
            ReportFormat::Json => "json",
        }
    }

    /// Parse a user-supplied format name, rejecting anything other than
    /// `markdown` or `json` with [`ReportError::UnsupportedFormat`]. This is
    /// the fail-closed gate that keeps an unsupported format from ever reaching
    /// [`ReportGenerator::render`].
    pub fn parse(name: &str) -> Result<Self, ReportError> {
        match name {
            "markdown" => Ok(ReportFormat::Markdown),
            "json" => Ok(ReportFormat::Json),
            other => Err(ReportError::UnsupportedFormat {
                requested: other.to_string(),
            }),
        }
    }
}

/// Errors the Report_Generator can return.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReportError {
    /// The requested format is neither `markdown` nor `json`. No report is
    /// produced.
    UnsupportedFormat { requested: String },
    /// Serializing the structured report to JSON failed.
    Serialization { message: String },
}

impl std::fmt::Display for ReportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReportError::UnsupportedFormat { requested } => write!(
                f,
                "unsupported report format '{requested}'; supported formats are 'markdown' and 'json'"
            ),
            ReportError::Serialization { message } => {
                write!(f, "failed to serialize report: {message}")
            }
        }
    }
}

impl std::error::Error for ReportError {}

/// Renders session reports from audit events (design "Audit_Store and
/// Report_Generator").
pub trait ReportGenerator {
    /// Render `events` as a report in `format`, or return a [`ReportError`].
    ///
    /// The report always contains all seven sections; sections with no
    /// matching events render empty.
    fn render(&self, events: &[AuditEvent], format: ReportFormat) -> Result<String, ReportError>;
}

/// The default [`ReportGenerator`], grouping events into the seven report
/// sections and rendering them as Markdown or JSON.
#[derive(Debug, Clone, Copy, Default)]
pub struct DefaultReportGenerator;

impl DefaultReportGenerator {
    /// Create a new generator.
    pub fn new() -> Self {
        Self
    }
}

impl ReportGenerator for DefaultReportGenerator {
    fn render(&self, events: &[AuditEvent], format: ReportFormat) -> Result<String, ReportError> {
        let report = SessionReport::from_events(events);
        match format {
            ReportFormat::Json => {
                serde_json::to_string_pretty(&report).map_err(|e| ReportError::Serialization {
                    message: e.to_string(),
                })
            }
            ReportFormat::Markdown => Ok(report.to_markdown()),
        }
    }
}

// ---------------------------------------------------------------------------
// Structured report model (also the JSON shape)
// ---------------------------------------------------------------------------

/// The structured report — the exact shape emitted for `--format json` and the
/// source the Markdown renderer reads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct SessionReport {
    summary: SessionSummary,
    commands_run: Vec<CommandEntry>,
    denied_actions: Vec<DeniedEntry>,
    human_approvals: Vec<ApprovalEntry>,
    changed_files: Vec<ChangedFileEntry>,
    secret_redactions: Vec<SecretEntry>,
    mcp_calls: Vec<McpEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct SessionSummary {
    /// The owning session, or `None` when there are no events to derive it from.
    #[serde(skip_serializing_if = "Option::is_none")]
    session_id: Option<String>,
    total_events: usize,
    /// Number of events whose `redacted` flag is set.
    redacted_events: usize,
    decision_counts: DecisionCounts,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
struct DecisionCounts {
    allow: usize,
    ask: usize,
    deny: usize,
    dry_run: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct CommandEntry {
    id: String,
    time: String,
    command: String,
    decision: Decision,
    result: AuditResult,
    matched_rule: String,
    risk: Risk,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct DeniedEntry {
    id: String,
    time: String,
    /// A redaction-safe one-line description of the denied action.
    action: String,
    matched_rule: String,
    risk: Risk,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct ApprovalEntry {
    id: String,
    time: String,
    action: String,
    /// `allowed_once` or `allowed_remembered`.
    result: AuditResult,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct ChangedFileEntry {
    id: String,
    time: String,
    path: String,
    /// `write` or `delete`.
    change: &'static str,
    decision: Decision,
    result: AuditResult,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct SecretEntry {
    id: String,
    time: String,
    pattern_id: String,
    reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct McpEntry {
    id: String,
    time: String,
    tool: String,
    decision: Decision,
    result: AuditResult,
}

fn rule_str(rule: &MatchedRule) -> String {
    rule.as_str().to_string()
}

/// A redaction-safe one-line description of an action for the denied/approval
/// sections, reusing only fields the event already persists.
fn describe_action(action: &AuditAction) -> String {
    match action {
        AuditAction::CommandRun { command } => format!("command.run: {command}"),
        AuditAction::CommandOutput { stream, .. } => format!("command.output: {stream}"),
        AuditAction::CommandRedactionFailure { stream } => {
            format!("command.redaction_failure: {stream}")
        }
        AuditAction::FileRead { path } => format!("file.read: {path}"),
        AuditAction::FileWrite { path } => format!("file.write: {path}"),
        AuditAction::FileDelete { path } => format!("file.delete: {path}"),
        AuditAction::NetworkRequest {
            domain,
            host,
            protocol,
        } => {
            let dest = domain.as_deref().unwrap_or(host.as_str());
            format!("network.request: {} {dest}", protocol.as_str_lower())
        }
        AuditAction::McpToolCall { tool } => format!("mcp.tool_call: {tool}"),
        AuditAction::SecretDetected { pattern_id, .. } => {
            format!("secret.detected: {pattern_id}")
        }
        AuditAction::SessionApplyChanges => "session.apply_changes".to_string(),
    }
}

/// Small helper so we can render the protocol without depending on serde here.
trait ProtocolName {
    fn as_str_lower(&self) -> &'static str;
}

impl ProtocolName for fida_action::Protocol {
    fn as_str_lower(&self) -> &'static str {
        match self {
            fida_action::Protocol::Http => "http",
            fida_action::Protocol::Https => "https",
        }
    }
}

impl SessionReport {
    fn from_events(events: &[AuditEvent]) -> Self {
        let mut decision_counts = DecisionCounts::default();
        let mut redacted_events = 0usize;

        let mut commands_run = Vec::new();
        let mut denied_actions = Vec::new();
        let mut human_approvals = Vec::new();
        let mut changed_files = Vec::new();
        let mut secret_redactions = Vec::new();
        let mut mcp_calls = Vec::new();

        for e in events {
            match e.decision {
                Decision::Allow => decision_counts.allow += 1,
                Decision::Ask => decision_counts.ask += 1,
                Decision::Deny => decision_counts.deny += 1,
                Decision::DryRun => decision_counts.dry_run += 1,
            }
            if e.redacted {
                redacted_events += 1;
            }

            let time = e.time.to_rfc3339();

            // Commands run.
            if let AuditAction::CommandRun { command } = &e.action {
                commands_run.push(CommandEntry {
                    id: e.id.clone(),
                    time: time.clone(),
                    command: command.clone(),
                    decision: e.decision,
                    result: e.result,
                    matched_rule: rule_str(&e.matched_rule),
                    risk: e.risk,
                });
            }

            // Denied actions (any kind denied by policy).
            if e.decision == Decision::Deny {
                denied_actions.push(DeniedEntry {
                    id: e.id.clone(),
                    time: time.clone(),
                    action: describe_action(&e.action),
                    matched_rule: rule_str(&e.matched_rule),
                    risk: e.risk,
                });
            }

            // Human approvals: resolved via an interactive/remembered approval.
            if matches!(
                e.result,
                AuditResult::AllowedOnce | AuditResult::AllowedRemembered
            ) {
                human_approvals.push(ApprovalEntry {
                    id: e.id.clone(),
                    time: time.clone(),
                    action: describe_action(&e.action),
                    result: e.result,
                });
            }

            // Changed files: write/delete actions.
            match &e.action {
                AuditAction::FileWrite { path } => changed_files.push(ChangedFileEntry {
                    id: e.id.clone(),
                    time: time.clone(),
                    path: path.clone(),
                    change: "write",
                    decision: e.decision,
                    result: e.result,
                }),
                AuditAction::FileDelete { path } => changed_files.push(ChangedFileEntry {
                    id: e.id.clone(),
                    time: time.clone(),
                    path: path.clone(),
                    change: "delete",
                    decision: e.decision,
                    result: e.result,
                }),
                _ => {}
            }

            // Secret redactions: explicit secret detections or any redacted event.
            if let AuditAction::SecretDetected { pattern_id, reason } = &e.action {
                secret_redactions.push(SecretEntry {
                    id: e.id.clone(),
                    time: time.clone(),
                    pattern_id: pattern_id.clone(),
                    reason: reason.clone(),
                });
            }

            // MCP calls.
            if let AuditAction::McpToolCall { tool } = &e.action {
                mcp_calls.push(McpEntry {
                    id: e.id.clone(),
                    time,
                    tool: tool.clone(),
                    decision: e.decision,
                    result: e.result,
                });
            }
        }

        let session_id = events.first().map(|e| e.session_id.clone());

        SessionReport {
            summary: SessionSummary {
                session_id,
                total_events: events.len(),
                redacted_events,
                decision_counts,
            },
            commands_run,
            denied_actions,
            human_approvals,
            changed_files,
            secret_redactions,
            mcp_calls,
        }
    }

    fn to_markdown(&self) -> String {
        let mut out = String::new();
        let s = &self.summary;

        out.push_str("# Session Report\n\n");

        out.push_str("## Summary\n\n");
        out.push_str(&format!(
            "- Session: {}\n",
            s.session_id.as_deref().unwrap_or("(none)")
        ));
        out.push_str(&format!("- Total events: {}\n", s.total_events));
        out.push_str(&format!("- Redacted events: {}\n", s.redacted_events));
        out.push_str(&format!(
            "- Decisions: allow={}, ask={}, deny={}, dry_run={}\n\n",
            s.decision_counts.allow,
            s.decision_counts.ask,
            s.decision_counts.deny,
            s.decision_counts.dry_run
        ));

        // Commands run.
        out.push_str("## Commands Run\n\n");
        if self.commands_run.is_empty() {
            out.push_str("_None._\n\n");
        } else {
            for c in &self.commands_run {
                out.push_str(&format!(
                    "- `{}` — {:?} ({}), result {:?}, rule `{}` [{}]\n",
                    c.command,
                    c.decision,
                    c.time,
                    c.result,
                    c.matched_rule,
                    risk_name(c.risk)
                ));
            }
            out.push('\n');
        }

        // Denied actions.
        out.push_str("## Denied Actions\n\n");
        if self.denied_actions.is_empty() {
            out.push_str("_None._\n\n");
        } else {
            for d in &self.denied_actions {
                out.push_str(&format!(
                    "- {} — rule `{}` [{}] ({})\n",
                    d.action,
                    d.matched_rule,
                    risk_name(d.risk),
                    d.time
                ));
            }
            out.push('\n');
        }

        // Human approvals.
        out.push_str("## Human Approvals\n\n");
        if self.human_approvals.is_empty() {
            out.push_str("_None._\n\n");
        } else {
            for a in &self.human_approvals {
                out.push_str(&format!("- {} — {:?} ({})\n", a.action, a.result, a.time));
            }
            out.push('\n');
        }

        // Changed files.
        out.push_str("## Changed Files\n\n");
        if self.changed_files.is_empty() {
            out.push_str("_None._\n\n");
        } else {
            for f in &self.changed_files {
                out.push_str(&format!(
                    "- {} `{}` — {:?} ({})\n",
                    f.change, f.path, f.decision, f.time
                ));
            }
            out.push('\n');
        }

        // Secret redactions.
        out.push_str("## Secret Redactions\n\n");
        if self.secret_redactions.is_empty() {
            out.push_str("_None._\n\n");
        } else {
            for r in &self.secret_redactions {
                out.push_str(&format!(
                    "- `{}` — {} ({})\n",
                    r.pattern_id, r.reason, r.time
                ));
            }
            out.push('\n');
        }

        // MCP calls.
        out.push_str("## MCP Calls\n\n");
        if self.mcp_calls.is_empty() {
            out.push_str("_None._\n\n");
        } else {
            for m in &self.mcp_calls {
                out.push_str(&format!(
                    "- `{}` — {:?}, result {:?} ({})\n",
                    m.tool, m.decision, m.result, m.time
                ));
            }
            out.push('\n');
        }

        out
    }
}

fn risk_name(risk: Risk) -> &'static str {
    match risk {
        Risk::Low => "low",
        Risk::Medium => "medium",
        Risk::High => "high",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{DateTime, TimeZone, Utc};
    use fida_action::{Actor, Protocol};
    use serde_json::Value;

    fn at(hour: u32, minute: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 6, 12, hour, minute, 0).unwrap()
    }

    fn base(id: &str, action: AuditAction) -> AuditEvent {
        AuditEvent {
            id: id.to_string(),
            session_id: "2026-06-12T070000Z-aaaa".to_string(),
            time: at(7, 0),
            actor: Actor::Agent,
            action,
            decision: Decision::Allow,
            result: AuditResult::Allowed,
            matched_rule: MatchedRule::NoExplicitRule,
            risk: Risk::Low,
            redacted: false,
            metrics: None,
        }
    }

    fn sample_events() -> Vec<AuditEvent> {
        let cmd = base(
            "evt_cmd",
            AuditAction::CommandRun {
                command: "pnpm install".to_string(),
            },
        );

        let mut denied = base(
            "evt_deny",
            AuditAction::CommandRun {
                command: "rm -rf /".to_string(),
            },
        );
        denied.decision = Decision::Deny;
        denied.matched_rule = MatchedRule::Rule("hard_deny.rm".to_string());
        denied.risk = Risk::High;

        let mut approved = base(
            "evt_ask",
            AuditAction::FileWrite {
                path: "src/app.ts".to_string(),
            },
        );
        approved.decision = Decision::Ask;
        approved.result = AuditResult::AllowedOnce;

        let deleted = {
            let mut e = base(
                "evt_del",
                AuditAction::FileDelete {
                    path: "old.txt".to_string(),
                },
            );
            e.time = at(7, 2);
            e
        };

        let secret = {
            let mut e = base(
                "evt_secret",
                AuditAction::SecretDetected {
                    pattern_id: "aws_key".to_string(),
                    reason: "matched AWS key".to_string(),
                },
            );
            e.redacted = true;
            e
        };

        let mcp = base(
            "evt_mcp",
            AuditAction::McpToolCall {
                tool: "browser.navigate".to_string(),
            },
        );

        let net = base(
            "evt_net",
            AuditAction::NetworkRequest {
                domain: Some("example.com".to_string()),
                host: "93.184.216.34".to_string(),
                protocol: Protocol::Https,
            },
        );

        vec![cmd, denied, approved, deleted, secret, mcp, net]
    }

    #[test]
    fn parse_rejects_unsupported_format() {
        assert_eq!(ReportFormat::parse("markdown"), Ok(ReportFormat::Markdown));
        assert_eq!(ReportFormat::parse("json"), Ok(ReportFormat::Json));
        assert_eq!(
            ReportFormat::parse("yaml"),
            Err(ReportError::UnsupportedFormat {
                requested: "yaml".to_string()
            })
        );
    }

    #[test]
    fn empty_events_render_all_sections_empty_markdown() {
        let generator = DefaultReportGenerator::new();
        let md = generator.render(&[], ReportFormat::Markdown).unwrap();
        for heading in [
            "## Summary",
            "## Commands Run",
            "## Denied Actions",
            "## Human Approvals",
            "## Changed Files",
            "## Secret Redactions",
            "## MCP Calls",
        ] {
            assert!(md.contains(heading), "missing section: {heading}");
        }
        // Each event-driven section is rendered as empty.
        assert_eq!(md.matches("_None._").count(), 6);
        assert!(md.contains("Total events: 0"));
    }

    #[test]
    fn empty_events_render_all_sections_empty_json() {
        let generator = DefaultReportGenerator::new();
        let json = generator.render(&[], ReportFormat::Json).unwrap();
        let v: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["summary"]["total_events"], 0);
        for section in [
            "commands_run",
            "denied_actions",
            "human_approvals",
            "changed_files",
            "secret_redactions",
            "mcp_calls",
        ] {
            assert!(v[section].is_array(), "missing array section: {section}");
            assert_eq!(v[section].as_array().unwrap().len(), 0);
        }
    }

    #[test]
    fn json_report_groups_events_into_sections() {
        let generator = DefaultReportGenerator::new();
        let json = generator
            .render(&sample_events(), ReportFormat::Json)
            .unwrap();
        let v: Value = serde_json::from_str(&json).unwrap();

        assert_eq!(v["summary"]["total_events"], 7);
        assert_eq!(v["summary"]["redacted_events"], 1);
        assert_eq!(v["summary"]["session_id"], "2026-06-12T070000Z-aaaa");
        // 5 allow (cmd, deleted, secret, mcp, net), 1 ask, 1 deny.
        assert_eq!(v["summary"]["decision_counts"]["allow"], 5);
        assert_eq!(v["summary"]["decision_counts"]["ask"], 1);
        assert_eq!(v["summary"]["decision_counts"]["deny"], 1);

        assert_eq!(v["commands_run"].as_array().unwrap().len(), 2); // pnpm + rm
        assert_eq!(v["denied_actions"].as_array().unwrap().len(), 1);
        assert_eq!(v["human_approvals"].as_array().unwrap().len(), 1);
        assert_eq!(v["changed_files"].as_array().unwrap().len(), 2); // write + delete
        assert_eq!(v["secret_redactions"].as_array().unwrap().len(), 1);
        assert_eq!(v["mcp_calls"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn markdown_report_contains_event_details() {
        let generator = DefaultReportGenerator::new();
        let md = generator
            .render(&sample_events(), ReportFormat::Markdown)
            .unwrap();
        assert!(md.contains("pnpm install"));
        assert!(md.contains("hard_deny.rm"));
        assert!(md.contains("src/app.ts"));
        assert!(md.contains("aws_key"));
        assert!(md.contains("browser.navigate"));
        assert!(md.contains("Total events: 7"));
    }

    #[test]
    fn secret_report_never_includes_value() {
        // The report only repeats redaction-safe fields it was given.
        let generator = DefaultReportGenerator::new();
        let json = generator
            .render(&sample_events(), ReportFormat::Json)
            .unwrap();
        let v: Value = serde_json::from_str(&json).unwrap();
        let secret = &v["secret_redactions"][0];
        assert_eq!(secret["pattern_id"], "aws_key");
        assert!(secret.get("value").is_none());
    }
}
