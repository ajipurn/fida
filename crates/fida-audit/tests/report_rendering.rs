//! Integration tests for the Report_Generator (spec task 7.6).
//!
//! Covers the three report-rendering behaviours:
//!   1. Empty-section rendering — an empty event list still renders all seven
//!      sections (markdown) and emits empty arrays per section (json).
//!   2. Markdown vs JSON output — a representative mix of events produces the
//!      expected human-readable fragments (markdown) and the expected grouped
//!      structure (json), and secret values never leak (only pattern_id/reason
//!      from the already-redacted events appear).
//!   3. Unsupported-format rejection — `ReportFormat::parse` fails closed for
//!      any name other than `markdown`/`json`.

use chrono::{DateTime, TimeZone, Utc};
use serde_json::Value;

use fida_action::{Actor, Decision, MatchedRule, Risk};
use fida_audit::{
    AuditAction, AuditEvent, AuditResult, DefaultReportGenerator, ReportError, ReportFormat,
    ReportGenerator,
};

const SESSION: &str = "2026-06-12T070000Z-int01";

fn ts(hour: u32, minute: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 6, 12, hour, minute, 0).unwrap()
}

/// An event with sensible allow/low defaults; callers override what they need.
fn event(id: &str, action: AuditAction) -> AuditEvent {
    AuditEvent {
        id: id.to_string(),
        session_id: SESSION.to_string(),
        time: ts(7, 0),
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

/// The seven Markdown section headings every report must carry.
const SECTION_HEADINGS: [&str; 7] = [
    "## Summary",
    "## Commands Run",
    "## Denied Actions",
    "## Human Approvals",
    "## Changed Files",
    "## Secret Redactions",
    "## MCP Calls",
];

/// The six event-driven JSON section arrays (Summary is an object).
const JSON_SECTIONS: [&str; 6] = [
    "commands_run",
    "denied_actions",
    "human_approvals",
    "changed_files",
    "secret_redactions",
    "mcp_calls",
];

// ---------------------------------------------------------------------------
// 1. Empty-section rendering
// ---------------------------------------------------------------------------

#[test]
fn empty_markdown_renders_every_section_with_empty_markers() {
    let generator = DefaultReportGenerator::new();
    let md = generator
        .render(&[], ReportFormat::Markdown)
        .expect("empty markdown render");

    // All seven headings present even with zero events.
    for heading in SECTION_HEADINGS {
        assert!(md.contains(heading), "missing section heading: {heading}");
    }

    // Each of the six event-driven sections shows the empty marker.
    assert_eq!(
        md.matches("_None._").count(),
        6,
        "expected an empty marker for each of the six event-driven sections"
    );

    // The summary reports a (none) session and zero totals.
    assert!(md.contains("- Session: (none)"));
    assert!(md.contains("- Total events: 0"));
}

#[test]
fn empty_json_renders_empty_arrays_for_every_section() {
    let generator = DefaultReportGenerator::new();
    let json = generator
        .render(&[], ReportFormat::Json)
        .expect("empty json render");

    // Must be valid JSON.
    let v: Value = serde_json::from_str(&json).expect("valid json");

    assert_eq!(v["summary"]["total_events"], 0);
    assert_eq!(v["summary"]["redacted_events"], 0);
    // With no events there is no session to derive; the field is omitted.
    assert!(v["summary"].get("session_id").is_none());

    for section in JSON_SECTIONS {
        let arr = v[section]
            .as_array()
            .unwrap_or_else(|| panic!("section {section} should be an array"));
        assert!(arr.is_empty(), "section {section} should be empty");
    }
}

// ---------------------------------------------------------------------------
// 2. Markdown vs JSON output for a representative event mix
// ---------------------------------------------------------------------------

/// A representative mix touching every section: a command, a deny, an
/// allowed-once approval, a file write and delete, a secret detection, and an
/// MCP tool call.
fn mixed_events() -> Vec<AuditEvent> {
    let command = event(
        "evt_cmd",
        AuditAction::CommandRun {
            command: "pnpm install".to_string(),
        },
    );

    let mut denied = event(
        "evt_deny",
        AuditAction::CommandRun {
            command: "rm -rf /".to_string(),
        },
    );
    denied.time = ts(7, 1);
    denied.decision = Decision::Deny;
    denied.result = AuditResult::Denied;
    denied.matched_rule = MatchedRule::Rule("hard_deny.rm_rf".to_string());
    denied.risk = Risk::High;

    let mut approved = event(
        "evt_ask",
        AuditAction::FileWrite {
            path: "src/app.ts".to_string(),
        },
    );
    approved.time = ts(7, 2);
    approved.decision = Decision::Ask;
    approved.result = AuditResult::AllowedOnce;

    let mut deleted = event(
        "evt_del",
        AuditAction::FileDelete {
            path: "legacy/old.txt".to_string(),
        },
    );
    deleted.time = ts(7, 3);

    let mut secret = event(
        "evt_secret",
        AuditAction::SecretDetected {
            pattern_id: "aws_access_key".to_string(),
            reason: "matched AWS access key pattern".to_string(),
        },
    );
    secret.time = ts(7, 4);
    secret.redacted = true;

    let mut mcp = event(
        "evt_mcp",
        AuditAction::McpToolCall {
            tool: "browser.navigate".to_string(),
        },
    );
    mcp.time = ts(7, 5);

    vec![command, denied, approved, deleted, secret, mcp]
}

#[test]
fn markdown_output_contains_human_readable_fragments() {
    let generator = DefaultReportGenerator::new();
    let md = generator
        .render(&mixed_events(), ReportFormat::Markdown)
        .expect("markdown render");

    // All seven headings are present.
    for heading in SECTION_HEADINGS {
        assert!(md.contains(heading), "missing section heading: {heading}");
    }

    // Summary reflects the event mix: 4 allow, 1 ask, 1 deny, 1 redacted.
    assert!(md.contains(&format!("- Session: {SESSION}")));
    assert!(md.contains("- Total events: 6"));
    assert!(md.contains("- Redacted events: 1"));
    assert!(md.contains("allow=4, ask=1, deny=1, dry_run=0"));

    // Per-section human-readable fragments.
    assert!(md.contains("pnpm install"), "command should be listed");
    assert!(md.contains("hard_deny.rm_rf"), "deny rule should be listed");
    assert!(
        md.contains("command.run: rm -rf /"),
        "denied action description should be listed"
    );
    assert!(md.contains("src/app.ts"), "approved file should be listed");
    assert!(
        md.contains("legacy/old.txt"),
        "deleted file should be listed"
    );
    assert!(md.contains("aws_access_key"), "secret pattern id");
    assert!(
        md.contains("matched AWS access key pattern"),
        "secret reason"
    );
    assert!(md.contains("browser.navigate"), "mcp tool should be listed");

    // No empty markers: every section has at least one entry given this mix
    // (commands_run gets both the command and the denied command).
    assert_eq!(
        md.matches("_None._").count(),
        0,
        "no section should be empty for the representative mix"
    );
}

#[test]
fn json_output_groups_events_into_expected_structure() {
    let generator = DefaultReportGenerator::new();
    let json = generator
        .render(&mixed_events(), ReportFormat::Json)
        .expect("json render");

    let v: Value = serde_json::from_str(&json).expect("valid json");

    // Summary.
    assert_eq!(v["summary"]["session_id"], SESSION);
    assert_eq!(v["summary"]["total_events"], 6);
    assert_eq!(v["summary"]["redacted_events"], 1);
    assert_eq!(v["summary"]["decision_counts"]["allow"], 4);
    assert_eq!(v["summary"]["decision_counts"]["ask"], 1);
    assert_eq!(v["summary"]["decision_counts"]["deny"], 1);
    assert_eq!(v["summary"]["decision_counts"]["dry_run"], 0);

    // Grouped sections.
    assert_eq!(
        v["commands_run"].as_array().unwrap().len(),
        2,
        "pnpm install + rm -rf /"
    );
    assert_eq!(v["denied_actions"].as_array().unwrap().len(), 1);
    assert_eq!(v["human_approvals"].as_array().unwrap().len(), 1);
    assert_eq!(
        v["changed_files"].as_array().unwrap().len(),
        2,
        "one write + one delete"
    );
    assert_eq!(v["secret_redactions"].as_array().unwrap().len(), 1);
    assert_eq!(v["mcp_calls"].as_array().unwrap().len(), 1);

    // Spot-check grouped field rendering.
    let denied = &v["denied_actions"][0];
    assert_eq!(denied["matched_rule"], "hard_deny.rm_rf");
    assert_eq!(denied["risk"], "high");

    let approval = &v["human_approvals"][0];
    assert_eq!(approval["result"], "allowed_once");

    let changes: Vec<&str> = v["changed_files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["change"].as_str().unwrap())
        .collect();
    assert!(changes.contains(&"write"));
    assert!(changes.contains(&"delete"));

    assert_eq!(v["mcp_calls"][0]["tool"], "browser.navigate");
}

#[test]
fn secret_section_renders_only_pattern_and_reason_never_value() {
    // Events arrive pre-redacted; the report only repeats pattern_id/reason and
    // must never carry a secret value field.
    let generator = DefaultReportGenerator::new();
    let json = generator
        .render(&mixed_events(), ReportFormat::Json)
        .expect("json render");
    let v: Value = serde_json::from_str(&json).expect("valid json");

    let secret = &v["secret_redactions"][0];
    assert_eq!(secret["pattern_id"], "aws_access_key");
    assert_eq!(secret["reason"], "matched AWS access key pattern");
    assert!(
        secret.get("value").is_none(),
        "secret entry must not expose a value field"
    );
    assert!(
        secret.get("secret").is_none(),
        "secret entry must not expose a secret field"
    );
}

// ---------------------------------------------------------------------------
// 3. Unsupported-format rejection
// ---------------------------------------------------------------------------

#[test]
fn parse_accepts_only_markdown_and_json() {
    assert_eq!(ReportFormat::parse("markdown"), Ok(ReportFormat::Markdown));
    assert_eq!(ReportFormat::parse("json"), Ok(ReportFormat::Json));
}

#[test]
fn parse_rejects_unsupported_formats() {
    for bad in ["yaml", "yml", "toml", "xml", "html", "", "JSON", "Markdown"] {
        match ReportFormat::parse(bad) {
            Err(ReportError::UnsupportedFormat { requested }) => {
                assert_eq!(requested, bad);
            }
            other => panic!("expected UnsupportedFormat for {bad:?}, got {other:?}"),
        }
    }
}
