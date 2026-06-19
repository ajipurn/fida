//! MCP Risk Scanner — classify configured agent MCP servers as risky (R8,
//! lower priority; design "MCP Risk Scanner").
//!
//! Parsing is robust by construction (Property 21): a missing config is
//! skipped, an unreadable or unparseable config records a non-fatal error and
//! the scan continues, and fields absent from legacy configs are treated as
//! their defaults. The agent-registry/file-location knowledge lives in the CLI,
//! which supplies each agent's raw config contents via [`McpAgentSource`];
//! this module owns only the parse + classification logic so it stays free of
//! any CLI dependency and is testable in isolation.

use serde::Serialize;
use serde_json::Value;

/// The result of reading one agent's MCP config file.
#[derive(Debug, Clone)]
pub enum McpRead {
    /// The config file is absent — skip the agent (R8.5).
    Missing,
    /// The config file was read; carries its raw contents.
    Present(String),
    /// The config file exists but could not be accessed; carries the reason
    /// (R8.5).
    Unreadable(String),
}

/// One agent's MCP configuration source, supplied by the CLI.
#[derive(Debug, Clone)]
pub struct McpAgentSource {
    /// The agent's display name.
    pub agent: String,
    /// The top-level JSON key holding the server map (`mcpServers` / `servers`).
    pub key: String,
    /// The read outcome for the agent's config file.
    pub read: McpRead,
}

/// A risk category a configured MCP server can fall into (R8.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskCategory {
    Filesystem,
    Shell,
    Browser,
    Git,
    Sqlite,
    Postgres,
    Docker,
    Kubernetes,
    Secrets,
}

impl RiskCategory {
    /// The category's canonical lowercase name.
    pub fn as_str(self) -> &'static str {
        match self {
            RiskCategory::Filesystem => "filesystem",
            RiskCategory::Shell => "shell",
            RiskCategory::Browser => "browser",
            RiskCategory::Git => "git",
            RiskCategory::Sqlite => "sqlite",
            RiskCategory::Postgres => "postgres",
            RiskCategory::Docker => "docker",
            RiskCategory::Kubernetes => "kubernetes",
            RiskCategory::Secrets => "secrets",
        }
    }
}

/// A risky MCP server finding (R8.2, R8.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct McpRiskFinding {
    /// The agent whose config declared the server.
    pub agent: String,
    /// The server's name (its key in the server map).
    pub server: String,
    /// The risk category matched.
    pub category: RiskCategory,
    /// A recommendation identifying both the agent and the server (R8.3).
    pub recommendation: String,
}

/// A non-fatal error reading or parsing an agent's config (R8.6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct McpConfigError {
    /// The affected agent.
    pub agent: String,
    /// What went wrong.
    pub message: String,
}

/// The MCP risk report: risky findings plus any non-fatal config errors.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct McpRiskReport {
    pub findings: Vec<McpRiskFinding>,
    pub errors: Vec<McpConfigError>,
}

/// Keyword table mapping each risk category to substrings that identify it in a
/// server name, command, or argument.
const KEYWORDS: &[(RiskCategory, &[&str])] = &[
    (RiskCategory::Filesystem, &["filesystem", "file-system"]),
    (
        RiskCategory::Shell,
        &["shell", "bash", "terminal", "command-runner"],
    ),
    (
        RiskCategory::Browser,
        &["browser", "puppeteer", "playwright", "chrome"],
    ),
    (RiskCategory::Git, &["git", "github"]),
    (RiskCategory::Sqlite, &["sqlite"]),
    (RiskCategory::Postgres, &["postgres", "postgresql"]),
    (RiskCategory::Docker, &["docker"]),
    (RiskCategory::Kubernetes, &["kubernetes", "k8s", "kubectl"]),
    (
        RiskCategory::Secrets,
        &["secret", "vault", "credential", "1password", "keychain"],
    ),
];

/// Classify a server as risky by matching its name/command/args against the
/// category keyword table; returns the first matching category, or `None`
/// (R8.2). Matching is case-insensitive substring.
pub fn classify_server(name: &str, command: Option<&str>, args: &[String]) -> Option<RiskCategory> {
    let mut haystack = String::new();
    haystack.push_str(&name.to_ascii_lowercase());
    haystack.push(' ');
    if let Some(cmd) = command {
        haystack.push_str(&cmd.to_ascii_lowercase());
        haystack.push(' ');
    }
    for arg in args {
        haystack.push_str(&arg.to_ascii_lowercase());
        haystack.push(' ');
    }
    for (category, keywords) in KEYWORDS {
        if keywords.iter().any(|kw| haystack.contains(kw)) {
            return Some(*category);
        }
    }
    None
}

/// Scan every agent's MCP config, classifying risky servers and recording
/// non-fatal errors without ever aborting (R8, R14.3).
pub fn scan_mcp(sources: &[McpAgentSource]) -> McpRiskReport {
    let mut report = McpRiskReport::default();

    for source in sources {
        let raw = match &source.read {
            // Missing config: skip the agent (R8.5).
            McpRead::Missing => continue,
            // Unreadable config: record and continue (R8.5/8.6).
            McpRead::Unreadable(reason) => {
                report.errors.push(McpConfigError {
                    agent: source.agent.clone(),
                    message: format!("config could not be accessed: {reason}"),
                });
                continue;
            }
            McpRead::Present(raw) => raw,
        };

        let value: Value = match serde_json::from_str(raw) {
            Ok(v) => v,
            Err(e) => {
                // Unparseable config: record and continue (R8.6).
                report.errors.push(McpConfigError {
                    agent: source.agent.clone(),
                    message: format!("config could not be parsed: {e}"),
                });
                continue;
            }
        };

        // A legacy/absent server map is treated as empty (R14.3): no servers,
        // no error.
        let Some(servers) = value.get(&source.key).and_then(Value::as_object) else {
            continue;
        };

        for (server_name, entry) in servers {
            let command = entry.get("command").and_then(Value::as_str);
            let args: Vec<String> = entry
                .get("args")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default();

            if let Some(category) = classify_server(server_name, command, &args) {
                report.findings.push(McpRiskFinding {
                    agent: source.agent.clone(),
                    server: server_name.clone(),
                    category,
                    recommendation: format!(
                        "Route `{server_name}` for {} through the Fida gateway",
                        source.agent
                    ),
                });
            }
        }
    }

    report
}

/// Render the MCP risk report as a human-readable section.
pub fn render_human(report: &McpRiskReport) -> String {
    let mut out = String::from("\nMCP risk scan:\n");
    if report.findings.is_empty() {
        out.push_str("  No risky MCP servers found.\n");
    } else {
        for f in &report.findings {
            out.push_str(&format!(
                "  [{}] {} / {} — {}\n",
                f.category.as_str(),
                f.agent,
                f.server,
                f.recommendation
            ));
        }
    }
    if !report.errors.is_empty() {
        out.push_str("  Config errors:\n");
        for e in &report.errors {
            out.push_str(&format!("    {} — {}\n", e.agent, e.message));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_risky_servers_and_ignores_benign() {
        assert_eq!(
            classify_server(
                "filesystem",
                Some("npx"),
                &["@modelcontextprotocol/server-filesystem".to_string()]
            ),
            Some(RiskCategory::Filesystem)
        );
        assert_eq!(
            classify_server("my-shell", None, &[]),
            Some(RiskCategory::Shell)
        );
        assert_eq!(
            classify_server("pg-tools", Some("postgres-mcp"), &[]),
            Some(RiskCategory::Postgres)
        );
        assert_eq!(
            classify_server("weather", Some("npx"), &["weather-mcp".to_string()]),
            None
        );
    }

    #[test]
    fn scan_skips_missing_records_unparseable_and_finds_risky() {
        let sources = vec![
            McpAgentSource {
                agent: "claude".to_string(),
                key: "mcpServers".to_string(),
                read: McpRead::Missing,
            },
            McpAgentSource {
                agent: "cursor".to_string(),
                key: "mcpServers".to_string(),
                read: McpRead::Unreadable("permission denied".to_string()),
            },
            McpAgentSource {
                agent: "kiro".to_string(),
                key: "mcpServers".to_string(),
                read: McpRead::Present("{ not json".to_string()),
            },
            McpAgentSource {
                agent: "windsurf".to_string(),
                key: "mcpServers".to_string(),
                read: McpRead::Present(
                    r#"{"mcpServers":{"docker":{"command":"docker-mcp"},"notes":{"command":"note-taker"}}}"#
                        .to_string(),
                ),
            },
            McpAgentSource {
                agent: "legacy".to_string(),
                key: "mcpServers".to_string(),
                read: McpRead::Present(r#"{"someOtherKey":42}"#.to_string()),
            },
        ];
        let report = scan_mcp(&sources);
        // One risky finding (docker), the benign note-taker ignored.
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].agent, "windsurf");
        assert_eq!(report.findings[0].server, "docker");
        assert_eq!(report.findings[0].category, RiskCategory::Docker);
        assert!(report.findings[0].recommendation.contains("windsurf"));
        assert!(report.findings[0].recommendation.contains("docker"));
        // Two errors: unreadable + unparseable. Missing and legacy are silent.
        assert_eq!(report.errors.len(), 2);
    }
}
