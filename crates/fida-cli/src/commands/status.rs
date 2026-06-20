//! `fida status` — show effective activation state.

use std::path::Path;

use clap::Args;
use fida_action::ProtectionLevel;
use fida_audit::JsonlAuditStore;

use crate::commands::setup_state::{
    SetupRecord, global_setup_path, read_config, read_project_config,
};
use crate::context::GlobalContext;
use crate::error::{CliError, CliResult};

#[derive(Debug, Args)]
pub struct StatusArgs {}

pub async fn run(_args: &StatusArgs, ctx: &GlobalContext) -> CliResult {
    let root = std::env::current_dir()
        .map_err(|e| CliError::general(format!("cannot determine current directory: {e}")))?;
    let project = read_project_config(&root)?;
    let global_path = global_setup_path()?;
    let global = read_config(&global_path)?;
    let secrets_protected = protected_secret_count(&root);
    report(
        project.as_ref(),
        global.as_ref(),
        &global_path,
        secrets_protected,
        ctx,
    )
}

/// Count redactions recorded in this repo's audit log — the running tally of
/// secret values Fida has kept out of model context. Resolved from the same
/// audit directory the gateway writes to (`policy.audit.path`, per-repo), this
/// fails soft to `0` when no log, policy, or directory is present.
fn protected_secret_count(repo: &Path) -> usize {
    let Ok(policy) = fida_policy::load_secret_guard_policy() else {
        return 0;
    };
    let root = if policy.audit.path.is_absolute() {
        policy.audit.path.clone()
    } else {
        repo.join(&policy.audit.path)
    };
    let store = JsonlAuditStore::new(&root);
    let Ok(entries) = std::fs::read_dir(&root) else {
        return 0;
    };
    let mut count = 0;
    for entry in entries.flatten() {
        if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }
        if let Some(session) = entry.file_name().to_str() {
            if let Ok(report) = store.read_report(session) {
                count += report.events.iter().filter(|e| e.redacted).count();
            }
        }
    }
    count
}

fn report(
    project: Option<&SetupRecord>,
    global: Option<&SetupRecord>,
    global_path: &std::path::Path,
    secrets_protected: usize,
    ctx: &GlobalContext,
) -> CliResult {
    let effective = effective_record(project, global);

    if ctx.json {
        let effective_protection = effective.map(|record| {
            let entries = protection_entries(record);
            overall_level(&entries)
        });
        let raw = serde_json::to_string(&serde_json::json!({
            "effective_scope": effective.map(|r| r.config.scope.label()),
            "protection": effective_protection,
            "verification": effective.and_then(|r| r.config.verification.as_ref()),
            "project": record_json(project),
            "global": record_json(global),
            "global_path": global_path,
            "secrets_protected": secrets_protected,
        }))
        .map_err(|e| CliError::general(format!("failed to encode status JSON: {e}")))?;
        println!("{raw}");
        return Ok(());
    }

    if ctx.is_quiet() {
        return Ok(());
    }

    match effective {
        Some(record) => {
            let levels = protection_entries(record);
            let overall = overall_level(&levels);
            println!(
                "Fida protection: {} ({})",
                overall.as_str(),
                record.config.scope.label()
            );
            println!("Secret values are redacted before reaching the model.");
            println!("Secrets protected (this repo): {secrets_protected}");
            println!("Effective config: {}", record.path.display());
            println!("Agents:");
            for entry in &levels {
                println!("  {}: {}", entry.0, entry.1.as_str());
            }
            if levels
                .iter()
                .any(|(_, level)| *level == ProtectionLevel::BestEffort)
            {
                println!("Warning: best-effort agents can bypass the gateway with native tools.");
            }
            match &record.config.verification {
                Some(v) => println!(
                    "Verification: {} ({})",
                    if v.passed { "passed" } else { "failed" },
                    v.detail
                ),
                None => println!("Verification: not recorded; run `fida` again."),
            }

            if let Some(policy) = &record.config.policy_hint {
                println!("Advanced policy: {policy}");
            }
        }
        None => {
            println!("Fida status: inactive");
            println!("No project or global setup found.");
            println!("Run `fida` to install protection.");
        }
    }

    println!();
    println!(
        "Project setup: {}",
        project
            .map(|r| r.path.display().to_string())
            .unwrap_or_else(|| "not configured".to_string())
    );
    println!(
        "Global setup: {}",
        global
            .map(|r| r.path.display().to_string())
            .unwrap_or_else(|| "not configured".to_string())
    );
    Ok(())
}

fn effective_record<'a>(
    project: Option<&'a SetupRecord>,
    global: Option<&'a SetupRecord>,
) -> Option<&'a SetupRecord> {
    project.or(global)
}

fn record_json(record: Option<&SetupRecord>) -> serde_json::Value {
    match record {
        Some(r) => serde_json::json!({
            "scope": r.config.scope.label(),
            "path": r.path,
            "agents": r.config.agents,
            "fallback": r.config.fallback,
            "hook_path": r.config.hook_path,
            "adapter_paths": r.config.adapter_paths,
            "shim_paths": r.config.shim_paths,
            "policy_hint": r.config.policy_hint,
            "protection": r.config.protection,
            "verification": r.config.verification,
        }),
        None => serde_json::Value::Null,
    }
}

fn protection_entries(record: &SetupRecord) -> Vec<(String, ProtectionLevel)> {
    record
        .config
        .agents
        .iter()
        .map(|agent| {
            let found = record
                .config
                .protection
                .iter()
                .find(|entry| &entry.agent == agent);
            (
                found
                    .map(|entry| entry.display.clone())
                    .unwrap_or_else(|| agent.clone()),
                found
                    .map(crate::commands::setup_state::effective_protection)
                    .unwrap_or(ProtectionLevel::Incomplete),
            )
        })
        .collect()
}

fn overall_level(entries: &[(String, ProtectionLevel)]) -> ProtectionLevel {
    if entries.is_empty() {
        return ProtectionLevel::Inactive;
    }
    if entries
        .iter()
        .any(|(_, level)| *level == ProtectionLevel::Incomplete)
    {
        ProtectionLevel::Incomplete
    } else if entries
        .iter()
        .any(|(_, level)| *level == ProtectionLevel::BestEffort)
    {
        ProtectionLevel::BestEffort
    } else {
        ProtectionLevel::Enforced
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::setup_state::{SetupConfig, SetupScope};

    #[test]
    fn project_record_wins_over_global_record() {
        let project = SetupRecord {
            path: ".fida/integrations/setup.yaml".into(),
            config: SetupConfig::new(
                SetupScope::Project,
                vec!["codex".to_string()],
                Some(".fida/integrations/guard.sh".to_string()),
                Some(".fida/policy.yaml".to_string()),
            ),
        };
        let global = SetupRecord {
            path: "/tmp/fida/config.yaml".into(),
            config: SetupConfig::new(
                SetupScope::Global,
                vec!["claude".to_string()],
                Some("/tmp/fida/guard.sh".to_string()),
                None,
            ),
        };

        let effective = effective_record(Some(&project), Some(&global)).unwrap();
        assert_eq!(effective.config.scope, SetupScope::Project);
        assert_eq!(effective.config.agents, ["codex"]);
    }

    #[test]
    fn count_tallies_only_redacted_events_in_the_repo_audit_log() {
        use fida_action::{Actor, Decision, MatchedRule, Risk};
        use fida_audit::{AuditAction, AuditEvent, AuditResult, AuditStore};

        let repo = tempfile::tempdir().unwrap();
        let policy = fida_policy::load_secret_guard_policy().unwrap();
        // Resolve the audit root exactly as `protected_secret_count` does, so the
        // event we write lands where the counter reads it.
        let root = if policy.audit.path.is_absolute() {
            policy.audit.path.clone()
        } else {
            repo.path().join(&policy.audit.path)
        };
        let mut store = JsonlAuditStore::new(&root);

        let event = |redacted: bool| AuditEvent {
            id: "evt".to_string(),
            session_id: "s1".to_string(),
            time: chrono::Utc::now(),
            actor: Actor::Agent,
            action: AuditAction::SecretDetected {
                pattern_id: "aws_access_key".to_string(),
                reason: "test".to_string(),
            },
            decision: Decision::Allow,
            result: AuditResult::Allowed,
            matched_rule: MatchedRule::NoExplicitRule,
            risk: Risk::Low,
            redacted,
            metrics: None,
        };
        store.append(&event(true)).unwrap();
        store.append(&event(false)).unwrap();

        assert_eq!(protected_secret_count(repo.path()), 1);
    }

    #[test]
    fn count_is_zero_when_no_audit_log_exists() {
        let repo = tempfile::tempdir().unwrap();
        assert_eq!(protected_secret_count(repo.path()), 0);
    }
}
