//! `fida status` — show effective activation state.

use clap::Args;
use fida_action::ProtectionLevel;

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
    report(project.as_ref(), global.as_ref(), &global_path, ctx)
}

fn report(
    project: Option<&SetupRecord>,
    global: Option<&SetupRecord>,
    global_path: &std::path::Path,
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
                None => println!("Verification: not recorded; run `fida init` again."),
            }

            if let Some(policy) = &record.config.policy_hint {
                println!("Advanced policy: {policy}");
            }
        }
        None => {
            println!("Fida status: inactive");
            println!("No project or global setup found.");
            println!("Run `fida init` to initialize Fida for your agents.");
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
}
