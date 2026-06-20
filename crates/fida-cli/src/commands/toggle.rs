//! `fida on` / `fida off` — toggle protection for one agent or all of them.
//!
//! Toggling is a *hard* wire/unwire, global-scope: `on` writes an agent's
//! integration layers (and re-proves the redaction path); `off` removes them.
//! There is no "installed but disabled" half-state — a turned-off agent has no
//! Fida files at all, so a stale flag can never silently pass a secret through.
//!
//! `on` shares the wire + verify + persist + report path with bare `fida` via
//! [`crate::commands::root::wire_and_report`]. `off` is the counterpart cleanup
//! that used to live in the standalone `uninstall` command.

use std::path::Path;

use clap::Args;

use crate::commands::integrations::{self, AgentSpec, Scope, known_agents, scope_base};
use crate::commands::setup_state::{
    SetupConfig, SetupScope, VerificationRecord, global_setup_path, hook_path_for_setup,
    read_config, remove_agent_adapters, remove_agent_shims, remove_config, remove_guard_hook,
    upsert_config,
};
use crate::commands::shell_hook::{self, ShellKind};
use crate::context::GlobalContext;
use crate::error::{CliError, CliResult};

#[derive(Debug, Args)]
pub struct OnArgs {
    /// Agents to protect (ids). Defaults to every detected agent.
    #[arg(value_name = "AGENT")]
    pub agents: Vec<String>,
}

#[derive(Debug, Args)]
pub struct OffArgs {
    /// Agents to disable (ids). Defaults to every protected agent.
    #[arg(value_name = "AGENT")]
    pub agents: Vec<String>,
}

pub async fn on(args: &OnArgs, ctx: &GlobalContext) -> CliResult {
    let workspace = current_workspace()?;
    let selected = if args.agents.is_empty() {
        crate::commands::root::detect_agents(&workspace)
    } else {
        resolve_ids(&args.agents)?
    };

    if selected.is_empty() {
        if !ctx.is_quiet() && !ctx.json {
            println!("No supported agents detected. Name one explicitly: `fida on <agent>`.");
        }
        return Ok(());
    }

    crate::commands::root::wire_and_report(&selected, &workspace, "Fida protection enabled", ctx)
}

pub async fn off(args: &OffArgs, ctx: &GlobalContext) -> CliResult {
    let workspace = current_workspace()?;
    let global_path = global_setup_path()?;
    let configured: Vec<String> = read_config(&global_path)?
        .map(|r| r.config.agents)
        .unwrap_or_default();

    // Default off = disable everything wired (fall back to the full registry so
    // we still clean up agents wired before any config existed).
    let selected = if args.agents.is_empty() {
        if configured.is_empty() {
            known_agents()
        } else {
            resolve_ids(&configured)?
        }
    } else {
        resolve_ids(&args.agents)?
    };

    let base = scope_base(Scope::Global, &workspace)?;
    let mut removed = Vec::new();
    for spec in &selected {
        removed.push(integrations::uninstall_agent(spec, Scope::Global, &base)?);
    }

    let target_ids: Vec<String> = selected.iter().map(|s| s.id.to_string()).collect();
    let remaining: Vec<String> = configured
        .iter()
        .filter(|id| !target_ids.contains(id))
        .cloned()
        .collect();

    if remaining.is_empty() {
        full_cleanup(&global_path)?;
    } else if let Some(record) = read_config(&global_path)? {
        let mut config = SetupConfig::new(SetupScope::Global, remaining.clone(), None, None);
        config.protection = record
            .config
            .protection
            .into_iter()
            .filter(|p| remaining.contains(&p.agent))
            .collect();
        config.verification = record.config.verification.map(|v| VerificationRecord {
            passed: v.passed,
            checked_at: v.checked_at,
            detail: v.detail,
        });
        upsert_config(&global_path, config)?;
    }

    emit_off(&removed, &remaining, ctx)
}

/// Remove the global setup file and any shared artifacts once no agent remains.
fn full_cleanup(global_path: &Path) -> CliResult {
    let agents: Vec<String> = read_config(global_path)?
        .map(|r| r.config.agents)
        .unwrap_or_default();
    let _ = remove_agent_adapters(global_path, &agents)?;
    let _ = remove_agent_shims(global_path, &agents)?;
    let _ = remove_guard_hook(&hook_path_for_setup(global_path))?;
    let _ = remove_config(global_path)?;
    remove_shell_blocks();
    Ok(())
}

fn remove_shell_blocks() {
    let Ok(home) = shell_hook::home_dir() else {
        return;
    };
    for shell in [ShellKind::Zsh, ShellKind::Bash, ShellKind::Fish] {
        let _ = shell_hook::remove(&shell.rc_path(&home));
    }
}

fn current_workspace() -> CliResult<std::path::PathBuf> {
    std::env::current_dir()
        .map_err(|e| CliError::general(format!("cannot determine current directory: {e}")))
}

/// Map ids to specs, deduping and rejecting any unknown id.
fn resolve_ids(ids: &[String]) -> CliResult<Vec<AgentSpec>> {
    let agents = known_agents();
    let mut out: Vec<AgentSpec> = Vec::new();
    for raw in ids {
        let id = raw.trim();
        match agents.iter().find(|a| a.id == id) {
            Some(spec) => {
                if !out.iter().any(|s| s.id == spec.id) {
                    out.push(spec.clone());
                }
            }
            None => {
                return Err(CliError::usage(format!(
                    "unknown agent `{id}`; supported: {}",
                    agents.iter().map(|a| a.id).collect::<Vec<_>>().join(", ")
                )));
            }
        }
    }
    Ok(out)
}

fn emit_off(
    removed: &[integrations::AgentUninstallReport],
    remaining: &[String],
    ctx: &GlobalContext,
) -> CliResult {
    if ctx.json {
        let items: Vec<serde_json::Value> = removed
            .iter()
            .map(|r| serde_json::json!({ "agent": r.id, "removed": r.removed }))
            .collect();
        println!(
            "{}",
            serde_json::json!({ "scope": "global", "disabled": items, "remaining": remaining })
        );
        return Ok(());
    }
    if ctx.is_quiet() {
        return Ok(());
    }
    println!("Fida protection disabled (global).");
    for r in removed {
        let what = if r.removed.is_empty() {
            "nothing present".to_string()
        } else {
            r.removed.join(", ")
        };
        println!("  - {}: {what}", r.display);
    }
    if remaining.is_empty() {
        println!("No agents remain protected. Run `fida` to set up again.");
    } else {
        println!("Still protected: {}", remaining.join(", "));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_ids_rejects_unknown() {
        let err = resolve_ids(&["codex".into(), "nope".into()]).unwrap_err();
        assert_eq!(err.exit_code(), 1);
    }

    #[test]
    fn resolve_ids_dedups() {
        let got = resolve_ids(&["codex".into(), "codex".into()]).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].id, "codex");
    }
}
