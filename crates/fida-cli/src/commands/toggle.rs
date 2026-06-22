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

    // Project-scope wiring (written when Fida was set up *inside* a repo) lives
    // in the workspace, not under home, so the global pass never touches it.
    // Clean the current workspace too — the common case is uninstalling from the
    // affected repo; other repos are covered by the printed hint. With no agents
    // named, sweep every known agent since project installs are not recorded in
    // the global config.
    let project_specs = if args.agents.is_empty() {
        known_agents()
    } else {
        selected.clone()
    };
    let mut project_removed = Vec::new();
    for spec in &project_specs {
        let report = integrations::uninstall_agent(spec, Scope::Project, &workspace)?;
        if !report.removed.is_empty() {
            project_removed.push(report);
        }
    }

    // Claude Code persists "always allow" for Fida's MCP tools into its own
    // settings.local.json — not a file Fida wrote, but the dangling
    // `mcp__fida__*` permissions can break Claude Code after uninstall.
    let perms_changed = integrations::strip_claude_fida_permissions(&workspace)?;

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

    emit_off(&removed, &project_removed, &perms_changed, &remaining, ctx)
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
    project_removed: &[integrations::AgentUninstallReport],
    perms_changed: &[String],
    remaining: &[String],
    ctx: &GlobalContext,
) -> CliResult {
    if ctx.json {
        let report = |r: &integrations::AgentUninstallReport| {
            serde_json::json!({ "agent": r.id, "removed": r.removed })
        };
        println!(
            "{}",
            serde_json::json!({
                "scope": "global",
                "disabled": removed.iter().map(report).collect::<Vec<_>>(),
                "project_disabled": project_removed.iter().map(report).collect::<Vec<_>>(),
                "claude_permissions_cleaned": perms_changed,
                "remaining": remaining,
            })
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
    if !project_removed.is_empty() {
        println!("Removed project-scope wiring in this repo:");
        for r in project_removed {
            println!("  - {}: {}", r.display, r.removed.join(", "));
        }
    }
    if !perms_changed.is_empty() {
        println!("Cleared Fida MCP permissions Claude Code had saved:");
        for p in perms_changed {
            println!("  - {p}");
        }
    }
    if remaining.is_empty() {
        println!("No agents remain protected. Run `fida` to set up again.");
    } else {
        println!("Still protected: {}", remaining.join(", "));
    }
    // A still-running editor/agent keeps the removed MCP + hook wiring in
    // memory and errors on the missing `fida` until it reloads config. Only
    // worth saying when we actually unwired something.
    if removed.iter().any(|r| !r.removed.is_empty())
        || !project_removed.is_empty()
        || !perms_changed.is_empty()
    {
        println!(
            "Restart any running editors or agents (Cursor, VS Code, Claude Code, …) so cached \
             Fida MCP/hook references are dropped."
        );
    }
    // We can only reach the current workspace; project-scope files in other
    // repos stay until `fida off` runs there too.
    if remaining.is_empty() {
        println!(
            "Fida files may remain in other repos where you ran `fida on`; run `fida off` inside each."
        );
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
