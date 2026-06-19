//! `fida uninstall` - remove Fida from every supported agent integration.
//!
//! This is the explicit, agent-agnostic counterpart to `fida init`. It removes
//! the gateway/skill/hook layers Fida owns, cleans setup-once shell-shim state,
//! and leaves the final binary removal to the user so the running process never
//! deletes itself.

use std::path::{Path, PathBuf};

use clap::Args;

use crate::commands::integrations::{self, AgentSpec, Scope};
use crate::commands::setup_state::{
    SetupScope, find_project_setup_path, global_setup_path, hook_path_for_setup,
    project_setup_path, read_config, remove_agent_adapters, remove_agent_shims, remove_config,
    remove_guard_hook,
};
use crate::commands::shell_hook::{self, ShellKind};
use crate::context::GlobalContext;
use crate::error::{CliError, CliResult};

/// Arguments for `fida uninstall`.
#[derive(Debug, Args)]
pub struct UninstallArgs {
    /// Workspace root for project-scope cleanup. Defaults to the current
    /// directory.
    #[arg(long)]
    pub workspace: Option<PathBuf>,

    /// Remove project integrations inside the workspace instead of global ones.
    #[arg(long, conflicts_with = "global")]
    pub project: bool,

    /// Remove global integrations. This is the default.
    #[arg(long, conflicts_with = "project")]
    pub global: bool,

    /// Remove only these agents (comma-separated ids). By default every
    /// supported agent is cleaned up.
    #[arg(long = "agents", value_delimiter = ',')]
    pub agents: Vec<String>,
}

pub async fn run(args: &UninstallArgs, ctx: &GlobalContext) -> CliResult {
    let workspace = match &args.workspace {
        Some(dir) => dir.clone(),
        None => std::env::current_dir()
            .map_err(|e| CliError::general(format!("cannot determine current directory: {e}")))?,
    };
    let scope = if args.project {
        Scope::Project
    } else {
        let _ = args.global;
        Scope::Global
    };
    let base = integrations::scope_base(scope, &workspace)?;
    let selected = selected_agents(&args.agents)?;

    let mut agents = Vec::new();
    for spec in &selected {
        agents.push(integrations::uninstall_agent(spec, scope, &base)?);
    }

    let setup = Some(remove_setup(scope, &workspace)?);
    let binary = std::env::current_exe().ok();
    let report = UninstallReport {
        scope,
        agents,
        setup,
        binary,
    };
    emit(&report, ctx)
}

fn selected_agents(ids: &[String]) -> CliResult<Vec<AgentSpec>> {
    let agents = integrations::known_agents();
    if ids.is_empty() {
        return Ok(agents);
    }

    let mut out = Vec::new();
    for raw in ids {
        let id = raw.trim();
        match agents.iter().find(|a| a.id == id) {
            Some(spec) => {
                if !out
                    .iter()
                    .any(|existing: &AgentSpec| existing.id == spec.id)
                {
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

fn remove_setup(scope: Scope, workspace: &Path) -> CliResult<SetupCleanup> {
    let setup_scope = match scope {
        Scope::Project => SetupScope::Project,
        Scope::Global => SetupScope::Global,
    };
    let path = match setup_scope {
        SetupScope::Project => {
            find_project_setup_path(workspace).unwrap_or_else(|| project_setup_path(workspace))
        }
        SetupScope::Global => global_setup_path()?,
    };

    let record = read_config(&path)?;
    let agents = record
        .as_ref()
        .map(|r| r.config.agents.clone())
        .unwrap_or_default();
    let hook_path = record
        .and_then(|record| record.config.hook_path.map(PathBuf::from))
        .unwrap_or_else(|| hook_path_for_setup(&path));

    let adapter_paths = remove_agent_adapters(&path, &agents)?;
    let shim_paths = remove_agent_shims(&path, &agents)?;
    let removed_config = remove_config(&path)?;
    let removed_hook = remove_guard_hook(&hook_path)?;
    let removed_shell_rcs = remove_shell_blocks();

    Ok(SetupCleanup {
        path,
        hook_path,
        adapter_paths,
        shim_paths,
        removed_config,
        removed_hook,
        removed_shell_rcs,
    })
}

fn remove_shell_blocks() -> Vec<PathBuf> {
    let mut removed = Vec::new();
    let Ok(home) = shell_hook::home_dir() else {
        return removed;
    };
    for shell in [ShellKind::Zsh, ShellKind::Bash, ShellKind::Fish] {
        let rc = shell.rc_path(&home);
        if let Ok(true) = shell_hook::remove(&rc) {
            removed.push(rc);
        }
    }
    removed
}

struct UninstallReport {
    scope: Scope,
    agents: Vec<integrations::AgentUninstallReport>,
    setup: Option<SetupCleanup>,
    binary: Option<PathBuf>,
}

struct SetupCleanup {
    path: PathBuf,
    hook_path: PathBuf,
    adapter_paths: Vec<PathBuf>,
    shim_paths: Vec<PathBuf>,
    removed_config: bool,
    removed_hook: bool,
    removed_shell_rcs: Vec<PathBuf>,
}

fn emit(report: &UninstallReport, ctx: &GlobalContext) -> CliResult {
    if ctx.json {
        return emit_json(report);
    }
    if ctx.is_quiet() {
        return Ok(());
    }

    println!("Fida uninstalled ({}).", report.scope.label());
    for agent in &report.agents {
        let what = if agent.removed.is_empty() {
            "nothing present".to_string()
        } else {
            agent.removed.join(", ")
        };
        println!("  - {}: {}", agent.display, what);
    }

    if let Some(setup) = &report.setup {
        if setup.removed_config {
            println!("  - setup: removed {}", setup.path.display());
        } else {
            println!("  - setup: nothing present at {}", setup.path.display());
        }
        if setup.removed_hook {
            println!("  - setup hook: removed {}", setup.hook_path.display());
        }
        for path in &setup.adapter_paths {
            println!("  - adapter: removed {}", path.display());
        }
        for path in &setup.shim_paths {
            println!("  - shim: removed {}", path.display());
        }
        for path in &setup.removed_shell_rcs {
            println!("  - shell rc: removed Fida block from {}", path.display());
        }
    }

    println!();
    println!("Last step: delete the Fida binary yourself.");
    match &report.binary {
        Some(path) => println!("  rm {}", path.display()),
        None => println!("  rm $(command -v fida)"),
    }
    Ok(())
}

fn emit_json(report: &UninstallReport) -> CliResult {
    let agents: Vec<serde_json::Value> = report
        .agents
        .iter()
        .map(|r| serde_json::json!({ "agent": r.id, "removed": r.removed.clone() }))
        .collect();
    let setup = report.setup.as_ref().map(|s| {
        serde_json::json!({
            "path": s.path.display().to_string(),
            "hook_path": s.hook_path.display().to_string(),
            "removed_config": s.removed_config,
            "removed_hook": s.removed_hook,
            "removed_adapters": display_paths(&s.adapter_paths),
            "removed_shims": display_paths(&s.shim_paths),
            "removed_shell_rcs": display_paths(&s.removed_shell_rcs),
        })
    });
    println!(
        "{}",
        serde_json::json!({
            "scope": report.scope.label(),
            "uninstalled": agents,
            "setup": setup,
            "next_step": {
                "remove_binary": report.binary.as_ref().map(|p| p.display().to_string()),
            },
        })
    );
    Ok(())
}

fn display_paths(paths: &[PathBuf]) -> Vec<String> {
    paths.iter().map(|p| p.display().to_string()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_selection_covers_every_supported_agent() {
        assert_eq!(
            selected_agents(&[]).unwrap().len(),
            integrations::known_agents().len()
        );
    }

    #[test]
    fn explicit_selection_dedups_and_rejects_unknown_ids() {
        let selected = selected_agents(&["codex".to_string(), "codex".to_string()]).unwrap();
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].id, "codex");

        let err = selected_agents(&["nope".to_string()]).unwrap_err();
        assert_eq!(err.exit_code(), 1);
    }
}
