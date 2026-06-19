//! `fida guard` — setup-aware command wrapper for hooks and shims.
//!
//! `fida exec` always mediates a command. `fida guard` is different: it
//! first checks the setup-once activation state. If neither project nor global
//! setup is active, it transparently runs the command. If setup is active, it
//! delegates to `fida exec` so the normal policy, approval, redaction, and
//! audit path is used.

use clap::Args;

use crate::commands::{exec, setup_state};
use crate::context::GlobalContext;
use crate::error::{CliError, CliResult};

pub const BOOTSTRAP_ENV: &str = "FIDA_BOOTSTRAP_AGENT";

#[derive(Debug, Args)]
pub struct GuardArgs {
    /// The command and its arguments, after `--`.
    #[arg(last = true, required = true)]
    pub command: Vec<String>,
}

pub async fn run(args: &GuardArgs, ctx: &GlobalContext) -> CliResult {
    let root = std::env::current_dir()
        .map_err(|e| CliError::general(format!("cannot determine current directory: {e}")))?;

    if bootstrap_requested() {
        return passthrough(&args.command);
    }

    if effective_setup_active(&root)? {
        let exec_args = exec::ExecArgs {
            cwd: None,
            env: Vec::new(),
            timeout: None,
            dry_run: false,
            command: args.command.clone(),
        };
        return exec::run(&exec_args, ctx).await;
    }

    passthrough(&args.command)
}

fn bootstrap_requested() -> bool {
    bootstrap_value_enabled(std::env::var(BOOTSTRAP_ENV).ok().as_deref())
}

fn bootstrap_value_enabled(value: Option<&str>) -> bool {
    matches!(value, Some("1") | Some("true") | Some("yes"))
}

fn effective_setup_active(root: &std::path::Path) -> CliResult<bool> {
    if setup_state::read_project_config(root)?.is_some() {
        return Ok(true);
    }
    let global = setup_state::global_setup_path()?;
    Ok(setup_state::read_config(&global)?.is_some())
}

fn passthrough(argv: &[String]) -> CliResult {
    let Some((program, args)) = argv.split_first() else {
        return Err(CliError::usage("guard requires a command after `--`"));
    };
    let mut command = std::process::Command::new(program);
    command.args(args).env_remove(BOOTSTRAP_ENV);
    let status = command.status().map_err(|e| {
        CliError::general(format!(
            "failed to run passthrough command `{program}`: {e}"
        ))
    })?;

    match status.code() {
        Some(0) => Ok(()),
        Some(code) => Err(CliError::CommandExit(code as u8)),
        None => Err(CliError::general(format!(
            "passthrough command `{program}` terminated by signal"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::setup_state::{SetupConfig, SetupScope, project_setup_path, write_config};
    use tempfile::tempdir;

    #[test]
    fn project_setup_makes_guard_active() {
        let dir = tempdir().unwrap();
        let config = SetupConfig::new(
            SetupScope::Project,
            vec!["codex".to_string()],
            Some(".fida/integrations/guard.sh".to_string()),
            None,
        );
        write_config(&project_setup_path(dir.path()), &config, false).unwrap();

        assert!(effective_setup_active(dir.path()).unwrap());
    }

    #[test]
    fn bootstrap_env_values_are_recognized() {
        assert!(bootstrap_value_enabled(Some("1")));
        assert!(bootstrap_value_enabled(Some("true")));
        assert!(bootstrap_value_enabled(Some("yes")));
        assert!(!bootstrap_value_enabled(Some("no")));
        assert!(!bootstrap_value_enabled(None));
    }
}
