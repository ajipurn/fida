//! `fida uninstall` — remove Fida completely.
//!
//! Three steps, in order:
//!
//! 1. Unwire every agent and drop the shared artifacts — this is exactly what
//!    `fida off` (no args) already does (adapters, shims, guard hook, global
//!    `config.yaml`, and the shell-rc blocks), so we reuse it rather than
//!    re-deriving the cleanup here.
//! 2. Remove the global config directory itself (`~/.config/fida`, or whatever
//!    `FIDA_HOME` / `XDG_CONFIG_HOME` resolve to), clearing anything `off` left
//!    behind plus the now-empty directory.
//! 3. Delete the running binary. On macOS/Linux unlinking a running executable
//!    is safe — the current process finishes normally.
//!
//! What this *cannot* undo: the PATH/install-dir edits that `install.sh` may
//! have made. We print a hint to remove the binary's directory from PATH
//! instead of silently editing more dotfiles.

use std::io::{self, IsTerminal};

use clap::Args;
use dialoguer::Confirm;
use dialoguer::theme::{ColorfulTheme, SimpleTheme};

use crate::commands::integrations::current_fida_bin;
use crate::commands::setup_state::global_setup_path;
use crate::commands::toggle::{self, OffArgs};
use crate::context::{GlobalContext, Verbosity};
use crate::error::{CliError, CliResult};

#[derive(Debug, Args)]
pub struct UninstallArgs {
    /// Skip the confirmation prompt. Required when stdin is not a terminal.
    #[arg(long)]
    pub yes: bool,
}

pub async fn run(args: &UninstallArgs, ctx: &GlobalContext) -> CliResult {
    if !args.yes && !ctx.json {
        let interactive = io::stdin().is_terminal() && io::stdout().is_terminal();
        if !interactive {
            return Err(CliError::usage(
                "uninstall needs confirmation; re-run `fida uninstall --yes`",
            ));
        }
        if !confirm("Remove Fida and all of its files?", ctx.no_color)? {
            if !ctx.is_quiet() {
                println!("Nothing changed.");
            }
            return Ok(());
        }
    }

    // 1. Unwire every agent + shared artifacts. Reuse `off` quietly so its
    //    "still protected"/"set up again" report doesn't leak into uninstall.
    let mut quiet = ctx.clone();
    quiet.json = false;
    quiet.verbosity = Verbosity::Quiet;
    toggle::off(&OffArgs { agents: Vec::new() }, &quiet).await?;

    // 2. Remove the global config directory (parent of config.yaml).
    let config_path = global_setup_path()?;
    let config_dir = config_path.parent().map(|p| p.to_path_buf());
    if let Some(dir) = &config_dir {
        let _ = std::fs::remove_dir_all(dir);
    }

    // 3. Remove the binary itself (safe to unlink while running on Unix).
    let bin = current_fida_bin()?;
    let bin_removed = std::fs::remove_file(&bin).is_ok();

    emit(config_dir.as_deref(), &bin, bin_removed, ctx)
}

fn emit(
    config_dir: Option<&std::path::Path>,
    bin: &std::path::Path,
    bin_removed: bool,
    ctx: &GlobalContext,
) -> CliResult {
    if ctx.json {
        println!(
            "{}",
            serde_json::json!({
                "uninstalled": true,
                "config_dir": config_dir,
                "binary": bin,
                "binary_removed": bin_removed,
            })
        );
        return Ok(());
    }
    if ctx.is_quiet() {
        return Ok(());
    }

    println!("Fida uninstalled.");
    if let Some(dir) = config_dir {
        println!("  - removed config {}", dir.display());
    }
    if bin_removed {
        println!("  - removed binary {}", bin.display());
        if let Some(parent) = bin.parent() {
            println!(
                "If you added {} to your PATH for Fida, you can remove it.",
                parent.display()
            );
        }
    } else {
        println!(
            "  ! could not remove the binary at {}; delete it manually.",
            bin.display()
        );
    }
    // A running editor/agent loaded Fida's MCP + hook wiring at startup and
    // still references the now-deleted binary, so it errors until it reloads
    // config. Tell the user to restart rather than leave them chasing a
    // phantom `fida: command not found`.
    println!(
        "Restart any running editors or agents (Cursor, VS Code, Claude Code, …) so cached \
         Fida MCP/hook references are dropped."
    );
    Ok(())
}

fn confirm(prompt: &str, no_color: bool) -> CliResult<bool> {
    let result = if no_color {
        Confirm::with_theme(&SimpleTheme)
            .with_prompt(prompt)
            .default(false)
            .interact()
    } else {
        Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt(prompt)
            .default(false)
            .interact()
    };
    result.map_err(|e| CliError::general(format!("prompt failed: {e}")))
}
