//! `fida uninstall` — remove Fida completely.
//!
//! Steps, in order:
//!
//! 1. Scan `$HOME` (plus the current repo, which may live outside `$HOME`) for
//!    project `.fida` directories. This is read-only so the confirmation prompt
//!    can name exactly how many folders will be deleted before the user agrees.
//! 2. Unwire every agent and drop the shared artifacts — this is exactly what
//!    `fida off` (no args) already does (adapters, shims, guard hook, global
//!    `config.yaml`, and the shell-rc blocks), so we reuse it rather than
//!    re-deriving the cleanup here.
//! 3. Delete each project `.fida` directory wholesale (policy.yaml, sessions,
//!    integrations). `off` strips per-agent wiring but leaves the `.fida` dir,
//!    so this is the step that clears the orphan files in every repo.
//! 4. Remove the global config directory itself (`~/.config/fida`, or whatever
//!    `FIDA_HOME` / `XDG_CONFIG_HOME` resolve to).
//! 5. Delete the running binary. On macOS/Linux unlinking a running executable
//!    is safe — the current process finishes normally.
//!
//! What this *cannot* undo: the PATH/install-dir edits that `install.sh` may
//! have made, and any repo that lives outside `$HOME` and isn't the cwd. We
//! print a hint for both instead of silently editing more dotfiles or walking
//! the whole filesystem.

use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::io::{self, IsTerminal};
use std::path::{Path, PathBuf};

use clap::Args;
use dialoguer::Confirm;
use dialoguer::theme::{ColorfulTheme, SimpleTheme};

use crate::commands::integrations::current_fida_bin;
use crate::commands::setup_state::global_setup_path;
use crate::commands::shell_hook;
use crate::commands::toggle::{self, OffArgs};
use crate::context::{GlobalContext, Verbosity};
use crate::error::{CliError, CliResult};

/// Heavy directory names we never wire into — skipped to keep the scan quick.
const PRUNE_DIRS: &[&str] = &[
    "node_modules",
    "target",
    "Library",
    ".git",
    ".cache",
    ".cargo",
    ".rustup",
    ".npm",
    ".pnpm-store",
    ".Trash",
    "Trash",
];

#[derive(Debug, Args)]
pub struct UninstallArgs {
    /// Skip the confirmation prompt. Required when stdin is not a terminal.
    #[arg(long)]
    pub yes: bool,
}

pub async fn run(args: &UninstallArgs, ctx: &GlobalContext) -> CliResult {
    // 1. Read-only scan first, so the prompt can name how many `.fida` folders
    //    will be deleted. remove_dir_all can't be undone — show before asking.
    let project_dirs = scan_project_fida_dirs();

    if !args.yes && !ctx.json {
        let interactive = io::stdin().is_terminal() && io::stdout().is_terminal();
        if !interactive {
            return Err(CliError::usage(
                "uninstall needs confirmation; re-run `fida uninstall --yes`",
            ));
        }
        if !project_dirs.is_empty() && !ctx.is_quiet() {
            println!(
                "Found {} project .fida folder(s) that will be deleted:",
                project_dirs.len()
            );
            for dir in &project_dirs {
                println!("  - {}", dir.display());
            }
        }
        let prompt = if project_dirs.is_empty() {
            "Remove Fida and all of its files?".to_string()
        } else {
            format!(
                "Remove Fida, its global config, and {} project .fida folder(s)?",
                project_dirs.len()
            )
        };
        if !confirm(&prompt, ctx.no_color)? {
            if !ctx.is_quiet() {
                println!("Nothing changed.");
            }
            return Ok(());
        }
    }

    // 2. Unwire every agent + shared artifacts. Reuse `off` quietly so its
    //    "still protected"/"set up again" report doesn't leak into uninstall.
    let mut quiet = ctx.clone();
    quiet.json = false;
    quiet.verbosity = Verbosity::Quiet;
    toggle::off(&OffArgs { agents: Vec::new() }, &quiet).await?;

    // 3. Delete each project `.fida` wholesale — the orphan cleanup `off` skips.
    let mut removed_dirs = Vec::new();
    for dir in &project_dirs {
        if std::fs::remove_dir_all(dir).is_ok() {
            removed_dirs.push(dir.clone());
        }
    }

    // 4. Remove the global config directory (parent of config.yaml).
    let config_path = global_setup_path()?;
    let config_dir = config_path.parent().map(|p| p.to_path_buf());
    if let Some(dir) = &config_dir {
        let _ = std::fs::remove_dir_all(dir);
    }

    // 5. Remove the binary itself (safe to unlink while running on Unix).
    let bin = current_fida_bin()?;
    let bin_removed = std::fs::remove_file(&bin).is_ok();

    emit(config_dir.as_deref(), &removed_dirs, &bin, bin_removed, ctx)
}

/// Find every project `.fida` directory under `$HOME`, plus the current repo's
/// (it may live outside `$HOME`, so the home walk misses it). Canonical,
/// de-duplicated.
fn scan_project_fida_dirs() -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    if let Ok(home) = shell_hook::home_dir() {
        candidates.extend(walk_for_fida(&home));
    }
    if let Ok(cwd) = std::env::current_dir() {
        let here = cwd.join(".fida");
        if is_fida_project_dir(&here) {
            candidates.push(here);
        }
    }

    // De-dupe by canonical path (the cwd may already sit under $HOME).
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for dir in candidates {
        let key = dir.canonicalize().unwrap_or_else(|_| dir.clone());
        if seen.insert(key) {
            out.push(dir);
        }
    }
    out
}

/// Walk `root` (lstat-only, so symlinks are never followed) collecting
/// directories named `.fida` that hold a Fida marker. Never descends into a
/// matched `.fida`.
//
// ponytail: naive single-threaded full walk with a prune list. Fine for a
// one-shot uninstall; bound the depth or parallelize if it ever drags.
fn walk_for_fida(root: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(ft) = entry.file_type() else {
                continue;
            };
            if !ft.is_dir() {
                continue;
            }
            let name = entry.file_name();
            let path = entry.path();
            if name == OsStr::new(".fida") {
                if is_fida_project_dir(&path) {
                    found.push(path);
                }
                continue; // never descend into a .fida dir
            }
            if PRUNE_DIRS.iter().any(|p| name == OsStr::new(p)) {
                continue;
            }
            stack.push(path);
        }
    }
    found
}

/// A `.fida` is a Fida *project* dir (vs. some unrelated folder) only if it
/// holds one of Fida's own artifacts — guards against deleting a stray `.fida`.
fn is_fida_project_dir(dir: &Path) -> bool {
    dir.join("integrations").exists()
        || dir.join("policy.yaml").exists()
        || dir.join("sessions").exists()
}

fn emit(
    config_dir: Option<&std::path::Path>,
    removed_dirs: &[PathBuf],
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
                "project_fida_removed": removed_dirs,
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
    if !removed_dirs.is_empty() {
        println!(
            "  - removed {} project .fida folder(s):",
            removed_dirs.len()
        );
        for dir in removed_dirs {
            println!("      {}", dir.display());
        }
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
    // The scan reaches everything under $HOME plus the cwd. A repo parked
    // elsewhere is the one case left — name it instead of pretending it's gone.
    println!(
        "Scanned $HOME (and this repo) for project .fida folders. A repo outside $HOME \
         won't have been reached — delete its `.fida` directory manually."
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn walk_finds_marked_fida_skips_pruned_and_stray() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();

        // A real project .fida (has a marker).
        let real = root.join("proj/.fida");
        std::fs::create_dir_all(real.join("integrations")).unwrap();

        // A .fida inside a pruned dir — must be skipped.
        let pruned = root.join("node_modules/pkg/.fida");
        std::fs::create_dir_all(pruned.join("integrations")).unwrap();

        // A stray .fida with no Fida marker — must not match.
        std::fs::create_dir_all(root.join("other/.fida/random")).unwrap();

        let found = walk_for_fida(root);
        assert_eq!(found.len(), 1, "found: {found:?}");
        assert_eq!(found[0], real);
    }

    #[test]
    fn is_fida_project_dir_requires_a_marker() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join(".fida");
        std::fs::create_dir_all(&dir).unwrap();
        assert!(!is_fida_project_dir(&dir));
        std::fs::write(dir.join("policy.yaml"), "{}").unwrap();
        assert!(is_fida_project_dir(&dir));
    }
}
