//! Argument parsing and the subcommand dispatch table.
//!
//! [`Cli`] is the clap entry point. Global options are defined once in
//! [`GlobalArgs`] and marked `global = true` so they may appear before or after
//! the subcommand. [`dispatch`] routes a parsed [`Command`] to the owning
//! module's handler (see [`crate::commands`]).
//!
//! The `--quiet` + `--verbose` conflict is **not** expressed with clap's
//! `conflicts_with` (which would exit with clap's own code); instead it is
//! validated in [`GlobalArgs::resolve`] so it maps to the CLI's exit code 1.

use clap::{Args, Parser, Subcommand};

use crate::commands;
use crate::context::{GlobalContext, Verbosity};
use crate::error::{CliError, CliResult};

/// `fida` — a local-first secret leak prevention CLI for AI coding agents.
#[derive(Debug, Parser)]
#[command(
    name = "fida",
    version,
    about = "Prevent secret values from reaching AI coding agents",
    long_about = None
)]
pub struct Cli {
    #[command(flatten)]
    pub globals: GlobalArgs,

    /// Flags for the bare `fida` install/update flow (used when no subcommand
    /// is given).
    #[command(flatten)]
    pub root: commands::root::RootArgs,

    #[command(subcommand)]
    pub command: Option<Command>,
}

/// Global options available on every subcommand.
#[derive(Debug, Args)]
pub struct GlobalArgs {
    /// Print machine-readable JSON for the primary result.
    #[arg(long, global = true)]
    pub json: bool,

    /// Compatibility option for the legacy policy engine.
    #[arg(long, value_name = "PATH", global = true, hide = true)]
    pub config: Option<std::path::PathBuf>,

    /// Disable ANSI color escape sequences.
    #[arg(long, global = true)]
    pub no_color: bool,

    /// Suppress non-essential output.
    #[arg(long, global = true)]
    pub quiet: bool,

    /// Include additional diagnostic detail.
    #[arg(long, global = true)]
    pub verbose: bool,
}

impl GlobalArgs {
    /// Validate and resolve the global options into a [`GlobalContext`].
    ///
    /// Returns a usage error (exit 1) when both `--quiet` and `--verbose` are
    /// supplied.
    pub fn resolve(self) -> CliResult<GlobalContext> {
        let verbosity = match (self.quiet, self.verbose) {
            (true, true) => {
                return Err(CliError::usage(
                    "`--quiet` and `--verbose` cannot be used together",
                ));
            }
            (true, false) => Verbosity::Quiet,
            (false, true) => Verbosity::Verbose,
            (false, false) => Verbosity::Normal,
        };
        Ok(GlobalContext {
            json: self.json,
            no_color: self.no_color,
            verbosity,
            config: self.config,
        })
    }
}

/// The top-level subcommand dispatch table. Each variant's argument struct and
/// handler live in the owning module under [`crate::commands`].
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Protect one agent or every detected agent.
    On(commands::toggle::OnArgs),
    /// Remove Fida protection from one agent or all of them.
    Off(commands::toggle::OffArgs),
    /// Show current secret-protection status.
    Status(commands::status::StatusArgs),
    /// Find secrets and report whether raw values can reach a model.
    Scan(commands::scan::ScanArgs),
    /// Remove Fida and all of its files.
    Uninstall(commands::uninstall::UninstallArgs),
    /// Setup-aware command wrapper for hooks and shims.
    #[command(hide = true)]
    Guard(commands::guard::GuardArgs),
    /// PreToolUse gate for Claude Code / Codex command hooks.
    #[command(hide = true)]
    Hook(commands::hook::HookArgs),
    /// Run one shell command through policy.
    #[command(hide = true)]
    Exec(commands::exec::ExecArgs),
    /// Inspect and proxy MCP servers.
    #[command(hide = true)]
    Mcp(commands::mcp::McpArgs),
}

/// Route a parsed command to its handler. A bare `fida` (no subcommand) runs the
/// install/update flow; `root` carries that flow's flags.
pub async fn dispatch(
    command: Option<Command>,
    root: &commands::root::RootArgs,
    ctx: &GlobalContext,
) -> CliResult {
    match command {
        None => commands::root::run(root, ctx).await,
        Some(Command::On(args)) => commands::toggle::on(&args, ctx).await,
        Some(Command::Off(args)) => commands::toggle::off(&args, ctx).await,
        Some(Command::Status(args)) => commands::status::run(&args, ctx).await,
        Some(Command::Scan(args)) => commands::scan::run(&args, ctx).await,
        Some(Command::Uninstall(args)) => commands::uninstall::run(&args, ctx).await,
        Some(Command::Guard(args)) => commands::guard::run(&args, ctx).await,
        Some(Command::Hook(args)) => commands::hook::run(&args, ctx).await,
        Some(Command::Exec(args)) => commands::exec::run(&args, ctx).await,
        Some(Command::Mcp(args)) => commands::mcp::run(&args, ctx).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn clap_definition_is_valid() {
        // Catches overlapping args, bad subcommand wiring, etc. at test time.
        Cli::command().debug_assert();
    }

    #[test]
    fn quiet_and_verbose_together_is_a_usage_error() {
        let cli = Cli::try_parse_from(["fida", "--quiet", "--verbose", "status"])
            .expect("clap should parse; the conflict is a runtime usage check");
        let err = cli
            .globals
            .resolve()
            .expect_err("must reject quiet+verbose");
        assert!(matches!(err, CliError::Usage(_)));
        assert_eq!(err.exit_code(), 1);
    }

    #[test]
    fn quiet_alone_resolves_to_quiet() {
        let cli = Cli::try_parse_from(["fida", "--quiet", "status"]).unwrap();
        let ctx = cli.globals.resolve().unwrap();
        assert!(ctx.is_quiet());
        assert!(!ctx.is_verbose());
    }

    #[test]
    fn verbose_alone_resolves_to_verbose() {
        let cli = Cli::try_parse_from(["fida", "--verbose", "status"]).unwrap();
        let ctx = cli.globals.resolve().unwrap();
        assert!(ctx.is_verbose());
        assert!(!ctx.is_quiet());
    }

    #[test]
    fn global_options_parse_after_subcommand() {
        let cli = Cli::try_parse_from(["fida", "status", "--json", "--no-color"]).unwrap();
        assert!(cli.globals.json);
        assert!(cli.globals.no_color);
    }

    #[test]
    fn config_path_is_captured() {
        let cli = Cli::try_parse_from(["fida", "--config", "/tmp/p.yaml", "status"]).unwrap();
        assert_eq!(
            cli.globals.config.as_deref(),
            Some(std::path::Path::new("/tmp/p.yaml"))
        );
    }

    #[test]
    fn unrecognized_command_is_a_parse_error() {
        let err = Cli::try_parse_from(["fida", "frobnicate"]).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::InvalidSubcommand);
    }

    #[test]
    fn unrecognized_option_is_a_parse_error() {
        let err = Cli::try_parse_from(["fida", "status", "--nope"]).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument);
    }

    #[test]
    fn bare_invocation_runs_the_root_flow() {
        // No subcommand is valid now: bare `fida` drives the install/update
        // flow, so it parses to `command: None` rather than erroring.
        let cli = Cli::try_parse_from(["fida"]).expect("bare fida parses");
        assert!(cli.command.is_none());
    }

    #[test]
    fn on_and_off_are_top_level_commands() {
        let on = Cli::try_parse_from(["fida", "on", "codex"]).unwrap();
        match on.command {
            Some(Command::On(args)) => assert_eq!(args.agents, ["codex"]),
            _ => panic!("on should parse as its own command"),
        }
        let off = Cli::try_parse_from(["fida", "off"]).unwrap();
        assert!(matches!(off.command, Some(Command::Off(_))));
    }

    #[test]
    fn primary_help_hides_advanced_commands_but_they_still_parse() {
        let help = Cli::command().render_help().to_string();
        for visible in ["off", "scan", "status"] {
            assert!(help.contains(visible), "{visible} should be visible");
        }
        for hidden in ["exec", "guard", "hook", "mcp"] {
            assert!(
                !help
                    .lines()
                    .any(|line| line.trim_start().starts_with(hidden)),
                "{hidden} should be hidden from primary help"
            );
        }
        assert!(Cli::try_parse_from(["fida", "exec", "--", "true"]).is_ok());
        assert!(Cli::try_parse_from(["fida", "mcp", "serve"]).is_ok());
    }
}
