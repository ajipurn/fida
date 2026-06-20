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

    #[command(subcommand)]
    pub command: Command,
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
    /// Install, verify, and scan secret protection for your agents.
    Init(commands::init::InitArgs),
    /// Remove Fida integrations and setup metadata.
    Uninstall(commands::uninstall::UninstallArgs),
    /// Show current secret-protection status.
    Status(commands::status::StatusArgs),
    /// Setup-aware command wrapper for hooks and shims.
    #[command(hide = true)]
    Guard(commands::guard::GuardArgs),
    /// PreToolUse gate for Claude Code / Codex command hooks.
    #[command(hide = true)]
    Hook(commands::hook::HookArgs),
    /// Run one shell command through policy.
    #[command(hide = true)]
    Exec(commands::exec::ExecArgs),
    /// Read audit events.
    Audit(commands::audit::AuditArgs),
    /// Inspect and proxy MCP servers.
    #[command(hide = true)]
    Mcp(commands::mcp::McpArgs),
    /// Check secret-protection setup.
    Doctor(commands::doctor::DoctorArgs),
    /// Find secrets and report whether raw values can reach a model.
    Scan(commands::scan::ScanArgs),
}

/// Route a parsed command to its handler. This is the single dispatch seam the
/// per-command tasks (19.2–19.10) plug into.
pub async fn dispatch(command: Command, ctx: &GlobalContext) -> CliResult {
    match command {
        Command::Init(args) => commands::init::run(&args, ctx).await,
        Command::Uninstall(args) => commands::uninstall::run(&args, ctx).await,
        Command::Status(args) => commands::status::run(&args, ctx).await,
        Command::Guard(args) => commands::guard::run(&args, ctx).await,
        Command::Hook(args) => commands::hook::run(&args, ctx).await,
        Command::Exec(args) => commands::exec::run(&args, ctx).await,
        Command::Audit(args) => commands::audit::run(&args, ctx).await,
        Command::Mcp(args) => commands::mcp::run(&args, ctx).await,
        Command::Doctor(args) => commands::doctor::run(&args, ctx).await,
        Command::Scan(args) => commands::scan::run(&args, ctx).await,
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
        let cli = Cli::try_parse_from(["fida", "--quiet", "--verbose", "doctor"])
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
        let cli = Cli::try_parse_from(["fida", "--quiet", "doctor"]).unwrap();
        let ctx = cli.globals.resolve().unwrap();
        assert!(ctx.is_quiet());
        assert!(!ctx.is_verbose());
    }

    #[test]
    fn verbose_alone_resolves_to_verbose() {
        let cli = Cli::try_parse_from(["fida", "--verbose", "doctor"]).unwrap();
        let ctx = cli.globals.resolve().unwrap();
        assert!(ctx.is_verbose());
        assert!(!ctx.is_quiet());
    }

    #[test]
    fn global_options_parse_after_subcommand() {
        let cli = Cli::try_parse_from(["fida", "doctor", "--json", "--no-color"]).unwrap();
        assert!(cli.globals.json);
        assert!(cli.globals.no_color);
    }

    #[test]
    fn config_path_is_captured() {
        let cli = Cli::try_parse_from(["fida", "--config", "/tmp/p.yaml", "doctor"]).unwrap();
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
        let err = Cli::try_parse_from(["fida", "doctor", "--nope"]).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument);
    }

    #[test]
    fn bare_invocation_is_not_treated_as_help_or_version() {
        // No subcommand → a usage error (exit 1), distinct from explicit
        // `--help`/`--version` (exit 0).
        let err = Cli::try_parse_from(["fida"]).unwrap_err();
        let kind = err.kind();
        assert_ne!(kind, clap::error::ErrorKind::DisplayHelp);
        assert_ne!(kind, clap::error::ErrorKind::DisplayVersion);
    }

    #[test]
    fn uninstall_is_a_top_level_command() {
        let cli = Cli::try_parse_from(["fida", "uninstall", "--project"]).unwrap();
        match cli.command {
            Command::Uninstall(args) => assert!(args.project),
            _ => panic!("uninstall should parse as its own command"),
        }
    }

    #[test]
    fn primary_help_hides_advanced_commands_but_they_still_parse() {
        let help = Cli::command().render_help().to_string();
        for visible in ["init", "scan", "status", "doctor", "audit", "uninstall"] {
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
