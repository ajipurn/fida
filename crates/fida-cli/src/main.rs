//! `fida` — CLI front door.
//!
//! Responsibilities owned by this binary (spec task 19.1):
//!
//! * Parse global options and subcommands ([`cli`]).
//! * Own the Tokio runtime — net/mcp/agent work is async, so a multi-threaded
//!   runtime is built here and the dispatch future is driven to completion.
//! * Map the single typed [`error::CliError`] to the documented process
//!   exit-code table (0-7) and call [`std::process::exit`].
//! * Translate clap parse failures (unrecognized command/option) into a usage
//!   error on stderr with exit code 1, while `--help`/`--version` print to
//!   stdout and exit 0.

mod cli;
mod commands;
mod context;
mod error;

use clap::Parser;

use error::{CliError, EXIT_GENERAL, EXIT_SUCCESS_CODE};

fn main() {
    let code = real_main();
    std::process::exit(i32::from(code));
}

/// Parse, dispatch, and resolve everything to a single exit code.
fn real_main() -> u8 {
    let cli = match cli::Cli::try_parse() {
        Ok(cli) => cli,
        Err(err) => return handle_clap_error(err),
    };

    // Resolve global options (rejects `--quiet` + `--verbose`).
    let ctx = match cli.globals.resolve() {
        Ok(ctx) => ctx,
        Err(err) => return report(err),
    };

    // The CLI owns the async runtime. Only the genuinely concurrent commands
    // (the agent session wrapper and the MCP proxy) need a worker pool; the hot
    // paths — `activate` on every shell startup and `guard`/`exec` on every
    // mediated command — are synchronous and run on a lightweight
    // current-thread runtime, avoiding the per-invocation worker-thread spawn.
    let runtime = match build_runtime(&cli.command) {
        Ok(rt) => rt,
        Err(err) => {
            return report(CliError::general(format!(
                "failed to start async runtime: {err}"
            )));
        }
    };

    match runtime.block_on(cli::dispatch(cli.command, &ctx)) {
        Ok(()) => EXIT_SUCCESS_CODE,
        Err(err) => report(err),
    }
}

/// Build the Tokio runtime sized to the command.
///
/// `run` and `mcp` drive concurrent network IO and keep the multi-threaded
/// runtime; every other command is synchronous and uses a current-thread
/// runtime, which spawns no worker threads. This removes the largest fixed cost
/// on the `activate`/`guard`/`exec` hot paths.
fn build_runtime(command: &cli::Command) -> std::io::Result<tokio::runtime::Runtime> {
    use cli::Command;
    if matches!(command, Command::Run(_) | Command::Mcp(_)) {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
    } else {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
    }
}

/// Print a typed CLI error to stderr and return its exit code.
fn report(err: CliError) -> u8 {
    eprintln!("fida: {err}");
    err.exit_code()
}

/// Map a clap parse failure to an exit code.
///
/// Explicit `--help` / `--version` are not errors: print them to stdout and
/// exit 0. Everything else — unrecognized command/option, missing/required
/// subcommand — is a usage error with exit 1; no command runs.
fn handle_clap_error(err: clap::Error) -> u8 {
    use clap::error::ErrorKind;
    // `err.print` routes help/version to stdout and real errors to stderr.
    let _ = err.print();
    match err.kind() {
        ErrorKind::DisplayHelp | ErrorKind::DisplayVersion => EXIT_SUCCESS_CODE,
        _ => EXIT_GENERAL,
    }
}
