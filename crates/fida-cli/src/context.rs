//! Resolved global options, threaded into every command handler.
//!
//! Built once in `main` from the parsed [`crate::cli::GlobalArgs`] after the
//! `--quiet` + `--verbose` conflict check. Command modules
//! (owned by tasks 19.2–19.10) read this to honor `--json`, `--no-color`,
//! `--quiet`, `--verbose`, and the `--config` policy-path override.

use std::path::PathBuf;

/// Output verbosity, derived from `--quiet` / `--verbose` (mutually exclusive).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verbosity {
    /// `--quiet`: suppress non-essential output.
    Quiet,
    /// Default verbosity.
    Normal,
    /// `--verbose`: include extra diagnostic detail.
    Verbose,
}

/// Immutable, resolved view of the global options for the running command.
///
/// Fields/methods are read by the per-command handlers added in tasks
/// 19.2–19.10; they form the scaffold's stable surface now.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct GlobalContext {
    /// Emit machine-readable JSON for the primary result.
    pub json: bool,
    /// Suppress ANSI color escapes on stdout and stderr.
    pub no_color: bool,
    /// Resolved output verbosity.
    pub verbosity: Verbosity,
    /// Explicit policy path from `--config`, overriding default resolution
    pub config: Option<PathBuf>,
}

impl GlobalContext {
    /// `true` when `--quiet` was supplied.
    #[allow(dead_code)]
    pub fn is_quiet(&self) -> bool {
        self.verbosity == Verbosity::Quiet
    }

    /// `true` when `--verbose` was supplied.
    #[allow(dead_code)]
    pub fn is_verbose(&self) -> bool {
        self.verbosity == Verbosity::Verbose
    }
}
