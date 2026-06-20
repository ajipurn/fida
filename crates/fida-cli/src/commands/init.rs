//! `fida init` — wire Fida's secret protection into supported agents.
//!
//! `fida init` is the interactive agent setup flow: it detects supported
//! agents, installs the redacting MCP gateway and steering, runs a
//! synthetic-secret self-test, and scans the repository. All the work lives in
//! [`install`]; this module is the thin command seam.

use clap::Args;

use crate::commands::install;
use crate::context::GlobalContext;
use crate::error::CliResult;

/// Arguments for `fida init`.
#[derive(Debug, Args)]
pub struct InitArgs {
    #[command(flatten)]
    pub install: install::InstallArgs,
}

/// Initialize Fida: detect supported agents and wire secret protection.
pub async fn run(args: &InitArgs, ctx: &GlobalContext) -> CliResult {
    install::run(&args.install, ctx).await
}
