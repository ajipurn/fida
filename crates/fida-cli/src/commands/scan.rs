//! `fida scan` — surface repository secret risk (R2, R3, R8, R13).
//!
//! Resolves the active policy and the set of installed agents, runs the
//! [`fida_scan`] traversal, optionally scans agent MCP configs (`--mcp` /
//! `--agents`, R8), records the project in the global registry (R7.5), and
//! renders a redaction-safe report. A missing/unreadable `--path` exits
//! non-zero before any traversal (R2.12); `--fail-on high` exits non-zero when
//! the assessed risk is high (R2.16).

use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use clap::Args;
use fida_action::ProtectionLevel;
use fida_policy::{load_source, resolve_source_in};
use fida_scan::mcp::{McpAgentSource, McpRead, scan_mcp};
use fida_scan::{AgentRoot, RiskLevel, ScanOptions, render_human, render_json, scan};

use crate::commands::integrations::{self, Scope};
use crate::context::GlobalContext;
use crate::error::{CliError, CliResult};

/// Arguments for `fida scan`.
#[derive(Debug, Args)]
pub struct ScanArgs {
    /// Scan this directory instead of the current directory.
    #[arg(long, value_name = "DIR")]
    pub path: Option<PathBuf>,

    /// Exit non-zero when the assessed risk reaches this level (`high`).
    #[arg(long, value_name = "LEVEL")]
    pub fail_on: Option<String>,

    /// Include git-ignored files in the scan.
    #[arg(long, hide = true)]
    pub include_ignored: bool,

    /// Additional directory name to exclude (repeatable).
    #[arg(long = "exclude", value_name = "DIR")]
    pub exclude: Vec<String>,

    /// Also scan installed agent MCP configs for risky servers.
    #[arg(long, hide = true)]
    pub mcp: bool,

    /// Alias of `--mcp`: scan installed agent MCP configs.
    #[arg(long)]
    pub agents: bool,
}

/// Run `fida scan`. Records the current repository in the registry (R7.5), then
/// scans the target root.
pub async fn run(args: &ScanArgs, ctx: &GlobalContext) -> CliResult {
    let root = args.path.clone().unwrap_or_else(|| PathBuf::from("."));
    run_in(&root, args, ctx)
}

/// The testable core of `fida scan` over an explicit root.
fn run_in(root: &Path, args: &ScanArgs, ctx: &GlobalContext) -> CliResult {
    let result = scan_root(root, args, ctx)?;

    if ctx.json {
        println!("{}", render_json(&result));
    } else if !ctx.is_quiet() {
        print!("{}", render_human(&result));
    }

    // R2.16: `--fail-on high` exits non-zero when the risk is high.
    if let Some(level) = &args.fail_on {
        if level.eq_ignore_ascii_case("high") && result.risk == RiskLevel::High {
            return Err(CliError::general("scan risk is high (--fail-on high)"));
        }
    }
    Ok(())
}

/// Run the redaction-safe scan without rendering or applying `--fail-on`.
/// Onboarding uses this after installing integrations so findings remain
/// informative and never roll back a successful setup.
pub(crate) fn scan_root(
    root: &Path,
    args: &ScanArgs,
    ctx: &GlobalContext,
) -> CliResult<fida_scan::ScanResult> {
    // Resolve + load the policy (built-in default allowed). Loader failures are
    // exit 4 via `From<LoadError>`.
    let source = resolve_source_in(root, ctx.config.as_deref())?;
    let policy = load_source(&source, None)?;

    let agents = detect_agent_roots(root);
    let opts = ScanOptions {
        root: root.to_path_buf(),
        include_ignored: args.include_ignored,
        extra_excludes: args.exclude.clone(),
        max_file_bytes: fida_scan::DEFAULT_MAX_FILE_BYTES,
    };

    // R2.12: a missing/unreadable root errors before any traversal -> exit 1.
    let mut result = scan(&opts, &policy, &agents).map_err(|e| CliError::general(e.to_string()))?;

    if args.mcp || args.agents {
        result.mcp = Some(scan_mcp_configs(root));
    }

    Ok(result)
}

/// Build the readable-root set for the agent-exposure check (R2.6): every
/// detected agent can read the scan root.
fn detect_agent_roots(root: &Path) -> Vec<AgentRoot> {
    let home = integrations::scope_base(Scope::Global, root).ok();
    let path_env = std::env::var_os("PATH");
    let project = crate::commands::setup_state::read_project_config(root)
        .ok()
        .flatten();
    let global = crate::commands::setup_state::global_setup_path()
        .ok()
        .and_then(|path| {
            crate::commands::setup_state::read_config(&path)
                .ok()
                .flatten()
        });
    integrations::known_agents()
        .into_iter()
        .filter(|spec| integrations::detect(spec, root, home.as_deref(), path_env.as_deref()))
        .map(|spec| AgentRoot {
            name: spec.display.to_string(),
            root: root.to_path_buf(),
            protection: recorded_level(spec.id, project.as_ref(), global.as_ref()),
        })
        .collect()
}

fn recorded_level(
    agent: &str,
    project: Option<&crate::commands::setup_state::SetupRecord>,
    global: Option<&crate::commands::setup_state::SetupRecord>,
) -> ProtectionLevel {
    for record in [project, global].into_iter().flatten() {
        if let Some(protection) = record
            .config
            .protection
            .iter()
            .find(|entry| entry.agent == agent)
        {
            return crate::commands::setup_state::effective_protection(protection);
        }
        if record
            .config
            .agents
            .iter()
            .any(|configured| configured == agent)
        {
            return ProtectionLevel::Incomplete;
        }
    }
    ProtectionLevel::Inactive
}

/// Read each installed agent's project- and global-scope MCP config and run the
/// MCP risk classifier (R8). Missing configs are skipped; unreadable ones are
/// recorded as non-fatal errors by [`scan_mcp`].
fn scan_mcp_configs(root: &Path) -> fida_scan::McpRiskReport {
    let home = integrations::scope_base(Scope::Global, root).ok();
    let mut sources = Vec::new();

    for spec in integrations::known_agents() {
        let Some(mcp) = &spec.mcp else {
            continue;
        };
        let bases = [
            (Scope::Project, Some(root.to_path_buf())),
            (Scope::Global, home.clone()),
        ];
        for (scope, base) in bases {
            let (Some(base), Some(rel)) = (base, mcp.path.rel(scope)) else {
                continue;
            };
            let path = base.join(rel);
            let read = match std::fs::read_to_string(&path) {
                Ok(contents) => McpRead::Present(contents),
                Err(e) if e.kind() == ErrorKind::NotFound => McpRead::Missing,
                Err(e) => McpRead::Unreadable(e.to_string()),
            };
            sources.push(McpAgentSource {
                agent: spec.display.to_string(),
                key: mcp.key.to_string(),
                read,
            });
        }
    }

    scan_mcp(&sources)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::Verbosity;

    fn ctx(json: bool) -> GlobalContext {
        GlobalContext {
            json,
            no_color: true,
            verbosity: Verbosity::Quiet,
            config: None,
        }
    }

    fn args() -> ScanArgs {
        ScanArgs {
            path: None,
            fail_on: None,
            include_ignored: false,
            exclude: Vec::new(),
            mcp: false,
            agents: false,
        }
    }

    #[test]
    fn missing_path_exits_one() {
        let mut a = args();
        a.path = Some(PathBuf::from("/no/such/dir/here"));
        let err = run_in(Path::new("/no/such/dir/here"), &a, &ctx(false)).unwrap_err();
        assert_eq!(err.exit_code(), 1);
    }

    #[test]
    fn fail_on_high_exits_one_for_tracked_secret() {
        // A temp git repo with a tracked .env is high risk -> --fail-on high
        // exits 1. Skipped when git is unavailable.
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path();
        let ok = std::process::Command::new("git")
            .arg("init")
            .arg("-q")
            .current_dir(repo)
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !ok {
            return;
        }
        for cfg in [["user.email", "t@e.com"], ["user.name", "t"]] {
            let _ = std::process::Command::new("git")
                .args(["config", cfg[0], cfg[1]])
                .current_dir(repo)
                .status();
        }
        std::fs::write(repo.join(".env"), "API_KEY=secretvalue\n").unwrap();
        let _ = std::process::Command::new("git")
            .args(["add", "-A"])
            .current_dir(repo)
            .status();

        let mut a = args();
        a.fail_on = Some("high".to_string());
        let err = run_in(repo, &a, &ctx(false)).unwrap_err();
        assert_eq!(err.exit_code(), 1);
    }
}
