//! `fida` (no subcommand) — install once, then forget it.
//!
//! Bare `fida` is the front door:
//!
//! * **Not installed yet** — detect every supported coding agent that is used
//!   in (or installed for) this machine, confirm, and wire Fida's redacting
//!   gateway + steering + native-read hook for all of them, globally. One self
//!   test proves the redaction path before exiting. There is no repository scan
//!   here: `fida scan` owns that.
//! * **Already installed** — check GitHub Releases for a newer build and, with
//!   the user's consent, re-run the published `install.sh` to replace the
//!   binary in place. Bare `fida` doubles as the updater.
//!
//! Per-agent on/off lives in [`crate::commands::toggle`]; both reuse
//! [`wire_and_report`] so the wire + verify + persist + report path is shared.

use std::io::{self, IsTerminal};
use std::path::Path;
use std::process::{Command, Stdio};

use clap::Args;
use dialoguer::Confirm;
use dialoguer::theme::{ColorfulTheme, SimpleTheme};
use fida_action::ProtectionLevel;

use crate::commands::integrations::{
    self, AgentInstallReport, AgentSpec, Scope, current_fida_bin, detect, known_agents, scope_base,
};
use crate::commands::setup_state::{
    AgentProtection, SetupConfig, SetupScope, VerificationRecord, global_setup_path, read_config,
    upsert_config,
};
use crate::context::GlobalContext;
use crate::error::{CliError, CliResult};

const DEFAULT_REPO: &str = "ajipurn/fida";

#[derive(Debug, Args)]
pub struct RootArgs {
    /// Non-interactive: accept the detected agents (or the available update)
    /// without prompting. Required when stdin is not a terminal.
    #[arg(long)]
    pub yes: bool,
}

pub async fn run(args: &RootArgs, ctx: &GlobalContext) -> CliResult {
    let workspace = std::env::current_dir()
        .map_err(|e| CliError::general(format!("cannot determine current directory: {e}")))?;

    let global_path = global_setup_path()?;
    let already_installed = read_config(&global_path)?.is_some();

    if already_installed {
        update_flow(args, ctx)
    } else {
        install_flow(args, &workspace, ctx)
    }
}

// ---------------------------------------------------------------------------
// Install flow (first run)
// ---------------------------------------------------------------------------

fn install_flow(args: &RootArgs, workspace: &Path, ctx: &GlobalContext) -> CliResult {
    let detected = detect_agents(workspace);

    if detected.is_empty() {
        if ctx.json {
            println!(
                "{}",
                serde_json::json!({ "scope": "global", "installed": [], "verification": null })
            );
        } else if !ctx.is_quiet() {
            wordmark(ctx.no_color);
            println!(
                "  No supported agents detected. Install one, then run `fida` again,\n  or wire a specific agent with `fida on <agent>`."
            );
        }
        return Ok(());
    }

    let interactive =
        !args.yes && !ctx.json && io::stdin().is_terminal() && io::stdout().is_terminal();
    if interactive {
        wordmark(ctx.no_color);
        let names = detected
            .iter()
            .map(|a| a.display)
            .collect::<Vec<_>>()
            .join(", ");
        println!("  Detected: {names}");
        if !confirm(
            &format!("Protect {} agent(s) now?", detected.len()),
            ctx.no_color,
        )? {
            println!("  Nothing changed. Run `fida` again when you're ready.");
            return Ok(());
        }
    } else if !args.yes {
        return Err(CliError::usage(
            "no terminal for the install prompt; re-run `fida --yes` to protect the detected agents",
        ));
    }

    wire_and_report(&detected, workspace, "Fida protection enabled", ctx)
}

pub(crate) fn detect_agents(workspace: &Path) -> Vec<AgentSpec> {
    let path_env = std::env::var_os("PATH");
    let home = crate::commands::shell_hook::home_dir().ok();
    known_agents()
        .into_iter()
        .filter(|a| detect(a, workspace, home.as_deref(), path_env.as_deref()))
        .collect()
}

// ---------------------------------------------------------------------------
// Shared wire + verify + persist + report (used by install and `fida on`)
// ---------------------------------------------------------------------------

/// Wire each agent globally, run the gateway self-test, persist setup metadata,
/// and print the report. Fails closed if the self-test cannot prove redaction.
pub(crate) fn wire_and_report(
    selected: &[AgentSpec],
    workspace: &Path,
    header: &str,
    ctx: &GlobalContext,
) -> CliResult {
    let scope = Scope::Global;
    let base = scope_base(scope, workspace)?;
    let fida_bin = current_fida_bin()?;

    let mut reports = Vec::new();
    for spec in selected {
        reports.push(integrations::install_agent(
            spec, scope, &base, workspace, &fida_bin,
        )?);
    }

    let verification = crate::commands::protection::verify_gateway()?;
    let protection = protection_records(selected, scope, &reports, verification.passed);

    let agent_ids: Vec<String> = selected.iter().map(|s| s.id.to_string()).collect();
    let mut config = SetupConfig::new(SetupScope::Global, agent_ids, None, None);
    config.protection = merge_protection(&global_setup_path()?, protection.clone())?;
    config.verification = Some(VerificationRecord {
        passed: verification.passed,
        checked_at: chrono::Utc::now(),
        detail: verification.detail.clone(),
    });
    upsert_config(&global_setup_path()?, config)?;

    if !verification.passed {
        return Err(CliError::general(format!(
            "secret-protection verification failed: {}",
            verification.detail
        )));
    }

    emit(&reports, &protection, &verification, header, ctx)
}

fn protection_records(
    selected: &[AgentSpec],
    scope: Scope,
    reports: &[AgentInstallReport],
    verified: bool,
) -> Vec<AgentProtection> {
    selected
        .iter()
        .zip(reports)
        .map(|(spec, report)| AgentProtection {
            agent: spec.id.to_string(),
            display: spec.display.to_string(),
            level: integrations::protection_level(spec, scope, report, verified),
            layers: report.layers.iter().map(|l| l.label.to_string()).collect(),
            artifacts: report.layers.iter().map(|l| l.path.clone()).collect(),
        })
        .collect()
}

/// Merge freshly wired agents into any agents already recorded globally so
/// `fida on <one-agent>` does not drop the rest.
fn merge_protection(
    global_path: &Path,
    fresh: Vec<AgentProtection>,
) -> CliResult<Vec<AgentProtection>> {
    let mut merged = match read_config(global_path)? {
        Some(record) => record.config.protection,
        None => Vec::new(),
    };
    for entry in fresh {
        if let Some(existing) = merged.iter_mut().find(|e| e.agent == entry.agent) {
            *existing = entry;
        } else {
            merged.push(entry);
        }
    }
    Ok(merged)
}

fn emit(
    reports: &[AgentInstallReport],
    protection: &[AgentProtection],
    verification: &crate::commands::protection::VerificationResult,
    header: &str,
    ctx: &GlobalContext,
) -> CliResult {
    if ctx.json {
        let installed: Vec<serde_json::Value> = reports
            .iter()
            .map(|r| {
                let layers: Vec<serde_json::Value> = r
                    .layers
                    .iter()
                    .map(|l| serde_json::json!({ "layer": l.label, "path": l.path }))
                    .collect();
                let level = protection
                    .iter()
                    .find(|e| e.agent == r.id)
                    .map(|e| e.level)
                    .unwrap_or(ProtectionLevel::Incomplete);
                serde_json::json!({ "agent": r.id, "layers": layers, "protection": level })
            })
            .collect();
        println!(
            "{}",
            serde_json::json!({
                "scope": "global",
                "installed": installed,
                "verification": { "passed": verification.passed, "detail": verification.detail },
            })
        );
        return Ok(());
    }
    if ctx.is_quiet() {
        return Ok(());
    }

    let ui = Ui::new(ctx.no_color);
    wordmark(ctx.no_color);
    println!("  {} {}", ui.tick(), ui.value(header));
    for r in reports {
        let level = protection
            .iter()
            .find(|e| e.agent == r.id)
            .map(|e| e.level)
            .unwrap_or(ProtectionLevel::Incomplete);
        let layers = r
            .layers
            .iter()
            .map(|l| l.label)
            .collect::<Vec<_>>()
            .join(" + ");
        let layers = if layers.is_empty() {
            "no global integration for this agent".to_string()
        } else {
            layers
        };
        println!(
            "    {} {:<14} [{}]  {}",
            ui.bullet(),
            r.display,
            level.as_str(),
            ui.muted(&layers)
        );
    }
    println!();
    println!(
        "  {} Secret values are redacted before reaching the model.",
        ui.tick()
    );
    println!(
        "  {} Verification: {}",
        ui.tick(),
        if verification.passed {
            "passed"
        } else {
            "failed"
        }
    );
    if protection
        .iter()
        .any(|e| e.level == ProtectionLevel::BestEffort)
    {
        println!(
            "  {} Best-effort agents can bypass the gateway with native tools.",
            ui.warn("!")
        );
    }
    println!();
    println!("  Next: restart your agent, then `fida status`. Run `fida scan` to check this repo.");
    Ok(())
}

// ---------------------------------------------------------------------------
// Update flow (already installed)
// ---------------------------------------------------------------------------

fn update_flow(args: &RootArgs, ctx: &GlobalContext) -> CliResult {
    let current = env!("CARGO_PKG_VERSION");
    let repo = std::env::var("FIDA_REPO").unwrap_or_else(|_| DEFAULT_REPO.to_string());
    let latest = fetch_latest_tag(&repo);
    let update_available = latest
        .as_deref()
        .map(|tag| is_newer(tag, current))
        .unwrap_or(false);

    if ctx.json {
        println!(
            "{}",
            serde_json::json!({
                "current": current,
                "latest": latest,
                "update_available": update_available,
            })
        );
        return Ok(());
    }

    if !update_available {
        if !ctx.is_quiet() {
            wordmark(ctx.no_color);
            match &latest {
                Some(_) => println!("  fida {current} is up to date."),
                None => println!("  fida {current} (could not reach GitHub to check for updates)."),
            }
            println!("  Run `fida status` to see protection coverage.");
        }
        return Ok(());
    }

    let tag = latest.expect("update_available implies a tag");
    if !ctx.is_quiet() {
        wordmark(ctx.no_color);
        println!("  Update available: {current} -> {tag}");
    }

    let interactive = !args.yes && io::stdin().is_terminal() && io::stdout().is_terminal();
    let proceed = if interactive {
        confirm(&format!("Update fida to {tag}?"), ctx.no_color)?
    } else {
        args.yes
    };

    if !proceed {
        if !ctx.is_quiet() {
            println!(
                "  Skipped. Update later with:\n    curl -fsSL https://raw.githubusercontent.com/{repo}/main/install.sh | sh"
            );
        }
        return Ok(());
    }

    run_installer(&repo)
}

/// Fetch the latest release tag from the GitHub API, or `None` on any failure
/// (offline, rate-limited, missing curl/wget). The updater fails soft: a check
/// it cannot complete just means "no update offered", never an error.
fn fetch_latest_tag(repo: &str) -> Option<String> {
    let url = format!("https://api.github.com/repos/{repo}/releases/latest");
    let body = download(&url)?;
    let value: serde_json::Value = serde_json::from_slice(&body).ok()?;
    value.get("tag_name")?.as_str().map(|s| s.to_string())
}

fn download(url: &str) -> Option<Vec<u8>> {
    if let Ok(out) = Command::new("curl").args(["-fsSL", url]).output() {
        if out.status.success() {
            return Some(out.stdout);
        }
    }
    if let Ok(out) = Command::new("wget").args(["-qO-", url]).output() {
        if out.status.success() {
            return Some(out.stdout);
        }
    }
    None
}

/// Re-run the published installer (`curl … install.sh | sh`) so all of the
/// hardened platform-detect + checksum + atomic-replace logic is reused. The
/// new binary replaces ours in place; on Unix the running process is unaffected.
fn run_installer(repo: &str) -> CliResult {
    let script_url = format!("https://raw.githubusercontent.com/{repo}/main/install.sh");
    let status = Command::new("sh")
        .arg("-c")
        .arg(format!("curl -fsSL {script_url} | sh"))
        .env("FIDA_REPO", repo)
        .stdin(Stdio::null())
        .status()
        .map_err(|e| CliError::general(format!("failed to launch installer: {e}")))?;
    if !status.success() {
        return Err(CliError::general(
            "installer exited with an error; update was not applied".to_string(),
        ));
    }
    Ok(())
}

/// Parse `vMAJOR.MINOR.PATCH` (the `v` and any pre-release suffix are optional)
/// into a comparable tuple. Unparseable input yields `None`.
fn parse_version(raw: &str) -> Option<(u64, u64, u64)> {
    let trimmed = raw.trim().trim_start_matches('v');
    let core = trimmed.split(['-', '+']).next().unwrap_or(trimmed);
    let mut parts = core.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next().unwrap_or("0").parse().ok()?;
    let patch = parts.next().unwrap_or("0").parse().ok()?;
    Some((major, minor, patch))
}

fn is_newer(latest: &str, current: &str) -> bool {
    match (parse_version(latest), parse_version(current)) {
        (Some(l), Some(c)) => l > c,
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// UI
// ---------------------------------------------------------------------------

fn confirm(prompt: &str, no_color: bool) -> CliResult<bool> {
    let result = if no_color {
        Confirm::with_theme(&SimpleTheme)
            .with_prompt(prompt)
            .default(true)
            .interact()
    } else {
        Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt(prompt)
            .default(true)
            .interact()
    };
    result.map_err(|e| CliError::general(format!("prompt failed: {e}")))
}

/// A compact two-line wordmark — the old multi-line ASCII logo is gone.
fn wordmark(no_color: bool) {
    let ui = Ui::new(no_color);
    println!();
    println!(
        "  {} {}",
        ui.brand("fida"),
        ui.muted(&format!("v{}", env!("CARGO_PKG_VERSION")))
    );
    println!(
        "  {}",
        ui.muted("local-first secret leak prevention for AI coding agents")
    );
    println!();
}

#[derive(Debug, Clone, Copy)]
struct Ui {
    no_color: bool,
}

impl Ui {
    fn new(no_color: bool) -> Self {
        Self { no_color }
    }
    fn brand(&self, text: &str) -> String {
        self.paint("1;36", text)
    }
    fn value(&self, text: &str) -> String {
        self.paint("1", text)
    }
    fn muted(&self, text: &str) -> String {
        self.paint("2", text)
    }
    fn warn(&self, text: &str) -> String {
        self.paint("33", text)
    }
    fn tick(&self) -> String {
        self.paint("32", "✓")
    }
    fn bullet(&self) -> String {
        self.paint("36", "•")
    }
    fn paint(&self, code: &str, text: &str) -> String {
        if self.no_color {
            text.to_string()
        } else {
            format!("\x1b[{code}m{text}\x1b[0m")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_versions_with_and_without_prefix() {
        assert_eq!(parse_version("v0.1.1"), Some((0, 1, 1)));
        assert_eq!(parse_version("1.2.3"), Some((1, 2, 3)));
        assert_eq!(parse_version("v2.0"), Some((2, 0, 0)));
        assert_eq!(parse_version("v1.4.0-rc.1"), Some((1, 4, 0)));
        assert_eq!(parse_version("nightly"), None);
    }

    #[test]
    fn newer_compares_semver_components() {
        assert!(is_newer("v0.2.0", "0.1.9"));
        assert!(is_newer("v0.1.2", "0.1.1"));
        assert!(!is_newer("v0.1.1", "0.1.1"));
        assert!(!is_newer("v0.1.0", "0.1.1"));
        assert!(!is_newer("garbage", "0.1.1"));
    }
}
