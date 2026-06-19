//! `fida init` — one interactive step to guard any supported agent.
//!
//! Detects which AI coding agents are used in (or installed for) the workspace,
//! shows a checklist so the user picks which ones to guard, then writes each
//! agent's integration layers (gateway MCP server, skill, hook). No further
//! setup is required beyond reconnecting MCP servers in the agent.
//!
//! The selection is interactive only when stdin/stdout are a terminal. For
//! scripts and CI it is fully driven by flags: `--agents`, `--all`, or `--yes`
//! (accept the detected set). `fida install` remains a hidden compatibility
//! alias for this flow. The checklist uses `dialoguer` for cross-platform
//! raw-mode navigation while the surrounding copy stays small and testable.

use std::io::{self, IsTerminal};
use std::path::PathBuf;

use clap::Args;
use dialoguer::MultiSelect;
use dialoguer::theme::{ColorfulTheme, SimpleTheme};
use fida_action::ProtectionLevel;

use crate::commands::integrations::{
    self, AgentInstallReport, AgentSpec, Scope, current_fida_bin, detect, known_agents, scope_base,
};
use crate::commands::setup_state::{
    self, AgentProtection, SetupConfig, SetupScope, VerificationRecord, policy_hint_for,
    project_setup_path,
};
use crate::context::GlobalContext;
use crate::error::{CliError, CliResult};

const FIDA_LOGO: &[&str] = &[
    r#"                                                                                                                   
                       +++++++++++               
                    ++++++++++++++++             
                  ++++++++++++++++++++           
              ++++++++++++++  ++++++++           
           +++++++++++++++++++  +++++++++        
          +++++++++++++ ++++++++++++++++++++     
          ++++++++++++++++++++++++++++   ++++    
          ++++  ++++++++++++++++++++++    +++    
        +++++++++++++++++++++++++++++      ++    
       ++++++++++++++++++++++++++++  ++++++      
        +++++++++++++++++++++++++   +++++++      
        ++++++++++++++++++++++++++    ++++ +     
         ++++++++++++++++++ +++++++        +     
        ++++++++++++++++++++++++++++        +    
      +++++++++++++++++++++++++++++++    ++++    
      ++++++++++++++++++++++++++++++++  +++      
      +++++++++++++++++++++++++++++++   +++      
      +++++++++++++++++++++++++++++++++  +       
       +++++++++++++++++++++++++++++++++++       
          +++++++++++++++++++++++    +++         
            ++++++++++++++++++++                 
            ++++++++++++++++++++                 
             +++++++++++++++++++                 
           ++++++++++++++++++++++++++++++        
      ++++++++++++++++++++++++ +++++++++++++                               
                                                                                                    
"#,
];

#[derive(Debug, Args)]
pub struct InstallArgs {
    /// Workspace root for project scope / detection. Defaults to the current
    /// directory.
    #[arg(long)]
    pub workspace: Option<PathBuf>,

    /// Initialize per-project (inside the repo) instead of globally for the user.
    #[arg(long)]
    pub project: bool,

    /// Initialize these agents (comma-separated ids), skipping the checklist.
    #[arg(long = "agents", value_delimiter = ',')]
    pub agents: Vec<String>,

    /// Initialize every supported agent.
    #[arg(long, conflicts_with = "agents")]
    pub all: bool,

    /// Non-interactive: accept the auto-detected agents without prompting.
    #[arg(long)]
    pub yes: bool,

    /// Remove Fida's integration for the selected agents instead of adding it.
    #[arg(long)]
    pub uninstall: bool,
}

pub async fn run(args: &InstallArgs, ctx: &GlobalContext) -> CliResult {
    let workspace = match &args.workspace {
        Some(dir) => dir.clone(),
        None => std::env::current_dir()
            .map_err(|e| CliError::general(format!("cannot determine current directory: {e}")))?,
    };
    let scope = if args.project {
        Scope::Project
    } else {
        Scope::Global
    };
    let base = scope_base(scope, &workspace)?;

    let agents = known_agents();
    let path_env = std::env::var_os("PATH");
    let home = crate::commands::shell_hook::home_dir().ok();
    let detected: Vec<bool> = agents
        .iter()
        .map(|a| detect(a, &workspace, home.as_deref(), path_env.as_deref()))
        .collect();

    let selected = select_agents(args, &agents, &detected, &workspace, scope, ctx)?;
    if selected.is_empty() {
        if !ctx.is_quiet() && !ctx.json {
            println!("No agents selected; nothing to do.");
        }
        return Ok(());
    }

    if args.uninstall {
        return run_uninstall(&selected, scope, &base, ctx);
    }
    run_install(&selected, scope, &base, &workspace, ctx)
}

/// Resolve which agents to act on from flags or the interactive checklist.
fn select_agents(
    args: &InstallArgs,
    agents: &[AgentSpec],
    detected: &[bool],
    workspace: &std::path::Path,
    scope: Scope,
    ctx: &GlobalContext,
) -> CliResult<Vec<AgentSpec>> {
    // Explicit list wins and is validated against the registry.
    if !args.agents.is_empty() {
        return resolve_ids(&args.agents, agents);
    }
    if args.all {
        return Ok(agents.to_vec());
    }

    let interactive = !args.yes && io::stdin().is_terminal() && io::stdout().is_terminal();
    if interactive {
        emit_select_intro(agents, detected, workspace, scope, ctx.no_color);
        let picks = multiselect(agents, detected, args.uninstall, ctx.no_color)?;
        return Ok(picks.into_iter().map(|i| agents[i].clone()).collect());
    }

    // Non-interactive without flags: fall back to the detected set.
    let chosen: Vec<AgentSpec> = agents
        .iter()
        .zip(detected)
        .filter(|&(_, &d)| d)
        .map(|(a, _)| a.clone())
        .collect();
    if chosen.is_empty() && !ctx.json {
        return Err(CliError::usage(format!(
            "no agents detected; choose explicitly with --agents <{}> or --all",
            known_ids(agents).join(",")
        )));
    }
    Ok(chosen)
}

/// Map explicit ids to specs, erroring on any unknown id.
fn resolve_ids(ids: &[String], agents: &[AgentSpec]) -> CliResult<Vec<AgentSpec>> {
    let mut out = Vec::new();
    for id in ids {
        let id = id.trim();
        match agents.iter().find(|a| a.id == id) {
            Some(spec) => {
                if !out.iter().any(|s: &AgentSpec| s.id == spec.id) {
                    out.push(spec.clone());
                }
            }
            None => {
                return Err(CliError::usage(format!(
                    "unknown agent `{id}`; supported: {}",
                    known_ids(agents).join(", ")
                )));
            }
        }
    }
    Ok(out)
}

fn known_ids(agents: &[AgentSpec]) -> Vec<&'static str> {
    agents.iter().map(|a| a.id).collect()
}

/// Interactive arrow-key multi-select (space toggles, enter confirms).
///
/// Detected agents start checked. Returns the selected indices into `agents`.
/// Cross-platform raw-mode handling comes from `dialoguer`.
fn multiselect(
    agents: &[AgentSpec],
    detected: &[bool],
    uninstall: bool,
    no_color: bool,
) -> CliResult<Vec<usize>> {
    let labels = agent_labels(agents, detected, no_color);
    let prompt = if uninstall {
        "Agents to remove"
    } else {
        "Agents to initialize"
    };

    let result = if no_color {
        let theme = SimpleTheme;
        MultiSelect::with_theme(&theme)
            .with_prompt(prompt)
            .items(&labels)
            .defaults(detected)
            .report(false)
            .interact()
    } else {
        let theme = ColorfulTheme::default();
        MultiSelect::with_theme(&theme)
            .with_prompt(prompt)
            .items(&labels)
            .defaults(detected)
            .report(false)
            .interact()
    };
    result.map_err(|e| CliError::general(format!("agent selection failed: {e}")))
}

fn emit_select_intro(
    agents: &[AgentSpec],
    detected: &[bool],
    workspace: &std::path::Path,
    scope: Scope,
    no_color: bool,
) {
    let ui = InstallUi::new(no_color);
    for (i, line) in FIDA_LOGO.iter().enumerate() {
        println!("{}", ui.logo(line, i));
    }
    println!(
        "  {}",
        ui.title(&format!("Fida {}", env!("CARGO_PKG_VERSION")))
    );
    println!(
        "  {}",
        ui.muted("Local-first secret leak prevention for AI coding agents.")
    );
    println!(
        "  {}",
        ui.accent("Choose integrations. Keep the policy local.")
    );
    println!();
    println!("  {} {}", ui.key("Scope     "), ui.value(scope.label()));
    println!("  {} {}", ui.key("Workspace "), workspace.display());
    println!(
        "  {} {}",
        ui.key("Detected  "),
        detected_summary(agents, detected)
    );
    println!();
    println!(
        "  {}",
        ui.muted("Use ↑/↓ to move · Space to toggle · Enter to continue")
    );
}

fn agent_labels(agents: &[AgentSpec], detected: &[bool], no_color: bool) -> Vec<String> {
    let ui = InstallUi::new(no_color);
    let width = agents
        .iter()
        .map(|agent| char_width(agent.display))
        .max()
        .unwrap_or(0);

    agents
        .iter()
        .zip(detected)
        .map(|(agent, &is_detected)| {
            let status = if is_detected {
                ui.ok("detected")
            } else {
                ui.warn("manual")
            };
            format!("{}  {status}", pad_agent(agent.display, width))
        })
        .collect()
}

fn detected_summary(agents: &[AgentSpec], detected: &[bool]) -> String {
    let names: Vec<&str> = agents
        .iter()
        .zip(detected)
        .filter(|&(_, &is_detected)| is_detected)
        .map(|(agent, _)| compact_agent_name(agent))
        .collect();

    match names.len() {
        0 => "none auto-detected".to_string(),
        n if n == agents.len() => format!("all {n} supported agents"),
        n => format!("{n} of {} ({})", agents.len(), names.join(", ")),
    }
}

fn compact_agent_name(agent: &AgentSpec) -> &'static str {
    agent.display
}

fn pad_agent(label: &str, width: usize) -> String {
    let pad = width.saturating_sub(char_width(label));
    format!("{label}{}", " ".repeat(pad))
}

fn char_width(value: &str) -> usize {
    value.chars().count()
}

fn run_install(
    selected: &[AgentSpec],
    scope: Scope,
    base: &std::path::Path,
    workspace: &std::path::Path,
    ctx: &GlobalContext,
) -> CliResult {
    let fida_bin = current_fida_bin()?;
    let mut reports = Vec::new();
    for spec in selected {
        reports.push(integrations::install_agent(
            spec, scope, base, workspace, &fida_bin,
        )?);
    }

    let verification = crate::commands::protection::verify_gateway()?;
    let protection: Vec<AgentProtection> = selected
        .iter()
        .zip(&reports)
        .map(|(spec, report)| AgentProtection {
            agent: spec.id.to_string(),
            display: spec.display.to_string(),
            level: integrations::protection_level(spec, scope, report, verification.passed),
            layers: report
                .layers
                .iter()
                .map(|layer| layer.label.to_string())
                .collect(),
            artifacts: report
                .layers
                .iter()
                .map(|layer| layer.path.clone())
                .collect(),
        })
        .collect();

    // Record setup metadata so `fida status` reports "active".
    let setup_scope = match scope {
        Scope::Project => SetupScope::Project,
        Scope::Global => SetupScope::Global,
    };
    let agent_ids: Vec<String> = selected.iter().map(|s| s.id.to_string()).collect();
    let setup_path = match scope {
        Scope::Project => project_setup_path(workspace),
        Scope::Global => setup_state::global_setup_path()?,
    };
    let policy_hint = match scope {
        Scope::Project => Some(policy_hint_for(workspace)),
        Scope::Global => None,
    };
    let mut config = SetupConfig::new(setup_scope, agent_ids, None, policy_hint);
    config.protection = protection.clone();
    config.verification = Some(VerificationRecord {
        passed: verification.passed,
        checked_at: chrono::Utc::now(),
        detail: verification.detail.clone(),
    });
    setup_state::upsert_config(&setup_path, config)?;

    if !verification.passed {
        return Err(CliError::general(format!(
            "secret-protection verification failed: {}",
            verification.detail
        )));
    }

    let scan_args = crate::commands::scan::ScanArgs {
        path: Some(workspace.to_path_buf()),
        fail_on: None,
        include_ignored: false,
        exclude: Vec::new(),
        mcp: false,
        agents: false,
    };
    let scan = crate::commands::scan::scan_root(workspace, &scan_args, ctx)?;

    emit_install(&reports, &protection, &verification, &scan, scope, ctx)
}

fn run_uninstall(
    selected: &[AgentSpec],
    scope: Scope,
    base: &std::path::Path,
    ctx: &GlobalContext,
) -> CliResult {
    let mut removed = Vec::new();
    for spec in selected {
        removed.push(integrations::uninstall_agent(spec, scope, base)?);
    }
    if ctx.json {
        let items: Vec<serde_json::Value> = removed
            .iter()
            .map(|r| serde_json::json!({ "agent": r.id, "removed": r.removed }))
            .collect();
        println!("{}", serde_json::json!({ "uninstalled": items }));
        return Ok(());
    }
    if ctx.is_quiet() {
        return Ok(());
    }
    let ui = InstallUi::new(ctx.no_color);
    println!(
        "{}",
        ui.title(&format!("Fida uninstall ({})", scope.label()))
    );
    for r in &removed {
        let what = if r.removed.is_empty() {
            "nothing present".to_string()
        } else {
            r.removed.join(", ")
        };
        println!(
            "  {} {} {}",
            ui.tick(),
            ui.value(r.display),
            ui.muted(&what)
        );
    }
    Ok(())
}

fn emit_install(
    reports: &[AgentInstallReport],
    protection: &[AgentProtection],
    verification: &crate::commands::protection::VerificationResult,
    scan: &fida_scan::ScanResult,
    scope: Scope,
    ctx: &GlobalContext,
) -> CliResult {
    if ctx.json {
        let items: Vec<serde_json::Value> = reports
            .iter()
            .map(|r| {
                let layers: Vec<serde_json::Value> = r
                    .layers
                    .iter()
                    .map(|l| serde_json::json!({ "layer": l.label, "path": l.path }))
                    .collect();
                let level = protection
                    .iter()
                    .find(|entry| entry.agent == r.id)
                    .map(|entry| entry.level)
                    .unwrap_or(ProtectionLevel::Incomplete);
                serde_json::json!({
                    "agent": r.id,
                    "layers": layers,
                    "protection": level,
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::json!({
                "scope": scope.label(),
                "installed": items,
                "verification": {
                    "passed": verification.passed,
                    "detail": verification.detail,
                },
                "scan": {
                    "risk": scan.risk,
                    "raw_secret_exposure": scan.raw_secret_exposure,
                    "sensitive_files": scan.findings.len(),
                    "hardcoded_secrets": scan.content_findings.len(),
                }
            })
        );
        return Ok(());
    }
    if ctx.is_quiet() {
        return Ok(());
    }

    let ui = InstallUi::new(ctx.no_color);
    println!(
        "{}",
        ui.title(&format!("Fida initialized ({})", scope.label()))
    );
    println!(
        "  {} {} agent(s) protected",
        ui.tick(),
        ui.value(&reports.len().to_string())
    );
    for r in reports {
        let level = protection
            .iter()
            .find(|entry| entry.agent == r.id)
            .map(|entry| entry.level)
            .unwrap_or(ProtectionLevel::Incomplete);
        println!();
        println!(
            "  {} {} [{}]",
            ui.tick(),
            ui.value(r.display),
            level.as_str()
        );
        if r.layers.is_empty() {
            println!(
                "    {}",
                ui.muted(&format!(
                    "no {} integration available for this agent",
                    scope.label()
                ))
            );
        }
        for layer in &r.layers {
            println!(
                "    {:<8} {}",
                format!("{}:", layer.label),
                ui.muted(&layer.path)
            );
        }
    }
    println!();
    let enforced = protection
        .iter()
        .filter(|entry| entry.level == ProtectionLevel::Enforced)
        .count();
    let best_effort = protection
        .iter()
        .filter(|entry| entry.level == ProtectionLevel::BestEffort)
        .count();
    println!("{}", ui.section("Protection"));
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
    println!("  {} Enforced: {enforced}", ui.bullet());
    println!("  {} Best-effort: {best_effort}", ui.bullet());
    if best_effort > 0 {
        println!(
            "  {} Best-effort agents can bypass the gateway with native tools.",
            ui.warn("!")
        );
    }
    println!(
        "  {} Scan: risk={:?}, sensitive_files={}, hardcoded_secrets={}, raw_secret_exposure={}",
        ui.bullet(),
        scan.risk,
        scan.findings.len(),
        scan.content_findings.len(),
        scan.raw_secret_exposure
    );
    println!();
    println!("{}", ui.section("Next"));
    println!("  {} Restart your agent to load the gateway.", ui.bullet());
    Ok(())
}

#[derive(Debug, Clone, Copy)]
struct InstallUi {
    no_color: bool,
}

impl InstallUi {
    fn new(no_color: bool) -> Self {
        Self { no_color }
    }

    fn title(&self, text: &str) -> String {
        self.paint("1;36", text)
    }

    fn logo(&self, text: &str, index: usize) -> String {
        let code = match index % 3 {
            0 => "1;36",
            1 => "1;34",
            _ => "1;35",
        };
        self.paint(code, text)
    }

    fn accent(&self, text: &str) -> String {
        self.paint("35", text)
    }

    fn section(&self, text: &str) -> String {
        self.paint("1", text)
    }

    fn key(&self, text: &str) -> String {
        self.paint("2", text)
    }

    fn value(&self, text: &str) -> String {
        self.paint("1", text)
    }

    fn muted(&self, text: &str) -> String {
        self.paint("2", text)
    }

    fn ok(&self, text: &str) -> String {
        self.paint("32", text)
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

    fn agents() -> Vec<AgentSpec> {
        known_agents()
    }

    #[test]
    fn resolve_ids_rejects_unknown_agent() {
        let a = agents();
        let err = resolve_ids(&["kiro".to_string(), "nope".to_string()], &a).unwrap_err();
        assert_eq!(err.exit_code(), 1);
    }

    #[test]
    fn resolve_ids_dedups() {
        let a = agents();
        let got = resolve_ids(&["kiro".to_string(), "kiro".to_string()], &a).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].id, "kiro");
    }

    #[test]
    fn agent_labels_show_status_without_repeating_prompt_copy() {
        let a = agents();
        // Registry order: codex, claude, antigravity, kiro, cursor, copilot, windsurf, opencode.
        let mut detected = vec![false; a.len()];
        detected[0] = true; // codex detected
        detected[3] = true; // kiro detected
        let labels = agent_labels(&a, &detected, true);

        assert_eq!(labels.len(), a.len());
        assert!(labels[0].contains("Codex") && labels[0].contains("detected"));
        assert!(labels[1].contains("Claude Code") && labels[1].contains("manual"));
        assert!(labels[3].contains("Kiro") && labels[3].contains("detected"));
    }

    #[test]
    fn detected_summary_is_compact() {
        let a = agents();
        let mut detected = vec![false; a.len()];
        detected[0] = true; // Codex
        detected[3] = true; // Kiro
        detected[6] = true; // Windsurf

        assert_eq!(
            detected_summary(&a, &detected),
            format!("3 of {} (Codex, Kiro, Windsurf)", a.len())
        );
    }
}
