//! `fida observe -- <agent>` — run an agent and record its observed actions to
//! an observation store for later policy suggestion (R10.1, R10.2).
//!
//! The agent runs through the normal session pipeline in observe mode (nothing
//! is blocked and no changes are applied), then the session's audit events are
//! categorized — file access, network access, package installation, or git
//! operation — and recorded to `.fida/observations.yaml`. A save is atomic, so
//! a failed write leaves the prior observations intact (R10.2).

use std::path::Path;

use clap::Args;
use fida_audit::{AuditAction, AuditStore, JsonlAuditStore};
use fida_policy::{
    ObservedCategory, classify_command, load_store, observation_store_path, save_store,
};

use crate::commands::run::{RunArgs, run as run_agent};
use crate::context::GlobalContext;
use crate::error::{CliError, CliResult};

/// Arguments for `fida observe`.
#[derive(Debug, Args)]
pub struct ObserveArgs {
    /// Policy profile to use while observing.
    #[arg(long)]
    pub profile: Option<String>,

    /// The agent command and its arguments, after `--`.
    #[arg(last = true, required = true)]
    pub command: Vec<String>,
}

/// Run `fida observe`.
pub async fn run(args: &ObserveArgs, ctx: &GlobalContext) -> CliResult {
    let repo = std::env::current_dir()
        .map_err(|e| CliError::general(format!("cannot determine current directory: {e}")))?;

    // Run the agent in observe mode, never applying changes.
    let run_args = RunArgs {
        profile: args.profile.clone(),
        mode: Some("observe".to_string()),
        workspace: None,
        apply: Some("never".to_string()),
        report: None,
        non_interactive: true,
        command: args.command.clone(),
    };
    // Run regardless of agent exit; harvest whatever the session recorded.
    let run_result = run_agent(&run_args, ctx).await;

    let recorded = harvest_latest(&repo, ctx)?;
    if !ctx.is_quiet() && !ctx.json {
        println!(
            "Recorded {recorded} observation(s) to {}",
            observation_store_path(&repo).display()
        );
    }

    // Surface a non-zero agent exit after harvesting so observations are kept.
    run_result
}

/// Categorize the latest session's audit events and record them, returning the
/// number of new observations added.
fn harvest_latest(repo: &Path, _ctx: &GlobalContext) -> CliResult<usize> {
    let session = match fida_session::resolve_session(repo, "latest") {
        Ok(s) => s,
        // No session was created (e.g. the run failed before starting one):
        // nothing to harvest.
        Err(_) => return Ok(0),
    };
    let store = JsonlAuditStore::new(fida_session::sessions_root(repo));
    let events = store
        .read(session.as_str())
        .map_err(|e| CliError::general(format!("failed to read session audit: {e}")))?;

    let path = observation_store_path(repo);
    let mut observations = load_store(&path);
    let mut added = 0usize;
    for event in &events {
        if let Some((category, detail)) = categorize(&event.action) {
            if observations.record(category, detail) {
                added += 1;
            }
        }
    }

    // Atomic save: a failure reports and leaves prior observations unchanged.
    save_store(&path, &observations)
        .map_err(|e| CliError::general(format!("failed to record observations: {e}")))?;
    Ok(added)
}

/// Map a redaction-safe audit action to an observation category + detail, or
/// `None` for actions outside the four categories (R10.1).
fn categorize(action: &AuditAction) -> Option<(ObservedCategory, String)> {
    match action {
        AuditAction::FileRead { path }
        | AuditAction::FileWrite { path }
        | AuditAction::FileDelete { path } => Some((ObservedCategory::FileAccess, path.clone())),
        AuditAction::NetworkRequest { domain, host, .. } => Some((
            ObservedCategory::NetworkAccess,
            domain.clone().unwrap_or_else(|| host.clone()),
        )),
        AuditAction::CommandRun { command } => {
            let argv: Vec<String> = command.split_whitespace().map(String::from).collect();
            classify_command(&argv).map(|category| (category, command.clone()))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn categorize_maps_each_category() {
        assert_eq!(
            categorize(&AuditAction::FileRead {
                path: "src/a.rs".to_string()
            }),
            Some((ObservedCategory::FileAccess, "src/a.rs".to_string()))
        );
        assert_eq!(
            categorize(&AuditAction::NetworkRequest {
                domain: Some("github.com".to_string()),
                host: "140.82.0.1".to_string(),
                protocol: fida_action::Protocol::Https,
            }),
            Some((ObservedCategory::NetworkAccess, "github.com".to_string()))
        );
        assert_eq!(
            categorize(&AuditAction::CommandRun {
                command: "git push origin main".to_string()
            }),
            Some((
                ObservedCategory::GitOperation,
                "git push origin main".to_string()
            ))
        );
        // A non-categorized command yields nothing.
        assert_eq!(
            categorize(&AuditAction::CommandRun {
                command: "ls -la".to_string()
            }),
            None
        );
        assert_eq!(categorize(&AuditAction::SessionApplyChanges), None);
    }
}
