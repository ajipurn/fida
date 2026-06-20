//! Shared setup-state helpers for `setup`, `unsetup`, and `status`.
//!
//! This is the first durable piece of the setup-once model: Fida can now
//! record whether it should be active for the current project or globally. The
//! actual agent-specific hook installers can build on this metadata without
//! changing the user-facing scope model.

use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use fida_action::ProtectionLevel;
use serde::{Deserialize, Serialize};

use crate::error::{CliError, CliResult};

pub const PROJECT_SETUP_PATH: &str = ".fida/integrations/setup.yaml";
pub const GUARD_HOOK_FILE: &str = "guard.sh";
pub const AGENT_ADAPTER_DIR: &str = "agents";
pub const AGENT_SHIM_DIR: &str = "bin";
pub const DEFAULT_FALLBACK_MODE: &str = "passthrough";
const CONFIG_ENV: &str = "FIDA_HOME";
const XDG_CONFIG_HOME: &str = "XDG_CONFIG_HOME";
const HOME_ENV: &str = "HOME";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SetupScope {
    Project,
    Global,
}

impl SetupScope {
    pub fn label(self) -> &'static str {
        match self {
            SetupScope::Project => "project",
            SetupScope::Global => "global",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupConfig {
    pub version: u8,
    pub scope: SetupScope,
    pub agents: Vec<String>,
    pub fallback: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hook_path: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub adapter_paths: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub shim_paths: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_hint: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub protection: Vec<AgentProtection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification: Option<VerificationRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentProtection {
    pub agent: String,
    pub display: String,
    pub level: ProtectionLevel,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub layers: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub artifacts: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationRecord {
    pub passed: bool,
    pub checked_at: DateTime<Utc>,
    pub detail: String,
}

pub fn effective_protection(entry: &AgentProtection) -> ProtectionLevel {
    if !entry.artifacts.is_empty() && entry.artifacts.iter().any(|path| !Path::new(path).exists()) {
        ProtectionLevel::Incomplete
    } else {
        entry.level
    }
}

impl SetupConfig {
    pub fn new(
        scope: SetupScope,
        agents: Vec<String>,
        hook_path: Option<String>,
        policy_hint: Option<String>,
    ) -> Self {
        let now = Utc::now();
        SetupConfig {
            version: 1,
            scope,
            agents,
            fallback: DEFAULT_FALLBACK_MODE.to_string(),
            created_at: now,
            updated_at: now,
            hook_path,
            adapter_paths: Vec::new(),
            shim_paths: Vec::new(),
            policy_hint,
            protection: Vec::new(),
            verification: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SetupRecord {
    pub path: PathBuf,
    pub config: SetupConfig,
}

pub fn project_setup_path(root: &Path) -> PathBuf {
    root.join(PROJECT_SETUP_PATH)
}

pub fn hook_path_for_setup(setup_path: &Path) -> PathBuf {
    setup_path.with_file_name(GUARD_HOOK_FILE)
}

pub fn adapter_dir_for_setup(setup_path: &Path) -> PathBuf {
    setup_path
        .parent()
        .map(|p| p.join(AGENT_ADAPTER_DIR))
        .unwrap_or_else(|| PathBuf::from(AGENT_ADAPTER_DIR))
}

pub fn adapter_manifest_path(setup_path: &Path, agent: &str) -> PathBuf {
    adapter_dir_for_setup(setup_path).join(format!("{agent}.yaml"))
}

pub fn shim_dir_for_setup(setup_path: &Path) -> PathBuf {
    setup_path
        .parent()
        .map(|p| p.join(AGENT_SHIM_DIR))
        .unwrap_or_else(|| PathBuf::from(AGENT_SHIM_DIR))
}

pub fn shim_path(setup_path: &Path, agent: &str) -> PathBuf {
    shim_dir_for_setup(setup_path).join(agent)
}

pub fn find_project_setup_path(start: &Path) -> Option<PathBuf> {
    for dir in start.ancestors() {
        let candidate = project_setup_path(dir);
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

pub fn read_project_config(start: &Path) -> CliResult<Option<SetupRecord>> {
    match find_project_setup_path(start) {
        Some(path) => read_config(&path),
        None => Ok(None),
    }
}

pub fn global_setup_path() -> CliResult<PathBuf> {
    if let Some(root) = std::env::var_os(CONFIG_ENV) {
        return Ok(PathBuf::from(root).join("config.yaml"));
    }
    if let Some(root) = std::env::var_os(XDG_CONFIG_HOME) {
        return Ok(PathBuf::from(root).join("fida/config.yaml"));
    }
    if let Some(home) = std::env::var_os(HOME_ENV) {
        return Ok(PathBuf::from(home).join(".config/fida/config.yaml"));
    }
    Err(CliError::general(
        "cannot resolve global setup path: set FIDA_HOME or HOME",
    ))
}
pub fn write_config(path: &Path, config: &SetupConfig, force: bool) -> CliResult {
    if path.exists() && !force {
        return Err(CliError::general(format!(
            "setup already exists at {}; pass --force to overwrite it",
            path.display()
        )));
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            CliError::general(format!(
                "failed to create setup directory {}: {e}",
                parent.display()
            ))
        })?;
    }
    let raw = serde_yaml::to_string(config)
        .map_err(|e| CliError::general(format!("failed to serialize setup config: {e}")))?;
    std::fs::write(path, raw).map_err(|e| {
        CliError::general(format!(
            "failed to write setup config to {}: {e}",
            path.display()
        ))
    })
}

/// Write `config` to `path`, overwriting any existing record in place.
///
/// Unlike [`write_config`], this never errors on an existing file: it is the
/// idempotent path used by `fida onboard`, which can be re-run safely. The
/// original `created_at` timestamp is preserved when a prior record exists.
pub fn upsert_config(path: &Path, mut config: SetupConfig) -> CliResult<SetupConfig> {
    if let Ok(Some(existing)) = read_config(path) {
        config.created_at = existing.config.created_at;
    }
    config.updated_at = Utc::now();
    write_config(path, &config, true)?;
    Ok(config)
}
pub fn remove_agent_adapters(setup_path: &Path, agents: &[String]) -> CliResult<Vec<PathBuf>> {
    let mut removed = Vec::new();
    for agent in agents {
        let path = adapter_manifest_path(setup_path, agent);
        if path.exists() {
            std::fs::remove_file(&path).map_err(|e| {
                CliError::general(format!(
                    "failed to remove adapter manifest {}: {e}",
                    path.display()
                ))
            })?;
            removed.push(path);
        }
    }
    let dir = adapter_dir_for_setup(setup_path);
    let _ = std::fs::remove_dir(&dir);
    Ok(removed)
}

pub fn remove_agent_shims(setup_path: &Path, agents: &[String]) -> CliResult<Vec<PathBuf>> {
    let mut removed = Vec::new();
    for agent in agents {
        let path = shim_path(setup_path, agent);
        if path.exists() {
            std::fs::remove_file(&path).map_err(|e| {
                CliError::general(format!(
                    "failed to remove agent shim {}: {e}",
                    path.display()
                ))
            })?;
            removed.push(path);
        }
    }
    let dir = shim_dir_for_setup(setup_path);
    let _ = std::fs::remove_dir(&dir);
    Ok(removed)
}

pub fn remove_guard_hook(path: &Path) -> CliResult<bool> {
    if !path.exists() {
        return Ok(false);
    }
    std::fs::remove_file(path).map_err(|e| {
        CliError::general(format!(
            "failed to remove guard hook {}: {e}",
            path.display()
        ))
    })?;
    Ok(true)
}
pub fn read_config(path: &Path) -> CliResult<Option<SetupRecord>> {
    if !path.exists() {
        return Ok(None);
    }
    let raw = std::fs::read_to_string(path).map_err(|e| {
        CliError::general(format!(
            "failed to read setup config {}: {e}",
            path.display()
        ))
    })?;
    let config: SetupConfig = serde_yaml::from_str(&raw).map_err(|e| {
        CliError::general(format!(
            "failed to parse setup config {}: {e}",
            path.display()
        ))
    })?;
    Ok(Some(SetupRecord {
        path: path.to_path_buf(),
        config,
    }))
}

pub fn remove_config(path: &Path) -> CliResult<bool> {
    if !path.exists() {
        return Ok(false);
    }
    std::fs::remove_file(path).map_err(|e| {
        CliError::general(format!(
            "failed to remove setup config {}: {e}",
            path.display()
        ))
    })?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_recorded_artifact_downgrades_protection() {
        let dir = tempfile::tempdir().unwrap();
        let artifact = dir.path().join("hook.json");
        std::fs::write(&artifact, "{}").unwrap();
        let entry = AgentProtection {
            agent: "codex".to_string(),
            display: "Codex".to_string(),
            level: ProtectionLevel::Enforced,
            layers: vec!["hook".to_string()],
            artifacts: vec![artifact.display().to_string()],
        };
        assert_eq!(effective_protection(&entry), ProtectionLevel::Enforced);
        std::fs::remove_file(artifact).unwrap();
        assert_eq!(effective_protection(&entry), ProtectionLevel::Incomplete);
    }

    #[test]
    fn legacy_entry_without_artifact_paths_keeps_recorded_level() {
        let entry = AgentProtection {
            agent: "cursor".to_string(),
            display: "Cursor".to_string(),
            level: ProtectionLevel::BestEffort,
            layers: Vec::new(),
            artifacts: Vec::new(),
        };
        assert_eq!(effective_protection(&entry), ProtectionLevel::BestEffort);
    }
}
