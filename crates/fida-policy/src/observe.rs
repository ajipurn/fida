//! Smart Policy Generator support — the observation store and the
//! suggested-policy builder behind `fida observe` / `fida policy suggest`
//! (R10, lower priority; design "Smart Policy Generator").
//!
//! This module is pure data + logic: it records categorized observed actions to
//! a store under `.fida` and builds an allowlist [`PolicyFile`] from them. It
//! never decides policy at runtime — it only proposes one. The CLI owns running
//! the agent, presenting the diff, and writing the suggested policy.

use std::collections::BTreeMap;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use fida_action::Decision;
use serde::{Deserialize, Serialize};

use crate::AuditSection;
use crate::schema::{
    CommandMatcher, CommandRule, CommandSection, FileSection, McpSection, NetRule,
    NetTargetMatcher, NetworkSection, PathRules, PolicyFile, SecretSection,
};

/// The store file name within `.fida`.
pub const OBSERVATIONS_FILE: &str = "observations.yaml";

/// Sensitive-file glob entries always denied in a suggested policy (R10.5).
pub const SENSITIVE_FILE_GLOBS: &[&str] = &[
    ".env",
    ".env.*",
    "**/*.pem",
    "**/*.key",
    "**/id_rsa",
    "**/id_ed25519",
];

/// One of the exactly-one categories an observed action falls into (R10.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservedCategory {
    FileAccess,
    NetworkAccess,
    PackageInstall,
    GitOperation,
}

/// A single recorded observation: its category plus a redaction-safe detail
/// (a path, host, or command string — never secret material).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Observation {
    pub category: ObservedCategory,
    pub detail: String,
}

/// The persisted set of observed actions.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ObservationStore {
    #[serde(default)]
    observations: Vec<Observation>,
}

impl ObservationStore {
    /// Every recorded observation, in insertion order.
    pub fn observations(&self) -> &[Observation] {
        &self.observations
    }

    /// Whether the store holds no observations.
    pub fn is_empty(&self) -> bool {
        self.observations.is_empty()
    }

    /// Record an observation, de-duplicating exact `(category, detail)` repeats.
    /// Returns `true` when a new observation was added.
    pub fn record(&mut self, category: ObservedCategory, detail: impl Into<String>) -> bool {
        let detail = detail.into();
        if self
            .observations
            .iter()
            .any(|o| o.category == category && o.detail == detail)
        {
            return false;
        }
        self.observations.push(Observation { category, detail });
        true
    }
}

/// The observation store path for `repo`: `<repo>/.fida/observations.yaml`.
pub fn observation_store_path(repo: &Path) -> PathBuf {
    repo.join(".fida").join(OBSERVATIONS_FILE)
}

/// Load the store at `path`. A missing or unparseable file yields an empty store
/// (never errors), mirroring the corruption-tolerant registry read.
pub fn load_store(path: &Path) -> ObservationStore {
    match std::fs::read_to_string(path) {
        Ok(raw) => serde_yaml::from_str(&raw).unwrap_or_default(),
        Err(_) => ObservationStore::default(),
    }
}

/// Save the store atomically: write a sibling temp file, fsync, then rename over
/// the target so an interrupted write leaves prior contents intact (R10.2).
pub fn save_store(path: &Path, store: &ObservationStore) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let yaml =
        serde_yaml::to_string(store).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let tmp = path.with_extension("yaml.fida-tmp");
    let write = (|| -> io::Result<()> {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(yaml.as_bytes())?;
        f.sync_all()?;
        Ok(())
    })();
    if let Err(e) = write {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(())
}

/// Classify a command's argv as a package installation or a git operation, or
/// `None` when it is neither (R10.1). Git is checked first so `git push` is a
/// git operation, not a package install.
pub fn classify_command(argv: &[String]) -> Option<ObservedCategory> {
    let first = argv.first()?.as_str();
    let second = argv.get(1).map(|s| s.as_str());

    if first == "git" {
        return Some(ObservedCategory::GitOperation);
    }

    let is_install = matches!(
        (first, second),
        (
            "npm",
            Some("install") | Some("i") | Some("add") | Some("ci")
        ) | ("pnpm", Some("install") | Some("i") | Some("add"))
            | ("yarn", Some("add") | Some("install"))
            | ("pip" | "pip3", Some("install"))
            | ("cargo", Some("install") | Some("add"))
            | ("go", Some("install") | Some("get"))
            | ("gem", Some("install"))
            | ("bundle", Some("install"))
            | ("apt" | "apt-get" | "brew", Some("install"))
    );
    if is_install {
        Some(ObservedCategory::PackageInstall)
    } else {
        None
    }
}

/// Build an allowlist [`PolicyFile`] from the observation store, or `None` when
/// there are no observations (R10.4).
///
/// The allow rules correspond exactly to the recorded observed actions (no
/// allow rule for an unobserved action, R10.3); the policy always adds a deny
/// rule for every sensitive-file entry (R10.5) and ask rules for network
/// access, package installation, and git push (R10.6).
pub fn suggest_policy(store: &ObservationStore) -> Option<PolicyFile> {
    if store.is_empty() {
        return None;
    }

    let mut read_allow: Vec<String> = Vec::new();
    let mut cmd_allow: Vec<CommandRule> = Vec::new();
    let mut net_allow: Vec<NetRule> = Vec::new();

    for obs in store.observations() {
        match obs.category {
            ObservedCategory::FileAccess => {
                if !read_allow.contains(&obs.detail) {
                    read_allow.push(obs.detail.clone());
                }
            }
            ObservedCategory::NetworkAccess => {
                let target = if obs.detail.chars().any(|c| c.is_ascii_alphabetic()) {
                    NetTargetMatcher::Domain(obs.detail.clone())
                } else {
                    NetTargetMatcher::Host(obs.detail.clone())
                };
                let rule = NetRule {
                    target,
                    reason: None,
                };
                if !net_allow.contains(&rule) {
                    net_allow.push(rule);
                }
            }
            ObservedCategory::PackageInstall | ObservedCategory::GitOperation => {
                let matcher = CommandMatcher::Exact(obs.detail.clone());
                if !cmd_allow.iter().any(|r| r.matcher == matcher) {
                    cmd_allow.push(CommandRule {
                        matcher,
                        working_dir: None,
                        reason: None,
                        auto_approve: false,
                    });
                }
            }
        }
    }

    // Mandatory ask rules (R10.6), regardless of observation.
    let cmd_ask = vec![
        ask_command("git push", "git push sends local changes to a remote"),
        ask_command("npm install", "package installs can run lifecycle scripts"),
        ask_command("pnpm install", "package installs can run lifecycle scripts"),
        ask_command("yarn add", "package installs can run lifecycle scripts"),
        ask_command("pip install", "package installs can run lifecycle scripts"),
    ];
    let net_ask = vec![NetRule {
        target: NetTargetMatcher::Domain("*".to_string()),
        reason: Some("arbitrary network access can transmit code or local data".to_string()),
    }];

    // Sensitive files remain writable only through an explicit policy change.
    // Reads are not denied by name: gateway reads redact their content, while
    // the default-deny fallback still protects unobserved paths.
    let sensitive: Vec<String> = SENSITIVE_FILE_GLOBS.iter().map(|s| s.to_string()).collect();

    Some(PolicyFile {
        version: 1,
        default_decision: Decision::Deny,
        profiles: BTreeMap::new(),
        commands: CommandSection {
            allow: cmd_allow,
            ask: cmd_ask,
            deny: Vec::new(),
        },
        files: FileSection {
            read: PathRules {
                allow: read_allow,
                ask: Vec::new(),
                deny: Vec::new(),
            },
            write: PathRules {
                allow: Vec::new(),
                ask: Vec::new(),
                deny: sensitive,
            },
        },
        network: NetworkSection {
            allow: net_allow,
            ask: net_ask,
            deny: Vec::new(),
        },
        mcp: McpSection::default(),
        secrets: SecretSection::default(),
        audit: AuditSection::default(),
        hard_denies_disabled: false,
        agents: Vec::new(),
    })
}

/// Build a prefix `ask` command rule with a reason.
fn ask_command(prefix: &str, reason: &str) -> CommandRule {
    CommandRule {
        matcher: CommandMatcher::Prefix(prefix.to_string()),
        working_dir: None,
        reason: Some(reason.to_string()),
        auto_approve: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn classify_command_detects_git_and_installs() {
        assert_eq!(
            classify_command(&argv(&["git", "push"])),
            Some(ObservedCategory::GitOperation)
        );
        assert_eq!(
            classify_command(&argv(&["git", "status"])),
            Some(ObservedCategory::GitOperation)
        );
        assert_eq!(
            classify_command(&argv(&["pnpm", "install"])),
            Some(ObservedCategory::PackageInstall)
        );
        assert_eq!(
            classify_command(&argv(&["pip", "install", "requests"])),
            Some(ObservedCategory::PackageInstall)
        );
        assert_eq!(classify_command(&argv(&["ls", "-la"])), None);
        assert_eq!(classify_command(&[]), None);
    }

    #[test]
    fn store_dedups_and_persists() {
        let dir = tempfile::tempdir().unwrap();
        let path = observation_store_path(dir.path());
        let mut store = ObservationStore::default();
        assert!(store.record(ObservedCategory::FileAccess, "src/main.rs"));
        assert!(!store.record(ObservedCategory::FileAccess, "src/main.rs")); // dup
        assert!(store.record(ObservedCategory::GitOperation, "git status"));
        save_store(&path, &store).unwrap();

        let loaded = load_store(&path);
        assert_eq!(loaded.observations().len(), 2);
    }

    #[test]
    fn empty_store_yields_no_policy() {
        assert!(suggest_policy(&ObservationStore::default()).is_none());
    }

    #[test]
    fn suggested_policy_allows_observed_and_adds_mandatory_rules() {
        let mut store = ObservationStore::default();
        store.record(ObservedCategory::FileAccess, "src/app.ts");
        store.record(ObservedCategory::GitOperation, "git status");
        store.record(ObservedCategory::NetworkAccess, "github.com");

        let policy = suggest_policy(&store).expect("policy");
        // Allow rules correspond exactly to observed actions.
        assert!(policy.files.read.allow.contains(&"src/app.ts".to_string()));
        assert!(
            policy
                .commands
                .allow
                .iter()
                .any(|r| r.matcher == CommandMatcher::Exact("git status".to_string()))
        );
        assert!(
            policy
                .network
                .allow
                .iter()
                .any(|r| r.target == NetTargetMatcher::Domain("github.com".to_string()))
        );
        // No allow rule for an unobserved action.
        assert!(!policy.files.read.allow.contains(&"secret.txt".to_string()));

        // Sensitive-file writes are denied; reads rely on least-privilege
        // defaults plus redaction when explicitly observed/allowed.
        for glob in SENSITIVE_FILE_GLOBS {
            assert!(policy.files.write.deny.contains(&glob.to_string()));
        }
        // Mandatory ask for network, package install, and git push.
        assert!(
            policy
                .network
                .ask
                .iter()
                .any(|r| r.target == NetTargetMatcher::Domain("*".to_string()))
        );
        assert!(
            policy
                .commands
                .ask
                .iter()
                .any(|r| r.matcher == CommandMatcher::Prefix("git push".to_string()))
        );
        assert!(
            policy
                .commands
                .ask
                .iter()
                .any(|r| matches!(&r.matcher, CommandMatcher::Prefix(p) if p.contains("install")))
        );

        // The suggested policy serializes to valid YAML.
        let yaml = serde_yaml::to_string(&policy).unwrap();
        assert!(crate::validate_raw(&yaml).is_ok());
    }
}
