//! Agent-agnostic integration registry and shared writers.
//!
//! IDE-embedded agents (Kiro, Cursor, Claude Code, Windsurf, …) cannot be
//! guarded through a PATH shim, so Fida wires into each one through up to three
//! layers — a **gateway MCP server**, an always-on **skill/rules file**, and
//! (where supported) a **preToolUse hook**. The layers are identical in intent;
//! only the *file locations and formats* differ per agent and per scope.
//!
//! Each layer is addressed by a [`Located`] pair so the same agent can be wired
//! either per-project (files inside the repo, version-controlled) or globally
//! (files under the user's home, install-once-for-every-repo). Adding an agent
//! is a registry entry, not new code.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use fida_action::ProtectionLevel;
use fida_mcp::{READ_TOOL, SHELL_TOOL};
use serde_json::{Map, Value, json};

use crate::error::{CliError, CliResult};

/// Markers delimiting Fida's region inside a shared file (e.g. `CLAUDE.md`,
/// `AGENTS.md`) so the rest of the file is preserved on install/uninstall.
const BLOCK_BEGIN: &str = "<!-- FIDA:BEGIN (managed by `fida init`) -->";
const LEGACY_BLOCK_BEGIN: &str = "<!-- FIDA:BEGIN (managed by `fida install`) -->";
const BLOCK_END: &str = "<!-- FIDA:END -->";

/// The MCP server key Fida owns inside the server map.
const SERVER_KEY: &str = "fida";

#[cfg(target_os = "macos")]
const VSCODE_USER_MCP_PATH: &str = "Library/Application Support/Code/User/mcp.json";
#[cfg(target_os = "linux")]
const VSCODE_USER_MCP_PATH: &str = ".config/Code/User/mcp.json";
#[cfg(target_os = "windows")]
const VSCODE_USER_MCP_PATH: &str = "AppData/Roaming/Code/User/mcp.json";
#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
const VSCODE_USER_MCP_PATH: &str = ".config/Code/User/mcp.json";

/// Install scope: per-repo or per-user.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// Files inside the repo (version-controlled, per-project policy).
    Project,
    /// Files under the user's home (one install guards every repo).
    Global,
}

/// A layer's location relative to the scope base (repo root or home dir).
/// `None` for a scope means the layer is unavailable there.
#[derive(Debug, Clone, Copy)]
pub struct Located {
    project: Option<&'static str>,
    global: Option<&'static str>,
}

impl Located {
    /// Same relative path in both scopes (e.g. `.kiro/...` → repo or `~/`).
    const fn both(path: &'static str) -> Self {
        Located {
            project: Some(path),
            global: Some(path),
        }
    }
    const fn new(project: Option<&'static str>, global: Option<&'static str>) -> Self {
        Located { project, global }
    }
    fn path(&self, scope: Scope) -> Option<&'static str> {
        match scope {
            Scope::Project => self.project,
            Scope::Global => self.global,
        }
    }
}

impl Located {
    /// The relative path for `scope`, or `None` when this layer is unavailable
    /// there. Public accessor used by `fida scan --mcp` to locate each agent's
    /// MCP config file.
    pub fn rel(&self, scope: Scope) -> Option<&'static str> {
        self.path(scope)
    }
}

/// How an agent's skill/rules file is written.
#[derive(Debug, Clone, Copy)]
pub enum SkillStyle {
    /// A standalone file with a YAML front-matter header (key/value lines).
    Frontmatter(&'static [(&'static str, &'static str)]),
    /// A managed block merged into a possibly-shared Markdown file.
    ManagedBlock,
}

/// Where an agent reads MCP servers, and under which JSON key.
#[derive(Debug, Clone, Copy)]
pub struct McpSpec {
    pub path: Located,
    /// Top-level key holding the server map (`mcpServers` for most agents,
    /// `servers` for VS Code / Copilot).
    pub key: &'static str,
    /// JSON shape of the server entry.
    pub shape: McpShape,
}

/// The JSON shape of a single MCP server entry.
#[derive(Debug, Clone, Copy)]
pub enum McpShape {
    /// `{command, args, disabled, autoApprove}` — Kiro, Cursor, Claude, …
    Standard,
    /// `{type: "local", command: [...], enabled}` — OpenCode.
    OpenCodeLocal,
    /// `{type: "stdio", command, args}` — VS Code / GitHub Copilot.
    VscodeStdio,
}

/// An agent's skill/rules target.
#[derive(Debug, Clone, Copy)]
pub struct SkillSpec {
    pub path: Located,
    pub style: SkillStyle,
    pub global_style: Option<SkillStyle>,
}

impl SkillSpec {
    fn style(self, scope: Scope) -> SkillStyle {
        match scope {
            Scope::Project => self.style,
            Scope::Global => self.global_style.unwrap_or(self.style),
        }
    }
}

/// How an agent's preToolUse hook is wired.
#[derive(Debug, Clone, Copy)]
pub enum HookTarget {
    /// A standalone Kiro `.kiro.hook` JSON file (askAgent backstop).
    KiroFile(Located),
    /// A standalone VS Code / Copilot hook file under `.github/hooks`.
    CommandFile(Located),
    /// A `hooks.PreToolUse` entry merged into a shared settings JSON file,
    /// calling `fida hook` to hard-block denied tool calls (Claude Code, Codex).
    Settings {
        path: Located,
        /// Tool-name matcher regex, e.g. `Read|Edit|Write|Bash`.
        matcher: &'static str,
    },
}

impl HookTarget {
    fn path(&self, scope: Scope) -> Option<&'static str> {
        match self {
            HookTarget::KiroFile(l) => l.path(scope),
            HookTarget::CommandFile(l) => l.path(scope),
            HookTarget::Settings { path, .. } => path.path(scope),
        }
    }
}

/// A single agent's integration surface.
#[derive(Debug, Clone)]
pub struct AgentSpec {
    pub id: &'static str,
    pub display: &'static str,
    pub mcp: Option<McpSpec>,
    pub skill: SkillSpec,
    pub hook: Option<HookTarget>,
    /// Files/dirs (relative to workspace or home) signalling the agent is used.
    pub detect_files: &'static [&'static str],
    /// Binaries on `PATH` signalling the agent is installed.
    pub detect_bins: &'static [&'static str],
    /// macOS app-bundle names (e.g. `Cursor.app`) checked under `/Applications`
    /// and `~/Applications`. ponytail: macOS-only; Linux/Windows rely on the
    /// home config-dir and `PATH` signals, which are already cross-platform.
    pub detect_apps: &'static [&'static str],
}

/// The built-in agent registry. Only conventions Fida is confident about are
/// encoded; an unavailable layer/scope is simply `None`.
pub fn known_agents() -> Vec<AgentSpec> {
    const FM_KIRO: &[(&str, &str)] = &[("inclusion", "always")];
    const FM_CURSOR: &[(&str, &str)] = &[("alwaysApply", "true")];
    const FM_COPILOT: &[(&str, &str)] = &[("applyTo", "\"**\"")];
    vec![
        AgentSpec {
            id: "codex",
            display: "Codex",
            // Codex MCP lives in config.toml (TOML); the hook is the real gate.
            mcp: None,
            skill: SkillSpec {
                path: Located::new(Some("AGENTS.md"), Some(".codex/AGENTS.md")),
                style: SkillStyle::ManagedBlock,
                global_style: None,
            },
            // Codex hooks intercept Bash and apply_patch (its read/edit paths).
            hook: Some(HookTarget::Settings {
                path: Located::both(".codex/hooks.json"),
                matcher: "Bash|apply_patch",
            }),
            detect_files: &[".codex", "AGENTS.md"],
            detect_bins: &["codex"],
            detect_apps: &[],
        },
        AgentSpec {
            id: "claude",
            display: "Claude Code",
            mcp: Some(McpSpec {
                path: Located::new(Some(".mcp.json"), Some(".claude.json")),
                key: "mcpServers",
                shape: McpShape::Standard,
            }),
            skill: SkillSpec {
                path: Located::new(Some("CLAUDE.md"), Some(".claude/CLAUDE.md")),
                style: SkillStyle::ManagedBlock,
                global_style: None,
            },
            // Real hard block: PreToolUse denies policy blocks and native reads
            // whose content contains a detected secret.
            hook: Some(HookTarget::Settings {
                path: Located::both(".claude/settings.json"),
                matcher: "Read|Edit|Write|MultiEdit|Grep|Glob|Bash",
            }),
            detect_files: &[".claude", ".mcp.json", "CLAUDE.md"],
            detect_bins: &["claude"],
            detect_apps: &[],
        },
        AgentSpec {
            id: "antigravity",
            display: "Antigravity",
            mcp: Some(McpSpec {
                // Antigravity (Gemini) MCP config — global only.
                path: Located::new(None, Some(".gemini/config/mcp_config.json")),
                key: "mcpServers",
                shape: McpShape::Standard,
            }),
            skill: SkillSpec {
                // Project: AGENTS.md in the workspace. Global: ~/.gemini/GEMINI.md
                // — the always-on context file the shared Antigravity harness
                // (IDE + CLI) loads for every session. Without a global skill a
                // global `fida init` wired only the gateway, so the agent had
                // `fida_read` available but was never told to use it or to
                // refuse secret files, and fell back to a native read.
                path: Located::new(Some("AGENTS.md"), Some(".gemini/GEMINI.md")),
                style: SkillStyle::ManagedBlock,
                global_style: None,
            },
            hook: None,
            detect_files: &[".gemini", ".antigravity"],
            detect_bins: &["antigravity"],
            detect_apps: &["Antigravity.app"],
        },
        AgentSpec {
            id: "kiro",
            display: "Kiro",
            mcp: Some(McpSpec {
                path: Located::both(".kiro/settings/mcp.json"),
                key: "mcpServers",
                shape: McpShape::Standard,
            }),
            skill: SkillSpec {
                path: Located::both(".kiro/steering/fida.md"),
                style: SkillStyle::Frontmatter(FM_KIRO),
                global_style: None,
            },
            hook: Some(HookTarget::KiroFile(Located::both(
                ".kiro/hooks/fida-guard.kiro.hook",
            ))),
            detect_files: &[".kiro"],
            detect_bins: &["kiro"],
            detect_apps: &["Kiro.app"],
        },
        AgentSpec {
            id: "cursor",
            display: "Cursor",
            mcp: Some(McpSpec {
                path: Located::both(".cursor/mcp.json"),
                key: "mcpServers",
                shape: McpShape::Standard,
            }),
            skill: SkillSpec {
                // Cursor project rules are files; global user rules are not.
                path: Located::new(Some(".cursor/rules/fida.mdc"), None),
                style: SkillStyle::Frontmatter(FM_CURSOR),
                global_style: None,
            },
            hook: None,
            detect_files: &[".cursor"],
            detect_bins: &["cursor", "cursor-agent"],
            detect_apps: &["Cursor.app"],
        },
        AgentSpec {
            id: "copilot",
            display: "GitHub Copilot",
            mcp: Some(McpSpec {
                // VS Code uses the `servers` key and a `{type:stdio}` entry.
                path: Located::new(Some(".vscode/mcp.json"), Some(VSCODE_USER_MCP_PATH)),
                key: "servers",
                shape: McpShape::VscodeStdio,
            }),
            skill: SkillSpec {
                path: Located::new(
                    Some(".github/copilot-instructions.md"),
                    Some(".copilot/instructions/fida.instructions.md"),
                ),
                style: SkillStyle::ManagedBlock,
                global_style: Some(SkillStyle::Frontmatter(FM_COPILOT)),
            },
            hook: Some(HookTarget::CommandFile(Located::new(
                Some(".github/hooks/fida.json"),
                Some(".copilot/hooks/fida.json"),
            ))),
            detect_files: &[".vscode", ".github/copilot-instructions.md", ".copilot"],
            detect_bins: &["code"],
            detect_apps: &["Visual Studio Code.app"],
        },
        AgentSpec {
            id: "windsurf",
            display: "Windsurf",
            mcp: Some(McpSpec {
                // Windsurf reads MCP only from its global config file.
                path: Located::new(None, Some(".codeium/windsurf/mcp_config.json")),
                key: "mcpServers",
                shape: McpShape::Standard,
            }),
            skill: SkillSpec {
                path: Located::new(
                    Some(".windsurf/rules/fida.md"),
                    Some(".codeium/windsurf/memories/global_rules.md"),
                ),
                style: SkillStyle::ManagedBlock,
                global_style: None,
            },
            hook: None,
            detect_files: &[".windsurf", ".codeium"],
            detect_bins: &["windsurf"],
            detect_apps: &["Windsurf.app"],
        },
        AgentSpec {
            id: "opencode",
            display: "OpenCode",
            mcp: Some(McpSpec {
                path: Located::new(
                    Some("opencode.json"),
                    Some(".config/opencode/opencode.json"),
                ),
                key: "mcp",
                shape: McpShape::OpenCodeLocal,
            }),
            skill: SkillSpec {
                path: Located::new(Some("OPENCODE.md"), Some(".config/opencode/OPENCODE.md")),
                style: SkillStyle::ManagedBlock,
                global_style: None,
            },
            hook: None,
            detect_files: &[".opencode", ".config/opencode", "opencode.json"],
            detect_bins: &["opencode"],
            detect_apps: &["OpenCode.app"],
        },
    ]
}

/// Look up an agent spec by its CLI id. Test-only helper.
#[cfg(test)]
pub fn find_agent(id: &str) -> Option<AgentSpec> {
    known_agents().into_iter().find(|a| a.id == id)
}

/// The strength of an agent's preToolUse backstop — the layer that catches a
/// *native* tool call the assertive skill failed to redirect.
///
/// Derived mechanically from the agent's [`HookTarget`] so documentation and
/// `fida status` can never claim a stronger guarantee than the registry wires.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backstop {
    /// A real hard block: the `fida hook` command returns a `deny` decision and
    /// the native tool never executes (Claude Code, Codex).
    HardBlock,
    /// A soft prompt: the hook asks the agent to self-check before proceeding
    /// (Kiro `askAgent`). Relies on the agent obeying.
    SoftPrompt,
    /// No hook; only the gateway tools + the assertive skill apply.
    SkillOnly,
}

/// One row of the agent guard-coverage matrix: which of the three layers an
/// agent supports, plus the strength of its backstop. Test-only.
#[cfg(test)]
#[derive(Debug, Clone)]
pub struct AgentCoverage {
    pub id: &'static str,
    /// Whether a gateway MCP server is wired for this agent in any scope.
    pub gateway: bool,
    /// Whether an always-on skill/rules file is written for this agent.
    pub skill: bool,
    /// The preToolUse backstop strength.
    pub backstop: Backstop,
}

/// The backstop level an agent's hook provides (mechanical: one `match` over
/// its [`HookTarget`]).
pub fn backstop_of(spec: &AgentSpec) -> Backstop {
    match spec.hook {
        Some(HookTarget::Settings { .. } | HookTarget::CommandFile(_)) => Backstop::HardBlock,
        Some(HookTarget::KiroFile(_)) => Backstop::SoftPrompt,
        None => Backstop::SkillOnly,
    }
}

/// The full agent × {gateway, skill, backstop} coverage matrix, derived from
/// the registry. Test-only: it pins the documented backstops so the registry and
/// docs table cannot silently drift.
#[cfg(test)]
pub fn coverage_matrix() -> Vec<AgentCoverage> {
    known_agents()
        .iter()
        .map(|spec| AgentCoverage {
            id: spec.id,
            gateway: spec.mcp.is_some(),
            // Every registered agent has a skill target today; kept explicit so
            // a future skill-less agent shows up correctly in the matrix.
            skill: spec.skill.path.rel(Scope::Project).is_some()
                || spec.skill.path.rel(Scope::Global).is_some(),
            backstop: backstop_of(spec),
        })
        .collect()
}

/// Whether the agent appears to be used here or installed for this user.
///
/// Checks the agent's marker files under the workspace (project signal) and the
/// home directory (global signal — e.g. `~/.cursor`, `~/.claude`), plus its CLI
/// binaries on `PATH`. This is what lets `fida` auto-detect every coding
/// agent actually present on the machine, not just those configured in the repo.
pub fn detect(
    spec: &AgentSpec,
    root: &Path,
    home: Option<&Path>,
    path_env: Option<&OsStr>,
) -> bool {
    let has_marker = |dir: &Path| spec.detect_files.iter().any(|f| dir.join(f).exists());
    if has_marker(root) {
        return true;
    }
    if let Some(h) = home {
        if h != root && has_marker(h) {
            return true;
        }
    }
    if spec.detect_bins.iter().any(|b| binary_on_path(b, path_env)) {
        return true;
    }
    app_installed(spec, home)
}

/// Whether a macOS app bundle for the agent is installed under `/Applications`
/// or `~/Applications`. Returns false on other platforms / when no app names
/// are registered (the path simply won't exist).
fn app_installed(spec: &AgentSpec, home: Option<&Path>) -> bool {
    spec.detect_apps.iter().any(|app| {
        Path::new("/Applications").join(app).exists()
            || home
                .map(|h| h.join("Applications").join(app).exists())
                .unwrap_or(false)
    })
}

fn binary_on_path(bin: &str, path_env: Option<&OsStr>) -> bool {
    let Some(path) = path_env else {
        return false;
    };
    std::env::split_paths(path).any(|dir| dir.join(bin).is_file())
}

/// The scope base directory: the repo root (project) or the user's home
/// (global).
pub fn scope_base(scope: Scope, workspace: &Path) -> CliResult<PathBuf> {
    match scope {
        Scope::Project => Ok(workspace.to_path_buf()),
        Scope::Global => crate::commands::shell_hook::home_dir(),
    }
}

// ---------------------------------------------------------------------------
// Install / uninstall
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct WrittenLayer {
    pub label: &'static str,
    pub path: String,
}

#[derive(Debug, Clone)]
pub struct AgentInstallReport {
    pub id: &'static str,
    pub display: &'static str,
    pub layers: Vec<WrittenLayer>,
}

/// Classify the protection actually written for one agent. Missing expected
/// artifacts are never silently promoted to a stronger level.
pub fn protection_level(
    spec: &AgentSpec,
    scope: Scope,
    report: &AgentInstallReport,
    self_test_passed: bool,
) -> ProtectionLevel {
    let installed = |label: &str| report.layers.iter().any(|layer| layer.label == label);
    let skill_expected = spec.skill.path.path(scope).is_some();
    let gateway_expected = spec
        .mcp
        .as_ref()
        .is_some_and(|m| m.path.path(scope).is_some());
    let hook_expected = spec.hook.as_ref().is_some_and(|h| h.path(scope).is_some());

    if !skill_expected && !gateway_expected && !hook_expected {
        return ProtectionLevel::Inactive;
    }

    if !self_test_passed {
        return ProtectionLevel::Incomplete;
    }

    if (skill_expected && !installed("skill"))
        || (gateway_expected && !installed("gateway"))
        || (hook_expected && !installed("hook"))
    {
        return ProtectionLevel::Incomplete;
    }

    if backstop_of(spec) == Backstop::HardBlock && installed("hook") {
        ProtectionLevel::Enforced
    } else {
        ProtectionLevel::BestEffort
    }
}

/// Install every supported layer for `spec` into `base` for `scope`.
///
/// `workspace` is the repo root the project-scope gateway pins to; the global
/// gateway omits it so the server resolves the workspace (and per-repo policy)
/// from its runtime working directory.
pub fn install_agent(
    spec: &AgentSpec,
    scope: Scope,
    base: &Path,
    workspace: &Path,
    fida_bin: &Path,
) -> CliResult<AgentInstallReport> {
    let mut layers = Vec::new();

    if let Some(mcp) = &spec.mcp {
        if let Some(rel) = mcp.path.path(scope) {
            let path = base.join(rel);
            upsert_mcp_server(&path, mcp.key, mcp.shape, fida_bin, scope, workspace)?;
            layers.push(WrittenLayer {
                label: "gateway",
                path: path.display().to_string(),
            });
        }
    }

    if let Some(rel) = spec.skill.path.path(scope) {
        let path = base.join(rel);
        write_skill(&path, &spec.skill.style(scope))?;
        layers.push(WrittenLayer {
            label: "skill",
            path: path.display().to_string(),
        });
    }

    if let Some(hook) = &spec.hook {
        if let Some(rel) = hook.path(scope) {
            let path = base.join(rel);
            match hook {
                HookTarget::KiroFile(_) => write_file(&path, &kiro_hook_contents())?,
                HookTarget::CommandFile(_) => write_file(&path, &command_hook_contents(fida_bin))?,
                HookTarget::Settings { matcher, .. } => {
                    upsert_settings_hook(&path, matcher, fida_bin)?
                }
            }
            layers.push(WrittenLayer {
                label: "hook",
                path: path.display().to_string(),
            });
        }
    }

    Ok(AgentInstallReport {
        id: spec.id,
        display: spec.display,
        layers,
    })
}

#[derive(Debug, Clone)]
pub struct AgentUninstallReport {
    pub id: &'static str,
    pub display: &'static str,
    pub removed: Vec<&'static str>,
}

/// Remove every layer Fida wrote for `spec` in `scope`, preserving unrelated
/// content in shared files.
pub fn uninstall_agent(
    spec: &AgentSpec,
    scope: Scope,
    base: &Path,
) -> CliResult<AgentUninstallReport> {
    let mut removed = Vec::new();

    if let Some(mcp) = &spec.mcp {
        if let Some(rel) = mcp.path.path(scope) {
            if remove_mcp_server(&base.join(rel), mcp.key)? {
                removed.push("gateway");
            }
        }
    }
    if let Some(rel) = spec.skill.path.path(scope) {
        if remove_skill(&base.join(rel), &spec.skill.style(scope))? {
            removed.push("skill");
        }
    }
    if let Some(hook) = &spec.hook {
        if let Some(rel) = hook.path(scope) {
            let path = base.join(rel);
            let hook_removed = match hook {
                HookTarget::KiroFile(_) | HookTarget::CommandFile(_) => remove_if_present(&path)?,
                HookTarget::Settings { .. } => remove_settings_hook(&path)?,
            };
            if hook_removed {
                removed.push("hook");
            }
        }
    }

    Ok(AgentUninstallReport {
        id: spec.id,
        display: spec.display,
        removed,
    })
}

// ---------------------------------------------------------------------------
// MCP config — merge, never clobber other servers
// ---------------------------------------------------------------------------

fn upsert_mcp_server(
    path: &Path,
    map_key: &str,
    shape: McpShape,
    fida_bin: &Path,
    scope: Scope,
    workspace: &Path,
) -> CliResult {
    let mut root = read_json_object(path)?;
    let servers = root
        .entry(map_key.to_string())
        .or_insert_with(|| Value::Object(Map::new()));
    let servers = servers.as_object_mut().ok_or_else(|| {
        CliError::general(format!(
            "{}: `{map_key}` is not a JSON object",
            path.display()
        ))
    })?;
    servers.insert(
        SERVER_KEY.to_string(),
        fida_server_entry(fida_bin, scope, workspace, shape),
    );
    write_json_object(path, &root)
}

fn remove_mcp_server(path: &Path, map_key: &str) -> CliResult<bool> {
    if !path.exists() {
        return Ok(false);
    }
    let mut root = read_json_object(path)?;
    let removed = root
        .get_mut(map_key)
        .and_then(Value::as_object_mut)
        .map(|servers| servers.remove(SERVER_KEY).is_some())
        .unwrap_or(false);
    if removed {
        write_json_object(path, &root)?;
    }
    Ok(removed)
}

/// Claude Code persists an "always allow" for Fida's MCP tools (e.g.
/// `mcp__fida__fida_read`) into its own `settings.local.json` — a file Fida
/// never writes. After uninstall those permissions dangle, referencing tools
/// that no longer exist, which can break Claude Code on startup. Strip only the
/// `mcp__fida__*` entries from the workspace's Claude settings, leaving the file
/// and every other permission intact. Returns the paths actually changed.
pub fn strip_claude_fida_permissions(workspace: &Path) -> CliResult<Vec<String>> {
    let candidates = [
        workspace.join(".claude/settings.local.json"),
        workspace.join(".claude/settings.json"),
    ];
    let mut changed = Vec::new();
    for path in candidates {
        if strip_fida_permissions(&path)? {
            changed.push(path.display().to_string());
        }
    }
    Ok(changed)
}

/// Remove every `mcp__fida__*` string from the `allow`/`ask`/`deny` lists under
/// `permissions` in a Claude settings file. Returns whether anything changed.
fn strip_fida_permissions(path: &Path) -> CliResult<bool> {
    if !path.exists() {
        return Ok(false);
    }
    let mut root = read_json_object(path)?;
    let Some(perms) = root.get_mut("permissions").and_then(Value::as_object_mut) else {
        return Ok(false);
    };
    let mut changed = false;
    for key in ["allow", "ask", "deny"] {
        if let Some(arr) = perms.get_mut(key).and_then(Value::as_array_mut) {
            let before = arr.len();
            arr.retain(|v| !v.as_str().is_some_and(|s| s.starts_with("mcp__fida__")));
            changed |= arr.len() != before;
        }
    }
    if changed {
        write_json_object(path, &root)?;
    }
    Ok(changed)
}

/// The Fida gateway server definition.
///
/// Project scope pins `--workspace` to the repo. Global scope omits it so
/// `fida mcp serve` resolves the workspace and per-repo policy from its runtime
/// cwd (falling back to Fida's built-in redaction-first policy) — that is what
/// makes one global install guard every repo.
fn fida_server_entry(fida_bin: &Path, scope: Scope, workspace: &Path, shape: McpShape) -> Value {
    let args = match scope {
        Scope::Project => json!([
            "mcp",
            "serve",
            "--workspace",
            workspace.display().to_string()
        ]),
        Scope::Global => json!(["mcp", "serve"]),
    };
    let command = fida_bin.display().to_string();
    match shape {
        // VS Code / Copilot: `servers` map, `{type:stdio, command, args}`.
        McpShape::VscodeStdio => json!({
            "type": "stdio",
            "command": command,
            "args": args,
        }),
        // Everyone else: command/args plus the disabled + autoApprove keys.
        McpShape::Standard => json!({
            "command": command,
            "args": args,
            "disabled": false,
            "autoApprove": [READ_TOOL],
        }),
        // OpenCode: local MCP config requires an enabled local server and the
        // full command as an array.
        McpShape::OpenCodeLocal => {
            let mut command = vec![command];
            if let Some(args) = args.as_array() {
                command.extend(
                    args.iter()
                        .filter_map(Value::as_str)
                        .map(ToString::to_string),
                );
            }
            json!({
                "type": "local",
                "command": command,
                "enabled": true,
            })
        }
    }
}

fn read_json_object(path: &Path) -> CliResult<Map<String, Value>> {
    if !path.exists() {
        return Ok(Map::new());
    }
    let raw = std::fs::read_to_string(path)
        .map_err(|e| CliError::general(format!("cannot read {}: {e}", path.display())))?;
    if raw.trim().is_empty() {
        return Ok(Map::new());
    }
    match serde_json::from_str::<Value>(&raw) {
        Ok(Value::Object(map)) => Ok(map),
        Ok(_) => Err(CliError::general(format!(
            "{} must contain a JSON object",
            path.display()
        ))),
        Err(e) => Err(CliError::general(format!(
            "{} is not valid JSON: {e}",
            path.display()
        ))),
    }
}

fn write_json_object(path: &Path, map: &Map<String, Value>) -> CliResult {
    create_parent(path)?;
    let pretty = serde_json::to_string_pretty(&Value::Object(map.clone()))
        .map_err(|e| CliError::general(format!("failed to encode {}: {e}", path.display())))?;
    std::fs::write(path, format!("{pretty}\n"))
        .map_err(|e| CliError::general(format!("failed to write {}: {e}", path.display())))
}

// ---------------------------------------------------------------------------
// Skill / rules files
// ---------------------------------------------------------------------------

fn write_skill(path: &Path, style: &SkillStyle) -> CliResult {
    match style {
        SkillStyle::Frontmatter(kv) => {
            let mut header = String::from("---\n");
            for (k, v) in *kv {
                header.push_str(&format!("{k}: {v}\n"));
            }
            header.push_str("---\n");
            write_file(path, &format!("{header}{}", skill_markdown()))
        }
        SkillStyle::ManagedBlock => {
            let existing = read_to_string_or_empty(path)?;
            write_file(path, &upsert_block(&existing, &skill_markdown()))
        }
    }
}

fn remove_skill(path: &Path, style: &SkillStyle) -> CliResult<bool> {
    match style {
        SkillStyle::ManagedBlock => {
            if !path.exists() {
                return Ok(false);
            }
            let existing = read_to_string_or_empty(path)?;
            let (stripped, removed) = remove_block(&existing);
            if !removed {
                return Ok(false);
            }
            if stripped.trim().is_empty() {
                remove_if_present(path)?;
            } else {
                write_file(path, &stripped)?;
            }
            Ok(true)
        }
        // Standalone files are fully owned by Fida; delete outright.
        _ => remove_if_present(path),
    }
}

/// Insert or replace Fida's managed block in `existing`, preserving the rest.
fn upsert_block(existing: &str, body: &str) -> String {
    let block = format!("{BLOCK_BEGIN}\n{body}{BLOCK_END}\n");
    match (find_block_begin(existing), existing.find(BLOCK_END)) {
        (Some(start), Some(end)) if end > start => {
            let end = end + BLOCK_END.len();
            let tail = existing[end..].trim_start_matches('\n');
            format!("{}{}{}", &existing[..start], block, tail)
        }
        _ if existing.trim().is_empty() => block,
        _ => format!("{}\n\n{block}", existing.trim_end()),
    }
}

/// Strip Fida's managed block from `existing`; returns `(text, removed?)`.
fn remove_block(existing: &str) -> (String, bool) {
    match (find_block_begin(existing), existing.find(BLOCK_END)) {
        (Some(start), Some(end)) if end > start => {
            let end = end + BLOCK_END.len();
            let tail = existing[end..].trim_start_matches('\n');
            let head = existing[..start].trim_end_matches('\n');
            let joined = if head.is_empty() {
                tail.to_string()
            } else if tail.is_empty() {
                format!("{head}\n")
            } else {
                format!("{head}\n\n{tail}")
            };
            (joined, true)
        }
        _ => (existing.to_string(), false),
    }
}

fn find_block_begin(existing: &str) -> Option<usize> {
    match existing.find(BLOCK_BEGIN) {
        Some(start) => Some(start),
        None => existing.find(LEGACY_BLOCK_BEGIN),
    }
}

/// The canonical skill body (without per-agent header), shared by every agent.
///
/// Deliberately assertive (lean-ctx style): agents reliably follow MANDATORY /
/// NEVER phrasing, and that obedience is what routes operations through Fida.
fn skill_markdown() -> String {
    format!(
        "# Fida guardrails (MANDATORY)\n\n\
         This workspace is guarded by Fida, a local-first secret leak prevention\n\
         layer. Native tools and non-Fida MCP tools cannot guarantee redaction\n\
         before output reaches you, so you MUST route reads and commands through\n\
         Fida whenever available.\n\n\
         ## Rules\n\n\
         - NEVER read a file with a native tool or a non-Fida MCP/file-context\n\
         \x20\x20tool when the `{read}` MCP tool is available. Use `{read}` for every\n\
         \x20\x20file read.\n\
         - NEVER use `ctx_read`, `lean-ctx`, filesystem/read-file MCP tools,\n\
         \x20\x20workspace context, reviewed-file context, or other non-Fida helpers to\n\
         \x20\x20inspect file contents. They can bypass Fida redaction.\n\
         - NEVER run a shell command with a native tool or non-Fida MCP shell\n\
         \x20\x20tool when the `{shell}` MCP tool is available. Use `{shell}` for every\n\
         \x20\x20command.\n\
         - If raw file content appears from a non-Fida tool or ambient context,\n\
         \x20\x20treat it as tainted: do not quote it, do not summarize secret-like\n\
         \x20\x20values, and immediately re-read through `{read}` before answering.\n\
         - Sensitive files may be read through `{read}` when policy allows it.\n\
         \x20\x20Fida returns a safe view with detected values redacted; never try to\n\
         \x20\x20recover, reconstruct, or bypass those redactions.\n\
         - If `{read}`/`{shell}` are NOT available, use `fida exec -- <command>`\n\
         \x20\x20for shell commands and `fida exec -- cat <path>` for file content so\n\
         \x20\x20output is still redacted before you see it. For writes, run\n\
         \x20\x20`fida policy explain file-write <path>` and obey the result.\n\
         - If any Fida call returns `blocked by Fida policy` / `blocked by Fida\n\
         \x20\x20PathJail`, STOP. Do not retry with a native tool. Tell the user the\n\
         \x20\x20operation is blocked and cite the `matched_rule`.\n\
         - A denial is final. If ANY tool or policy blocks a sensitive read, do\n\
         \x20\x20NOT route around it with a different tool, a native read, a shell\n\
         \x20\x20command, `git show`, base64, or any other workaround. Treat the\n\
         \x20\x20block as the answer and report it.\n\
         - A user may ask you to inspect a sensitive file. Use the redacted `{read}`\n\
         \x20\x20view and explain any suppressed values; never expose raw secret data.\n\
         - Access stays inside this workspace. Never read paths outside the\n\
         \x20\x20project root (`/etc/...`, `~/.ssh/...`, `../` escapes).\n\n\
         These rules are not optional. Bypassing Fida's redaction or a policy\n\
         denial is a policy violation, not a workaround.\n",
        read = READ_TOOL,
        shell = SHELL_TOOL,
    )
}

/// The Kiro-style `preToolUse` backstop hook (JSON, askAgent).
fn kiro_hook_contents() -> String {
    let hook = json!({
        "name": "Fida Guard",
        "version": "1.0.0",
        "description": "Route file reads/writes through Fida policy before they run.",
        "when": { "type": "preToolUse", "toolTypes": ["read", "write"] },
        "then": {
            "type": "askAgent",
            "prompt":
                "A file read or write is about to run. Before proceeding, evaluate the \
                 target path against the Fida policy: run `fida policy explain file-read <path>` \
                 for a read or `fida policy explain file-write <path>` for a write. If the \
                 decision is `deny`, do NOT perform the operation — tell the user it is blocked \
                 by Fida policy and cite the matched rule. If the decision is `ask`, pause and \
                 get explicit user confirmation first. If `allow`, proceed only through \
                 `fida_read` / `fida_shell` when those gateway tools are available. Do not use \
                 ctx_read, lean-ctx, workspace context, reviewed-file context, or other non-Fida \
                 file-content tools to inspect file contents."
        }
    });
    format!(
        "{}\n",
        serde_json::to_string_pretty(&hook).expect("hook json encodes")
    )
}

// ---------------------------------------------------------------------------
// Command PreToolUse hooks (Claude Code, Codex, VS Code) — real hard block
// ---------------------------------------------------------------------------

/// The shell command both agents invoke for the gate. Quoted so a binary path
/// with spaces survives the agent's shell tokenization.
fn fida_hook_command(fida_bin: &Path) -> String {
    format!("\"{}\" hook", fida_bin.display())
}

/// A dedicated hook file for clients such as VS Code / GitHub Copilot.
fn command_hook_contents(fida_bin: &Path) -> String {
    let hook = json!({
        "hooks": {
            "PreToolUse": [
                {
                    "type": "command",
                    "command": fida_hook_command(fida_bin),
                    "timeout": 15
                }
            ]
        }
    });
    format!(
        "{}\n",
        serde_json::to_string_pretty(&hook).expect("hook json encodes")
    )
}

/// Whether a `PreToolUse` matcher group is one Fida wrote (so install is
/// idempotent and uninstall is surgical).
fn is_fida_hook_group(group: &Value) -> bool {
    group
        .get("hooks")
        .and_then(Value::as_array)
        .map(|handlers| {
            handlers.iter().any(|h| {
                h.get("command")
                    .and_then(Value::as_str)
                    .map(|c| c.contains("fida") && c.trim_end().ends_with("hook"))
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false)
}

/// Insert (or refresh) Fida's `hooks.PreToolUse` entry in a settings JSON file,
/// preserving any other hooks and unrelated keys.
fn upsert_settings_hook(path: &Path, matcher: &str, fida_bin: &Path) -> CliResult {
    let mut root = read_json_object(path)?;
    let hooks = root
        .entry("hooks".to_string())
        .or_insert_with(|| Value::Object(Map::new()));
    let hooks = hooks.as_object_mut().ok_or_else(|| {
        CliError::general(format!("{}: `hooks` is not a JSON object", path.display()))
    })?;
    let pre = hooks
        .entry("PreToolUse".to_string())
        .or_insert_with(|| Value::Array(Vec::new()));
    let arr = pre.as_array_mut().ok_or_else(|| {
        CliError::general(format!(
            "{}: `hooks.PreToolUse` is not an array",
            path.display()
        ))
    })?;

    arr.retain(|g| !is_fida_hook_group(g));
    arr.push(json!({
        "matcher": matcher,
        "hooks": [ { "type": "command", "command": fida_hook_command(fida_bin) } ]
    }));
    write_json_object(path, &root)
}

/// Remove Fida's `hooks.PreToolUse` entry, leaving other hooks intact.
fn remove_settings_hook(path: &Path) -> CliResult<bool> {
    if !path.exists() {
        return Ok(false);
    }
    let mut root = read_json_object(path)?;
    let mut changed = false;
    let mut hooks_now_empty = false;

    if let Some(hooks) = root.get_mut("hooks").and_then(Value::as_object_mut) {
        let mut pre_now_empty = false;
        if let Some(arr) = hooks.get_mut("PreToolUse").and_then(Value::as_array_mut) {
            let before = arr.len();
            arr.retain(|g| !is_fida_hook_group(g));
            changed = arr.len() != before;
            pre_now_empty = arr.is_empty();
        }
        if pre_now_empty {
            hooks.remove("PreToolUse");
        }
        hooks_now_empty = hooks.is_empty();
    }
    if hooks_now_empty {
        root.remove("hooks");
    }

    if changed {
        if root.is_empty() {
            remove_if_present(path)?;
        } else {
            write_json_object(path, &root)?;
        }
    }
    Ok(changed)
}

// ---------------------------------------------------------------------------
// Small filesystem helpers
// ---------------------------------------------------------------------------

fn create_parent(path: &Path) -> CliResult {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| {
                CliError::general(format!(
                    "failed to create directory {}: {e}",
                    parent.display()
                ))
            })?;
        }
    }
    Ok(())
}

fn write_file(path: &Path, contents: &str) -> CliResult {
    create_parent(path)?;
    std::fs::write(path, contents)
        .map_err(|e| CliError::general(format!("failed to write {}: {e}", path.display())))
}

fn read_to_string_or_empty(path: &Path) -> CliResult<String> {
    if !path.exists() {
        return Ok(String::new());
    }
    std::fs::read_to_string(path)
        .map_err(|e| CliError::general(format!("cannot read {}: {e}", path.display())))
}

fn remove_if_present(path: &Path) -> CliResult<bool> {
    if !path.exists() {
        return Ok(false);
    }
    std::fs::remove_file(path)
        .map_err(|e| CliError::general(format!("failed to remove {}: {e}", path.display())))?;
    Ok(true)
}

/// The current fida binary path, for embedding in generated MCP configs.
pub fn current_fida_bin() -> CliResult<PathBuf> {
    std::env::current_exe()
        .map_err(|e| CliError::general(format!("cannot resolve current fida binary: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn bin() -> PathBuf {
        PathBuf::from("/usr/local/bin/fida")
    }

    /// Project-scope install with base == workspace == the repo root.
    fn install_project(spec: &AgentSpec, root: &Path) -> AgentInstallReport {
        install_agent(spec, Scope::Project, root, root, &bin()).unwrap()
    }

    #[test]
    fn registry_ids_are_unique() {
        let agents = known_agents();
        let mut ids: Vec<&str> = agents.iter().map(|a| a.id).collect();
        ids.sort_unstable();
        let mut deduped = ids.clone();
        deduped.dedup();
        assert_eq!(ids, deduped, "agent ids must be unique");
    }

    #[test]
    fn install_kiro_writes_all_three_layers() {
        let dir = tempdir().unwrap();
        let spec = find_agent("kiro").unwrap();
        let report = install_project(&spec, dir.path());
        assert_eq!(report.layers.len(), 3);
        assert!(dir.path().join(".kiro/settings/mcp.json").exists());
        assert!(dir.path().join(".kiro/steering/fida.md").exists());
        assert!(dir.path().join(".kiro/hooks/fida-guard.kiro.hook").exists());
    }

    #[test]
    fn project_gateway_pins_workspace_global_does_not() {
        let entry_p = fida_server_entry(
            &bin(),
            Scope::Project,
            Path::new("/repo"),
            McpShape::Standard,
        );
        let args_p: Vec<String> = entry_p["args"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        assert!(args_p.contains(&"--workspace".to_string()));

        let entry_g = fida_server_entry(
            &bin(),
            Scope::Global,
            Path::new("/repo"),
            McpShape::Standard,
        );
        let args_g: Vec<String> = entry_g["args"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        assert!(!args_g.contains(&"--workspace".to_string()));
    }

    #[test]
    fn claude_global_uses_home_relative_paths() {
        let spec = find_agent("claude").unwrap();
        assert_eq!(
            spec.mcp.unwrap().path.path(Scope::Global),
            Some(".claude.json")
        );
        assert_eq!(
            spec.skill.path.path(Scope::Global),
            Some(".claude/CLAUDE.md")
        );
        // Project scope differs.
        assert_eq!(
            spec.mcp.unwrap().path.path(Scope::Project),
            Some(".mcp.json")
        );
    }

    #[test]
    fn cursor_has_no_global_skill() {
        let spec = find_agent("cursor").unwrap();
        assert_eq!(spec.skill.path.path(Scope::Global), None);
    }

    #[test]
    fn antigravity_global_install_writes_gateway_and_skill() {
        // Regression: a global `fida init` (the default) used to wire only the
        // gateway for Antigravity (skill was project-only), so the agent had
        // `fida_read` but no rules telling it to use it — and read secrets via a
        // native tool. The global skill must now land in ~/.gemini/GEMINI.md.
        let home = tempdir().unwrap();
        let spec = find_agent("antigravity").unwrap();
        let report = install_agent(&spec, Scope::Global, home.path(), home.path(), &bin()).unwrap();
        assert!(home.path().join(".gemini/config/mcp_config.json").exists());
        assert!(home.path().join(".gemini/GEMINI.md").exists());
        assert!(report.layers.iter().any(|l| l.label == "skill"));
        let s = std::fs::read_to_string(home.path().join(".gemini/GEMINI.md")).unwrap();
        assert!(s.contains("MANDATORY"));
        assert!(s.contains("safe view with detected values redacted"));
        // The anti-circumvention rule that closes the observed bypass.
        assert!(s.contains("A denial is final"));
    }

    #[test]
    fn windsurf_global_install_writes_under_home_base() {
        let home = tempdir().unwrap();
        let spec = find_agent("windsurf").unwrap();
        let report = install_agent(&spec, Scope::Global, home.path(), home.path(), &bin()).unwrap();
        // Global windsurf has both an MCP config and a rules file.
        assert_eq!(report.layers.len(), 2);
        assert!(
            home.path()
                .join(".codeium/windsurf/mcp_config.json")
                .exists()
        );
        assert!(
            home.path()
                .join(".codeium/windsurf/memories/global_rules.md")
                .exists()
        );
    }

    #[test]
    fn frontmatter_skill_has_header_and_is_assertive() {
        let dir = tempdir().unwrap();
        let spec = find_agent("kiro").unwrap();
        install_project(&spec, dir.path());
        let s = std::fs::read_to_string(dir.path().join(".kiro/steering/fida.md")).unwrap();
        assert!(s.starts_with("---\ninclusion: always\n---\n"));
        assert!(s.contains("MANDATORY"));
        assert!(s.contains("NEVER read a file with a native tool or a non-Fida MCP/file-context"));
        assert!(s.contains("ctx_read"));
        assert!(s.contains("reviewed-file context"));
        assert!(s.contains(READ_TOOL));
    }

    #[test]
    fn kiro_hook_redirects_non_fida_file_tools() {
        let hook: Value = serde_json::from_str(&kiro_hook_contents()).unwrap();
        let prompt = hook["then"]["prompt"].as_str().unwrap();
        assert!(prompt.contains("fida_read"));
        assert!(prompt.contains("ctx_read"));
        assert!(prompt.contains("reviewed-file context"));
    }

    #[test]
    fn managed_block_preserves_surrounding_content() {
        let dir = tempdir().unwrap();
        let claude = dir.path().join("CLAUDE.md");
        std::fs::write(&claude, "# My project\n\nExisting guidance.\n").unwrap();
        let spec = find_agent("claude").unwrap();
        install_project(&spec, dir.path());

        let s = std::fs::read_to_string(&claude).unwrap();
        assert!(s.contains("# My project"));
        assert!(s.contains("Existing guidance."));
        assert!(s.contains(BLOCK_BEGIN));

        uninstall_agent(&spec, Scope::Project, dir.path()).unwrap();
        let after = std::fs::read_to_string(&claude).unwrap();
        assert!(after.contains("Existing guidance."));
        assert!(!after.contains(BLOCK_BEGIN));
    }

    #[test]
    fn managed_block_upsert_is_idempotent() {
        let body = "BODY\n";
        let once = upsert_block("# Title\n\ntext\n", body);
        let twice = upsert_block(&once, body);
        assert_eq!(once, twice);
        assert_eq!(once.matches(BLOCK_BEGIN).count(), 1);
    }

    #[test]
    fn managed_block_upgrades_legacy_install_marker() {
        let body = "BODY\n";
        let existing = format!("head\n\n{LEGACY_BLOCK_BEGIN}\nold\n{BLOCK_END}\ntail\n");
        let updated = upsert_block(&existing, body);

        assert!(updated.contains(BLOCK_BEGIN));
        assert!(!updated.contains(LEGACY_BLOCK_BEGIN));
        assert!(updated.contains("head"));
        assert!(updated.contains("tail"));
    }

    #[test]
    fn mcp_upsert_preserves_other_servers() {
        let dir = tempdir().unwrap();
        let path = dir.path().join(".cursor/mcp.json");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, r#"{"mcpServers":{"other":{"command":"node"}}}"#).unwrap();

        let spec = find_agent("cursor").unwrap();
        install_project(&spec, dir.path());

        let v: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(v["mcpServers"]["other"]["command"], "node");
        assert_eq!(v["mcpServers"]["fida"]["command"], "/usr/local/bin/fida");
    }

    #[test]
    fn strip_claude_permissions_drops_only_fida_entries() {
        let dir = tempdir().unwrap();
        let path = dir.path().join(".claude/settings.local.json");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            &path,
            r#"{"permissions":{"allow":["mcp__fida__fida_read","mcp__fida__fida_shell","Bash(ls)"]}}"#,
        )
        .unwrap();

        let changed = strip_claude_fida_permissions(dir.path()).unwrap();
        assert_eq!(changed.len(), 1, "the touched file should be reported");

        let v: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let allow = v["permissions"]["allow"].as_array().unwrap();
        // Only the unrelated permission survives; both fida tools are gone.
        assert_eq!(allow.len(), 1);
        assert_eq!(allow[0], "Bash(ls)");

        // Idempotent: a second pass finds nothing left to strip.
        assert!(
            strip_claude_fida_permissions(dir.path())
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn opencode_uses_current_local_mcp_schema() {
        let dir = tempdir().unwrap();
        let spec = find_agent("opencode").unwrap();
        install_project(&spec, dir.path());

        let v: Value = serde_json::from_str(
            &std::fs::read_to_string(dir.path().join("opencode.json")).unwrap(),
        )
        .unwrap();
        let fida = &v["mcp"]["fida"];
        assert_eq!(fida["type"], "local");
        assert_eq!(
            fida["command"].as_array().unwrap(),
            &[
                json!("/usr/local/bin/fida"),
                json!("mcp"),
                json!("serve"),
                json!("--workspace"),
                json!(dir.path().display().to_string()),
            ]
        );
        assert_eq!(fida["enabled"], true);
        assert!(fida.get("args").is_none());
        assert!(fida.get("disabled").is_none());
        assert!(fida.get("autoApprove").is_none());
    }

    #[test]
    fn detect_matches_marker_dir() {
        let dir = tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".kiro")).unwrap();
        assert!(detect(&find_agent("kiro").unwrap(), dir.path(), None, None));
        let cursor = AgentSpec {
            detect_bins: &[],
            detect_apps: &[],
            ..find_agent("cursor").unwrap()
        };
        assert!(!detect(&cursor, dir.path(), None, None));
    }

    #[test]
    fn detect_matches_home_config_dir() {
        // Not used in the repo, but the agent's global config dir is in home.
        let repo = tempdir().unwrap();
        let home = tempdir().unwrap();
        std::fs::create_dir_all(home.path().join(".cursor")).unwrap();
        assert!(detect(
            &find_agent("cursor").unwrap(),
            repo.path(),
            Some(home.path()),
            None
        ));
    }

    #[test]
    fn detect_matches_user_applications_bundle() {
        // Agent app installed under ~/Applications, no config dir or CLI.
        let repo = tempdir().unwrap();
        let home = tempdir().unwrap();
        std::fs::create_dir_all(home.path().join("Applications/Cursor.app")).unwrap();
        assert!(detect(
            &find_agent("cursor").unwrap(),
            repo.path(),
            Some(home.path()),
            None
        ));
        // An agent with no app bundle (Codex, CLI-only) is not matched this way.
        assert!(!detect(
            &find_agent("codex").unwrap(),
            repo.path(),
            Some(home.path()),
            None
        ));
    }

    #[test]
    fn claude_install_merges_pretooluse_hook() {
        let dir = tempdir().unwrap();
        let spec = find_agent("claude").unwrap();
        install_project(&spec, dir.path());
        let v: Value = serde_json::from_str(
            &std::fs::read_to_string(dir.path().join(".claude/settings.json")).unwrap(),
        )
        .unwrap();
        let group = &v["hooks"]["PreToolUse"][0];
        assert!(group["matcher"].as_str().unwrap().contains("Read"));
        let cmd = group["hooks"][0]["command"].as_str().unwrap();
        assert!(cmd.ends_with("hook"));
        assert!(cmd.contains("/usr/local/bin/fida"));
    }

    #[test]
    fn claude_hook_merge_preserves_other_hooks_and_is_idempotent() {
        let dir = tempdir().unwrap();
        let path = dir.path().join(".claude/settings.json");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            &path,
            r#"{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"/bin/other.sh"}]}]},"model":"sonnet"}"#,
        )
        .unwrap();
        let spec = find_agent("claude").unwrap();
        install_project(&spec, dir.path());
        install_project(&spec, dir.path()); // twice → no duplicate fida group

        let v: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(v["model"], "sonnet", "unrelated keys preserved");
        let groups = v["hooks"]["PreToolUse"].as_array().unwrap();
        let fida_groups = groups
            .iter()
            .filter(|g| {
                g["hooks"][0]["command"]
                    .as_str()
                    .unwrap_or("")
                    .ends_with("hook")
            })
            .count();
        assert_eq!(fida_groups, 1, "exactly one fida hook group");
        let other = groups
            .iter()
            .any(|g| g["hooks"][0]["command"] == "/bin/other.sh");
        assert!(other, "pre-existing hook preserved");

        // Uninstall removes only the fida group, keeping the other.
        uninstall_agent(&spec, Scope::Project, dir.path()).unwrap();
        let v: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let groups = v["hooks"]["PreToolUse"].as_array().unwrap();
        assert!(
            groups
                .iter()
                .any(|g| g["hooks"][0]["command"] == "/bin/other.sh")
        );
        assert!(!groups.iter().any(|g| {
            g["hooks"][0]["command"]
                .as_str()
                .unwrap_or("")
                .ends_with("hook")
        }));
    }

    #[test]
    fn codex_install_merges_bash_hook() {
        let dir = tempdir().unwrap();
        let spec = find_agent("codex").unwrap();
        install_project(&spec, dir.path());
        let v: Value = serde_json::from_str(
            &std::fs::read_to_string(dir.path().join(".codex/hooks.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(v["hooks"]["PreToolUse"][0]["matcher"], "Bash|apply_patch");
    }

    #[test]
    fn copilot_uses_servers_key_and_stdio_shape() {
        let dir = tempdir().unwrap();
        let spec = find_agent("copilot").unwrap();
        // Project scope: base == workspace.
        let report = install_agent(&spec, Scope::Project, dir.path(), dir.path(), &bin()).unwrap();
        let v: Value = serde_json::from_str(
            &std::fs::read_to_string(dir.path().join(".vscode/mcp.json")).unwrap(),
        )
        .unwrap();
        // `servers` key (not `mcpServers`) and a `{type:stdio}` entry.
        assert_eq!(v["servers"]["fida"]["type"], "stdio");
        assert_eq!(v["servers"]["fida"]["command"], "/usr/local/bin/fida");
        assert!(v["servers"]["fida"].get("autoApprove").is_none());

        let hook: Value = serde_json::from_str(
            &std::fs::read_to_string(dir.path().join(".github/hooks/fida.json")).unwrap(),
        )
        .unwrap();
        let command = hook["hooks"]["PreToolUse"][0]["command"].as_str().unwrap();
        assert!(command.ends_with("fida\" hook"));
        assert_eq!(hook["hooks"]["PreToolUse"][0]["type"], "command");
        assert_eq!(hook["hooks"]["PreToolUse"][0]["timeout"], 15);
        assert_eq!(report.layers.len(), 3);
        assert_eq!(
            protection_level(&spec, Scope::Project, &report, true),
            ProtectionLevel::Enforced
        );

        let removed = uninstall_agent(&spec, Scope::Project, dir.path()).unwrap();
        assert_eq!(removed.removed, vec!["gateway", "skill", "hook"]);
        assert!(!dir.path().join(".github/hooks/fida.json").exists());
    }

    #[test]
    fn copilot_global_install_writes_user_mcp_instructions_and_hook() {
        let home = tempdir().unwrap();
        let spec = find_agent("copilot").unwrap();
        let report = install_agent(&spec, Scope::Global, home.path(), home.path(), &bin()).unwrap();

        let mcp: Value = serde_json::from_str(
            &std::fs::read_to_string(home.path().join(VSCODE_USER_MCP_PATH)).unwrap(),
        )
        .unwrap();
        assert_eq!(mcp["servers"]["fida"]["type"], "stdio");

        let instructions = std::fs::read_to_string(
            home.path()
                .join(".copilot/instructions/fida.instructions.md"),
        )
        .unwrap();
        assert!(instructions.starts_with("---\napplyTo: \"**\"\n---\n"));
        assert!(instructions.contains("Fida guardrails"));
        assert!(home.path().join(".copilot/hooks/fida.json").exists());
        assert_eq!(
            protection_level(&spec, Scope::Global, &report, true),
            ProtectionLevel::Enforced
        );

        let removed = uninstall_agent(&spec, Scope::Global, home.path()).unwrap();
        assert_eq!(removed.removed, vec!["gateway", "skill", "hook"]);
    }

    #[test]
    fn coverage_matrix_pins_documented_backstops_and_stays_consistent() {
        let matrix = coverage_matrix();
        // Exactly one row per registered agent.
        assert_eq!(matrix.len(), known_agents().len());

        let row = |id: &str| {
            matrix
                .iter()
                .find(|c| c.id == id)
                .unwrap_or_else(|| panic!("agent {id} missing from coverage matrix"))
        };
        // Pinned to the documented hook matrix. This guard fails if a registry
        // change would make the README/security-model table over- or
        // under-state an agent's real backstop.
        assert_eq!(row("claude").backstop, Backstop::HardBlock);
        assert_eq!(row("codex").backstop, Backstop::HardBlock);
        assert_eq!(row("copilot").backstop, Backstop::HardBlock);
        assert_eq!(row("kiro").backstop, Backstop::SoftPrompt);
        for id in ["cursor", "windsurf", "antigravity"] {
            assert_eq!(row(id).backstop, Backstop::SkillOnly, "{id} is skill-only");
        }

        // The matrix is a pure projection of the registry.
        for spec in known_agents() {
            assert_eq!(backstop_of(&spec), row(spec.id).backstop);
            assert_eq!(row(spec.id).gateway, spec.mcp.is_some());
            assert!(row(spec.id).skill, "{} has a skill layer", spec.id);
        }
    }

    #[test]
    fn installed_protection_distinguishes_hard_block_and_best_effort() {
        let codex = find_agent("codex").unwrap();
        let codex_report = AgentInstallReport {
            id: codex.id,
            display: codex.display,
            layers: vec![
                WrittenLayer {
                    label: "skill",
                    path: "AGENTS.md".to_string(),
                },
                WrittenLayer {
                    label: "hook",
                    path: ".codex/hooks.json".to_string(),
                },
            ],
        };
        assert_eq!(
            protection_level(&codex, Scope::Project, &codex_report, true),
            ProtectionLevel::Enforced
        );

        let cursor = find_agent("cursor").unwrap();
        let cursor_report = AgentInstallReport {
            id: cursor.id,
            display: cursor.display,
            layers: vec![
                WrittenLayer {
                    label: "gateway",
                    path: ".cursor/mcp.json".to_string(),
                },
                WrittenLayer {
                    label: "skill",
                    path: ".cursor/rules/fida.mdc".to_string(),
                },
            ],
        };
        assert_eq!(
            protection_level(&cursor, Scope::Project, &cursor_report, true),
            ProtectionLevel::BestEffort
        );
        assert_eq!(
            protection_level(&cursor, Scope::Project, &cursor_report, false),
            ProtectionLevel::Incomplete
        );
    }
}
