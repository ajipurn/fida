//! `fida doctor` — check local setup. **Owner: task 19.10.**
//!
//! Runs eight environment checks, prints one
//! result line per check, completes well within the 10-second budget (every
//! check is a bounded filesystem / env / single `git` probe), and resolves to
//! an exit code:
//!
//! * all checks pass -> exit 0;
//! * any *fatal* check fails -> remediation hints + exit 1.
//!
//! ## Fatal vs. informational checks
//!
//! The specification lists a pass condition per check, but two of those
//! conditions describe ordinary, expected states rather than broken setups:
//! a project may legitimately live outside a git repository, and the built-in
//! default policy ships with no MCP configuration, so a literal "fail -> exit 1"
//! for those would make `fida doctor` exit non-zero in healthy projects.
//!
//! We therefore classify the checks by severity (the latitude called out in
//! the task; still aligned with pass conditions, which we report
//! faithfully on every line):
//!
//! | Check | Severity | Rationale |
//! |-------------------------------|---------------|-----------|
//! | Policy discovery | fatal | A policy must always resolve (built-in fallback); only a bad `--config` fails it. |
//! | Session-dir writability | fatal | Fida cannot record sessions without it. |
//! | Configured agent availability | fatal | A configured agent binary missing from `PATH` is clearly broken. |
//! | Git repository detection | informational | Running outside a repo is a valid, non-broken state. |
//! | Proxy env support | always passes | Env vars are always readable on supported platforms. |
//! | MCP configuration detection | informational | Absent MCP config is the common default, not a fault. |
//! | Agent guard coverage | informational | Reports each detected agent's backstop level; skill-only agents warn. |
//! | OS sandbox availability | informational | Reports the sandbox backend + `FIDA_SANDBOX`; a no-op platform is not a fault. |
//!
//! Only a failing **fatal** check drives the exit-1 path; informational checks
//! still print their true pass/warn status and a hint when relevant.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::Args;
use fida_action::ProtectionLevel;

use fida_policy::{PolicySource, load_source, resolve_source_in};
use fida_session::sessions_root;

use crate::commands::integrations::{self, AgentCoverage, Backstop};
use crate::context::GlobalContext;
use crate::error::{CliError, CliResult};

/// Arguments for `fida doctor`.
#[derive(Debug, Args)]
pub struct DoctorArgs {}

/// Per-check severity. Only [`Status::Fail`] drives the exit-1 path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Status {
    /// The check's pass condition holds.
    Pass,
    /// An informational check whose pass condition does not hold, but which is
    /// not a broken setup (e.g. not in a git repo, no MCP config).
    Warn,
    /// A fatal check failed; the command will exit 1.
    Fail,
}

impl Status {
    /// Lowercase tag used in JSON and as the basis for the text label.
    fn tag(self) -> &'static str {
        match self {
            Status::Pass => "pass",
            Status::Warn => "warn",
            Status::Fail => "fail",
        }
    }

    /// ANSI color for the bracketed label, or `""` when color is disabled.
    fn color(self, no_color: bool) -> &'static str {
        if no_color {
            return "";
        }
        match self {
            Status::Pass => "\u{1b}[32m", // green
            Status::Warn => "\u{1b}[33m", // yellow
            Status::Fail => "\u{1b}[31m", // red
        }
    }
}

/// The outcome of a single environment check.
#[derive(Debug)]
struct CheckResult {
    /// Stable machine name, e.g. `policy_discovery`.
    key: &'static str,
    /// Human-readable check name for the text line.
    name: &'static str,
    status: Status,
    /// One-line description of what was found.
    detail: String,
    /// Remediation hint, printed for non-pass results.
    hint: Option<String>,
}

/// Stub-free handler (task 19.10).
pub async fn run(_args: &DoctorArgs, ctx: &GlobalContext) -> CliResult {
    let root = std::env::current_dir()
        .map_err(|e| CliError::general(format!("cannot determine current directory: {e}")))?;

    let results = run_checks(&root, ctx.config.as_deref());
    emit(&results, ctx);

    if any_fatal(&results) {
        // Exit 1 with a generic error; the per-check hints were already printed.
        Err(CliError::general(
            "one or more environment checks failed; see the hints above",
        ))
    } else {
        Ok(())
    }
}

/// `true` if any check is fatal — the exit-1 trigger.
fn any_fatal(results: &[CheckResult]) -> bool {
    results.iter().any(|r| r.status == Status::Fail)
}

/// Perform the checks against `root` (the working directory) and the
/// optional `--config` policy path. Pure aside from reads of the filesystem,
/// environment, and a single `git` invocation, so it is unit-testable with a
/// scratch directory.
fn run_checks(root: &Path, config: Option<&Path>) -> Vec<CheckResult> {
    // Resolve once; checks 1, 4 and 6 all consult the resolved policy.
    let source = resolve_source_in(root, config);
    let compiled = source.as_ref().ok().and_then(|s| load_source(s, None).ok());

    vec![
        check_policy_discovery(&source),
        check_secret_protection(root),
        check_git_repository(root),
        check_session_writability(root),
        check_agent_binaries(compiled.as_ref().map(|c| c.agents.as_slice())),
        check_proxy_env(),
        check_mcp_config(compiled.as_ref()),
        check_agent_coverage(root),
        check_os_sandbox(),
    ]
}

fn check_secret_protection(root: &Path) -> CheckResult {
    let key = "secret_protection";
    let name = "Secret-to-model protection";
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
    let record = project.as_ref().or(global.as_ref());

    let Some(record) = record else {
        return CheckResult {
            key,
            name,
            status: Status::Warn,
            detail: "Fida is not initialized for any agent".to_string(),
            hint: Some("run `fida init` to install and verify secret protection".to_string()),
        };
    };

    match crate::commands::protection::verify_gateway() {
        Err(err) => CheckResult {
            key,
            name,
            status: Status::Fail,
            detail: err.to_string(),
            hint: Some("run `fida init` again to repair the gateway integration".to_string()),
        },
        Ok(verification) if !verification.passed => CheckResult {
            key,
            name,
            status: Status::Fail,
            detail: verification.detail,
            hint: Some("raw secret suppression could not be verified".to_string()),
        },
        Ok(verification) => {
            let incomplete = record
                .config
                .protection
                .iter()
                .filter(|entry| {
                    crate::commands::setup_state::effective_protection(entry)
                        == ProtectionLevel::Incomplete
                })
                .map(|entry| entry.display.as_str())
                .collect::<Vec<_>>();
            let best_effort = record
                .config
                .protection
                .iter()
                .filter(|entry| {
                    crate::commands::setup_state::effective_protection(entry)
                        == ProtectionLevel::BestEffort
                })
                .map(|entry| entry.display.as_str())
                .collect::<Vec<_>>();
            if !incomplete.is_empty() {
                CheckResult {
                    key,
                    name,
                    status: Status::Fail,
                    detail: format!(
                        "gateway self-test passed, but integrations are incomplete: {}",
                        incomplete.join(", ")
                    ),
                    hint: Some("run `fida init` again to restore missing artifacts".to_string()),
                }
            } else if !best_effort.is_empty() {
                CheckResult {
                    key,
                    name,
                    status: Status::Warn,
                    detail: format!(
                        "{}; best-effort native-tool coverage: {}",
                        verification.detail,
                        best_effort.join(", ")
                    ),
                    hint: Some(
                        "these agents have no hard-block hook; use the Fida gateway for every read"
                            .to_string(),
                    ),
                }
            } else {
                CheckResult {
                    key,
                    name,
                    status: Status::Pass,
                    detail: verification.detail,
                    hint: None,
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Check 1 — Policy discovery
// ---------------------------------------------------------------------------

fn check_policy_discovery(source: &Result<PolicySource, fida_policy::LoadError>) -> CheckResult {
    match source {
        Ok(src) => CheckResult {
            key: "policy_discovery",
            name: "Policy discovery",
            status: Status::Pass,
            detail: format!("resolved from {}", describe_source(src)),
            hint: None,
        },
        Err(err) => CheckResult {
            key: "policy_discovery",
            name: "Policy discovery",
            status: Status::Fail,
            detail: err.to_string(),
            hint: Some(
                "ensure --config points to a readable policy file, or remove it \
                 to use.fida/policy.yaml, fida.yaml, or the built-in default"
                    .to_string(),
            ),
        },
    }
}

/// Human description of where a policy came from.
fn describe_source(source: &PolicySource) -> String {
    match source {
        PolicySource::Config(p) => format!("--config ({})", p.display()),
        PolicySource::DotFida(p) => format!(".fida/policy.yaml ({})", p.display()),
        PolicySource::FidaYaml(p) => format!("fida.yaml ({})", p.display()),
        PolicySource::BuiltinDefault => "the built-in default policy".to_string(),
    }
}

// ---------------------------------------------------------------------------
// Check 2 — Git repository detection
// ---------------------------------------------------------------------------

fn check_git_repository(root: &Path) -> CheckResult {
    if is_inside_git_repo(root) {
        CheckResult {
            key: "git_repository",
            name: "Git repository detection",
            status: Status::Pass,
            detail: "current directory is inside a git repository".to_string(),
            hint: None,
        }
    } else {
        CheckResult {
            key: "git_repository",
            name: "Git repository detection",
            status: Status::Warn,
            detail: "current directory is not inside a git repository".to_string(),
            hint: Some("run `git init` (the diff gate and session baselines use git)".to_string()),
        }
    }
}

/// Probe via `git rev-parse --is-inside-work-tree`, falling back to a `.git`
/// walk if `git` is not installed. Bounded and fast.
fn is_inside_git_repo(root: &Path) -> bool {
    let probed = std::process::Command::new("git")
        .args(["rev-parse", "--is-inside-work-tree"])
        .current_dir(root)
        .output();
    if let Ok(out) = probed {
        if out.status.success() && String::from_utf8_lossy(&out.stdout).trim() == "true" {
            return true;
        }
        // git ran and said "no" — trust it.
        if out.status.success() {
            return false;
        }
    }
    // git missing or errored: fall back to walking up for a `.git` entry.
    let mut dir = Some(root);
    while let Some(d) = dir {
        if d.join(".git").exists() {
            return true;
        }
        dir = d.parent();
    }
    false
}

// ---------------------------------------------------------------------------
// Check 3 — Session directory writability
// ---------------------------------------------------------------------------

fn check_session_writability(root: &Path) -> CheckResult {
    let sessions = sessions_root(root);
    match probe_writable(&sessions) {
        Ok(()) => CheckResult {
            key: "session_dir_writable",
            name: "Session directory writability",
            status: Status::Pass,
            detail: format!("{} is writable", sessions.display()),
            hint: None,
        },
        Err(message) => CheckResult {
            key: "session_dir_writable",
            name: "Session directory writability",
            status: Status::Fail,
            detail: message,
            hint: Some(format!(
                "ensure {} can be created and written (check directory permissions)",
                sessions.display()
            )),
        },
    }
}

/// Create `dir` (if needed), write then remove a uniquely named temp file under
/// it, and report any failure as a message.
fn probe_writable(dir: &Path) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;

    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let probe = dir.join(format!(".fida-doctor-{}-{}", std::process::id(), nanos));

    std::fs::write(&probe, b"ok")
        .map_err(|e| format!("cannot write under {}: {e}", dir.display()))?;
    std::fs::remove_file(&probe)
        .map_err(|e| format!("cannot remove temp file {}: {e}", probe.display()))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Check 4 — Configured agent binary availability
// ---------------------------------------------------------------------------

fn check_agent_binaries(agents: Option<&[String]>) -> CheckResult {
    let key = "agent_binaries";
    let name = "Configured agent availability";

    let Some(agents) = agents else {
        // Policy could not be compiled; we cannot enumerate agents.
        return CheckResult {
            key,
            name,
            status: Status::Warn,
            detail: "policy could not be loaded to check configured agents".to_string(),
            hint: Some("run `fida policy check` to diagnose the policy".to_string()),
        };
    };

    if agents.is_empty() {
        return CheckResult {
            key,
            name,
            status: Status::Pass,
            detail: "no agent binaries configured in policy".to_string(),
            hint: None,
        };
    }

    let missing: Vec<&String> = agents.iter().filter(|a| !binary_on_path(a)).collect();
    if missing.is_empty() {
        CheckResult {
            key,
            name,
            status: Status::Pass,
            detail: format!("all configured agents found on PATH: {}", agents.join(", ")),
            hint: None,
        }
    } else {
        let names: Vec<&str> = missing.iter().map(|s| s.as_str()).collect();
        CheckResult {
            key,
            name,
            status: Status::Fail,
            detail: format!("agent binaries not found on PATH: {}", names.join(", ")),
            hint: Some(format!(
                "install the missing agent(s) or remove them from the policy `agents` list: {}",
                names.join(", ")
            )),
        }
    }
}

/// Whether `bin` resolves to an executable on `PATH` (or as a direct path).
fn binary_on_path(bin: &str) -> bool {
    if bin.contains('/') || bin.contains('\\') {
        return is_executable_file(Path::new(bin));
    }
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };
    for dir in std::env::split_paths(&path) {
        if is_executable_file(&dir.join(bin)) {
            return true;
        }
        #[cfg(windows)]
        {
            for ext in ["exe", "cmd", "bat", "com"] {
                if is_executable_file(&dir.join(format!("{bin}.{ext}"))) {
                    return true;
                }
            }
        }
    }
    false
}

/// `true` when `path` is a regular file that is executable on this platform.
fn is_executable_file(path: &Path) -> bool {
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    if !meta.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

// ---------------------------------------------------------------------------
// Check 5 — Proxy environment support
// ---------------------------------------------------------------------------

fn check_proxy_env() -> CheckResult {
    // On supported platforms the variables are always readable; reading them
    // never fails (an unset variable simply reads as absent).
    let http = std::env::var_os("FIDA_HTTP_PROXY").is_some();
    let https = std::env::var_os("FIDA_HTTPS_PROXY").is_some();
    let detail = match (http, https) {
        (true, true) => "FIDA_HTTP_PROXY and FIDA_HTTPS_PROXY are set".to_string(),
        (true, false) => "FIDA_HTTP_PROXY is set; FIDA_HTTPS_PROXY is unset".to_string(),
        (false, true) => "FIDA_HTTPS_PROXY is set; FIDA_HTTP_PROXY is unset".to_string(),
        (false, false) => {
            "proxy variables are readable (FIDA_HTTP_PROXY/FIDA_HTTPS_PROXY currently unset)"
                .to_string()
        }
    };
    CheckResult {
        key: "proxy_env",
        name: "Proxy environment support",
        status: Status::Pass,
        detail,
        hint: None,
    }
}

// ---------------------------------------------------------------------------
// Check 6 — MCP configuration detection
// ---------------------------------------------------------------------------

fn check_mcp_config(compiled: Option<&fida_policy::CompiledPolicy>) -> CheckResult {
    let key = "mcp_config";
    let name = "MCP configuration detection";

    let Some(policy) = compiled else {
        return CheckResult {
            key,
            name,
            status: Status::Warn,
            detail: "policy could not be loaded to detect MCP configuration".to_string(),
            hint: Some("run `fida policy check` to diagnose the policy".to_string()),
        };
    };

    let tools = &policy.mcp.tools;
    let rule_count = tools.allow.len() + tools.ask.len() + tools.deny.len();
    if rule_count > 0 {
        CheckResult {
            key,
            name,
            status: Status::Pass,
            detail: format!("found MCP tool policy ({rule_count} rule(s))"),
            hint: None,
        }
    } else {
        CheckResult {
            key,
            name,
            status: Status::Warn,
            detail: "no MCP configuration found in policy".to_string(),
            hint: Some(
                "add an `mcp.tools` section to your policy if you use MCP servers".to_string(),
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// Check 7 — Agent guard coverage (per-detected-agent backstop level)
// ---------------------------------------------------------------------------

fn check_agent_coverage(root: &Path) -> CheckResult {
    let key = "agent_guard_coverage";
    let name = "Agent guard coverage";

    let home = crate::commands::shell_hook::home_dir().ok();
    let path_env = std::env::var_os("PATH");

    // Which known agents are present here, with their full layer coverage.
    let detected: Vec<AgentCoverage> = integrations::coverage_matrix()
        .into_iter()
        .filter(|cov| {
            integrations::find_agent(cov.id)
                .map(|spec| integrations::detect(&spec, root, home.as_deref(), path_env.as_deref()))
                .unwrap_or(false)
        })
        .collect();

    if detected.is_empty() {
        return CheckResult {
            key,
            name,
            status: Status::Pass,
            detail: "no IDE-embedded coding agents detected on this machine".to_string(),
            hint: None,
        };
    }

    // Render each agent's wired layers honestly: gateway + skill + the actual
    // backstop strength (no "hook" part when the agent has no hook).
    let describe = |c: &AgentCoverage| {
        let mut parts: Vec<String> = Vec::new();
        if c.gateway {
            parts.push("gateway".to_string());
        }
        if c.skill {
            parts.push("skill".to_string());
        }
        if c.backstop != Backstop::SkillOnly {
            parts.push(format!("hook:{}", c.backstop.label()));
        }
        format!("{} [{}]", c.display, parts.join("+"))
    };
    let summary = detected.iter().map(describe).collect::<Vec<_>>().join(", ");

    // Agents without a hard block rely on the gateway + assertive skill alone
    // for their *native* tools — surface that honestly rather than implying
    // every agent is airtight.
    let weak: Vec<&str> = detected
        .iter()
        .filter(|c| c.backstop != Backstop::HardBlock)
        .map(|c| c.display)
        .collect();

    if weak.is_empty() {
        CheckResult {
            key,
            name,
            status: Status::Pass,
            detail: format!("detected agents have a hard-block backstop: {summary}"),
            hint: Some("run `fida init` to wire each agent if you have not already".to_string()),
        }
    } else {
        CheckResult {
            key,
            name,
            status: Status::Warn,
            detail: format!("detected agents: {summary}"),
            hint: Some(format!(
                "{} rely on the gateway + skill (no hard block on native tools); add an \
                 OS-level backstop with `FIDA_SANDBOX=1`, and run `fida init` to wire them",
                weak.join(", ")
            )),
        }
    }
}

// ---------------------------------------------------------------------------
// Check 8 — OS sandbox availability
// ---------------------------------------------------------------------------

fn check_os_sandbox() -> CheckResult {
    let key = "os_sandbox";
    let name = "OS sandbox availability";

    let available = fida_mcp::sandbox::available();
    let enabled = matches!(
        std::env::var("FIDA_SANDBOX").ok().as_deref(),
        Some("1") | Some("true") | Some("yes")
    );

    match (available, enabled) {
        (true, true) => CheckResult {
            key,
            name,
            status: Status::Pass,
            detail: "OS sandbox backend available and FIDA_SANDBOX is enabled".to_string(),
            hint: None,
        },
        (true, false) => CheckResult {
            key,
            name,
            status: Status::Pass,
            detail: "OS sandbox backend available (FIDA_SANDBOX is off)".to_string(),
            hint: Some(
                "set FIDA_SANDBOX=1 to network-isolate gateway commands and block \
                 secret-store reads"
                    .to_string(),
            ),
        },
        (false, true) => CheckResult {
            key,
            name,
            status: Status::Warn,
            detail: "FIDA_SANDBOX is enabled but no sandbox backend is available here".to_string(),
            hint: Some(
                "install sandbox-exec (macOS) or bwrap (Linux); without a backend \
                 FIDA_SANDBOX is a no-op"
                    .to_string(),
            ),
        },
        (false, false) => CheckResult {
            key,
            name,
            status: Status::Pass,
            detail: "no OS sandbox backend on this platform (gateway + skill + hook still apply)"
                .to_string(),
            hint: None,
        },
    }
}

// ---------------------------------------------------------------------------
// Output (honors --json/--no-color/--quiet/--verbose)
// ---------------------------------------------------------------------------

/// Print all six results, then a summary. JSON when `--json`, otherwise a
/// per-check text line with remediation hints for non-pass results.
fn emit(results: &[CheckResult], ctx: &GlobalContext) {
    if ctx.json {
        println!("{}", to_json(results));
        return;
    }

    let no_color = ctx.no_color;
    let reset = if no_color { "" } else { "\u{1b}[0m" };

    for r in results {
        // In quiet mode, only surface checks that need attention.
        if ctx.is_quiet() && r.status == Status::Pass {
            continue;
        }
        let color = r.status.color(no_color);
        let label = r.status.tag().to_uppercase();
        println!("[{color}{label}{reset}] {}: {}", r.name, r.detail);
        if let Some(hint) = &r.hint {
            println!("        ↳ hint: {hint}");
        }
    }

    let passes = results.iter().filter(|r| r.status == Status::Pass).count();
    let warns = results.iter().filter(|r| r.status == Status::Warn).count();
    let fails = results.iter().filter(|r| r.status == Status::Fail).count();

    if any_fatal(results) {
        println!("doctor: {fails} check(s) failed, {warns} warning(s), {passes} passed");
    } else if ctx.is_verbose() || !ctx.is_quiet() {
        println!("doctor: all checks passed ({passes} ok, {warns} warning(s))");
    }
}

/// Render the results as a single JSON object. Built by hand to avoid pulling a
/// serializer into the CLI crate; all dynamic strings are escaped.
fn to_json(results: &[CheckResult]) -> String {
    let mut out = String::from("{\"checks\":[");
    for (i, r) in results.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str("{\"name\":\"");
        out.push_str(&json_escape(r.key));
        out.push_str("\",\"label\":\"");
        out.push_str(&json_escape(r.name));
        out.push_str("\",\"status\":\"");
        out.push_str(r.status.tag());
        out.push_str("\",\"detail\":\"");
        out.push_str(&json_escape(&r.detail));
        out.push_str("\",\"hint\":");
        match &r.hint {
            Some(h) => {
                out.push('"');
                out.push_str(&json_escape(h));
                out.push('"');
            }
            None => out.push_str("null"),
        }
        out.push('}');
    }
    out.push_str("],\"ok\":");
    out.push_str(if any_fatal(results) { "false" } else { "true" });
    out.push('}');
    out
}

/// Minimal JSON string escaper for control characters and `"`/`\`.
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// A scratch directory under the system temp dir, removed on drop. Avoids a
    /// dev-dependency on `tempfile` (this module owns only `doctor.rs`).
    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new(tag: &str) -> Self {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "fida-doctor-test-{tag}-{}-{nanos}",
                std::process::id()
            ));
            std::fs::create_dir_all(&path).unwrap();
            TempDir { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    fn write_policy(root: &Path, rel: &str, body: &str) {
        let path = root.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, body).unwrap();
    }

    /// A policy with an MCP tools rule and no configured agents — satisfies the
    /// MCP and agent checks for the all-pass scenario.
    const POLICY_WITH_MCP: &str = "version: 1
default_decision: ask
mcp:
  tools:
    allow:
      - pattern: \"docs.*\"
";

    #[test]
    fn runs_all_checks() {
        let dir = TempDir::new("six");
        let results = run_checks(dir.path(), None);
        assert_eq!(
            results.len(),
            9,
            "policy/protection/git/session/agents/proxy/mcp + coverage + sandbox"
        );
        // Every check produces a name + status line.
        for r in &results {
            assert!(!r.name.is_empty());
            assert!(!r.detail.is_empty());
        }
    }

    #[test]
    fn all_checks_pass_in_initialized_repo() {
        let dir = TempDir::new("allpass");
        // Best-effort git repo; the git check is informational either way.
        let _ = std::process::Command::new("git")
            .arg("init")
            .current_dir(dir.path())
            .output();
        write_policy(dir.path(), ".fida/policy.yaml", POLICY_WITH_MCP);

        let results = run_checks(dir.path(), None);

        assert!(
            !any_fatal(&results),
            "no fatal checks should fail: {results:?}"
        );
        // The three fatal checks must each pass.
        for key in ["policy_discovery", "session_dir_writable", "agent_binaries"] {
            let r = results.iter().find(|r| r.key == key).unwrap();
            assert_eq!(r.status, Status::Pass, "{key} should pass: {r:?}");
        }
        // MCP config is detected from the policy.
        let mcp = results.iter().find(|r| r.key == "mcp_config").unwrap();
        assert_eq!(mcp.status, Status::Pass);
    }

    #[test]
    fn missing_config_is_a_fatal_failure_with_hint() {
        let dir = TempDir::new("badconfig");
        let missing = dir.path().join("does-not-exist.yaml");

        let results = run_checks(dir.path(), Some(&missing));

        assert!(any_fatal(&results), "a bad --config must fail the run");
        let policy = results
            .iter()
            .find(|r| r.key == "policy_discovery")
            .unwrap();
        assert_eq!(policy.status, Status::Fail);
        assert!(
            policy.hint.is_some(),
            "failing checks carry a remediation hint"
        );
    }

    #[test]
    fn missing_agent_binary_is_fatal() {
        let agents = ["fida-agent-that-does-not-exist-zzz".to_string()];
        let result = check_agent_binaries(Some(&agents));
        assert_eq!(result.status, Status::Fail);
        assert!(result.hint.is_some());
    }

    #[test]
    fn no_configured_agents_passes() {
        let agents: [String; 0] = [];
        let result = check_agent_binaries(Some(&agents));
        assert_eq!(result.status, Status::Pass);
    }

    #[test]
    fn proxy_check_always_passes() {
        assert_eq!(check_proxy_env().status, Status::Pass);
    }

    #[test]
    fn session_writability_detects_writable_dir() {
        let dir = TempDir::new("writable");
        let result = check_session_writability(dir.path());
        assert_eq!(result.status, Status::Pass);
        // The probe file must be cleaned up.
        let leftovers: Vec<_> = std::fs::read_dir(sessions_root(dir.path()))
            .map(|rd| {
                rd.filter_map(Result::ok)
                    .filter(|e| e.file_name().to_string_lossy().starts_with(".fida-doctor-"))
                    .collect()
            })
            .unwrap_or_default();
        assert!(leftovers.is_empty(), "temp probe file should be removed");
    }

    #[test]
    fn json_output_is_well_formed_and_escaped() {
        let results = vec![CheckResult {
            key: "demo",
            name: "Demo \"check\"",
            status: Status::Fail,
            detail: "line1\nline2\tend".to_string(),
            hint: Some("do \\ this".to_string()),
        }];
        let json = to_json(&results);
        assert!(json.starts_with('{') && json.ends_with('}'));
        assert!(json.contains("\\\"check\\\""));
        assert!(json.contains("line1\\nline2\\tend"));
        assert!(json.contains("\"ok\":false"));
    }
}
