//! `fida-scan` — Secret_Scan: repository secret-risk traversal, classification,
//! enrichment, and redaction-safe reporting (spec tasks 2.x, 13.x; design
//! "`fida-scan` — Secret Scan").
//!
//! The crate is intentionally free of any CLI or network dependency so the
//! redaction-safety (R3) and traversal (R13) invariants can be reasoned about
//! in isolation. It reuses [`fida_secrets::Scanner`] for content detection and
//! [`fida_policy::evaluate`] for per-file policy coverage; it never
//! re-implements detection and never copies secret bytes into any output.
//!
//! The MCP risk scanner (R8, lower priority) lives in [`mod@mcp`].

use std::path::{Path, PathBuf};

use fida_action::{Action, ActionKind, ActionPayload, Actor, Decision, ProtectionLevel};
use fida_policy::CompiledPolicy;
use fida_secrets::{Scanner, SecretScanner};
use serde::Serialize;

pub mod mcp;

pub use mcp::{
    McpAgentSource, McpConfigError, McpRead, McpRiskFinding, McpRiskReport, RiskCategory,
};

/// The default per-file content-scan size cap: 5 MiB (R2.2). Files larger than
/// this are recorded but never opened for content scanning.
pub const DEFAULT_MAX_FILE_BYTES: u64 = 5 * 1024 * 1024;

/// Directories pruned from traversal by default, together with their entire
/// subtree (R13.1).
pub const DEFAULT_EXCLUDED_DIRS: &[&str] =
    &[".git", "target", "node_modules", "dist", "build", ".next"];

/// Marker emitted in place of any output item that cannot be proven free of
/// secret material (R3.5, fail-closed).
pub const WITHHELD_MARKER: &str = "<withheld for redaction safety>";

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Inputs controlling a scan.
#[derive(Debug, Clone)]
pub struct ScanOptions {
    /// Root directory to scan (`--path`, default `.`).
    pub root: PathBuf,
    /// Include git-ignored files (`--include-ignored`, R2.18).
    pub include_ignored: bool,
    /// Additional directory names to prune, in addition to the defaults (R13.5).
    pub extra_excludes: Vec<String>,
    /// Per-file content-scan size cap in bytes (R2.2).
    pub max_file_bytes: u64,
}

impl ScanOptions {
    /// Options for scanning `root` with all defaults.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        ScanOptions {
            root: root.into(),
            include_ignored: false,
            extra_excludes: Vec::new(),
            max_file_bytes: DEFAULT_MAX_FILE_BYTES,
        }
    }
}

/// A configured agent's readable root, used for the agent-exposure check (R2.6).
#[derive(Debug, Clone)]
pub struct AgentRoot {
    /// The agent's display name (for recommendations).
    pub name: String,
    /// A directory the agent can read.
    pub root: PathBuf,
    /// Strength of the installed integration that mediates reads from this root.
    pub protection: ProtectionLevel,
}

/// The assessed repository risk level (R2.7–2.9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    High,
    Medium,
    Low,
}

/// Whether a sensitive file is tracked by git (R2.3, R2.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Tracked {
    Yes,
    No,
    NotApplicable,
}

/// Which sensitive-file pattern a file name matched (R2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SensitiveKind {
    /// `.env` or `.env.*`.
    DotEnv,
    /// `*.pem`.
    Pem,
    /// `*.key`.
    Key,
    /// `id_rsa`.
    IdRsa,
    /// `id_ed25519`.
    IdEd25519,
}

/// One discovered sensitive file. Carries the path and pattern ids only — never
/// any secret value, length, or fragment (R2.19, R3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FileFinding {
    /// Path relative to the scan root.
    pub path: PathBuf,
    /// The sensitive-file category the name matched.
    pub category: SensitiveKind,
    /// Whether git tracks the file.
    pub git_tracked: Tracked,
    /// Whether the active policy covers (deny/ask) a read of this file (R2.5).
    pub policy_covered: bool,
    /// Whether a configured agent can reach the file (R2.6).
    pub agent_reachable: bool,
    /// Strongest honest statement about whether raw values can reach a model.
    pub protection: ProtectionLevel,
    /// Whether at least one reachable agent lacks an enforced native-tool
    /// backstop, so a raw value could bypass the redacting gateway.
    pub raw_secret_exposure: bool,
    /// Pattern ids of secret content matches — never the matched text (R3.4).
    pub content_patterns: Vec<String>,
    /// Whether content was scanned (`false` for files over the size cap, R2.2).
    pub content_scanned: bool,
}

/// One regular (non-name-sensitive) source file found to contain a hardcoded
/// secret (R2.1 content-in-source). Carries the path and pattern ids only —
/// never any secret value, length, or fragment (R2.19, R3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ContentFinding {
    /// Path relative to the scan root.
    pub path: PathBuf,
    /// Whether git tracks the file (a tracked hardcoded secret is committed).
    pub git_tracked: Tracked,
    /// Pattern ids of secret content matches — never the matched text (R3.4).
    pub content_patterns: Vec<String>,
}

/// An entry skipped during traversal: an excluded directory or an inaccessible
/// path (R2.13, R13.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SkippedEntry {
    /// Path relative to the scan root.
    pub path: PathBuf,
    /// Why the entry was skipped.
    pub reason: String,
}

/// The full result of a scan.
#[derive(Debug, Clone, Serialize)]
pub struct ScanResult {
    /// The assessed risk level.
    pub risk: RiskLevel,
    /// Whether the scan root is a git repository.
    pub git_repo: bool,
    /// Weakest protection level among agents that can read this scan root.
    pub protection: ProtectionLevel,
    /// Whether any discovered sensitive file has a path to a model that is not
    /// enforced by a hard-blocking integration.
    pub raw_secret_exposure: bool,
    /// Discovered sensitive files.
    pub findings: Vec<FileFinding>,
    /// Hardcoded secrets discovered inside regular source files (R2.1).
    pub content_findings: Vec<ContentFinding>,
    /// Skipped (excluded or inaccessible) entries.
    pub skipped: Vec<SkippedEntry>,
    /// Risk-appropriate recommendations.
    pub recommendations: Vec<String>,
    /// MCP risk report, populated only for `--mcp`/`--agents` (R8).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mcp: Option<McpRiskReport>,
}

/// A scan failure that happens before any traversal.
#[derive(Debug)]
pub enum ScanError {
    /// `--path` is missing or unreadable (R2.12).
    UnreadableRoot { path: PathBuf, reason: String },
}

impl std::fmt::Display for ScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanError::UnreadableRoot { path, reason } => {
                write!(
                    f,
                    "scan path {} is missing or unreadable: {reason}",
                    path.display()
                )
            }
        }
    }
}

impl std::error::Error for ScanError {}

// ---------------------------------------------------------------------------
// Classification (R2.1)
// ---------------------------------------------------------------------------

/// Classify a file *name* as a sensitive file, or `None` (R2.1).
///
/// Matches exactly `.env`, `.env.*`, `*.pem`, `*.key`, `id_rsa`, `id_ed25519`.
pub fn classify(name: &str) -> Option<SensitiveKind> {
    if name == ".env" || name.starts_with(".env.") {
        Some(SensitiveKind::DotEnv)
    } else if name == "id_rsa" {
        Some(SensitiveKind::IdRsa)
    } else if name == "id_ed25519" {
        Some(SensitiveKind::IdEd25519)
    } else if name.ends_with(".pem") {
        Some(SensitiveKind::Pem)
    } else if name.ends_with(".key") {
        Some(SensitiveKind::Key)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Scan orchestration
// ---------------------------------------------------------------------------

/// A sensitive file discovered during traversal, before enrichment.
struct Candidate {
    /// Path relative to the scan root.
    rel: PathBuf,
    category: SensitiveKind,
    /// Size in bytes, as reported by the single metadata lookup.
    len: u64,
}

/// Scan `root` for sensitive files, classifying, enriching, and assessing risk.
///
/// Returns [`ScanError::UnreadableRoot`] before any traversal when the root is
/// missing or unreadable (R2.12). The MCP report is left `None`; callers wanting
/// it run [`mcp::scan_mcp`] and assign [`ScanResult::mcp`].
pub fn scan(
    opts: &ScanOptions,
    policy: &CompiledPolicy,
    agents: &[AgentRoot],
) -> Result<ScanResult, ScanError> {
    // R2.12: a missing/unreadable root is a typed error before any traversal.
    match std::fs::read_dir(&opts.root) {
        Ok(_) => {}
        Err(e) => {
            return Err(ScanError::UnreadableRoot {
                path: opts.root.clone(),
                reason: e.to_string(),
            });
        }
    }

    let git_repo = opts.root.join(".git").exists();
    let scanner = Scanner::new(&policy.secrets);

    let mut excludes: Vec<String> = DEFAULT_EXCLUDED_DIRS
        .iter()
        .map(|s| s.to_string())
        .collect();
    excludes.extend(opts.extra_excludes.iter().cloned());

    let walk = walk(&opts.root, &excludes);
    let mut skipped = walk.skipped;

    let mut findings = Vec::new();
    for cand in walk.candidates {
        // Sensitive names are always scanned, even when git-ignored. Ignored
        // `.env` and private-key files are exactly the local files most likely
        // to hold credentials an agent can accidentally read.
        // ponytail: one `git check-ignore` per *sensitive* candidate (few),
        // not per traversed file; relies on the `git` binary the project
        // already requires. Upgrade path: a bundled gitignore matcher.
        let finding = enrich(
            opts,
            policy,
            agents,
            &scanner,
            git_repo,
            &cand,
            &mut skipped,
        );
        findings.push(finding);
    }

    // Content-only pass: scan regular source files for hardcoded secrets.
    let content_findings =
        scan_regular_files(opts, &scanner, git_repo, &walk.regular, &mut skipped);

    let protection = weakest_protection(agents);
    let raw_secret_exposure = findings.iter().any(|f| f.raw_secret_exposure);
    let risk = assess_risk(&findings, &content_findings);
    let recommendations = recommendations(risk, &findings, &content_findings);

    Ok(ScanResult {
        risk,
        git_repo,
        protection,
        raw_secret_exposure,
        findings,
        content_findings,
        skipped,
        recommendations,
        mcp: None,
    })
}

/// Scan each regular (non-name-sensitive) file for hardcoded secrets using the
/// high-precision source detector ([`Scanner::scan_code`], which skips the
/// broad `.env` `KEY=value` heuristic). Only files that actually contain a
/// secret incur a `git` lookup, so the expensive subprocess work stays
/// proportional to findings, not to repository size.
///
/// ponytail: reads every non-excluded file under the size cap to regex it in
/// process — the inherent cost of content scanning, bounded by the default
/// directory excludes and the 5 MiB cap. Ceiling: a huge repo pays one read per
/// file; upgrade path is parallel reads or a gitignore-aware streaming walker.
/// Over-cap, unreadable, and binary (NUL-containing) files are skipped silently
/// to keep the skipped list signal-rich rather than listing every large asset.
fn scan_regular_files(
    opts: &ScanOptions,
    scanner: &Scanner,
    git_repo: bool,
    regular: &[RegularFile],
    skipped: &mut Vec<SkippedEntry>,
) -> Vec<ContentFinding> {
    let mut out = Vec::new();
    for file in regular {
        if file.len > opts.max_file_bytes {
            continue;
        }
        let abs = opts.root.join(&file.rel);
        let Ok(bytes) = std::fs::read(&abs) else {
            continue;
        };
        // Skip binaries: a NUL byte means it is not source text, and the
        // anchored provider patterns would only yield noise.
        if bytes.contains(&0) {
            continue;
        }

        let text = String::from_utf8_lossy(&bytes);
        let mut ids: Vec<String> = scanner
            .scan_code(&text)
            .into_iter()
            .map(|f| safe_pattern_id(&f.pattern_id))
            .collect();
        if ids.is_empty() {
            continue;
        }
        ids.sort();
        ids.dedup();

        // Only files with a real match reach git (R2.18 + perf): respect
        // --include-ignored, then record tracking status.
        if !opts.include_ignored && git_repo && git_check_ignore(&opts.root, &file.rel) {
            skipped.push(SkippedEntry {
                path: file.rel.clone(),
                reason: "git-ignored (pass --include-ignored to include)".to_string(),
            });
            continue;
        }
        let git_tracked = if git_repo {
            if git_is_tracked(&opts.root, &file.rel) {
                Tracked::Yes
            } else {
                Tracked::No
            }
        } else {
            Tracked::NotApplicable
        };

        out.push(ContentFinding {
            path: file.rel.clone(),
            git_tracked,
            content_patterns: ids,
        });
    }
    out
}

/// Enrich one candidate into a [`FileFinding`]: content scan, git tracking,
/// policy coverage, and agent reachability.
fn enrich(
    opts: &ScanOptions,
    policy: &CompiledPolicy,
    agents: &[AgentRoot],
    scanner: &Scanner,
    git_repo: bool,
    cand: &Candidate,
    skipped: &mut Vec<SkippedEntry>,
) -> FileFinding {
    let abs = opts.root.join(&cand.rel);

    // Content scan (R2.2): only files within the size cap are opened.
    let (content_patterns, content_scanned) = if cand.len <= opts.max_file_bytes {
        match std::fs::read(&abs) {
            Ok(bytes) => {
                let text = String::from_utf8_lossy(&bytes);
                let mut ids: Vec<String> = scanner
                    .scan(&text)
                    .into_iter()
                    .map(|f| safe_pattern_id(&f.pattern_id))
                    .collect();
                ids.sort();
                ids.dedup();
                (ids, true)
            }
            Err(e) => {
                // Unreadable content: record and continue without opening (R2.13).
                skipped.push(SkippedEntry {
                    path: cand.rel.clone(),
                    reason: format!("content unreadable: {e}"),
                });
                (Vec::new(), false)
            }
        }
    } else {
        (Vec::new(), false)
    };

    let git_tracked = if git_repo {
        if git_is_tracked(&opts.root, &cand.rel) {
            Tracked::Yes
        } else {
            Tracked::No
        }
    } else {
        Tracked::NotApplicable
    };

    // Strict policy coverage (R2.5): a read resolves to deny or ask. An allowed
    // read can still be safe when it goes through Fida's redaction gateway.
    let read_decision = fida_policy::evaluate(policy, &file_read_action(&cand.rel)).decision;
    let policy_covered = matches!(read_decision, Decision::Deny | Decision::Ask);

    // Agent reachability (R2.6): under a configured agent's readable root and
    // not denied by policy.
    let reachable: Vec<&AgentRoot> = if read_decision == Decision::Deny {
        Vec::new()
    } else {
        agents.iter().filter(|a| abs.starts_with(&a.root)).collect()
    };
    let agent_reachable = !reachable.is_empty();
    let protection = weakest_protection_refs(&reachable);
    let raw_secret_exposure = reachable
        .iter()
        .any(|a| a.protection.raw_secret_exposure_possible());

    FileFinding {
        path: cand.rel.clone(),
        category: cand.category,
        git_tracked,
        policy_covered,
        agent_reachable,
        protection,
        raw_secret_exposure,
        content_patterns,
        content_scanned,
    }
}

/// Build a synthetic `file.read` action for policy evaluation against `rel`.
fn file_read_action(rel: &Path) -> Action {
    Action {
        kind: ActionKind::FileRead,
        actor: Actor::Agent,
        payload: ActionPayload::File {
            path: rel.to_path_buf(),
        },
    }
}

// ---------------------------------------------------------------------------
// Risk + recommendations (R2.7–2.10)
// ---------------------------------------------------------------------------

/// Assign the risk level from the set of findings (R2.7–2.9).
fn assess_risk(findings: &[FileFinding], content_findings: &[ContentFinding]) -> RiskLevel {
    let sensitive_high = findings
        .iter()
        .any(|f| f.git_tracked == Tracked::Yes || f.raw_secret_exposure);
    // A hardcoded secret committed to git is the worst case: it is in history.
    let content_high = content_findings
        .iter()
        .any(|f| f.git_tracked == Tracked::Yes);
    if sensitive_high || content_high {
        RiskLevel::High
    } else if !findings.is_empty() || !content_findings.is_empty() {
        // Any sensitive file or hardcoded secret (not tracked/reachable) -> medium.
        RiskLevel::Medium
    } else {
        RiskLevel::Low
    }
}

/// Produce recommendations corresponding to the assigned risk level (R2.10).
fn recommendations(
    risk: RiskLevel,
    findings: &[FileFinding],
    content_findings: &[ContentFinding],
) -> Vec<String> {
    let mut recs = Vec::new();
    match risk {
        RiskLevel::High => {
            for f in findings.iter().filter(|f| f.git_tracked == Tracked::Yes) {
                recs.push(format!(
                    "Untrack {} from git and rotate any exposed secret",
                    f.path.display()
                ));
            }
            if findings.iter().any(|f| f.raw_secret_exposure) {
                recs.push(
                    "Run `fida init` and restart the agent; at least one reachable agent can bypass Fida's redacting gateway with native tools"
                        .to_string(),
                );
            }
            if findings.iter().any(|f| !f.policy_covered) {
                recs.push(
                    "Use the strict-firewall preset or explicit read deny rules only when a redacted safe view is not sufficient"
                        .to_string(),
                );
            }
            for f in content_findings
                .iter()
                .filter(|f| f.git_tracked == Tracked::Yes)
            {
                recs.push(format!(
                    "Remove the hardcoded secret in {} and rotate it immediately — it is committed to git history; load it from an environment variable or secret manager instead",
                    f.path.display()
                ));
            }
        }
        RiskLevel::Medium => {
            if !findings.is_empty() {
                recs.push(
                    "Keep sensitive reads on the Fida gateway; use strict-firewall only when path blocking is required"
                        .to_string(),
                );
            }
            if findings.iter().any(|f| !f.content_patterns.is_empty()) {
                recs.push(
                    "A sensitive file contains secret-looking content; rotate it and keep it out of the working tree"
                        .to_string(),
                );
            }
            for f in content_findings {
                recs.push(format!(
                    "Remove the hardcoded secret in {} and rotate it; load it from an environment variable or secret manager instead",
                    f.path.display()
                ));
            }
        }
        RiskLevel::Low => {
            recs.push("No sensitive files found; no action needed".to_string());
        }
    }
    recs
}

// ---------------------------------------------------------------------------
// Traversal (R13)
// ---------------------------------------------------------------------------

/// The output of a directory walk.
struct Walk {
    candidates: Vec<Candidate>,
    /// Regular (non-name-sensitive) files, scanned for hardcoded secrets.
    regular: Vec<RegularFile>,
    skipped: Vec<SkippedEntry>,
}

/// A regular file discovered during traversal: a candidate for content-only
/// secret scanning (its name matched no sensitive pattern).
struct RegularFile {
    /// Path relative to the scan root.
    rel: PathBuf,
    /// Size in bytes, as reported by the single metadata lookup.
    len: u64,
}

/// A canonical key identifying a directory so a cycle never visits it twice.
#[cfg(unix)]
type DirKey = (u64, u64);
#[cfg(not(unix))]
type DirKey = PathBuf;

/// Iteratively walk `root`, pruning every excluded directory subtree, visiting
/// each non-excluded regular file at most once, and recording skipped entries
/// (R13.1, R13.2, R13.4).
///
/// ponytail: symlinks are never followed (neither descended nor scanned). A
/// normal directory tree has no cycles, so not following symlinks is the
/// simplest sound defense against symlink loops; a `visited` set on
/// `(dev, inode)` guards against bind-mount style aliasing too. Ceiling: a
/// regular file reachable only via a symlink is not scanned.
fn walk(root: &Path, excludes: &[String]) -> Walk {
    let mut candidates = Vec::new();
    let mut regular = Vec::new();
    let mut skipped = Vec::new();
    let mut visited: std::collections::HashSet<DirKey> = std::collections::HashSet::new();

    // Stack of absolute directories left to visit.
    let mut stack: Vec<PathBuf> = vec![root.to_path_buf()];

    while let Some(dir) = stack.pop() {
        if let Some(key) = dir_key(&dir) {
            if !visited.insert(key) {
                continue; // already visited via another path (cycle/alias)
            }
        }

        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(e) => {
                skipped.push(SkippedEntry {
                    path: rel(root, &dir),
                    reason: format!("unreadable directory: {e}"),
                });
                continue;
            }
        };

        for entry in entries {
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    skipped.push(SkippedEntry {
                        path: rel(root, &dir),
                        reason: format!("unreadable entry: {e}"),
                    });
                    continue;
                }
            };
            let path = entry.path();
            // One metadata lookup per entry; do not follow symlinks (R13.3).
            let meta = match std::fs::symlink_metadata(&path) {
                Ok(m) => m,
                Err(e) => {
                    skipped.push(SkippedEntry {
                        path: rel(root, &path),
                        reason: format!("unreadable entry: {e}"),
                    });
                    continue;
                }
            };
            let ft = meta.file_type();

            if ft.is_symlink() {
                // Never follow symlinks (loop-safe); record and continue.
                continue;
            } else if ft.is_dir() {
                let name = entry.file_name().to_string_lossy().into_owned();
                if excludes.iter().any(|x| x == &name) {
                    skipped.push(SkippedEntry {
                        path: rel(root, &path),
                        reason: "excluded directory".to_string(),
                    });
                    continue;
                }
                stack.push(path);
            } else if ft.is_file() {
                let name = entry.file_name().to_string_lossy().into_owned();
                if let Some(category) = classify(&name) {
                    candidates.push(Candidate {
                        rel: rel(root, &path),
                        category,
                        len: meta.len(),
                    });
                } else {
                    // Non-sensitive name: still scanned for hardcoded secrets.
                    regular.push(RegularFile {
                        rel: rel(root, &path),
                        len: meta.len(),
                    });
                }
            }
            // Other entry kinds (sockets, fifos, devices) are ignored.
        }
    }

    Walk {
        candidates,
        regular,
        skipped,
    }
}

/// The canonical identity of a directory, or `None` when it cannot be stat-ed.
#[cfg(unix)]
fn dir_key(dir: &Path) -> Option<DirKey> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(dir).ok().map(|m| (m.dev(), m.ino()))
}

#[cfg(not(unix))]
fn dir_key(dir: &Path) -> Option<DirKey> {
    std::fs::canonicalize(dir).ok()
}

/// The path of `child` relative to `root`, falling back to `child` itself.
fn rel(root: &Path, child: &Path) -> PathBuf {
    child
        .strip_prefix(root)
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|_| child.to_path_buf())
}

// ---------------------------------------------------------------------------
// Git helpers
// ---------------------------------------------------------------------------

/// Whether git tracks `rel` within `root` (R2.3).
fn git_is_tracked(root: &Path, rel: &Path) -> bool {
    std::process::Command::new("git")
        .current_dir(root)
        .arg("ls-files")
        .arg("--error-unmatch")
        .arg("--")
        .arg(rel)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Whether git ignores `rel` within `root`.
fn git_check_ignore(root: &Path, rel: &Path) -> bool {
    std::process::Command::new("git")
        .current_dir(root)
        .arg("check-ignore")
        .arg("-q")
        .arg("--")
        .arg(rel)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Redaction-safe rendering (R2.14, R2.15, R3)
// ---------------------------------------------------------------------------

/// Return `id` when it is a safe identifier (no secret bytes could hide here),
/// else the withheld marker — fail-closed (R3.5).
fn safe_pattern_id(id: &str) -> String {
    let safe = !id.is_empty()
        && id.len() <= 128
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'));
    if safe {
        id.to_string()
    } else {
        WITHHELD_MARKER.to_string()
    }
}

/// Render a [`ScanResult`] as a single JSON document (R2.14). The result only
/// holds redaction-safe fields, so the rendering carries no secret material.
pub fn render_json(result: &ScanResult) -> String {
    serde_json::to_string_pretty(result).unwrap_or_else(|_| "{}".to_string())
}

/// Render a [`ScanResult`] as a human-readable report (R2.15).
pub fn render_human(result: &ScanResult) -> String {
    let mut out = String::new();
    out.push_str(&format!("Fida scan — risk: {}\n", risk_word(result.risk)));
    out.push_str(&format!(
        "git repository: {}\n\n",
        if result.git_repo { "yes" } else { "no" }
    ));
    out.push_str(&format!(
        "model protection: {} | raw secret exposure: {}\n\n",
        result.protection.as_str(),
        result.raw_secret_exposure
    ));

    if result.findings.is_empty() {
        out.push_str("No sensitive files found.\n");
    } else {
        out.push_str(&format!("Sensitive files ({}):\n", result.findings.len()));
        for f in &result.findings {
            out.push_str(&format!(
                "  {} [{}] git_tracked={} policy_covered={} agent_reachable={} protection={} raw_secret_exposure={}\n",
                f.path.display(),
                kind_word(f.category),
                tracked_word(f.git_tracked),
                f.policy_covered,
                f.agent_reachable,
                f.protection.as_str(),
                f.raw_secret_exposure,
            ));
            if !f.content_scanned {
                out.push_str("    content: not scanned (over size cap)\n");
            } else if !f.content_patterns.is_empty() {
                // Pattern ids only — never matched text (R3.4).
                out.push_str(&format!(
                    "    content matches: {}\n",
                    f.content_patterns.join(", ")
                ));
            }
        }
    }

    if !result.content_findings.is_empty() {
        out.push_str(&format!(
            "\nHardcoded secrets in source ({}):\n",
            result.content_findings.len()
        ));
        for f in &result.content_findings {
            // Pattern ids only — never matched text (R3.4).
            out.push_str(&format!(
                "  {} git_tracked={} patterns: {}\n",
                f.path.display(),
                tracked_word(f.git_tracked),
                f.content_patterns.join(", "),
            ));
        }
    }

    if !result.skipped.is_empty() {
        out.push_str(&format!("\nSkipped ({}):\n", result.skipped.len()));
        for s in &result.skipped {
            out.push_str(&format!("  {} — {}\n", s.path.display(), s.reason));
        }
    }

    if !result.recommendations.is_empty() {
        out.push_str("\nRecommendations:\n");
        for r in &result.recommendations {
            out.push_str(&format!("  - {r}\n"));
        }
    }

    if let Some(mcp) = &result.mcp {
        out.push_str(&mcp::render_human(mcp));
    }

    out
}

fn protection_rank(level: ProtectionLevel) -> u8 {
    match level {
        ProtectionLevel::Enforced => 0,
        ProtectionLevel::BestEffort => 1,
        ProtectionLevel::Incomplete => 2,
        ProtectionLevel::Inactive => 3,
    }
}

fn weakest_protection(agents: &[AgentRoot]) -> ProtectionLevel {
    agents
        .iter()
        .map(|a| a.protection)
        .max_by_key(|level| protection_rank(*level))
        .unwrap_or(ProtectionLevel::Inactive)
}

fn weakest_protection_refs(agents: &[&AgentRoot]) -> ProtectionLevel {
    agents
        .iter()
        .map(|a| a.protection)
        .max_by_key(|level| protection_rank(*level))
        .unwrap_or(ProtectionLevel::Inactive)
}

fn risk_word(r: RiskLevel) -> &'static str {
    match r {
        RiskLevel::High => "high",
        RiskLevel::Medium => "medium",
        RiskLevel::Low => "low",
    }
}

fn tracked_word(t: Tracked) -> &'static str {
    match t {
        Tracked::Yes => "yes",
        Tracked::No => "no",
        Tracked::NotApplicable => "n/a",
    }
}

fn kind_word(k: SensitiveKind) -> &'static str {
    match k {
        SensitiveKind::DotEnv => "dot_env",
        SensitiveKind::Pem => "pem",
        SensitiveKind::Key => "key",
        SensitiveKind::IdRsa => "id_rsa",
        SensitiveKind::IdEd25519 => "id_ed25519",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fida_policy::{PolicySource, load_source};

    fn builtin_policy() -> CompiledPolicy {
        load_source(&PolicySource::BuiltinDefault, None).expect("builtin policy compiles")
    }

    #[test]
    fn classify_matches_only_sensitive_names() {
        assert_eq!(classify(".env"), Some(SensitiveKind::DotEnv));
        assert_eq!(classify(".env.local"), Some(SensitiveKind::DotEnv));
        assert_eq!(classify("server.pem"), Some(SensitiveKind::Pem));
        assert_eq!(classify("private.key"), Some(SensitiveKind::Key));
        assert_eq!(classify("id_rsa"), Some(SensitiveKind::IdRsa));
        assert_eq!(classify("id_ed25519"), Some(SensitiveKind::IdEd25519));
        // Non-matches.
        assert_eq!(classify("environment"), None);
        assert_eq!(classify(".environment"), None);
        assert_eq!(classify("readme.md"), None);
        assert_eq!(classify("keys.txt"), None);
    }

    #[test]
    fn scan_finds_dotenv_and_assigns_risk() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(".env"), "API_KEY=super-secret-value\n").unwrap();
        std::fs::write(dir.path().join("main.rs"), "fn main() {}\n").unwrap();
        // Excluded dir with a secret inside must be pruned.
        std::fs::create_dir_all(dir.path().join("node_modules")).unwrap();
        std::fs::write(dir.path().join("node_modules/.env"), "X=y\n").unwrap();

        let opts = ScanOptions::new(dir.path());
        let policy = builtin_policy();
        let result = scan(&opts, &policy, &[]).unwrap();

        // Exactly the top-level .env (node_modules pruned).
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].path, PathBuf::from(".env"));
        assert_eq!(result.findings[0].category, SensitiveKind::DotEnv);
        // The built-in default relies on gateway redaction rather than a strict
        // path deny, so this is intentionally not marked policy-covered.
        assert!(!result.findings[0].policy_covered);
        // Not git-tracked (no repo), not agent-reachable (no agents).
        assert_eq!(result.findings[0].git_tracked, Tracked::NotApplicable);
        assert!(!result.findings[0].agent_reachable);
        // Content scanned, dotenv value detected by pattern id only.
        assert!(result.findings[0].content_scanned);
        assert!(
            result.findings[0]
                .content_patterns
                .iter()
                .any(|p| p == fida_secrets::DOTENV_PATTERN_ID)
        );
        // No git tracking + no agent reach -> medium.
        assert_eq!(result.risk, RiskLevel::Medium);
        // node_modules recorded as skipped/excluded.
        assert!(result.skipped.iter().any(|s| s.reason.contains("excluded")));
    }

    #[test]
    fn scan_detects_hardcoded_secret_in_source_file() {
        let dir = tempfile::tempdir().unwrap();
        // Assemble the synthetic provider key at runtime so repository secret
        // scanning does not mistake this test fixture for a live credential.
        let secret = ["sk", "_live_", "1234567890abcdefghijklmnopqrstuv"].concat();
        std::fs::write(
            dir.path().join("page.tsx"),
            format!("const key = \"{secret}\";\nexport default function Home() {{}}\n"),
        )
        .unwrap();
        // A benign `key = value` line must NOT be flagged: scan_code excludes
        // the broad .env heuristic, so ordinary source assignments are quiet.
        std::fs::write(dir.path().join("config.toml"), "version = \"1.2.3\"\n").unwrap();

        let result = scan(&ScanOptions::new(dir.path()), &builtin_policy(), &[]).unwrap();

        // No name-sensitive files; the hardcoded key is a content finding.
        assert!(result.findings.is_empty());
        assert_eq!(result.content_findings.len(), 1);
        assert_eq!(result.content_findings[0].path, PathBuf::from("page.tsx"));
        assert!(
            result.content_findings[0]
                .content_patterns
                .iter()
                .any(|p| p == "stripe_secret_key")
        );
        // No git repo -> tracking n/a -> medium (present but not committed).
        assert_eq!(
            result.content_findings[0].git_tracked,
            Tracked::NotApplicable
        );
        assert_eq!(result.risk, RiskLevel::Medium);

        // Redaction-safety: neither renderer leaks the secret value.
        let human = render_human(&result);
        let json = render_json(&result);
        assert!(!human.contains(&secret));
        assert!(!json.contains(&secret));
    }

    #[test]
    fn empty_dir_is_low_risk() {
        let dir = tempfile::tempdir().unwrap();
        let result = scan(&ScanOptions::new(dir.path()), &builtin_policy(), &[]).unwrap();
        assert!(result.findings.is_empty());
        assert_eq!(result.risk, RiskLevel::Low);
    }

    #[test]
    fn missing_root_is_an_error_before_traversal() {
        let opts = ScanOptions::new("/this/path/does/not/exist/at/all");
        let err = scan(&opts, &builtin_policy(), &[]).unwrap_err();
        assert!(matches!(err, ScanError::UnreadableRoot { .. }));
    }

    #[test]
    fn agent_reachable_when_default_policy_allows_redacted_read() {
        let dir = tempfile::tempdir().unwrap();
        // A sensitive file under the default policy remains readable through
        // the redaction gateway, so it exercises agent reachability.
        std::fs::write(dir.path().join("notes.txt"), "x\n").unwrap();
        // Use a *.key path so the filename is classified as sensitive.
        std::fs::write(dir.path().join("app.key"), "AKIA0000000000000000\n").unwrap();
        let agents = vec![AgentRoot {
            name: "claude".to_string(),
            root: dir.path().to_path_buf(),
            protection: ProtectionLevel::Enforced,
        }];
        let result = scan(&ScanOptions::new(dir.path()), &builtin_policy(), &agents).unwrap();
        let f = result
            .findings
            .iter()
            .find(|f| f.path == Path::new("app.key"))
            .unwrap();
        // Default policy allows the read so the gateway can return a redacted
        // safe view; scan still reports that an installed agent can reach it.
        assert!(!f.policy_covered);
        assert!(f.agent_reachable);
        assert!(!f.raw_secret_exposure);
        assert_eq!(result.risk, RiskLevel::Medium);
    }

    #[test]
    fn best_effort_agent_makes_raw_secret_exposure_high() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(".env"), "TOKEN=synthetic-secret-value\n").unwrap();
        let agents = vec![AgentRoot {
            name: "cursor".to_string(),
            root: dir.path().to_path_buf(),
            protection: ProtectionLevel::BestEffort,
        }];
        let result = scan(&ScanOptions::new(dir.path()), &builtin_policy(), &agents).unwrap();
        assert!(result.raw_secret_exposure);
        assert_eq!(result.risk, RiskLevel::High);
    }

    #[test]
    fn ignored_sensitive_file_is_still_scanned() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path();
        if !std::process::Command::new("git")
            .arg("init")
            .arg("-q")
            .current_dir(repo)
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
        {
            return;
        }
        std::fs::write(repo.join(".gitignore"), ".env\n").unwrap();
        std::fs::write(repo.join(".env"), "TOKEN=synthetic-secret-value\n").unwrap();
        let result = scan(&ScanOptions::new(repo), &builtin_policy(), &[]).unwrap();
        assert!(result.findings.iter().any(|f| f.path == Path::new(".env")));
    }

    #[test]
    fn rendered_output_never_contains_secret_value() {
        let dir = tempfile::tempdir().unwrap();
        let secret = "SUPER-SECRET-TOKEN-0123456789";
        std::fs::write(dir.path().join(".env"), format!("TOKEN={secret}\n")).unwrap();
        let result = scan(&ScanOptions::new(dir.path()), &builtin_policy(), &[]).unwrap();
        let human = render_human(&result);
        let json = render_json(&result);
        assert!(!human.contains(secret));
        assert!(!json.contains(secret));
        // No >=4-char fragment of the secret leaks either.
        for win in secret.as_bytes().windows(8) {
            let frag = std::str::from_utf8(win).unwrap();
            assert!(!human.contains(frag));
            assert!(!json.contains(frag));
        }
    }
}
