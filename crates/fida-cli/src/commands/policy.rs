//! `fida policy …` — inspect, validate, and test policy.
//!
//! **Owners:** `list-presets` -> task 19.2; `check`/`explain`/`test`/`schema`
//! -> task 19.3.

use std::path::{Path, PathBuf};

use clap::{Args, Subcommand};
use fida_action::{Action, ActionKind, ActionPayload, Actor, Decision, DecisionResult, Risk};
use fida_policy::{
    CompiledPolicy, PolicySource, evaluate, load_source, policy_json_schema, resolve_source_in,
    validate_raw,
};
use serde::Deserialize;

use crate::commands::presets;
use crate::context::GlobalContext;
use crate::error::{CliError, CliResult};

/// Arguments for the `fida policy` command family.
#[derive(Debug, Args)]
pub struct PolicyArgs {
    #[command(subcommand)]
    pub command: PolicyCommand,
}

/// `fida policy` subcommands.
#[derive(Debug, Subcommand)]
pub enum PolicyCommand {
    /// Validate policy syntax and schema.
    Check,
    /// Explain the decision for one action.
    Explain(ExplainArgs),
    /// Run policy test cases.
    Test(TestArgs),
    /// Show built-in presets.
    ListPresets,
    /// Print the policy JSON schema.
    Schema,
    /// Suggest an allowlist policy from recorded observations.
    Suggest(SuggestArgs),
}

/// `fida policy suggest [--write]`.
#[derive(Debug, Args)]
pub struct SuggestArgs {
    /// Write the suggested policy as the new current policy after the diff.
    #[arg(long)]
    pub write: bool,
}

/// `fida policy explain <kind> <target>`.
#[derive(Debug, Args)]
pub struct ExplainArgs {
    /// Action kind, e.g. `command` or `file-write`.
    pub kind: String,
    /// The command string or file path to explain.
    pub target: String,
}

/// `fida policy test <cases-file>`.
#[derive(Debug, Args)]
pub struct TestArgs {
    /// Path to a YAML file of policy test cases.
    pub cases_file: std::path::PathBuf,
}

/// Stub dispatcher. Individual arms are implemented by tasks 19.2 / 19.3.
pub async fn run(args: &PolicyArgs, ctx: &GlobalContext) -> CliResult {
    match &args.command {
        // Owned by task 19.2.
        PolicyCommand::ListPresets => list_presets(ctx),
        // Owned by task 19.3.
        PolicyCommand::Check => check(ctx),
        PolicyCommand::Explain(args) => explain(args, ctx),
        PolicyCommand::Test(args) => test(args, ctx),
        PolicyCommand::Schema => schema(ctx),
        PolicyCommand::Suggest(args) => suggest(args, ctx),
    }
}

// ---------------------------------------------------------------------------
// `policy check
// ---------------------------------------------------------------------------

/// Validate the resolved Policy_File against the schema.
///
/// * Conforms -> report valid, exit 0.
/// * Schema violations -> report each as a separate field-attributed entry,
///   exit 4.
/// * No readable policy file found / unreadable -> exit 1. For `check`
///   the built-in default is *not* substituted: a missing repo file means there
///   is nothing to validate.
fn check(ctx: &GlobalContext) -> CliResult {
    let source = resolve_source_in(Path::new("."), ctx.config.as_deref())
        .map_err(|e| CliError::general(e.to_string()))?;

    // `check` validates a real file; the built-in default has no file to read.
    let path = match source.path() {
        Some(p) => p.to_path_buf(),
        None => {
            return Err(CliError::general(
                "no readable policy file was found (looked for --config,.fida/policy.yaml, fida.yaml)",
            ));
        }
    };

    // Read the resolved file directly so an unreadable file is a "no readable
    // policy" condition (exit 1), not a loader error (exit 4).
    let raw = std::fs::read_to_string(&path).map_err(|e| {
        CliError::general(format!(
            "no readable policy file was found: cannot read {}: {e}",
            path.display()
        ))
    })?;

    match validate_raw(&raw) {
        Ok(()) => {
            if ctx.json {
                println!(
                    "{{\"valid\":true,\"path\":{},\"violations\":[]}}",
                    json_string(&path.display().to_string())
                );
            } else if !ctx.is_quiet() {
                println!("Policy {} is valid.", path.display());
            }
            Ok(())
        }
        Err(violations) => {
            if ctx.json {
                let entries = violations
                    .iter()
                    .map(|v| {
                        format!(
                            "{{\"field\":{},\"message\":{}}}",
                            json_string(&v.field_path),
                            json_string(&v.message)
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(",");
                println!(
                    "{{\"valid\":false,\"path\":{},\"violations\":[{entries}]}}",
                    json_string(&path.display().to_string())
                );
            } else {
                eprintln!("Policy {} is invalid:", path.display());
                for v in &violations {
                    eprintln!("  - {}: {}", v.field_path, v.message);
                }
            }
            // Exit 4. The detail mirrors the per-field entries already printed.
            let summary = violations
                .iter()
                .map(|v| format!("{}: {}", v.field_path, v.message))
                .collect::<Vec<_>>()
                .join("; ");
            Err(CliError::InvalidPolicy(summary))
        }
    }
}

// ---------------------------------------------------------------------------
// `policy explain`
// ---------------------------------------------------------------------------

/// Evaluate one action and report decision/risk/reason/matched-rule.
///
/// `command` builds a `command.run` Action (argv = whitespace split of the
/// command string, cwd = current dir); `file-read`/`file-write` build a
/// `file.read`/`file.write` Action for the path. An unknown kind is a usage
/// error -> exit 1.
fn explain(args: &ExplainArgs, ctx: &GlobalContext) -> CliResult {
    let action = build_action(&args.kind, &args.target).ok_or_else(|| {
        CliError::usage(format!(
            "unknown explain kind `{}`; expected `command`, `file-read`, or `file-write`",
            args.kind
        ))
    })?;

    let policy = load_policy(ctx)?;
    let result = evaluate(&policy, &action);
    report_decision(ctx, &args.kind, &args.target, &result);
    Ok(())
}

/// Print a single evaluation result (shared by `explain`).
fn report_decision(ctx: &GlobalContext, kind: &str, target: &str, result: &DecisionResult) {
    if ctx.json {
        println!("{}", decision_json(result));
        return;
    }
    if ctx.is_quiet() {
        // Even when quiet, the decision is the primary result users asked for.
        println!("{}", decision_label(result.decision));
        return;
    }
    println!("{kind} {target}");
    println!("  decision:     {}", decision_label(result.decision));
    println!("  risk:         {}", risk_label(result.risk));
    println!("  reason:       {}", result.reason);
    println!("  matched-rule: {}", result.matched_rule.as_str());
}

// ---------------------------------------------------------------------------
// `policy test`
// ---------------------------------------------------------------------------

/// A single policy test case (design "Policy Test Case File").
#[derive(Debug, Deserialize)]
struct PolicyTestCase {
    id: String,
    action: String,
    input: String,
    expected: String,
}

/// The top-level cases file: `{ "cases": [... ] }`.
#[derive(Debug, Deserialize)]
struct PolicyTestCaseFile {
    cases: Vec<PolicyTestCase>,
}

/// Evaluate each case in the file, report per-case + summary, and map the
/// outcome to an exit code: all pass -> 0, any fail -> 1,
/// unreadable/malformed -> 1.
fn test(args: &TestArgs, ctx: &GlobalContext) -> CliResult {
    let raw = std::fs::read_to_string(&args.cases_file).map_err(|e| {
        CliError::general(format!(
            "cannot read cases file {}: {e}",
            args.cases_file.display()
        ))
    })?;

    // YAML is a superset of JSON, so a single YAML parse accepts both `.json`
    // and `.yaml` cases files. A parse failure means the file does not conform.
    let parsed: PolicyTestCaseFile = serde_yaml::from_str(&raw).map_err(|e| {
        CliError::general(format!(
            "cases file {} is malformed: {e}",
            args.cases_file.display()
        ))
    })?;

    let policy = load_policy(ctx)?;

    let mut total = 0usize;
    let mut passed = 0usize;
    let mut results: Vec<CaseResult> = Vec::with_capacity(parsed.cases.len());

    for case in &parsed.cases {
        total += 1;
        let action = build_action(&case.action, &case.input).ok_or_else(|| {
            CliError::general(format!(
                "cases file {} is malformed: case `{}` has unknown action kind `{}` (expected `command`, `file-read`, or `file-write`)",
                args.cases_file.display(),
                case.id,
                case.action
            ))
        })?;
        let expected = parse_expected(&case.expected).ok_or_else(|| {
            CliError::general(format!(
                "cases file {} is malformed: case `{}` has unknown expected decision `{}`",
                args.cases_file.display(),
                case.id,
                case.expected
            ))
        })?;

        let actual = evaluate(&policy, &action).decision;
        let pass = actual == expected;
        if pass {
            passed += 1;
        }
        results.push(CaseResult {
            id: case.id.clone(),
            expected,
            actual,
            pass,
        });
    }

    let failed = total - passed;
    report_test_results(ctx, &results, total, passed, failed);

    if failed == 0 {
        Ok(())
    } else {
        Err(CliError::general(format!(
            "{failed} of {total} policy test case(s) failed"
        )))
    }
}

/// One evaluated case outcome.
struct CaseResult {
    id: String,
    expected: Decision,
    actual: Decision,
    pass: bool,
}

/// Print per-case lines and the total/passed/failed summary.
fn report_test_results(
    ctx: &GlobalContext,
    results: &[CaseResult],
    total: usize,
    passed: usize,
    failed: usize,
) {
    if ctx.json {
        let cases = results
            .iter()
            .map(|r| {
                format!(
                    "{{\"id\":{},\"expected\":{},\"actual\":{},\"pass\":{}}}",
                    json_string(&r.id),
                    json_string(decision_label(r.expected)),
                    json_string(decision_label(r.actual)),
                    r.pass
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        println!(
            "{{\"total\":{total},\"passed\":{passed},\"failed\":{failed},\"cases\":[{cases}]}}"
        );
        return;
    }

    if !ctx.is_quiet() {
        for r in results {
            let status = if r.pass { "PASS" } else { "FAIL" };
            println!(
                "{status} {} (expected {}, actual {})",
                r.id,
                decision_label(r.expected),
                decision_label(r.actual)
            );
        }
    }
    println!("{total} cases: {passed} passed, {failed} failed");
}

// ---------------------------------------------------------------------------
// `policy schema`
// ---------------------------------------------------------------------------

/// Print the policy JSON schema as pretty JSON and exit 0.
fn schema(_ctx: &GlobalContext) -> CliResult {
    let schema = policy_json_schema();
    let pretty = serde_json::to_string_pretty(&schema)
        .map_err(|e| CliError::general(format!("failed to render policy schema: {e}")))?;
    println!("{pretty}");
    Ok(())
}

// ---------------------------------------------------------------------------
// `policy suggest`
// ---------------------------------------------------------------------------

/// Suggest an allowlist policy from the observation store, present a
/// line-by-line diff against the current policy, and optionally write it
/// (R10.3–10.10).
fn suggest(args: &SuggestArgs, ctx: &GlobalContext) -> CliResult {
    let repo = Path::new(".");
    let store = fida_policy::load_store(&fida_policy::observation_store_path(repo));

    // R10.4: no observations -> report, produce no policy, leave current policy
    // unchanged.
    let Some(policy) = fida_policy::suggest_policy(&store) else {
        if !ctx.is_quiet() {
            println!(
                "No observations available; run `fida observe -- <agent>` first. Current policy unchanged."
            );
        }
        return Ok(());
    };

    let suggested = serde_yaml::to_string(&policy)
        .map_err(|e| CliError::general(format!("failed to render suggested policy: {e}")))?;

    let target = current_policy_path(ctx);
    let current = std::fs::read_to_string(&target).unwrap_or_default();

    // R10.7: present a line-by-line diff before any write.
    if !ctx.is_quiet() {
        println!("--- current ({})", target.display());
        println!("+++ suggested");
        print!("{}", line_diff(&current, &suggested));
    }

    if args.write {
        // R10.9/10.10: write atomically; a failure leaves the current policy
        // unchanged.
        write_policy_atomic(&target, &suggested).map_err(|e| {
            CliError::general(format!(
                "failed to write suggested policy to {}: {e}",
                target.display()
            ))
        })?;
        if !ctx.is_quiet() {
            println!("Wrote suggested policy to {}", target.display());
        }
    } else if !ctx.is_quiet() {
        println!("(dry run — pass --write to apply the suggested policy)");
    }
    Ok(())
}

/// Resolve where the suggested policy would be written: `--config`, else the
/// resolved current policy path, else the default `.fida/policy.yaml`.
fn current_policy_path(ctx: &GlobalContext) -> PathBuf {
    if let Some(config) = &ctx.config {
        return config.clone();
    }
    match resolve_source_in(Path::new("."), None) {
        Ok(source) => source
            .path()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from(".fida/policy.yaml")),
        Err(_) => PathBuf::from(".fida/policy.yaml"),
    }
}

/// A line-by-line diff via LCS: unchanged lines are prefixed `  `, removed lines
/// `- `, added lines `+ `.
///
/// ponytail: O(n·m) LCS table, which is fine for small policy files; not a
/// streaming diff for huge inputs.
fn line_diff(old: &str, new: &str) -> String {
    let a: Vec<&str> = old.lines().collect();
    let b: Vec<&str> = new.lines().collect();
    let (n, m) = (a.len(), b.len());
    let mut dp = vec![vec![0usize; m + 1]; n + 1];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            dp[i][j] = if a[i] == b[j] {
                dp[i + 1][j + 1] + 1
            } else {
                dp[i + 1][j].max(dp[i][j + 1])
            };
        }
    }
    let mut out = String::new();
    let (mut i, mut j) = (0, 0);
    while i < n && j < m {
        if a[i] == b[j] {
            out.push_str(&format!("  {}\n", a[i]));
            i += 1;
            j += 1;
        } else if dp[i + 1][j] >= dp[i][j + 1] {
            out.push_str(&format!("- {}\n", a[i]));
            i += 1;
        } else {
            out.push_str(&format!("+ {}\n", b[j]));
            j += 1;
        }
    }
    while i < n {
        out.push_str(&format!("- {}\n", a[i]));
        i += 1;
    }
    while j < m {
        out.push_str(&format!("+ {}\n", b[j]));
        j += 1;
    }
    out
}

/// Write `contents` to `target` atomically (temp file + fsync + rename) so a
/// failed write never leaves a partial file and the prior policy is preserved
/// on failure (R10.10).
fn write_policy_atomic(target: &Path, contents: &str) -> std::io::Result<()> {
    use std::io::Write;
    if let Some(parent) = target.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let tmp = target.with_extension("yaml.fida-tmp");
    let write = (|| -> std::io::Result<()> {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(contents.as_bytes())?;
        f.sync_all()?;
        Ok(())
    })();
    if let Err(e) = write {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    if let Err(e) = std::fs::rename(&tmp, target) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Resolve and load the policy, allowing the built-in default.
/// Loader failures surface as invalid-policy -> exit 4 via `From<LoadError>`.
fn load_policy(ctx: &GlobalContext) -> Result<CompiledPolicy, CliError> {
    let source: PolicySource = resolve_source_in(Path::new("."), ctx.config.as_deref())?;
    Ok(load_source(&source, None)?)
}

/// Build an [`Action`] for an explain/test `kind` + `target` pair.
/// Returns `None` for an unrecognized kind so callers can choose the error.
fn build_action(kind: &str, target: &str) -> Option<Action> {
    match kind {
        "command" => {
            let argv: Vec<String> = target.split_whitespace().map(str::to_string).collect();
            let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
            Some(Action {
                kind: ActionKind::CommandRun,
                actor: Actor::Agent,
                payload: ActionPayload::Command { argv, cwd },
            })
        }
        "file-read" => Some(Action {
            kind: ActionKind::FileRead,
            actor: Actor::Agent,
            payload: ActionPayload::File {
                path: PathBuf::from(target),
            },
        }),
        "file-write" => Some(Action {
            kind: ActionKind::FileWrite,
            actor: Actor::Agent,
            payload: ActionPayload::File {
                path: PathBuf::from(target),
            },
        }),
        _ => None,
    }
}

/// Map an `expected` decision string to a [`Decision`] (accepts both the
/// audit-wire `dry_run` and the CLI-facing `dry-run`).
fn parse_expected(s: &str) -> Option<Decision> {
    match s {
        "allow" => Some(Decision::Allow),
        "ask" => Some(Decision::Ask),
        "deny" => Some(Decision::Deny),
        "dry_run" | "dry-run" => Some(Decision::DryRun),
        _ => None,
    }
}

/// Human/CLI-facing decision label (use `dry-run`).
fn decision_label(d: Decision) -> &'static str {
    match d {
        Decision::Allow => "allow",
        Decision::Ask => "ask",
        Decision::Deny => "deny",
        Decision::DryRun => "dry-run",
    }
}

/// Human/CLI-facing risk label.
fn risk_label(r: Risk) -> &'static str {
    match r {
        Risk::Low => "low",
        Risk::Medium => "medium",
        Risk::High => "high",
    }
}

/// JSON object for a single decision result (used by `explain --json`).
fn decision_json(result: &DecisionResult) -> String {
    format!(
        "{{\"decision\":{},\"risk\":{},\"reason\":{},\"matched_rule\":{}}}",
        json_string(decision_label(result.decision)),
        json_string(risk_label(result.risk)),
        json_string(&result.reason),
        json_string(result.matched_rule.as_str())
    )
}

/// Encode a string as a JSON string literal (quoted + escaped).
fn json_string(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_else(|_| "\"\"".to_string())
}

/// Print each built-in preset name, one per line, and exit 0.
/// Honors `--json` for a machine-readable list.
fn list_presets(ctx: &GlobalContext) -> CliResult {
    if ctx.json {
        let quoted = presets::PRESET_NAMES
            .iter()
            .map(|n| format!("\"{n}\""))
            .collect::<Vec<_>>()
            .join(",");
        println!("[{quoted}]");
    } else {
        for name in presets::PRESET_NAMES {
            println!("{name}");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::Verbosity;

    fn ctx(json: bool) -> GlobalContext {
        GlobalContext {
            json,
            no_color: false,
            verbosity: Verbosity::Normal,
            config: None,
        }
    }

    fn ctx_with_config(path: std::path::PathBuf, json: bool) -> GlobalContext {
        GlobalContext {
            json,
            no_color: false,
            verbosity: Verbosity::Normal,
            config: Some(path),
        }
    }

    /// A minimal, valid version-1 policy: deny everything by default.
    const VALID_POLICY: &str = "version: 1\ndefault_decision: deny\n";

    fn write_temp(dir: &tempfile::TempDir, name: &str, contents: &str) -> std::path::PathBuf {
        let path = dir.path().join(name);
        std::fs::write(&path, contents).unwrap();
        path
    }

    #[tokio::test]
    async fn list_presets_lists_every_builtin_preset() {
        let args = PolicyArgs {
            command: PolicyCommand::ListPresets,
        };
        // Exercises the success path; the names themselves are asserted against
        // the shared source of truth.
        run(&args, &ctx(false)).await.expect("list-presets exits 0");

        assert_eq!(
            presets::PRESET_NAMES,
            &[
                "secret-safe",
                "starter",
                "relaxed",
                "careful",
                "oss-maintainer",
                "ci-readonly",
                "strict-firewall"
            ]
        );
    }

    #[tokio::test]
    async fn list_presets_json_succeeds() {
        let args = PolicyArgs {
            command: PolicyCommand::ListPresets,
        };
        run(&args, &ctx(true))
            .await
            .expect("json list-presets exits 0");
    }

    // --- policy check ------------------------------------

    #[tokio::test]
    async fn check_valid_policy_exits_zero() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_temp(&dir, "policy.yaml", VALID_POLICY);
        let args = PolicyArgs {
            command: PolicyCommand::Check,
        };
        run(&args, &ctx_with_config(path, false))
            .await
            .expect("valid policy check exits 0");
    }

    #[tokio::test]
    async fn check_invalid_policy_exits_four_with_per_field_violations() {
        let dir = tempfile::tempdir().unwrap();
        // Missing required `version` and an out-of-domain `default_decision`.
        let path = write_temp(&dir, "policy.yaml", "default_decision: maybe\n");
        let args = PolicyArgs {
            command: PolicyCommand::Check,
        };
        let err = run(&args, &ctx_with_config(path, false))
            .await
            .expect_err("invalid policy must error");
        assert_eq!(err.exit_code(), 4);
        let msg = err.to_string();
        // Each violation is attributed to its field path.
        assert!(
            msg.contains("version"),
            "should flag missing version: {msg}"
        );
        assert!(
            msg.contains("default_decision"),
            "should flag bad default_decision: {msg}"
        );
    }

    #[tokio::test]
    async fn check_unreadable_policy_exits_one() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("does-not-exist.yaml");
        let args = PolicyArgs {
            command: PolicyCommand::Check,
        };
        let err = run(&args, &ctx_with_config(missing, false))
            .await
            .expect_err("unreadable policy must error");
        assert_eq!(err.exit_code(), 1);
    }

    // --- policy explain --------------------------------------

    #[tokio::test]
    async fn explain_command_reports_decision() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_temp(&dir, "policy.yaml", VALID_POLICY);
        let args = ExplainArgs {
            kind: "command".to_string(),
            target: "git status".to_string(),
        };
        explain(&args, &ctx_with_config(path, true)).expect("explain command exits 0");
    }

    #[tokio::test]
    async fn explain_command_hard_deny_is_deny() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_temp(&dir, "policy.yaml", VALID_POLICY);
        let policy = load_policy(&ctx_with_config(path, false)).unwrap();
        let action = build_action("command", "rm -rf /").unwrap();
        assert_eq!(evaluate(&policy, &action).decision, Decision::Deny);
    }

    #[tokio::test]
    async fn explain_file_write_reports_decision() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_temp(&dir, "policy.yaml", VALID_POLICY);
        let cfg = ctx_with_config(path, false);
        let args = ExplainArgs {
            kind: "file-write".to_string(),
            target: "src/app.ts".to_string(),
        };
        explain(&args, &cfg).expect("explain file-write exits 0");

        // Default-deny policy with no file rules -> deny.
        let policy = load_policy(&cfg).unwrap();
        let action = build_action("file-write", "src/app.ts").unwrap();
        assert_eq!(evaluate(&policy, &action).decision, Decision::Deny);
    }

    #[tokio::test]
    async fn explain_file_read_evaluates_read_rules() {
        // A policy that denies reading.env must surface a deny for file-read.
        let policy_yaml = "version: 1\n\
             default_decision: allow\n\
             files:\n\
             \x20\x20read:\n\
             \x20\x20\x20\x20allow:\n\
             \x20\x20\x20\x20\x20\x20- \"**/*\"\n\
             \x20\x20\x20\x20deny:\n\
             \x20\x20\x20\x20\x20\x20- .env\n";
        let dir = tempfile::tempdir().unwrap();
        let path = write_temp(&dir, "policy.yaml", policy_yaml);
        let cfg = ctx_with_config(path, false);

        // The CLI path must accept the `file-read` kind.
        let args = ExplainArgs {
            kind: "file-read".to_string(),
            target: ".env".to_string(),
        };
        explain(&args, &cfg).expect("explain file-read exits 0");

        let policy = load_policy(&cfg).unwrap();
        let denied = build_action("file-read", ".env").unwrap();
        assert_eq!(evaluate(&policy, &denied).decision, Decision::Deny);
        let allowed = build_action("file-read", "src/app.ts").unwrap();
        assert_eq!(evaluate(&policy, &allowed).decision, Decision::Allow);
    }

    #[tokio::test]
    async fn explain_unknown_kind_is_usage_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_temp(&dir, "policy.yaml", VALID_POLICY);
        let args = ExplainArgs {
            kind: "teleport".to_string(),
            target: "x".to_string(),
        };
        let err =
            explain(&args, &ctx_with_config(path, false)).expect_err("unknown kind must error");
        assert_eq!(err.exit_code(), 1);
    }

    // --- policy test ---------------------------------

    #[tokio::test]
    async fn test_all_pass_exits_zero() {
        let dir = tempfile::tempdir().unwrap();
        let policy = write_temp(&dir, "policy.yaml", VALID_POLICY);
        let cases = write_temp(
            &dir,
            "cases.json",
            r#"{"cases":[
                {"id":"c1","action":"command","input":"git status","expected":"deny"},
                {"id":"c2","action":"file-write","input":"src/app.ts","expected":"deny"}
            ]}"#,
        );
        let args = TestArgs { cases_file: cases };
        test(&args, &ctx_with_config(policy, false)).expect("all-pass exits 0");
    }

    #[tokio::test]
    async fn test_any_fail_exits_one() {
        let dir = tempfile::tempdir().unwrap();
        let policy = write_temp(&dir, "policy.yaml", VALID_POLICY);
        let cases = write_temp(
            &dir,
            "cases.json",
            r#"{"cases":[
                {"id":"c1","action":"command","input":"git status","expected":"allow"}
            ]}"#,
        );
        let args = TestArgs { cases_file: cases };
        let err =
            test(&args, &ctx_with_config(policy, false)).expect_err("failing case must error");
        assert_eq!(err.exit_code(), 1);
    }

    #[tokio::test]
    async fn test_malformed_cases_file_exits_one() {
        let dir = tempfile::tempdir().unwrap();
        let policy = write_temp(&dir, "policy.yaml", VALID_POLICY);
        let cases = write_temp(&dir, "cases.json", "this: is: not: valid: cases");
        let args = TestArgs { cases_file: cases };
        let err =
            test(&args, &ctx_with_config(policy, false)).expect_err("malformed cases must error");
        assert_eq!(err.exit_code(), 1);
    }

    #[tokio::test]
    async fn test_unreadable_cases_file_exits_one() {
        let dir = tempfile::tempdir().unwrap();
        let policy = write_temp(&dir, "policy.yaml", VALID_POLICY);
        let args = TestArgs {
            cases_file: dir.path().join("nope.json"),
        };
        let err =
            test(&args, &ctx_with_config(policy, false)).expect_err("unreadable cases must error");
        assert_eq!(err.exit_code(), 1);
    }

    // --- policy schema ------------------------------------------

    #[tokio::test]
    async fn schema_prints_and_exits_zero() {
        let args = PolicyArgs {
            command: PolicyCommand::Schema,
        };
        run(&args, &ctx(false)).await.expect("schema exits 0");
    }

    // --- helpers ------------------------------------------------------------

    #[test]
    fn decision_and_risk_labels_are_cli_facing() {
        assert_eq!(decision_label(Decision::DryRun), "dry-run");
        assert_eq!(parse_expected("dry-run"), Some(Decision::DryRun));
        assert_eq!(parse_expected("dry_run"), Some(Decision::DryRun));
        assert_eq!(parse_expected("nonsense"), None);
        assert_eq!(risk_label(Risk::Medium), "medium");
        assert!(build_action("file-write", "x").is_some());
        assert!(build_action("file-read", "x").is_some());
        assert!(build_action("bogus", "x").is_none());
    }
}
