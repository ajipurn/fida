//! `fida exec -- <command>` — run one shell command, redacting secret output.
//!
//! `fida exec` is the non-MCP fallback the managed steering points agents to
//! when the `fida_read`/`fida_shell` gateway tools are unavailable. It:
//!
//! 1. Resolves and loads the secret-guard policy (`--config` honored), surfacing
//!    load failures as exit 4 via the existing `From<LoadError>` impl.
//! 2. Resolves the working directory, parses `--env KEY=value` and `--timeout`,
//!    and validates the resulting [`fida_exec::ExecRequest`]. Bad cwd / env /
//!    timeout map to exit 1.
//! 3. Evaluates the inferred file reads and the `command.run` action against the
//!    secret-guard policy: a `deny` is exit 2, an `ask` is exit 3. fida is not
//!    an approval system, so `ask` always fails closed.
//! 4. On allow, runs the command through [`StdCommandExecutor`], which redacts
//!    captured stdout/stderr before it is printed or audited, and propagates the
//!    command's own exit code.

use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use chrono::Utc;
use clap::Args;

use fida_action::{Action, ActionKind, ActionPayload, Actor, Decision, DecisionResult};
use fida_audit::{AuditAction, AuditEvent, AuditResult};
use fida_exec::{
    AuditSink, CommandExecutor, ExecError, ExecRequest, OutputStream, StdCommandExecutor,
};
use fida_policy::{evaluate, load_source, resolve_source_in};
use fida_secrets::Scanner;

use crate::context::GlobalContext;
use crate::error::{CliError, CliResult};

/// Arguments for `fida exec`.
#[derive(Debug, Args)]
pub struct ExecArgs {
    /// Working directory for the command.
    #[arg(long)]
    pub cwd: Option<std::path::PathBuf>,

    /// Additional environment variable, `KEY=value` (repeatable).
    #[arg(long = "env")]
    pub env: Vec<String>,

    /// Command timeout (e.g. `30s`, `5m`).
    #[arg(long)]
    pub timeout: Option<String>,

    /// Evaluate policy but do not run the command.
    #[arg(long)]
    pub dry_run: bool,

    /// The command and its arguments, after `--`.
    #[arg(last = true, required = true)]
    pub command: Vec<String>,
}

/// Run `fida exec`.
pub async fn run(args: &ExecArgs, ctx: &GlobalContext) -> CliResult {
    // 1. Resolve + load the policy. A load failure surfaces as exit 4 through
    // the `From<fida_policy::LoadError>` impl on `CliError`.
    let root = PathBuf::from(".");
    let source = resolve_source_in(&root, ctx.config.as_deref())?;
    let policy = load_source(&source, None)?;

    // 2. Build and validate the execution request.
    let request = build_request(args)?;

    // 3. Gate the inferred file reads and the command against the secret-guard
    // policy. A deny is exit 2; an `ask` fails closed at exit 3 (fida does not
    // prompt for approval).
    for action in inferred_file_read_actions(&request) {
        gate(&evaluate(&policy, &action))?;
    }

    let command_action = Action {
        kind: ActionKind::CommandRun,
        actor: Actor::User,
        payload: ActionPayload::Command {
            argv: request.argv.clone(),
            cwd: request.cwd.clone(),
        },
    };
    let decision = evaluate(&policy, &command_action);
    gate(&decision)?;

    // --dry-run evaluates policy but never executes.
    if args.dry_run {
        print_dry_run(ctx, &decision);
        return Ok(());
    }

    // 4. Allowed: run the command, redacting captured stdout/stderr before it is
    // printed or audited, and propagate the command's own exit code.
    let scanner = Scanner::new(&policy.secrets);
    let audit_root = fida_session::sessions_root(&root);
    let executor = StdCommandExecutor::new();
    let mut sink = StreamingAuditSink::new(audit_root);
    match executor.run(&request, &scanner, &mut sink) {
        // A signal/timeout termination reports `-1`; surface it as a generic
        // non-zero (1) since it does not fit a u8 exit code.
        Ok(result) => match u8::try_from(result.exit_code).unwrap_or(1) {
            0 => Ok(()),
            code => Err(CliError::CommandExit(code)),
        },
        Err(err) => Err(CliError::general(format!("failed to run command: {err}"))),
    }
}

fn print_dry_run(ctx: &GlobalContext, decision: &DecisionResult) {
    if ctx.is_quiet() {
        return;
    }
    println!(
        "dry-run: {decision:?} ({reason}) [rule: {rule}]",
        decision = decision.decision,
        reason = decision.reason,
        rule = decision.matched_rule.as_str(),
    );
}

/// Translate a secret-guard policy decision into a gate result. Pure and
/// side-effect free so it can be unit-tested without a tty.
///
/// * [`Decision::Allow`] / [`Decision::DryRun`] -> proceed.
/// * [`Decision::Deny`] -> exit 2 with the matched rule.
/// * [`Decision::Ask`] -> exit 3; fida does not prompt, so `ask` fails closed.
fn gate(decision: &DecisionResult) -> CliResult {
    let detail = format!(
        "{reason} [rule: {rule}]",
        reason = decision.reason,
        rule = decision.matched_rule.as_str(),
    );
    match decision.decision {
        Decision::Allow | Decision::DryRun => Ok(()),
        Decision::Deny => Err(CliError::PolicyDenied { reason: detail }),
        Decision::Ask => Err(CliError::ApprovalRequired { reason: detail }),
    }
}

/// Build a validated [`ExecRequest`] from the parsed arguments.
///
/// Maps every input failure to exit 1: an unresolvable working directory, a
/// malformed `--env` value, an out-of-range `--timeout`,
/// or an invalid `--cwd`.
fn build_request(args: &ExecArgs) -> CliResult<ExecRequest> {
    // --cwd defaults to the current directory.
    let cwd = match &args.cwd {
        Some(p) => p.clone(),
        None => std::env::current_dir()
            .map_err(|e| CliError::general(format!("cannot determine current directory: {e}")))?,
    };

    // --env KEY=value (repeatable); malformed -> exit 1.
    let mut extra_env = Vec::with_capacity(args.env.len());
    for raw in &args.env {
        let pair = fida_exec::parse_env_var(raw).map_err(exec_error_to_cli)?;
        extra_env.push(pair);
    }

    // --timeout; out of range / unparseable -> exit 1.
    let timeout = match &args.timeout {
        Some(raw) => Some(parse_timeout(raw)?),
        None => None,
    };

    let request = ExecRequest {
        argv: args.command.clone(),
        cwd,
        extra_env,
        timeout,
    };

    // Final structural validation (empty argv, missing/non-dir cwd, env keys,
    // timeout bounds) -> exit 1.
    fida_exec::validate(&request).map_err(exec_error_to_cli)?;
    Ok(request)
}

fn inferred_file_read_actions(request: &ExecRequest) -> Vec<Action> {
    infer_file_read_paths(&request.argv)
        .into_iter()
        .map(|path| Action {
            kind: ActionKind::FileRead,
            actor: Actor::User,
            payload: ActionPayload::File { path },
        })
        .collect()
}

fn infer_file_read_paths(argv: &[String]) -> Vec<PathBuf> {
    let Some((program, args)) = argv.split_first() else {
        return Vec::new();
    };
    let command = command_name(program);
    let mut paths = match command {
        "cat" | "less" | "more" | "bat" | "batcat" => direct_operand_paths(args, &[]),
        "head" | "tail" => direct_operand_paths(
            args,
            &[
                opt("n", OptionValue::Skip),
                opt("lines", OptionValue::Skip),
                opt("c", OptionValue::Skip),
                opt("bytes", OptionValue::Skip),
            ],
        ),
        "wc" | "nl" | "strings" => direct_operand_paths(args, &[]),
        "cut" => direct_operand_paths(
            args,
            &[
                opt("b", OptionValue::Skip),
                opt("bytes", OptionValue::Skip),
                opt("c", OptionValue::Skip),
                opt("characters", OptionValue::Skip),
                opt("d", OptionValue::Skip),
                opt("delimiter", OptionValue::Skip),
                opt("f", OptionValue::Skip),
                opt("fields", OptionValue::Skip),
                opt("output-delimiter", OptionValue::Skip),
            ],
        ),
        "sort" => direct_operand_paths(
            args,
            &[
                opt("k", OptionValue::Skip),
                opt("key", OptionValue::Skip),
                opt("o", OptionValue::Skip),
                opt("output", OptionValue::Skip),
                opt("S", OptionValue::Skip),
                opt("buffer-size", OptionValue::Skip),
                opt("T", OptionValue::Skip),
                opt("temporary-directory", OptionValue::Skip),
                opt("t", OptionValue::Skip),
                opt("field-separator", OptionValue::Skip),
                opt("parallel", OptionValue::Skip),
                opt("batch-size", OptionValue::Skip),
            ],
        ),
        "uniq" => direct_operand_paths(
            args,
            &[
                opt("f", OptionValue::Skip),
                opt("skip-fields", OptionValue::Skip),
                opt("s", OptionValue::Skip),
                opt("skip-chars", OptionValue::Skip),
                opt("w", OptionValue::Skip),
                opt("check-chars", OptionValue::Skip),
            ],
        ),
        "grep" | "egrep" | "fgrep" => grep_like_paths(args, grep_options()),
        "rg" | "ripgrep" => grep_like_paths(args, ripgrep_options()),
        "sed" => script_then_file_paths(args, sed_options()),
        "awk" | "gawk" | "mawk" | "nawk" => script_then_file_paths(args, awk_options()),
        _ => Vec::new(),
    };
    dedupe_paths(&mut paths);
    paths
}

fn command_name(program: &str) -> &str {
    Path::new(program)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(program)
}

fn direct_operand_paths(args: &[String], specs: &[OptionSpec]) -> Vec<PathBuf> {
    let scan = scan_args(args, specs);
    scan.positionals.into_iter().map(PathBuf::from).collect()
}

fn grep_like_paths(args: &[String], specs: Vec<OptionSpec>) -> Vec<PathBuf> {
    let scan = scan_args(args, &specs);
    let mut paths = scan.option_file_reads;
    if scan.marker_seen {
        paths.extend(scan.positionals.into_iter().map(PathBuf::from));
    } else {
        paths.extend(scan.positionals.into_iter().skip(1).map(PathBuf::from));
    }
    paths
}

fn script_then_file_paths(args: &[String], specs: Vec<OptionSpec>) -> Vec<PathBuf> {
    let scan = scan_args(args, &specs);
    let mut paths = scan.option_file_reads;
    if scan.marker_seen {
        paths.extend(scan.positionals.into_iter().map(PathBuf::from));
    } else {
        paths.extend(scan.positionals.into_iter().skip(1).map(PathBuf::from));
    }
    paths
}

fn grep_options() -> Vec<OptionSpec> {
    vec![
        opt("e", OptionValue::Marker),
        opt("regexp", OptionValue::Marker),
        opt("f", OptionValue::ReadFileAndMarker),
        opt("file", OptionValue::ReadFileAndMarker),
        opt("m", OptionValue::Skip),
        opt("max-count", OptionValue::Skip),
        opt("A", OptionValue::Skip),
        opt("after-context", OptionValue::Skip),
        opt("B", OptionValue::Skip),
        opt("before-context", OptionValue::Skip),
        opt("C", OptionValue::Skip),
        opt("context", OptionValue::Skip),
        opt("D", OptionValue::Skip),
        opt("devices", OptionValue::Skip),
        opt("d", OptionValue::Skip),
        opt("directories", OptionValue::Skip),
        opt("include", OptionValue::Skip),
        opt("exclude", OptionValue::Skip),
        opt("exclude-dir", OptionValue::Skip),
        opt("exclude-from", OptionValue::Skip),
        opt("binary-files", OptionValue::Skip),
        opt("label", OptionValue::Skip),
        opt("color", OptionValue::Skip),
    ]
}

fn ripgrep_options() -> Vec<OptionSpec> {
    vec![
        opt("e", OptionValue::Marker),
        opt("regexp", OptionValue::Marker),
        opt("f", OptionValue::ReadFileAndMarker),
        opt("file", OptionValue::ReadFileAndMarker),
        opt("g", OptionValue::Skip),
        opt("glob", OptionValue::Skip),
        opt("t", OptionValue::Skip),
        opt("type", OptionValue::Skip),
        opt("T", OptionValue::Skip),
        opt("type-not", OptionValue::Skip),
        opt("m", OptionValue::Skip),
        opt("max-count", OptionValue::Skip),
        opt("A", OptionValue::Skip),
        opt("after-context", OptionValue::Skip),
        opt("B", OptionValue::Skip),
        opt("before-context", OptionValue::Skip),
        opt("C", OptionValue::Skip),
        opt("context", OptionValue::Skip),
        opt("E", OptionValue::Skip),
        opt("encoding", OptionValue::Skip),
        opt("engine", OptionValue::Skip),
        opt("color", OptionValue::Skip),
        opt("colors", OptionValue::Skip),
        opt("path-separator", OptionValue::Skip),
        opt("sort", OptionValue::Skip),
        opt("sortr", OptionValue::Skip),
    ]
}

fn sed_options() -> Vec<OptionSpec> {
    vec![
        opt("e", OptionValue::Marker),
        opt("expression", OptionValue::Marker),
        opt("f", OptionValue::ReadFileAndMarker),
        opt("file", OptionValue::ReadFileAndMarker),
    ]
}

fn awk_options() -> Vec<OptionSpec> {
    vec![
        opt("f", OptionValue::ReadFileAndMarker),
        opt("file", OptionValue::ReadFileAndMarker),
        opt("v", OptionValue::Skip),
        opt("assign", OptionValue::Skip),
        opt("F", OptionValue::Skip),
        opt("field-separator", OptionValue::Skip),
    ]
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OptionValue {
    Skip,
    Marker,
    ReadFileAndMarker,
}

#[derive(Debug, Clone, Copy)]
struct OptionSpec {
    name: &'static str,
    value: OptionValue,
}

fn opt(name: &'static str, value: OptionValue) -> OptionSpec {
    OptionSpec { name, value }
}

#[derive(Default)]
struct ArgScan {
    positionals: Vec<String>,
    option_file_reads: Vec<PathBuf>,
    marker_seen: bool,
}

fn scan_args(args: &[String], specs: &[OptionSpec]) -> ArgScan {
    let mut scan = ArgScan::default();
    let mut pending: Option<OptionValue> = None;
    let mut positional_mode = false;

    for arg in args {
        if let Some(kind) = pending.take() {
            apply_option_value(&mut scan, kind, arg);
            continue;
        }

        if positional_mode {
            push_positional(&mut scan, arg);
            continue;
        }

        if arg == "--" {
            positional_mode = true;
            continue;
        }

        if let Some(long) = arg.strip_prefix("--") {
            if long.is_empty() {
                continue;
            }
            let (name, inline) = match long.split_once('=') {
                Some((name, value)) => (name, Some(value)),
                None => (long, None),
            };
            if let Some(kind) = option_kind(specs, name) {
                if let Some(value) = inline {
                    apply_option_value(&mut scan, kind, value);
                } else {
                    pending = Some(kind);
                }
            }
            continue;
        }

        if arg.starts_with('-') && arg != "-" {
            let short = &arg[1..];
            if let Some(first) = short.chars().next() {
                let name = first.to_string();
                if let Some(kind) = option_kind(specs, &name) {
                    let rest = &short[first.len_utf8()..];
                    if rest.is_empty() {
                        pending = Some(kind);
                    } else {
                        apply_option_value(&mut scan, kind, rest);
                    }
                }
            }
            continue;
        }

        push_positional(&mut scan, arg);
    }

    scan
}

fn option_kind(specs: &[OptionSpec], name: &str) -> Option<OptionValue> {
    specs
        .iter()
        .find(|spec| spec.name == name)
        .map(|spec| spec.value)
}

fn apply_option_value(scan: &mut ArgScan, kind: OptionValue, value: &str) {
    match kind {
        OptionValue::Skip => {}
        OptionValue::Marker => {
            scan.marker_seen = true;
        }
        OptionValue::ReadFileAndMarker => {
            scan.marker_seen = true;
            push_file_read(&mut scan.option_file_reads, value);
        }
    }
}

fn push_positional(scan: &mut ArgScan, value: &str) {
    if value != "-" && !value.is_empty() {
        scan.positionals.push(value.to_string());
    }
}

fn push_file_read(paths: &mut Vec<PathBuf>, value: &str) {
    if value != "-" && !value.is_empty() {
        paths.push(PathBuf::from(value));
    }
}

fn dedupe_paths(paths: &mut Vec<PathBuf>) {
    let mut seen = HashSet::new();
    paths.retain(|path| seen.insert(path.clone()));
}

/// Parse a `--timeout` value into a [`Duration`] in the executor's accepted
/// `1..=86400` second range.
///
/// Accepts a bare integer number of seconds (`30`) or a unit-suffixed duration
/// (`30s`, `5m`, `2h`, `1d`) via [`fida_session::parse_duration`]. Anything
/// else, or a value outside the valid range, maps to exit 1.
fn parse_timeout(raw: &str) -> CliResult<Duration> {
    let trimmed = raw.trim();
    let duration = if trimmed.bytes().all(|b| b.is_ascii_digit()) && !trimmed.is_empty() {
        // Bare integer seconds.
        let secs: u64 = trimmed
            .parse()
            .map_err(|_| CliError::general(format!("invalid --timeout '{raw}'")))?;
        Duration::from_secs(secs)
    } else {
        // Unit-suffixed duration (s/m/h/d) via the session parser.
        let chrono_dur = fida_session::parse_duration(trimmed)
            .map_err(|_| CliError::general(format!("invalid --timeout '{raw}'")))?;
        chrono_dur
            .to_std()
            .map_err(|_| CliError::general(format!("invalid --timeout '{raw}'")))?
    };

    // Enforce the executor's 1..=86400 second bound.
    fida_exec::validate_timeout(Some(duration)).map_err(exec_error_to_cli)?;
    Ok(duration)
}

/// Every [`ExecError`] is an input/validation failure -> exit 1.
fn exec_error_to_cli(err: ExecError) -> CliError {
    CliError::general(err.to_string())
}

/// Records redacted command output into the same audit namespace as one-off
/// `fida exec` decisions.
///
/// The session log is opened **once**, lazily, and reused via a [`BufWriter`]
/// for the lifetime of the sink. This replaces the previous per-event
/// open+`create_dir_all`+`flush` pattern, which issued those syscalls for every
/// streamed stdout/stderr chunk — a real bottleneck for chatty commands. The
/// buffer is flushed when the sink is dropped (or when its buffer fills).
struct StreamingAuditSink {
    events_path: PathBuf,
    writer: Option<BufWriter<File>>,
    next_id: usize,
}

impl StreamingAuditSink {
    fn new(audit_root: PathBuf) -> Self {
        // Mirrors `JsonlAuditStore::events_path("exec")` so the streamed output
        // lands in the same log as the `exec` decision events.
        let events_path = audit_root.join("exec").join("events.jsonl");
        StreamingAuditSink {
            events_path,
            writer: None,
            next_id: 1,
        }
    }

    /// Lazily open (and memoize) the append-mode handle to the session log.
    /// `create_dir_all` runs at most once, on first write.
    fn writer(&mut self) -> Option<&mut BufWriter<File>> {
        if self.writer.is_none() {
            if let Some(parent) = self.events_path.parent() {
                if std::fs::create_dir_all(parent).is_err() {
                    return None;
                }
            }
            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.events_path)
                .ok()?;
            self.writer = Some(BufWriter::new(file));
        }
        self.writer.as_mut()
    }

    fn append(&mut self, action: AuditAction, redacted: bool) {
        let event = AuditEvent {
            id: format!("evt_stream_{:06}", self.next_id),
            session_id: "exec".to_string(),
            time: Utc::now(),
            actor: Actor::Agent,
            action,
            decision: fida_action::Decision::Allow,
            result: AuditResult::Allowed,
            matched_rule: fida_action::MatchedRule::NoExplicitRule,
            risk: fida_action::Risk::Low,
            redacted,
            metrics: None,
        };
        self.next_id += 1;

        // Serialize first; preserve the JSONL one-event-per-line invariant by
        // rejecting any event whose encoding contains a newline.
        let Ok(line) = serde_json::to_string(&event) else {
            return;
        };
        if line.contains('\n') {
            return;
        }
        if let Some(writer) = self.writer() {
            let _ = writer.write_all(line.as_bytes());
            let _ = writer.write_all(b"\n");
        }
    }
}

impl Drop for StreamingAuditSink {
    fn drop(&mut self) {
        if let Some(writer) = self.writer.as_mut() {
            let _ = writer.flush();
        }
    }
}

impl AuditSink for StreamingAuditSink {
    fn record_stdout(&mut self, redacted: &str) {
        self.append(
            AuditAction::CommandOutput {
                stream: "stdout".to_string(),
                content: redacted.to_string(),
            },
            false,
        );
    }

    fn record_stderr(&mut self, redacted: &str) {
        self.append(
            AuditAction::CommandOutput {
                stream: "stderr".to_string(),
                content: redacted.to_string(),
            },
            false,
        );
    }

    fn record_redaction_failure(&mut self, stream: OutputStream) {
        self.append(
            AuditAction::CommandRedactionFailure {
                stream: stream_label(stream).to_string(),
            },
            true,
        );
    }
}

fn stream_label(stream: OutputStream) -> &'static str {
    match stream {
        OutputStream::Stdout => "stdout",
        OutputStream::Stderr => "stderr",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fida_audit::{AuditStore, JsonlAuditStore};

    fn ctx_with_policy(policy_path: &std::path::Path) -> GlobalContext {
        GlobalContext {
            json: false,
            no_color: true,
            verbosity: crate::context::Verbosity::Normal,
            config: Some(policy_path.to_path_buf()),
        }
    }

    fn write_policy(name: &str, body: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "fida_exec_test_{}_{}.yaml",
            name,
            std::process::id()
        ));
        let mut f = std::fs::File::create(&path).expect("create temp policy");
        f.write_all(body.as_bytes()).expect("write temp policy");
        path
    }

    fn block_on<F: std::future::Future>(fut: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(fut)
    }

    fn read_paths(argv: &[&str]) -> Vec<PathBuf> {
        infer_file_read_paths(
            &argv
                .iter()
                .map(|part| (*part).to_string())
                .collect::<Vec<_>>(),
        )
    }

    #[test]
    fn read_preflight_detects_direct_file_readers() {
        assert_eq!(read_paths(&["cat", ".env"]), vec![PathBuf::from(".env")]);
        assert_eq!(
            read_paths(&["head", "-n", "5", ".env.local"]),
            vec![PathBuf::from(".env.local")]
        );
        assert_eq!(
            read_paths(&["tail", "-n5", "--", "-secret"]),
            vec![PathBuf::from("-secret")]
        );
        assert_eq!(
            read_paths(&["cut", "-d", ":", "-f1", ".env"]),
            vec![PathBuf::from(".env")]
        );
    }

    #[test]
    fn read_preflight_detects_search_and_script_file_operands() {
        assert_eq!(
            read_paths(&["grep", "-n", "TOKEN", ".env"]),
            vec![PathBuf::from(".env")]
        );
        assert_eq!(
            read_paths(&["grep", "-f", ".env", "src/main.rs"]),
            vec![PathBuf::from(".env"), PathBuf::from("src/main.rs")]
        );
        assert_eq!(
            read_paths(&["rg", "-g", "*.rs", "TOKEN", ".env"]),
            vec![PathBuf::from(".env")]
        );
        assert_eq!(
            read_paths(&["sed", "-n", "p", ".env"]),
            vec![PathBuf::from(".env")]
        );
        assert_eq!(
            read_paths(&["awk", "-F:", "{print $1}", ".env"]),
            vec![PathBuf::from(".env")]
        );
    }

    #[test]
    fn read_preflight_deduplicates_repeated_paths() {
        assert_eq!(
            read_paths(&["cat", ".env", ".env"]),
            vec![PathBuf::from(".env")]
        );
    }

    #[test]
    fn malformed_env_exits_1() {
        let policy = write_policy("allow_env", "version: 1\ndefault_decision: allow\n");
        let args = ExecArgs {
            cwd: None,
            env: vec!["NOT_KEY_VALUE".to_string()],
            timeout: None,
            dry_run: false,
            command: vec!["true".to_string()],
        };
        let err = block_on(run(&args, &ctx_with_policy(&policy))).expect_err("must fail");
        assert_eq!(err.exit_code(), 1);
        let _ = std::fs::remove_file(&policy);
    }

    #[test]
    fn invalid_cwd_exits_1() {
        let policy = write_policy("allow_cwd", "version: 1\ndefault_decision: allow\n");
        let args = ExecArgs {
            cwd: Some(PathBuf::from("/no/such/fida/dir/exists")),
            env: vec![],
            timeout: None,
            dry_run: false,
            command: vec!["true".to_string()],
        };
        let err = block_on(run(&args, &ctx_with_policy(&policy))).expect_err("must fail");
        assert_eq!(err.exit_code(), 1);
        let _ = std::fs::remove_file(&policy);
    }

    #[test]
    fn out_of_range_timeout_exits_1() {
        let policy = write_policy("allow_to", "version: 1\ndefault_decision: allow\n");
        let args = ExecArgs {
            cwd: None,
            env: vec![],
            timeout: Some("0s".to_string()),
            dry_run: false,
            command: vec!["true".to_string()],
        };
        let err = block_on(run(&args, &ctx_with_policy(&policy))).expect_err("must fail");
        assert_eq!(err.exit_code(), 1);
        let _ = std::fs::remove_file(&policy);
    }

    #[test]
    fn dry_run_exits_0_without_executing() {
        let policy = write_policy("dry_allow", "version: 1\ndefault_decision: allow\n");
        // A command that would fail if run; dry-run must not execute it.
        let args = ExecArgs {
            cwd: None,
            env: vec![],
            timeout: None,
            dry_run: true,
            command: vec!["false".to_string()],
        };
        let result = block_on(run(&args, &ctx_with_policy(&policy)));
        assert!(result.is_ok(), "dry-run should exit 0, got {result:?}");
        let _ = std::fs::remove_file(&policy);
    }

    #[test]
    fn denied_inferred_file_read_blocks_before_command_policy() {
        let policy = write_policy(
            "deny_read_env",
            r#"version: 1
default_decision: allow
hard_denies_disabled: true
files:
  read:
    deny:
      - .env
"#,
        );
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join(".env"), "TOKEN=secret\n").unwrap();
        let args = ExecArgs {
            cwd: Some(tmp.path().to_path_buf()),
            env: vec![],
            timeout: None,
            dry_run: false,
            command: vec!["cat".to_string(), ".env".to_string()],
        };

        let err = block_on(run(&args, &ctx_with_policy(&policy))).expect_err("must deny");
        assert_eq!(err.exit_code(), 2);
        assert!(matches!(err, CliError::PolicyDenied { .. }));
        let _ = std::fs::remove_file(&policy);
    }

    #[test]
    fn streaming_audit_sink_persists_redacted_output_events() {
        let tmp = tempfile::tempdir().unwrap();
        let mut sink = StreamingAuditSink::new(tmp.path().to_path_buf());

        sink.record_stdout("hello");
        sink.record_redaction_failure(OutputStream::Stderr);

        // The buffered writer flushes on drop (as it does in production when
        // the dispatcher returns); read the log only after that.
        drop(sink);

        let store = JsonlAuditStore::new(tmp.path());
        let events = store.read("exec").unwrap();
        assert_eq!(events.len(), 2);
        assert!(matches!(
            &events[0].action,
            AuditAction::CommandOutput { stream, content }
                if stream == "stdout" && content == "hello"
        ));
        assert!(matches!(
            &events[1].action,
            AuditAction::CommandRedactionFailure { stream } if stream == "stderr"
        ));
        assert!(events[1].redacted);
    }

    #[test]
    fn deny_exits_2() {
        let policy = write_policy("deny_all", "version: 1\ndefault_decision: deny\n");
        let args = ExecArgs {
            cwd: None,
            env: vec![],
            timeout: None,
            dry_run: false,
            command: vec!["true".to_string()],
        };
        let err = block_on(run(&args, &ctx_with_policy(&policy))).expect_err("must deny");
        assert_eq!(err.exit_code(), 2);
        assert!(matches!(err, CliError::PolicyDenied { .. }));
        let _ = std::fs::remove_file(&policy);
    }

    #[test]
    fn non_interactive_ask_fails_closed_to_exit_3() {
        // fida does not prompt for approval, so an `ask` decision always fails
        // closed at exit 3.
        let err = block_on(run(
            &ExecArgs {
                cwd: None,
                env: vec![],
                timeout: None,
                dry_run: false,
                command: vec!["true".to_string()],
            },
            &ctx_with_policy(&write_policy(
                "ask_all",
                "version: 1\ndefault_decision: ask\n",
            )),
        ))
        .expect_err("ask must fail closed");
        assert_eq!(err.exit_code(), 3);
        assert!(matches!(err, CliError::ApprovalRequired { .. }));
    }

    #[test]
    fn gate_maps_each_decision() {
        use fida_action::{MatchedRule, Risk};
        let result = |d: Decision| DecisionResult {
            decision: d,
            reason: "r".to_string(),
            matched_rule: MatchedRule::NoExplicitRule,
            risk: Risk::Low,
            stage: fida_action::EvalStage::ProfileDefault,
        };
        assert!(gate(&result(Decision::Allow)).is_ok());
        assert!(gate(&result(Decision::DryRun)).is_ok());
        assert_eq!(
            gate(&result(Decision::Deny)).expect_err("deny").exit_code(),
            2
        );
        assert_eq!(
            gate(&result(Decision::Ask)).expect_err("ask").exit_code(),
            3
        );
    }

    #[test]
    fn allow_propagates_command_exit_code() {
        let policy = write_policy("allow_exit", "version: 1\ndefault_decision: allow\n");
        // `false` exits 1; allow -> the command's own code is surfaced.
        let args = ExecArgs {
            cwd: None,
            env: vec![],
            timeout: None,
            dry_run: false,
            command: vec!["false".to_string()],
        };
        let err = block_on(run(&args, &ctx_with_policy(&policy))).expect_err("nonzero exit");
        assert!(matches!(err, CliError::CommandExit(1)));
        assert_eq!(err.exit_code(), 1);
        let _ = std::fs::remove_file(&policy);
    }

    #[test]
    fn allow_zero_exit_is_ok() {
        let policy = write_policy("allow_ok", "version: 1\ndefault_decision: allow\n");
        let args = ExecArgs {
            cwd: None,
            env: vec![],
            timeout: None,
            dry_run: false,
            command: vec!["true".to_string()],
        };
        let result = block_on(run(&args, &ctx_with_policy(&policy)));
        assert!(result.is_ok(), "expected Ok, got {result:?}");
        let _ = std::fs::remove_file(&policy);
    }

    #[test]
    fn parse_timeout_accepts_bare_seconds_and_units() {
        assert_eq!(parse_timeout("30").unwrap(), Duration::from_secs(30));
        assert_eq!(parse_timeout("30s").unwrap(), Duration::from_secs(30));
        assert_eq!(parse_timeout("5m").unwrap(), Duration::from_secs(300));
        assert!(parse_timeout("0").is_err());
        assert!(parse_timeout("90000s").is_err());
        assert!(parse_timeout("abc").is_err());
    }
}
