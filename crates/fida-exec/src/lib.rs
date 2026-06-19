//! `fida-exec` — Command_Executor: run approved commands with env/cwd/timeout,
//! streaming output through redaction before audit (spec task 12.1;
//! design "Command_Executor").
//!
//! The executor is the subsystem the [`Action_Broker`] dispatches to once a
//! `command.run` Action resolves to `allow`. It:
//!
//! * validates `--cwd` (must exist and be a directory) and every
//!   `--env KEY=value` entry's format **before** spawning, surfacing
//!   a typed [`ExecError`] the CLI maps to exit code 1;
//! * captures the child's stdout/stderr without exposing raw bytes;
//! * routes each captured stream through a [`Redactor`] (the Secret_Scanner)
//!   before printing or handing it to the [`AuditSink`];
//! * records the integer exit code and execution duration in milliseconds
//! * enforces a `--timeout` of 1..=86400 seconds: when the command
//!   runs longer it terminates the process and records `timed_out` with the
//!   elapsed milliseconds.
//!
//! # Process-tree termination
//!
//! On timeout the executor terminates the spawned child. Terminating an entire
//! process *tree* (orphaned grandchildren) portably requires platform support
//! — `killpg`/process groups on Unix, job objects on Windows — typically via a
//! crate such as `nix` or `windows`. That is deferred for the MVP; killing the
//! direct child is the accepted behavior here (see task 12.1 notes).

use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use fida_secrets::SecretScanner;

/// Inclusive lower bound (seconds) for a `--timeout` value.
pub const MIN_TIMEOUT_SECS: u64 = 1;
/// Inclusive upper bound (seconds) for a `--timeout` value — 24 hours.
pub const MAX_TIMEOUT_SECS: u64 = 86_400;

/// A request to run a single approved command (design "Command_Executor").
///
/// `argv[0]` is the program; the remaining entries are its arguments. `cwd` is
/// the working directory the command runs in and must exist and be a directory.
/// `extra_env` are additional environment variables added to the command's
/// environment; each key must be a valid environment-variable name. `timeout`,
/// when present, must fall in `1..=86400` seconds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecRequest {
    /// Program plus arguments; `argv[0]` is the executable.
    pub argv: Vec<String>,
    /// Working directory for the spawned process.
    pub cwd: PathBuf,
    /// Additional environment variables, already split into `(key, value)`.
    pub extra_env: Vec<(String, String)>,
    /// Optional wall-clock limit; the process is terminated if it is exceeded.
    pub timeout: Option<Duration>,
}

/// The outcome of running a command (design "Command_Executor").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecResult {
    /// The process exit code. When the process was terminated by a signal (no
    /// numeric code, e.g. after a timeout kill) this is `-1`.
    pub exit_code: i32,
    /// Wall-clock execution time in milliseconds; on timeout, the elapsed time
    /// until termination.
    pub duration_ms: u64,
    /// `true` when the command was terminated because it exceeded its timeout.
    pub timed_out: bool,
}

/// A typed error surfaced before (or instead of) spawning a command.
///
/// The CLI maps every variant to exit code 1. None of the
/// variants carry secret data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecError {
    /// `argv` was empty, so there is no program to run.
    EmptyArgv,
    /// `--cwd <path>` does not exist.
    CwdDoesNotExist(PathBuf),
    /// `--cwd <path>` exists but is not a directory.
    CwdNotDirectory(PathBuf),
    /// A `--env` option value was not in `KEY=value` format. Carries
    /// the offending raw text (or key) for the error message.
    MalformedEnv(String),
    /// A `--timeout` value fell outside `1..=86400` seconds. Carries
    /// the offending value in seconds.
    TimeoutOutOfRange(u64),
}

impl std::fmt::Display for ExecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExecError::EmptyArgv => f.write_str("no command supplied to execute"),
            ExecError::CwdDoesNotExist(p) => {
                write!(
                    f,
                    "invalid working directory: '{}' does not exist",
                    p.display()
                )
            }
            ExecError::CwdNotDirectory(p) => {
                write!(
                    f,
                    "invalid working directory: '{}' is not a directory",
                    p.display()
                )
            }
            ExecError::MalformedEnv(raw) => {
                write!(
                    f,
                    "malformed environment variable '{raw}': expected KEY=value"
                )
            }
            ExecError::TimeoutOutOfRange(secs) => write!(
                f,
                "invalid --timeout {secs}: must be between {MIN_TIMEOUT_SECS} and {MAX_TIMEOUT_SECS} seconds"
            ),
        }
    }
}

impl std::error::Error for ExecError {}

impl From<ExecError> for io::Error {
    /// Carries the typed [`ExecError`] as the source of an
    /// [`io::ErrorKind::InvalidInput`] error so callers can downcast it while
    /// the [`CommandExecutor::run`] signature stays `io::Result` (design).
    fn from(err: ExecError) -> Self {
        io::Error::new(io::ErrorKind::InvalidInput, err)
    }
}

/// Which captured stream a piece of output came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputStream {
    /// Standard output.
    Stdout,
    /// Standard error.
    Stderr,
}

/// Redacts captured command output before it is recorded.
///
/// This is a thin, error-shaped abstraction over the Secret_Scanner so the
/// executor does not depend on the scanner's concrete error type. Any
/// [`SecretScanner`] (e.g. `fida_secrets::Scanner`) is automatically a
/// `Redactor` via the blanket implementation below.
pub trait Redactor {
    /// Returns a redacted copy of `content`, or [`RedactionFailed`] when
    /// redaction cannot be completed safely. On failure the caller must
    /// suppress the content item and record a redaction-failure indicator
    /// instead.
    fn redact(&self, content: &str) -> Result<String, RedactionFailed>;
}

/// Redaction of a captured output item could not be completed; the item must be
/// suppressed. Carries no secret data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RedactionFailed;

impl std::fmt::Display for RedactionFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("secret redaction could not be completed; output suppressed")
    }
}

impl std::error::Error for RedactionFailed {}

impl<T: SecretScanner> Redactor for T {
    fn redact(&self, content: &str) -> Result<String, RedactionFailed> {
        SecretScanner::redact(self, content).map_err(|_| RedactionFailed)
    }
}

/// Receives redacted copies of captured command output for recording.
///
/// Kept intentionally minimal (task 12.1): the executor only hands it
/// already-redacted text or a redaction-failure indicator. Wiring these into
/// the append-only Audit_Store lives in the broker/audit layer.
pub trait AuditSink {
    /// Record a redacted copy of the command's standard output.
    fn record_stdout(&mut self, redacted: &str);
    /// Record a redacted copy of the command's standard error.
    fn record_stderr(&mut self, redacted: &str);
    /// Record that redaction of the given stream failed; no secret data is
    /// recorded, only a failure indicator.
    fn record_redaction_failure(&mut self, stream: OutputStream);
}

/// The command-execution contract (design "Command_Executor").
pub trait CommandExecutor {
    /// Run `req`, capture stdout/stderr, then redact each stream before printing
    /// or writing it to `audit`. Returns the integer exit code and duration, or
    /// a timeout result with elapsed milliseconds.
    ///
    /// Validation failures ([`ExecError`]) are surfaced as
    /// [`io::ErrorKind::InvalidInput`] errors carrying the typed cause.
    fn run(
        &self,
        req: &ExecRequest,
        redactor: &dyn Redactor,
        audit: &mut dyn AuditSink,
    ) -> io::Result<ExecResult>;
}

/// Validates `req`'s argv, working directory, and environment entries without
/// spawning anything.
pub fn validate(req: &ExecRequest) -> Result<(), ExecError> {
    if req.argv.is_empty() {
        return Err(ExecError::EmptyArgv);
    }
    if !req.cwd.exists() {
        return Err(ExecError::CwdDoesNotExist(req.cwd.clone()));
    }
    if !req.cwd.is_dir() {
        return Err(ExecError::CwdNotDirectory(req.cwd.clone()));
    }
    for (key, _value) in &req.extra_env {
        if !is_valid_env_key(key) {
            return Err(ExecError::MalformedEnv(key.clone()));
        }
    }
    validate_timeout(req.timeout)?;
    Ok(())
}

/// Validates that an optional timeout falls within `1..=86400` seconds
/// `None` (no timeout) is always valid.
pub fn validate_timeout(timeout: Option<Duration>) -> Result<(), ExecError> {
    if let Some(d) = timeout {
        let secs = d.as_secs();
        // A sub-second duration rounds to 0 seconds and is out of range.
        if !(MIN_TIMEOUT_SECS..=MAX_TIMEOUT_SECS).contains(&secs) {
            return Err(ExecError::TimeoutOutOfRange(secs));
        }
    }
    Ok(())
}

/// Parses a raw `--env` argument of the form `KEY=value` into its parts
///
/// The key must be a valid environment-variable name (`[A-Za-z_][A-Za-z0-9_]*`)
/// and a `=` must be present; everything after the first `=` is the value and
/// may be empty or contain further `=` characters. Returns
/// [`ExecError::MalformedEnv`] (carrying the original text) on any violation.
pub fn parse_env_var(raw: &str) -> Result<(String, String), ExecError> {
    let (key, value) = raw
        .split_once('=')
        .ok_or_else(|| ExecError::MalformedEnv(raw.to_string()))?;
    if !is_valid_env_key(key) {
        return Err(ExecError::MalformedEnv(raw.to_string()));
    }
    Ok((key.to_string(), value.to_string()))
}

/// Returns `true` when `key` is a valid environment-variable name.
fn is_valid_env_key(key: &str) -> bool {
    let mut chars = key.chars();
    match chars.next() {
        Some(c) if c == '_' || c.is_ascii_alphabetic() => {}
        _ => return false,
    }
    chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
}

/// The standard-library-backed [`CommandExecutor`].
///
/// Uses `std::process` plus one reader thread per output stream and a polling
/// wait loop for the timeout — no async runtime required.
#[derive(Debug, Clone, Copy, Default)]
pub struct StdCommandExecutor;

impl StdCommandExecutor {
    /// Create a new executor.
    pub fn new() -> Self {
        StdCommandExecutor
    }
}

/// Poll interval for the timeout wait loop.
const POLL_INTERVAL: Duration = Duration::from_millis(10);

impl CommandExecutor for StdCommandExecutor {
    fn run(
        &self,
        req: &ExecRequest,
        redactor: &dyn Redactor,
        audit: &mut dyn AuditSink,
    ) -> io::Result<ExecResult> {
        // Validate everything before spawning.
        validate(req)?;

        let mut cmd = Command::new(&req.argv[0]);
        cmd.args(&req.argv[1..])
            .current_dir(&req.cwd)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (key, value) in &req.extra_env {
            cmd.env(key, value);
        }

        let start = Instant::now();
        let mut child = cmd.spawn()?;

        // Capture each output stream on its own thread. Raw child output is
        // never mirrored to the parent before redaction.
        let stdout = child.stdout.take().expect("stdout was piped");
        let stderr = child.stderr.take().expect("stderr was piped");
        let out_handle = capture_stream(stdout);
        let err_handle = capture_stream(stderr);

        // Wait for exit, terminating the child if the timeout elapses.
        let mut timed_out = false;
        let status = loop {
            if let Some(status) = child.try_wait()? {
                break status;
            }
            if let Some(limit) = req.timeout {
                if start.elapsed() >= limit {
                    let _ = child.kill();
                    let status = child.wait()?;
                    timed_out = true;
                    break status;
                }
            }
            thread::sleep(POLL_INTERVAL);
        };

        let duration_ms = start.elapsed().as_millis() as u64;

        // Reader threads finish once the pipes close (child exited or killed).
        let captured_stdout = out_handle.join().unwrap_or_default();
        let captured_stderr = err_handle.join().unwrap_or_default();

        // Redact before either the terminal or audit can observe the output.
        let stdout = redact_and_record(audit, redactor, OutputStream::Stdout, &captured_stdout);
        let stderr = redact_and_record(audit, redactor, OutputStream::Stderr, &captured_stderr);
        emit(OutputStream::Stdout, &stdout);
        emit(OutputStream::Stderr, &stderr);

        // A signal-terminated process has no numeric code; report -1.
        let exit_code = status.code().unwrap_or(-1);

        Ok(ExecResult {
            exit_code,
            duration_ms,
            timed_out,
        })
    }
}

/// Spawn a thread that captures `reader` without exposing raw bytes.
fn capture_stream<R>(mut reader: R) -> thread::JoinHandle<Vec<u8>>
where
    R: Read + Send + 'static,
{
    thread::spawn(move || {
        let mut captured = Vec::new();
        let mut buf = [0u8; 8192];
        loop {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    captured.extend_from_slice(&buf[..n]);
                }
                Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
        captured
    })
}

/// Redact one captured stream and hand it to the sink. On failure, suppress the
/// stream and return a fixed safe notice for the terminal.
fn redact_and_record(
    audit: &mut dyn AuditSink,
    redactor: &dyn Redactor,
    stream: OutputStream,
    bytes: &[u8],
) -> String {
    let text = String::from_utf8_lossy(bytes);
    match redactor.redact(&text) {
        Ok(redacted) => {
            match stream {
                OutputStream::Stdout => audit.record_stdout(&redacted),
                OutputStream::Stderr => audit.record_stderr(&redacted),
            }
            redacted
        }
        Err(RedactionFailed) => {
            audit.record_redaction_failure(stream);
            format!(
                "[{} suppressed: secret redaction failed]\n",
                match stream {
                    OutputStream::Stdout => "stdout",
                    OutputStream::Stderr => "stderr",
                }
            )
        }
    }
}

/// Print only content that has already passed through redaction.
fn emit(stream: OutputStream, text: &str) {
    if text.is_empty() {
        return;
    }
    match stream {
        OutputStream::Stdout => {
            let mut out = io::stdout();
            let _ = out.write_all(text.as_bytes());
            let _ = out.flush();
        }
        OutputStream::Stderr => {
            let mut err = io::stderr();
            let _ = err.write_all(text.as_bytes());
            let _ = err.flush();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fida_secrets::Scanner;

    /// A no-secret redactor: the real Secret_Scanner with no policy patterns,
    /// so output is recorded verbatim unless it contains `.env`/private-key
    /// material.
    fn redactor() -> Scanner {
        Scanner::with_patterns(&[])
    }

    /// Captures everything handed to the sink so tests can assert on it.
    #[derive(Default)]
    struct CapturingSink {
        stdout: Vec<String>,
        stderr: Vec<String>,
        failures: Vec<OutputStream>,
    }

    impl AuditSink for CapturingSink {
        fn record_stdout(&mut self, redacted: &str) {
            self.stdout.push(redacted.to_string());
        }
        fn record_stderr(&mut self, redacted: &str) {
            self.stderr.push(redacted.to_string());
        }
        fn record_redaction_failure(&mut self, stream: OutputStream) {
            self.failures.push(stream);
        }
    }

    fn temp_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "fida-exec-test-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    // --- Validation (platform-independent) ---------------------------------

    #[test]
    fn validate_rejects_missing_cwd() {
        let req = ExecRequest {
            argv: vec!["echo".into()],
            cwd: PathBuf::from("/this/path/does/not/exist/fida"),
            extra_env: vec![],
            timeout: None,
        };
        assert!(matches!(validate(&req), Err(ExecError::CwdDoesNotExist(_))));
    }

    #[test]
    fn validate_rejects_non_directory_cwd() {
        // A regular file as cwd.
        let dir = temp_dir();
        let file = dir.join("not-a-dir");
        std::fs::write(&file, b"x").unwrap();
        let req = ExecRequest {
            argv: vec!["echo".into()],
            cwd: file,
            extra_env: vec![],
            timeout: None,
        };
        assert!(matches!(validate(&req), Err(ExecError::CwdNotDirectory(_))));
    }

    #[test]
    fn validate_rejects_empty_argv() {
        let req = ExecRequest {
            argv: vec![],
            cwd: temp_dir(),
            extra_env: vec![],
            timeout: None,
        };
        assert_eq!(validate(&req), Err(ExecError::EmptyArgv));
    }

    #[test]
    fn parse_env_var_accepts_well_formed() {
        assert_eq!(
            parse_env_var("API_KEY=secret-value"),
            Ok(("API_KEY".to_string(), "secret-value".to_string()))
        );
        // Empty value and embedded '=' are allowed.
        assert_eq!(
            parse_env_var("EMPTY="),
            Ok(("EMPTY".to_string(), String::new()))
        );
        assert_eq!(
            parse_env_var("URL=https://x/?a=b"),
            Ok(("URL".to_string(), "https://x/?a=b".to_string()))
        );
    }

    #[test]
    fn parse_env_var_rejects_malformed() {
        // No '='.
        assert!(matches!(
            parse_env_var("NOEQUALS"),
            Err(ExecError::MalformedEnv(_))
        ));
        // Empty key.
        assert!(matches!(
            parse_env_var("=value"),
            Err(ExecError::MalformedEnv(_))
        ));
        // Key starting with a digit.
        assert!(matches!(
            parse_env_var("1BAD=v"),
            Err(ExecError::MalformedEnv(_))
        ));
        // Key with an illegal character.
        assert!(matches!(
            parse_env_var("BAD-KEY=v"),
            Err(ExecError::MalformedEnv(_))
        ));
    }

    #[test]
    fn validate_rejects_malformed_env_key() {
        let req = ExecRequest {
            argv: vec!["echo".into()],
            cwd: temp_dir(),
            extra_env: vec![("BAD-KEY".into(), "v".into())],
            timeout: None,
        };
        assert!(matches!(validate(&req), Err(ExecError::MalformedEnv(_))));
    }

    #[test]
    fn validate_timeout_bounds() {
        assert!(validate_timeout(None).is_ok());
        assert!(validate_timeout(Some(Duration::from_secs(MIN_TIMEOUT_SECS))).is_ok());
        assert!(validate_timeout(Some(Duration::from_secs(MAX_TIMEOUT_SECS))).is_ok());
        // Sub-second rounds to 0 -> out of range.
        assert_eq!(
            validate_timeout(Some(Duration::from_millis(500))),
            Err(ExecError::TimeoutOutOfRange(0))
        );
        // Above the 24h cap.
        assert_eq!(
            validate_timeout(Some(Duration::from_secs(MAX_TIMEOUT_SECS + 1))),
            Err(ExecError::TimeoutOutOfRange(MAX_TIMEOUT_SECS + 1))
        );
    }

    #[test]
    fn exec_error_maps_to_invalid_input_io_error() {
        let io_err: io::Error = ExecError::EmptyArgv.into();
        assert_eq!(io_err.kind(), io::ErrorKind::InvalidInput);
    }

    // --- Execution (Unix; uses /bin/sh) ------------------------------------

    #[cfg(unix)]
    #[test]
    fn run_echo_captures_output_and_zero_exit() {
        let exec = StdCommandExecutor::new();
        let req = ExecRequest {
            argv: vec!["sh".into(), "-c".into(), "echo hello".into()],
            cwd: temp_dir(),
            extra_env: vec![],
            timeout: Some(Duration::from_secs(10)),
        };
        let red = redactor();
        let mut sink = CapturingSink::default();
        let result = exec.run(&req, &red, &mut sink).unwrap();

        assert_eq!(result.exit_code, 0);
        assert!(!result.timed_out);
        assert!(sink.stdout.iter().any(|s| s.contains("hello")));
        assert!(sink.failures.is_empty());
    }

    #[test]
    fn captured_secret_is_redacted_before_recording() {
        let red = redactor();
        let mut sink = CapturingSink::default();
        let raw = b"API_KEY=[REDACTED:API key param]\n";
        let rendered = redact_and_record(&mut sink, &red, OutputStream::Stdout, raw);

        assert!(!rendered.contains("super-secret-value"));
        assert!(rendered.contains(fida_secrets::REDACTION_MARKER));
        assert_eq!(sink.stdout, vec![rendered]);
    }

    #[cfg(unix)]
    #[test]
    fn run_propagates_nonzero_exit_code() {
        let exec = StdCommandExecutor::new();
        let req = ExecRequest {
            argv: vec!["sh".into(), "-c".into(), "exit 3".into()],
            cwd: temp_dir(),
            extra_env: vec![],
            timeout: None,
        };
        let red = redactor();
        let mut sink = CapturingSink::default();
        let result = exec.run(&req, &red, &mut sink).unwrap();
        assert_eq!(result.exit_code, 3);
        assert!(!result.timed_out);
    }

    #[cfg(unix)]
    #[test]
    fn run_passes_extra_env_to_command() {
        let exec = StdCommandExecutor::new();
        let req = ExecRequest {
            argv: vec!["sh".into(), "-c".into(), "printf %s \"$FIDA_TEST\"".into()],
            cwd: temp_dir(),
            extra_env: vec![("FIDA_TEST".into(), "present".into())],
            timeout: None,
        };
        let red = redactor();
        let mut sink = CapturingSink::default();
        exec.run(&req, &red, &mut sink).unwrap();
        assert!(sink.stdout.iter().any(|s| s.contains("present")));
    }

    #[cfg(unix)]
    #[test]
    fn run_terminates_on_timeout_and_records_elapsed() {
        let exec = StdCommandExecutor::new();
        let req = ExecRequest {
            argv: vec!["sh".into(), "-c".into(), "sleep 30".into()],
            cwd: temp_dir(),
            extra_env: vec![],
            timeout: Some(Duration::from_secs(1)),
        };
        let red = redactor();
        let mut sink = CapturingSink::default();
        let result = exec.run(&req, &red, &mut sink).unwrap();

        assert!(result.timed_out, "command should have timed out");
        // Terminated near the 1s deadline, well before the 30s sleep.
        assert!(
            result.duration_ms >= 1_000,
            "elapsed {} ms",
            result.duration_ms
        );
        assert!(
            result.duration_ms < 10_000,
            "elapsed {} ms",
            result.duration_ms
        );
    }
}
