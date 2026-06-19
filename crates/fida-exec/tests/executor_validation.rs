//! Integration tests for `fida-exec` executor validation and timeout
//! handling (spec task 12.2).
//!
//! These complete the coverage of the inline unit tests against the crate's
//! public surface:
//!
//! * invalid `--cwd` (nonexistent path / not a directory)
//! * malformed `--env KEY=value` rejection
//! * `--timeout` range bounds (1..=86400 s)
//! * timeout-termination recording elapsed milliseconds

use std::path::PathBuf;
use std::time::Duration;

use fida_exec::{
    ExecError, ExecRequest, MAX_TIMEOUT_SECS, MIN_TIMEOUT_SECS, parse_env_var, validate,
    validate_timeout,
};
use fida_secrets::Scanner;

/// Create a fresh, unique temporary directory usable as a valid `--cwd`.
fn temp_dir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "fida-exec-it-{}-{:?}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

// --- invalid --cwd ----------------------------------------------------------

#[test]
fn nonexistent_cwd_is_rejected() {
    let req = ExecRequest {
        argv: vec!["echo".into()],
        cwd: PathBuf::from("/no/such/fida/path/zzz"),
        extra_env: vec![],
        timeout: None,
    };
    match validate(&req) {
        Err(ExecError::CwdDoesNotExist(p)) => {
            assert_eq!(p, PathBuf::from("/no/such/fida/path/zzz"));
        }
        other => panic!("expected CwdDoesNotExist, got {other:?}"),
    }
}

#[test]
fn file_as_cwd_is_rejected_as_not_directory() {
    let dir = temp_dir();
    let file = dir.join("regular-file");
    std::fs::write(&file, b"contents").unwrap();
    let req = ExecRequest {
        argv: vec!["echo".into()],
        cwd: file.clone(),
        extra_env: vec![],
        timeout: None,
    };
    match validate(&req) {
        Err(ExecError::CwdNotDirectory(p)) => assert_eq!(p, file),
        other => panic!("expected CwdNotDirectory, got {other:?}"),
    }
}

#[test]
fn valid_directory_cwd_passes_validation() {
    let req = ExecRequest {
        argv: vec!["echo".into()],
        cwd: temp_dir(),
        extra_env: vec![],
        timeout: None,
    };
    assert_eq!(validate(&req), Ok(()));
}

// --- malformed --env --------------------------------------------------------

#[test]
fn parse_env_var_rejects_missing_equals() {
    assert!(matches!(
        parse_env_var("NOEQUALS"),
        Err(ExecError::MalformedEnv(_))
    ));
}

#[test]
fn parse_env_var_rejects_empty_key() {
    assert!(matches!(
        parse_env_var("=value"),
        Err(ExecError::MalformedEnv(_))
    ));
}

#[test]
fn parse_env_var_rejects_key_starting_with_digit() {
    assert!(matches!(
        parse_env_var("1BAD=v"),
        Err(ExecError::MalformedEnv(_))
    ));
}

#[test]
fn parse_env_var_rejects_key_with_illegal_char() {
    assert!(matches!(
        parse_env_var("BAD-KEY=v"),
        Err(ExecError::MalformedEnv(_))
    ));
}

#[test]
fn parse_env_var_accepts_value_with_embedded_equals() {
    assert_eq!(
        parse_env_var("CONN=a=b=c"),
        Ok(("CONN".to_string(), "a=b=c".to_string()))
    );
}

#[test]
fn validate_rejects_request_with_bad_env_key() {
    let req = ExecRequest {
        argv: vec!["echo".into()],
        cwd: temp_dir(),
        extra_env: vec![("BAD-KEY".into(), "v".into())],
        timeout: None,
    };
    assert!(matches!(validate(&req), Err(ExecError::MalformedEnv(_))));
}

// --- timeout range bounds ---------------------------------------------------

#[test]
fn timeout_accepts_inclusive_bounds() {
    assert_eq!(
        validate_timeout(Some(Duration::from_secs(MIN_TIMEOUT_SECS))),
        Ok(())
    );
    assert_eq!(
        validate_timeout(Some(Duration::from_secs(MAX_TIMEOUT_SECS))),
        Ok(())
    );
}

#[test]
fn timeout_none_is_always_valid() {
    assert_eq!(validate_timeout(None), Ok(()));
}

#[test]
fn timeout_rejects_zero_and_sub_second() {
    assert_eq!(
        validate_timeout(Some(Duration::from_secs(0))),
        Err(ExecError::TimeoutOutOfRange(0))
    );
    // Sub-second rounds down to 0 seconds and is out of range.
    assert_eq!(
        validate_timeout(Some(Duration::from_millis(500))),
        Err(ExecError::TimeoutOutOfRange(0))
    );
}

#[test]
fn timeout_rejects_above_max() {
    assert_eq!(
        validate_timeout(Some(Duration::from_secs(MAX_TIMEOUT_SECS + 1))),
        Err(ExecError::TimeoutOutOfRange(MAX_TIMEOUT_SECS + 1))
    );
}

// --- timeout termination records elapsed ms --------------------------------

#[cfg(unix)]
mod timeout_run {
    use super::*;
    use fida_exec::{AuditSink, CommandExecutor, OutputStream, StdCommandExecutor};

    /// Minimal sink that records nothing of interest; the run-based test only
    /// asserts on the returned `ExecResult`.
    #[derive(Default)]
    struct NullSink {
        failures: Vec<OutputStream>,
    }

    impl AuditSink for NullSink {
        fn record_stdout(&mut self, _redacted: &str) {}
        fn record_stderr(&mut self, _redacted: &str) {}
        fn record_redaction_failure(&mut self, stream: OutputStream) {
            self.failures.push(stream);
        }
    }

    #[test]
    fn timed_out_run_records_elapsed_near_deadline() {
        let exec = StdCommandExecutor::new();
        let req = ExecRequest {
            argv: vec!["sh".into(), "-c".into(), "sleep 30".into()],
            cwd: temp_dir(),
            extra_env: vec![],
            timeout: Some(Duration::from_secs(1)),
        };
        let redactor = Scanner::with_patterns(&[]);
        let mut sink = NullSink::default();
        let result = exec.run(&req, &redactor, &mut sink).unwrap();

        assert!(result.timed_out, "command should have been timed out");
        // Terminated at/after the 1s deadline...
        assert!(
            result.duration_ms >= 1_000,
            "elapsed {} ms should be >= 1000",
            result.duration_ms
        );
        // ...and well before the 30s the command would otherwise run.
        assert!(
            result.duration_ms < 30_000,
            "elapsed {} ms should be well under 30000",
            result.duration_ms
        );
    }
}
