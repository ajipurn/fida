//! End-to-end CLI integration tests for the documented exit-code table and
//! global behavior (spec task 19.11).
//!
//! These tests run the **actual built `fida` binary** via
//! `Command::new(env!("CARGO_BIN_EXE_fida"))` and assert on the process exit
//! code and output. No new runtime dependency is introduced (the binary path
//! is provided by Cargo); fixtures use the `tempfile` dev-dependency.
//!
//! Exit-code table under test:
//!
//! | Code | Meaning | Covered here |
//! |------|------------------------------------------|--------------|
//! | 0 | success / command's own zero exit | yes (exec allow, dry-run) |
//! | 1 | usage / general error | yes (quiet+verbose, unknown cmd/opt) |
//! | 2 | policy deny | yes (exec deny) |
//! | 3 | non-interactive `ask` (fail closed) | yes (exec ask, stdin not a tty) |
//! | 4 | invalid / unresolvable policy | yes (version-2, missing --config) |
//! | 5 | agent command failed | n/a (agent runner removed) |
//! | 6 | secret exposure blocked | documented (see `exit_6_secret_blocked_coverage_note`) |
//! | 7 | session apply failed | n/a (agent runner removed) |
//!
//! Determinism: every invocation that could otherwise prompt is run with stdin
//! redirected to `/dev/null` (not a tty) so the broker fails closed instead of
//! hanging on an interactive prompt.

use std::path::PathBuf;
use std::process::{Command, Stdio};

use tempfile::TempDir;

/// Absolute path to the built `fida` binary (provided by Cargo).
fn fida() -> &'static str {
    env!("CARGO_BIN_EXE_fida")
}

/// Write a policy file into a fresh temp directory and return both (the
/// `TempDir` must be kept alive for the file to exist).
fn temp_policy(body: &str) -> (TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("create temp dir");
    let path = dir.path().join("policy.yaml");
    std::fs::write(&path, body).expect("write policy");
    (dir, path)
}

/// Build a `fida` invocation with stdin redirected to null (non-interactive,
/// so `ask` fails closed rather than prompting).
fn cmd() -> Command {
    let mut c = Command::new(fida());
    c.stdin(Stdio::null());
    c
}

/// Run a command and return its exit code (panicking on signal termination).
fn code(mut c: Command) -> i32 {
    let out = c.output().expect("spawn fida");
    out.status
        .code()
        .expect("process exited via code, not signal")
}

fn output(mut c: Command) -> std::process::Output {
    c.output().expect("spawn fida")
}

const ALLOW: &str = "version: 1\ndefault_decision: allow\n";
const DENY: &str = "version: 1\ndefault_decision: deny\n";
const ASK: &str = "version: 1\ndefault_decision: ask\n";

// ---------------------------------------------------------------------------
// Exit 1 — usage errors
// ---------------------------------------------------------------------------

#[test]
fn quiet_and_verbose_together_exits_1() {
    // Conflicting global flags are a usage error.
    let mut c = cmd();
    c.args(["--quiet", "--verbose", "doctor"]);
    assert_eq!(code(c), 1);
}

#[test]
fn unknown_command_exits_1() {
    // An unrecognized subcommand is a usage error; no command runs.
    let mut c = cmd();
    c.arg("frobnicate");
    assert_eq!(code(c), 1);
}

#[test]
fn unknown_option_exits_1() {
    // An unrecognized option is a usage error.
    let mut c = cmd();
    c.args(["doctor", "--definitely-not-a-flag"]);
    assert_eq!(code(c), 1);
}

// ---------------------------------------------------------------------------
// Exit 0 — exec allow + dry-run
// ---------------------------------------------------------------------------

#[cfg(unix)]
#[test]
fn exec_allow_propagates_zero_exit() {
    // Allow -> the command's own exit code; `true` exits 0.
    let (_dir, policy) = temp_policy(ALLOW);
    let mut c = cmd();
    c.arg("--config").arg(&policy).args(["exec", "--", "true"]);
    assert_eq!(code(c), 0);
}

#[cfg(unix)]
#[test]
fn exec_allow_propagates_nonzero_command_exit() {
    // Allow -> transparent passthrough of the command's own code;
    // `false` exits 1.
    let (_dir, policy) = temp_policy(ALLOW);
    let mut c = cmd();
    c.arg("--config").arg(&policy).args(["exec", "--", "false"]);
    assert_eq!(code(c), 1);
}

#[cfg(unix)]
#[test]
fn exec_dry_run_exits_0_without_executing() {
    // --dry-run evaluates policy but does not run the command, so a
    // command that would fail (`false`) still yields exit 0.
    let (_dir, policy) = temp_policy(ALLOW);
    let mut c = cmd();
    c.arg("--config")
        .arg(&policy)
        .args(["exec", "--dry-run", "--", "false"]);
    assert_eq!(code(c), 0);
}

// ---------------------------------------------------------------------------
#[cfg(unix)]
#[test]
fn guard_inactive_passthrough_propagates_command_status() {
    // With no project or global setup, `guard` must be transparent: this is the
    // mode hooks/shims rely on when Fida is not active for the current repo.
    let home = tempfile::tempdir().unwrap();
    let project = tempfile::tempdir().unwrap();

    let mut zero = cmd();
    zero.current_dir(project.path())
        .env("FIDA_HOME", home.path())
        .args(["guard", "--", "true"]);
    assert_eq!(code(zero), 0);

    let mut one = cmd();
    one.current_dir(project.path())
        .env("FIDA_HOME", home.path())
        .args(["guard", "--", "false"]);
    assert_eq!(code(one), 1);
}

// Exit 2 — policy deny
// ---------------------------------------------------------------------------

#[cfg(unix)]
#[test]
fn exec_deny_exits_2() {
    let (_dir, policy) = temp_policy(DENY);
    let mut c = cmd();
    c.arg("--config").arg(&policy).args(["exec", "--", "true"]);
    assert_eq!(code(c), 2);
}

#[cfg(unix)]
#[test]
fn exec_denies_cat_env_before_secret_reaches_stdout() {
    let (_pdir, policy) = temp_policy(
        r#"version: 1
default_decision: allow
hard_denies_disabled: true
files:
  read:
    deny:
      - .env
"#,
    );
    let project = tempfile::tempdir().unwrap();
    std::fs::write(project.path().join(".env"), "TOP_SECRET=fida\n").unwrap();

    let mut c = cmd();
    c.current_dir(project.path())
        .arg("--config")
        .arg(&policy)
        .args(["exec", "--", "cat", ".env"]);

    let out = output(c);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        !String::from_utf8_lossy(&out.stdout).contains("TOP_SECRET"),
        "denied file read must not run `cat.env`"
    );
}

#[cfg(unix)]
#[test]
fn active_guard_denies_cat_env_before_secret_reaches_stdout() {
    let (_pdir, policy) = temp_policy(
        r#"version: 1
default_decision: allow
hard_denies_disabled: true
files:
  read:
    deny:
      - .env
"#,
    );
    let project = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    std::fs::write(project.path().join(".env"), "TOP_SECRET=fida\n").unwrap();

    // Activate protection globally (isolated via FIDA_HOME/HOME) so the guard
    // mediates instead of passing the command through.
    let mut on_cmd = cmd();
    on_cmd
        .current_dir(project.path())
        .env("HOME", home.path())
        .env("FIDA_HOME", home.path())
        .args(["on", "codex"]);
    assert_eq!(code(on_cmd), 0);

    let mut c = cmd();
    c.current_dir(project.path())
        .env("HOME", home.path())
        .env("FIDA_HOME", home.path())
        .arg("--config")
        .arg(&policy)
        .args(["guard", "--", "cat", ".env"]);

    let out = output(c);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        !String::from_utf8_lossy(&out.stdout).contains("TOP_SECRET"),
        "active guard must mediate and block `cat.env`"
    );
}

// ---------------------------------------------------------------------------
// Exit 3 — non-interactive `ask` fails closed
// ---------------------------------------------------------------------------

#[cfg(unix)]
#[test]
fn exec_non_interactive_ask_exits_3() {
    // stdin is redirected to /dev/null by `cmd`, so the session is
    // non-interactive: an `ask` decision has no way to be approved and the
    // broker fails closed to exit 3 (it must NOT hang on a prompt).
    let (_dir, policy) = temp_policy(ASK);
    let mut c = cmd();
    c.arg("--config").arg(&policy).args(["exec", "--", "true"]);
    assert_eq!(code(c), 3);
}

// ---------------------------------------------------------------------------
// Exit 4 — invalid / unresolvable policy
// ---------------------------------------------------------------------------

#[cfg(unix)]
#[test]
fn invalid_policy_version_exits_4() {
    // An unsupported schema version is an invalid policy.
    let (_dir, policy) = temp_policy("version: 2\ndefault_decision: allow\n");
    let mut c = cmd();
    c.arg("--config").arg(&policy).args(["exec", "--", "true"]);
    assert_eq!(code(c), 4);
}

#[test]
fn missing_config_path_exits_4() {
    // A --config path with no readable file must not fall back; it is
    // an unresolvable policy -> exit 4.
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("does-not-exist.yaml");
    let mut c = cmd();
    c.arg("--config").arg(&missing).args(["exec", "--", "true"]);
    assert_eq!(code(c), 4);
}

// ---------------------------------------------------------------------------
// Exit 6 / 7 — coverage notes
// ---------------------------------------------------------------------------

/// Exit 6 (secret exposure blocked) is produced by the diff/apply
/// path: a changed file containing a detected secret is blocked when the policy
/// has `secrets.block_in_diffs` enabled. The CLI mapping from that outcome to
/// exit 6 lives in `commands/run.rs` (`EXIT_SECRET_BLOCKED => SecretBlocked`)
/// and is exercised by the broker/diff property tests and `run.rs` unit tests;
/// the `exec` path cannot reach a secret-deny (it mediates `command.run`, not
/// file diffs), so this end-to-end harness documents the coverage rather than
/// duplicating the multi-step git+agent+secret fixture here.
#[test]
fn exit_6_secret_blocked_coverage_note() {
    // Intentionally a no-op: the behavior is verified end-to-end in the diff
    // crate's apply tests and mapped to exit 6 in run.rs.
}

/// Exit 7 (session apply failed) is produced when one or more file
/// changes cannot be applied to the main workspace. Forcing a real apply
/// failure end-to-end requires provoking a filesystem error during apply, which
/// is brittle across platforms; the CLI mapping (`_ => ApplyFailed`) lives in
/// `commands/run.rs` and is covered by the diff-gate apply tests and run.rs
/// unit tests. Documented here for traceability.
#[test]
fn exit_7_apply_failed_coverage_note() {
    // Intentionally a no-op: see the doc comment above for where exit 7 is
    // mapped (run.rs) and verified (diff-gate apply tests).
}

// ---------------------------------------------------------------------------
// Exit 0 — --json output is valid JSON
// ---------------------------------------------------------------------------

#[test]
fn json_output_is_valid_json() {
    // `--json` prints valid, parseable JSON for the command's primary result.
    // `scan` over an empty directory finds nothing and exits 0.
    let dir = tempfile::tempdir().unwrap();
    let mut c = cmd();
    c.current_dir(dir.path()).args(["--json", "scan"]);
    let out = c.output().expect("spawn fida");
    assert_eq!(out.status.code(), Some(0), "clean scan must exit 0");
    let parsed: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("stdout must be valid JSON");
    assert!(parsed.is_object(), "scan JSON is an object");
}
