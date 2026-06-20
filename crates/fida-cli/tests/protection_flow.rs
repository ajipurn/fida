//! End-to-end coverage for the install/toggle surface: `fida on`, `fida off`,
//! and bare `fida`. Each run uses a throwaway HOME (global scope) and a
//! throwaway workspace so nothing touches the developer's real agents.

use std::process::Command;

const SECRET: &str = "fida-flow-test-secret-0123456789";

fn fida() -> Command {
    Command::new(env!("CARGO_BIN_EXE_fida"))
}

/// Run `fida on <agent> --json` and return (workspace, home, parsed JSON).
/// Asserts the synthetic secret never appears on stdout or stderr.
fn run_on(agent: &str) -> (tempfile::TempDir, tempfile::TempDir, serde_json::Value) {
    let workspace = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    std::fs::write(workspace.path().join(".env"), format!("API_KEY={SECRET}\n")).unwrap();

    let output = fida()
        .args(["on", agent, "--json"])
        .current_dir(workspace.path())
        .env("HOME", home.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(!stdout.contains(SECRET), "secret leaked to stdout");
    assert!(!stderr.contains(SECRET), "secret leaked to stderr");
    let json = serde_json::from_str(&stdout).unwrap();
    (workspace, home, json)
}

#[test]
fn on_reports_enforced_for_hard_block_agent() {
    let (_ws, _home, json) = run_on("codex");
    assert_eq!(json["installed"][0]["protection"], "enforced");
    assert_eq!(json["verification"]["passed"], true);
}

#[test]
fn on_reports_best_effort_for_gateway_only_agent() {
    let (_ws, _home, json) = run_on("cursor");
    assert_eq!(json["installed"][0]["protection"], "best_effort");
    assert_eq!(json["verification"]["passed"], true);
}

#[test]
fn off_removes_a_previously_protected_agent() {
    let (workspace, home, _json) = run_on("codex");

    let off = fida()
        .args(["off", "codex", "--json"])
        .current_dir(workspace.path())
        .env("HOME", home.path())
        .output()
        .unwrap();
    assert!(
        off.status.success(),
        "{}",
        String::from_utf8_lossy(&off.stderr)
    );
    let off_json: serde_json::Value = serde_json::from_slice(&off.stdout).unwrap();
    assert!(off_json["remaining"].as_array().unwrap().is_empty());

    // With nothing left wired, status reports an inactive (null) effective scope.
    let status = fida()
        .args(["status", "--json"])
        .current_dir(workspace.path())
        .env("HOME", home.path())
        .output()
        .unwrap();
    let status_json: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();
    assert!(status_json["effective_scope"].is_null());
}

#[test]
fn bare_fida_runs_the_global_install_flow() {
    let workspace = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();

    // Bare `fida --yes` runs the install flow non-interactively. With an
    // isolated HOME it wires whatever it detects into the throwaway home and
    // always emits the global install contract. (We can't assert *which* agents
    // are detected: `detect_apps` inspects the real /Applications, which the
    // test environment cannot isolate.)
    let output = fida()
        .args(["--yes", "--json"])
        .current_dir(workspace.path())
        .env("HOME", home.path())
        .env("FIDA_HOME", home.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["scope"], "global");
    assert!(json["installed"].is_array());
}
