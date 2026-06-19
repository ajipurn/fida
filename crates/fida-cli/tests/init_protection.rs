use std::process::Command;

fn run_init(agent: &str) -> (tempfile::TempDir, serde_json::Value, String) {
    let workspace = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let secret = "fida-init-test-secret-0123456789";
    std::fs::write(workspace.path().join(".env"), format!("API_KEY={secret}\n")).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_fida"))
        .args([
            "init",
            "--project",
            "--agents",
            agent,
            "--workspace",
            workspace.path().to_str().unwrap(),
            "--json",
        ])
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
    assert!(!stdout.contains(secret));
    assert!(!stderr.contains(secret));
    let json = serde_json::from_str(&stdout).unwrap();
    (workspace, json, secret.to_string())
}

#[test]
fn init_reports_enforced_for_hard_block_agent() {
    let (_workspace, json, _secret) = run_init("codex");
    assert_eq!(json["installed"][0]["protection"], "enforced");
    assert_eq!(json["verification"]["passed"], true);
}

#[test]
fn init_reports_best_effort_for_gateway_only_agent() {
    let (_workspace, json, _secret) = run_init("cursor");
    assert_eq!(json["installed"][0]["protection"], "best_effort");
    assert_eq!(json["verification"]["passed"], true);
}
