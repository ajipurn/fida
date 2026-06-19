//! Shared secret-protection verification used by onboarding and `doctor`.

use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use fida_audit::JsonlAuditStore;
use fida_broker::SessionHandle;
use fida_mcp::{GatewayServer, READ_TOOL, SHELL_TOOL};
use fida_policy::{PolicySource, load_source};
use fida_secrets::REDACTION_MARKER;
use serde_json::{Value, json};

use crate::error::{CliError, CliResult};

const SYNTHETIC_SECRET: &str = "fida-self-test-secret-0123456789abcdef";
const SESSION: &str = "protection-self-test";

#[derive(Debug, Clone)]
pub struct VerificationResult {
    pub passed: bool,
    pub detail: String,
}

/// Exercise the same MCP gateway used by agents. The test succeeds only when
/// file reads are redacted, shell output is redacted or safely blocked, and
/// neither responses nor the audit log contain the synthetic secret.
pub fn verify_gateway() -> CliResult<VerificationResult> {
    let temp = TempDir::new("protection")?;
    std::fs::write(
        temp.path().join(".env"),
        format!("FIDA_SELF_TEST_TOKEN={SYNTHETIC_SECRET}\n"),
    )
    .map_err(|e| CliError::general(format!("cannot create protection fixture: {e}")))?;

    let policy = load_source(&PolicySource::BuiltinDefault, None)?;
    let server = GatewayServer::new(policy, temp.path());
    let audit_root = temp.path().join("audit");
    let mut audit = JsonlAuditStore::new(&audit_root);
    let mut session = SessionHandle::new(SESSION);

    let read = roundtrip(
        &server,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": { "name": READ_TOOL, "arguments": { "path": ".env" } }
        }),
        &mut audit,
        &mut session,
    )?;
    let shell = roundtrip(
        &server,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": { "name": SHELL_TOOL, "arguments": {
                "command": shell_probe_command()
            } }
        }),
        &mut audit,
        &mut session,
    )?;

    let read_wire = read.to_string();
    let shell_wire = shell.to_string();
    let audit_wire = std::fs::read_to_string(audit.events_path(SESSION)).unwrap_or_default();

    let no_leak = [&read_wire, &shell_wire, &audit_wire]
        .iter()
        .all(|text| !text.contains(SYNTHETIC_SECRET));
    let read_redacted = read_wire.contains(REDACTION_MARKER);
    let shell_safe = shell_wire.contains(REDACTION_MARKER) || shell.get("error").is_some();
    let passed = no_leak && read_redacted && shell_safe;
    let detail = if passed {
        "file reads and shell output suppress raw secret values before model delivery".to_string()
    } else {
        format!(
            "verification failed (no_leak={no_leak}, read_redacted={read_redacted}, shell_safe={shell_safe})"
        )
    };

    Ok(VerificationResult { passed, detail })
}

fn roundtrip(
    server: &GatewayServer,
    request: Value,
    audit: &mut JsonlAuditStore,
    session: &mut SessionHandle,
) -> CliResult<Value> {
    let mut reader = Cursor::new(format!("{request}\n").into_bytes());
    let mut output = Vec::new();
    server
        .serve(&mut reader, &mut output, audit, session)
        .map_err(|e| CliError::general(format!("protection gateway self-test failed: {e}")))?;
    serde_json::from_slice(&output)
        .map_err(|e| CliError::general(format!("invalid self-test gateway response: {e}")))
}

#[cfg(unix)]
fn shell_probe_command() -> &'static str {
    "cat .env"
}

#[cfg(windows)]
fn shell_probe_command() -> &'static str {
    // The built-in policy may deny this command; a policy block is still a
    // safe result because no output reaches the model.
    "cmd /C type .env"
}

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(tag: &str) -> CliResult<Self> {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let path = std::env::temp_dir().join(format!("fida-{tag}-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&path)
            .map_err(|e| CliError::general(format!("cannot create self-test directory: {e}")))?;
        Ok(Self { path })
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gateway_self_test_proves_no_model_bound_leak() {
        let result = verify_gateway().expect("self-test runs");
        assert!(result.passed, "{}", result.detail);
        assert!(!result.detail.contains(SYNTHETIC_SECRET));
    }
}
