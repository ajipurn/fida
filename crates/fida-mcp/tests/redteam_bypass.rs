//! Red-team self-check for the Fida gateway.
//!
//! The built-in default is leak-prevention-first: paths inside the workspace
//! remain readable, but detected secret values must be redacted before a tool
//! result reaches the agent. PathJail still blocks attempts to escape the
//! workspace through absolute paths, traversal, or symlinks.

use std::io::Cursor;

use serde_json::{Value, json};

use fida_broker::SessionHandle;
use fida_broker::testing::MemoryAuditStore;
use fida_mcp::server::PATHJAIL_DENIED_CODE;
use fida_mcp::{GatewayServer, READ_TOOL};
use fida_policy::{CompiledPolicy, PolicySource, load_source};

fn builtin_policy() -> CompiledPolicy {
    load_source(&PolicySource::BuiltinDefault, None).expect("built-in default policy compiles")
}

fn read_call(path: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": { "name": READ_TOOL, "arguments": { "path": path } }
    })
}

fn roundtrip(server: &GatewayServer, request: &Value) -> Value {
    let input = format!("{request}\n");
    let mut reader = Cursor::new(input.into_bytes());
    let mut output: Vec<u8> = Vec::new();
    let mut audit = MemoryAuditStore::new();
    let mut session = SessionHandle::new("redteam-session");
    server
        .serve(&mut reader, &mut output, &mut audit, &mut session)
        .expect("serve loop ok");
    let line = String::from_utf8(output).unwrap();
    serde_json::from_str(line.trim()).expect("response is json")
}

#[test]
fn redteam_workspace_escapes_remain_blocked_under_default_policy() {
    let root = tempfile::tempdir().unwrap();
    let ws = root.path().join("ws");
    std::fs::create_dir_all(&ws).unwrap();

    let outside_secret = "outside-secret-abcdefghijklmnopqrstuvwxyz";
    let outside = root.path().join("escape.env");
    std::fs::write(&outside, format!("API_KEY={outside_secret}\n")).unwrap();

    let srv = GatewayServer::new(builtin_policy(), ws.clone());
    let mut cases = vec![
        outside.display().to_string(),
        "../escape.env".to_string(),
        "../../../../../../etc/passwd".to_string(),
    ];

    #[cfg(unix)]
    {
        cases.push("/etc/passwd".to_string());
        std::os::unix::fs::symlink(&outside, ws.join("link.env")).unwrap();
        cases.push("link.env".to_string());
    }

    for path in cases {
        let resp = roundtrip(&srv, &read_call(&path));
        assert_eq!(
            resp["error"]["code"], PATHJAIL_DENIED_CODE,
            "workspace escape was not blocked: {path:?}; response: {resp}"
        );
        assert!(!resp.to_string().contains(outside_secret));
    }
}

#[test]
fn redteam_sensitive_files_inside_workspace_return_only_redacted_views() {
    let dir = tempfile::tempdir().unwrap();
    let secret = "abcdefghijklmnopqrstuvwxyz123456";
    let files = [
        (".env", format!("API_KEY={secret}\n")),
        (".env.production", format!("TOKEN={secret}\n")),
        ("app.key", format!("SECRET={secret}\n")),
        (
            "server.pem",
            format!("-----BEGIN PRIVATE KEY-----\n{secret}\n-----END PRIVATE KEY-----\n"),
        ),
    ];
    for (name, body) in &files {
        std::fs::write(dir.path().join(name), body).unwrap();
    }

    let srv = GatewayServer::new(builtin_policy(), dir.path().to_path_buf());
    for (name, _) in &files {
        let resp = roundtrip(&srv, &read_call(name));
        assert_eq!(
            resp["result"]["isError"], false,
            "mediated read should succeed for {name}: {resp}"
        );
        let text = resp["result"]["content"][0]["text"].as_str().unwrap();
        assert!(!text.contains(secret), "{name} leaked the planted secret");
        assert!(
            text.contains(fida_secrets::REDACTION_MARKER),
            "{name} did not report a redaction"
        );
    }
}

#[test]
fn redteam_allowed_source_file_still_redacts_embedded_provider_key() {
    let dir = tempfile::tempdir().unwrap();
    let secret = "abcdefghijklmnopqrstuvwxyz123456";
    std::fs::write(
        dir.path().join("notes.md"),
        format!("setup notes\nAPI_KEY={secret}\n"),
    )
    .unwrap();

    let srv = GatewayServer::new(builtin_policy(), dir.path().to_path_buf());
    let resp = roundtrip(&srv, &read_call("notes.md"));

    assert_eq!(resp["result"]["isError"], false);
    let text = resp["result"]["content"][0]["text"].as_str().unwrap();
    assert!(!text.contains(secret));
    assert!(text.contains(fida_secrets::REDACTION_MARKER));
}

#[test]
fn redteam_allowed_source_file_redacts_openai_project_key() {
    let dir = tempfile::tempdir().unwrap();
    let secret = [
        "sk",
        "-proj-",
        "0123456789abcdefghijklmnopqrstuv",
        "_",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcd",
        "-",
        "efghijklmnopqrstuvwxyz012345",
    ]
    .concat();
    std::fs::write(
        dir.path().join("person.js"),
        format!(r#"export const firstName = "{secret}";"#),
    )
    .unwrap();

    let srv = GatewayServer::new(builtin_policy(), dir.path().to_path_buf());
    let resp = roundtrip(&srv, &read_call("person.js"));

    assert_eq!(resp["result"]["isError"], false);
    let text = resp["result"]["content"][0]["text"].as_str().unwrap();
    assert!(!text.contains(&secret));
    assert!(text.contains(fida_secrets::REDACTION_MARKER));
}
