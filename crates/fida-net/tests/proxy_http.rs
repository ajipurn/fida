//! Integration tests for the Network_Proxy against a real local HTTP origin
//! (spec task 15.2; design "Network Proxy Design").
//!
//! These exercise the full async [`NetworkProxy::serve`] path over real
//! loopback sockets:
//!
//! * **Allow forwarding**: a request to an explicitly
//!   allowed loopback origin is forwarded and the origin's `200` body comes
//!   back through the proxy; the decision is audited as `Allowed`.
//! * **Metadata-IP denial**: a request to
//!   `169.254.169.254` returns a policy-denial connection failure (`403`),
//!   never reaches an origin, and is audited as `Denied`.
//! * **Private-CIDR denial**: a `CONNECT` to a
//!   `10/8` host is refused (`403`, no tunnel established) and audited as
//!   `Denied`.
//!
//! Short timeouts guard every socket read so a misbehaving path fails fast
//! rather than hanging the suite.

use std::io;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio::time::timeout;

use fida_audit::{AuditResult, AuditStore};
use fida_broker::testing::MemoryAuditStore;
use fida_net::NetworkProxy;
use fida_policy::{CompiledPolicy, PolicySource, load_source};

const SESSION: &str = "sess-net-15-2";
const ORIGIN_BODY: &str = "hello-from-origin";
const IO_TIMEOUT: Duration = Duration::from_secs(3);

/// Build a policy that allows the loopback origin host (`127.0.0.1`) while the
/// global default is `deny`. `127.0.0.1` is loopback — neither the metadata IP
/// nor inside a private-CIDR hard-deny range — so an explicit allow rule lets
/// it through.
fn allow_loopback_policy() -> Arc<CompiledPolicy> {
    let raw = r#"
version: 1
default_decision: deny
commands: {}
files: {}
network:
  allow:
    - host: 127.0.0.1
mcp: {}
secrets:
  redact: true
  block_in_diffs: true
  patterns: []
audit:
  path: .fida/sessions
  format: jsonl
  redact_stdout: true
  redact_stderr: true
"#;
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("fida.yaml");
    std::fs::write(&path, raw).expect("write policy");
    let policy = load_source(&PolicySource::Config(path), None).expect("policy compiles");
    // Keep the tempdir alive for the policy's lifetime by leaking it; tests are
    // short-lived processes so this is harmless and avoids a borrow dance.
    std::mem::forget(dir);
    Arc::new(policy)
}

/// Spawn a trivial HTTP/1.1 origin on `127.0.0.1` that, for each connection,
/// reads the request head and writes a fixed `200` response with a known body.
/// Returns the bound port.
async fn spawn_origin() -> Option<u16> {
    let listener = match TcpListener::bind(("127.0.0.1", 0)).await {
        Ok(listener) => listener,
        Err(err) if err.kind() == io::ErrorKind::PermissionDenied => return None,
        Err(err) => panic!("bind origin: {err}"),
    };
    let port = listener.local_addr().expect("origin addr").port();
    tokio::spawn(async move {
        loop {
            let (mut conn, _) = match listener.accept().await {
                Ok(pair) => pair,
                Err(_) => break,
            };
            tokio::spawn(async move {
                // Read the request head (up to the blank line) so the client's
                // write completes before we respond.
                let mut buf = Vec::new();
                let mut chunk = [0u8; 1024];
                loop {
                    match conn.read(&mut chunk).await {
                        Ok(0) => break,
                        Ok(n) => {
                            buf.extend_from_slice(&chunk[..n]);
                            if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    ORIGIN_BODY.len(),
                    ORIGIN_BODY
                );
                let _ = conn.write_all(response.as_bytes()).await;
                let _ = conn.flush().await;
            });
        }
    });
    Some(port)
}

/// Start the proxy on its own task with a shared in-memory audit store.
async fn spawn_proxy(
    policy: Arc<CompiledPolicy>,
) -> Option<(std::net::SocketAddr, Arc<Mutex<MemoryAuditStore>>)> {
    let proxy = match NetworkProxy::bind(policy, SESSION).await {
        Ok(proxy) => proxy,
        Err(err) if err.kind() == io::ErrorKind::PermissionDenied => return None,
        Err(err) => panic!("bind proxy: {err}"),
    };
    let addr = proxy.local_addr();
    let audit = Arc::new(Mutex::new(MemoryAuditStore::new()));
    let serve_audit = Arc::clone(&audit);
    tokio::spawn(async move {
        let _ = proxy.serve(serve_audit).await;
    });
    Some((addr, audit))
}

/// Send `request` to the proxy and read the response bytes (until EOF or
/// timeout), returning them as a lossy string.
async fn send_through_proxy(proxy_addr: std::net::SocketAddr, request: &str) -> String {
    let mut stream = timeout(IO_TIMEOUT, TcpStream::connect(proxy_addr))
        .await
        .expect("connect proxy (timeout)")
        .expect("connect proxy");
    timeout(IO_TIMEOUT, stream.write_all(request.as_bytes()))
        .await
        .expect("write request (timeout)")
        .expect("write request");
    let _ = stream.flush().await;

    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        match timeout(IO_TIMEOUT, stream.read(&mut chunk)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                buf.extend_from_slice(&chunk[..n]);
                // Stop once we have a full status line + the known body, so the
                // allow path does not wait for the proxy's bidirectional copy
                // to close.
                if String::from_utf8_lossy(&buf).contains(ORIGIN_BODY) {
                    break;
                }
                // For a denial we get a small 403 with Connection: close, which
                // ends via EOF above.
            }
            Ok(Err(_)) => break,
            // Timed out waiting for more — return what we have.
            Err(_) => break,
        }
    }
    String::from_utf8_lossy(&buf).into_owned()
}

/// Poll the shared audit store until at least one event is recorded for the
/// session, then return the most recent event's result.
async fn await_last_result(audit: &Arc<Mutex<MemoryAuditStore>>) -> AuditResult {
    for _ in 0..50 {
        {
            let guard = audit.lock().await;
            let events = guard.read(SESSION).expect("read audit");
            if let Some(last) = events.last() {
                return last.result;
            }
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("no audit event recorded for session {SESSION}");
}

// ---------------------------------------------------------------------------

#[tokio::test]
async fn allow_path_forwards_to_origin_and_audits_allowed() {
    let Some(origin_port) = spawn_origin().await else {
        return;
    };
    let Some((proxy_addr, audit)) = spawn_proxy(allow_loopback_policy()).await else {
        return;
    };

    let request = format!(
        "GET http://127.0.0.1:{port}/ HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n",
        port = origin_port
    );
    let response = send_through_proxy(proxy_addr, &request).await;

    // Allow forwarding: the origin's 200 body is received through the proxy
    assert!(
        response.contains("200"),
        "expected 200 status, got: {response:?}"
    );
    assert!(
        response.contains(ORIGIN_BODY),
        "expected origin body forwarded, got: {response:?}"
    );

    // The decision was audited as Allowed.
    let result = await_last_result(&audit).await;
    assert_eq!(
        result,
        AuditResult::Allowed,
        "allow path must audit Allowed"
    );
}

#[tokio::test]
async fn metadata_ip_is_denied_without_forwarding() {
    // No origin needed: a denied request must never reach one.
    let Some((proxy_addr, audit)) = spawn_proxy(allow_loopback_policy()).await else {
        return;
    };

    let request = "GET http://169.254.169.254/latest/meta-data/ HTTP/1.1\r\nHost: 169.254.169.254\r\nConnection: close\r\n\r\n";
    let response = send_through_proxy(proxy_addr, request).await;

    // Policy-denial connection failure: 403, body never the origin's
    assert!(
        response.contains("403"),
        "metadata IP must return a 403 policy denial, got: {response:?}"
    );
    assert!(
        !response.contains(ORIGIN_BODY),
        "metadata IP must not be forwarded to any origin"
    );

    let result = await_last_result(&audit).await;
    assert_eq!(result, AuditResult::Denied, "metadata IP must audit Denied");
}

#[tokio::test]
async fn private_cidr_connect_is_denied_without_tunnel() {
    let Some((proxy_addr, audit)) = spawn_proxy(allow_loopback_policy()).await else {
        return;
    };

    // CONNECT to a private-CIDR (10/8) host: the tunnel must never be
    // established.
    let request = "CONNECT 10.0.0.5:443 HTTP/1.1\r\nHost: 10.0.0.5:443\r\n\r\n";
    let response = send_through_proxy(proxy_addr, request).await;

    assert!(
        response.contains("403"),
        "private-CIDR CONNECT must return a 403 policy denial, got: {response:?}"
    );
    assert!(
        !response.contains("200 Connection Established"),
        "private-CIDR CONNECT must not establish a tunnel"
    );

    let result = await_last_result(&audit).await;
    assert_eq!(
        result,
        AuditResult::Denied,
        "private CIDR must audit Denied"
    );
}

#[tokio::test]
async fn private_cidr_absolute_form_is_denied() {
    let Some((proxy_addr, audit)) = spawn_proxy(allow_loopback_policy()).await else {
        return;
    };

    // Plain-HTTP absolute-form to a private-CIDR (192.168/16) host.
    let request =
        "GET http://192.168.1.10/ HTTP/1.1\r\nHost: 192.168.1.10\r\nConnection: close\r\n\r\n";
    let response = send_through_proxy(proxy_addr, request).await;

    assert!(
        response.contains("403"),
        "private-CIDR request must return a 403 policy denial, got: {response:?}"
    );
    assert!(
        !response.contains(ORIGIN_BODY),
        "private-CIDR request must not be forwarded"
    );

    let result = await_last_result(&audit).await;
    assert_eq!(
        result,
        AuditResult::Denied,
        "private CIDR must audit Denied"
    );
}
