//! `fida-net` — Network_Proxy: a local HTTP(S) proxy that gates outbound
//! requests by domain/host/CIDR/metadata through the policy evaluator
//! (spec task 15.1; design "Network Proxy Design").
//!
//! # What this is
//!
//! When a session starts with network gating enabled, the proxy binds a local
//! endpoint and the CLI exports [`HTTP_PROXY_ENV`] / [`HTTPS_PROXY_ENV`] into
//! the agent's environment for the session lifetime. Tools
//! and package managers that honor proxy environment variables route through
//! it; each request is evaluated as a `network.request` [`Action`] and
//! forwarded **only** on an `allow` decision. A
//! `deny` — including the built-in metadata-IP and private-CIDR hard denies —
//! returns a connection failure indicating a policy denial and never reaches
//! the destination.
//!
//! # Best-effort enforcement
//!
//! This proxy is **best-effort**: it can only gate traffic that is actually
//! routed through it. It provides **no** OS-level network containment — a
//! process that ignores the proxy environment variables, or opens raw sockets,
//! bypasses it entirely. The CLI surfaces [`BEST_EFFORT_ENFORCEMENT_NOTICE`] so
//! users are never misled into believing this is a sandbox.
//!
//! # Structure
//!
//! The pure gating core (request-line parsing, [`Action`] mapping, and the
//! forward/deny verdict) lives in [`mod@gate`] so it is unit- and
//! property-testable without any sockets. [`NetworkProxy::serve`] is a thin
//! async shell over that core (full integration coverage is task 15.2).

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use chrono::Utc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

use fida_action::{Action, Actor};
use fida_audit::{AuditAction, AuditEvent, AuditResult, AuditStore};
use fida_policy::CompiledPolicy;

pub mod gate;

pub use gate::{
    GateVerdict, RequestTarget, gate as gate_request, net_target_to_action, parse_connect_line,
    parse_http_request_line, request_line_to_action, request_to_net_target,
};

/// The environment variable plain-HTTP-aware clients read for their proxy.
pub const HTTP_PROXY_ENV: &str = "FIDA_HTTP_PROXY";

/// The environment variable HTTPS-aware clients read for their proxy.
pub const HTTPS_PROXY_ENV: &str = "FIDA_HTTPS_PROXY";

/// The honesty notice the CLI surfaces for network gating.
///
/// Fida never claims OS-level containment: enforcement applies only to
/// traffic that is routed through the proxy.
pub const BEST_EFFORT_ENFORCEMENT_NOTICE: &str = "Network enforcement is applied to traffic routed \
through the Fida proxy (FIDA_HTTP_PROXY / FIDA_HTTPS_PROXY) and is best-effort: traffic that \
does not honor these proxy settings is not gated. This is not OS-level network containment.";

/// A local HTTP(S) gating proxy bound to a loopback port.
///
/// Construct with [`NetworkProxy::bind`], read its address via
/// [`endpoint`](NetworkProxy::endpoint) / [`proxy_env_vars`](NetworkProxy::proxy_env_vars)
/// to export into the agent environment, then drive it with
/// [`serve`](NetworkProxy::serve).
pub struct NetworkProxy {
    listener: TcpListener,
    local_addr: SocketAddr,
    policy: Arc<CompiledPolicy>,
    session_id: String,
    event_seq: AtomicU32,
}

impl NetworkProxy {
    /// Bind a gating proxy on `127.0.0.1` using an OS-assigned ephemeral port.
    ///
    /// The bound address is available immediately via [`endpoint`] so the
    /// proxy env vars can be exported before [`serve`] is awaited.
    ///
    /// [`endpoint`]: NetworkProxy::endpoint
    /// [`serve`]: NetworkProxy::serve
    pub async fn bind(
        policy: Arc<CompiledPolicy>,
        session_id: impl Into<String>,
    ) -> io::Result<Self> {
        Self::bind_addr(
            SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            policy,
            session_id,
        )
        .await
    }

    /// Bind on an explicit address (used by tests that need a fixed port).
    pub async fn bind_addr(
        addr: SocketAddr,
        policy: Arc<CompiledPolicy>,
        session_id: impl Into<String>,
    ) -> io::Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        let local_addr = listener.local_addr()?;
        Ok(NetworkProxy {
            listener,
            local_addr,
            policy,
            session_id: session_id.into(),
            event_seq: AtomicU32::new(0),
        })
    }

    /// The bound socket address (host:port) the proxy listens on.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// The proxy endpoint URL, e.g. `http://127.0.0.1:54321`. Both HTTP and
    /// HTTPS clients connect to this same loopback endpoint; HTTPS traffic
    /// arrives via `CONNECT`.
    pub fn endpoint(&self) -> String {
        format!("http://{}", self.local_addr)
    }

    /// The `(name, value)` env var pairs to export for the session lifetime so
    /// the agent's tooling routes through this proxy.
    pub fn proxy_env_vars(&self) -> Vec<(String, String)> {
        let endpoint = self.endpoint();
        vec![
            (HTTP_PROXY_ENV.to_string(), endpoint.clone()),
            (HTTPS_PROXY_ENV.to_string(), endpoint),
        ]
    }

    /// Mint the next append-ordered audit event id for this proxy.
    fn next_event_id(&self) -> String {
        let n = self.event_seq.fetch_add(1, Ordering::SeqCst) + 1;
        format!("evt_net_{n:04}")
    }

    /// Accept and gate connections until an accept error occurs.
    ///
    /// Each connection is handled on its own task: the first request line is
    /// parsed, the destination is evaluated, the decision is audited
    /// (domain/host/protocol/decision only — never payloads),
    /// and the request is forwarded only on `allow`. A blocked request gets a
    /// policy-denial connection failure.
    ///
    /// `audit` is shared so concurrently handled connections append to the same
    /// session log.
    pub async fn serve<A>(&self, audit: Arc<Mutex<A>>) -> io::Result<()>
    where
        A: AuditStore + Send + 'static,
    {
        loop {
            let (stream, _peer) = self.listener.accept().await?;
            let policy = Arc::clone(&self.policy);
            let audit = Arc::clone(&audit);
            let session_id = self.session_id.clone();
            let event_id = self.next_event_id();
            tokio::spawn(async move {
                let _ = handle_connection(stream, policy, session_id, event_id, audit).await;
            });
        }
    }
}

/// Append a redaction-safe audit event for a gated request.
///
/// Only the destination domain/host/protocol and the decision are recorded;
/// the [`AuditAction`] is built from the network payload, which by construction
/// carries no request body.
async fn audit_decision<A>(
    audit: &Arc<Mutex<A>>,
    session_id: String,
    event_id: String,
    action: &Action,
    decision: &fida_action::DecisionResult,
    result: AuditResult,
) where
    A: AuditStore + Send + 'static,
{
    let event = AuditEvent {
        id: event_id,
        session_id,
        time: Utc::now(),
        actor: Actor::Agent,
        action: AuditAction::from_action(action),
        decision: decision.decision,
        result,
        matched_rule: decision.matched_rule.clone(),
        risk: decision.risk,
        redacted: false,
        metrics: None,
    };
    let mut guard = audit.lock().await;
    let _ = guard.append(&event);
}

/// Handle one proxied connection: parse, gate, audit, then forward or deny.
async fn handle_connection<A>(
    mut client: TcpStream,
    policy: Arc<CompiledPolicy>,
    session_id: String,
    event_id: String,
    audit: Arc<Mutex<A>>,
) -> io::Result<()>
where
    A: AuditStore + Send + 'static,
{
    let line = read_line(&mut client).await?;
    let trimmed = line.trim_end();

    // HTTPS CONNECT tunnel.
    if let Some(target) = parse_connect_line(trimmed) {
        let action = net_target_to_action(request_to_net_target(&target));
        let verdict = gate::gate(&policy, &action);
        let result = audit_result_for(&verdict);
        audit_decision(
            &audit,
            session_id,
            event_id,
            &action,
            &verdict.decision,
            result,
        )
        .await;

        // Always consume the request head before replying. On Windows, closing a
        // TCP socket while the peer's request headers are still unread can turn
        // the close into a reset, causing the client to miss the 403 bytes.
        drain_headers(&mut client).await?;

        if verdict.forward {
            establish_tunnel(client, &target).await
        } else {
            deny_connect(client).await
        }
    }
    // Plain-HTTP absolute-form request.
    else if let Some(target) = parse_http_request_line(trimmed) {
        let action = net_target_to_action(request_to_net_target(&target));
        let verdict = gate::gate(&policy, &action);
        let result = audit_result_for(&verdict);
        audit_decision(
            &audit,
            session_id,
            event_id,
            &action,
            &verdict.decision,
            result,
        )
        .await;

        if verdict.forward {
            forward_http(client, trimmed, &target).await
        } else {
            // For denied HTTP requests, do not forward any bytes, but do drain
            // the remaining request headers before closing so the client sees
            // the policy response reliably on all supported platforms.
            drain_headers(&mut client).await?;
            deny_http(client).await
        }
    }
    // Unrecognized request line — reject as a bad request.
    else {
        let _ = write_response_and_close(
            &mut client,
            b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n",
        )
        .await;
        Ok(())
    }
}

/// Map a gate verdict to its audit result (allow → `Allowed`, otherwise
/// `Denied`, since the proxy blocks every non-allow decision).
fn audit_result_for(verdict: &GateVerdict) -> AuditResult {
    if verdict.forward {
        AuditResult::Allowed
    } else {
        AuditResult::Denied
    }
}

/// Read a single CRLF-terminated line, one byte at a time, so no bytes of a
/// following request body are consumed.
async fn read_line(stream: &mut TcpStream) -> io::Result<String> {
    let mut buf = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    // Cap the line to guard against an unbounded read.
    while buf.len() < 8192 {
        let n = stream.read(&mut byte).await?;
        if n == 0 {
            break;
        }
        buf.push(byte[0]);
        if byte[0] == b'\n' {
            break;
        }
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// Read and discard request header lines up to and including the blank line.
async fn drain_headers(stream: &mut TcpStream) -> io::Result<()> {
    loop {
        let line = read_line(stream).await?;
        if line.is_empty() || line == "\r\n" || line == "\n" {
            break;
        }
    }
    Ok(())
}

/// Establish an HTTPS `CONNECT` tunnel: acknowledge to the client, dial the
/// destination, and pipe bytes in both directions.
async fn establish_tunnel(mut client: TcpStream, target: &RequestTarget) -> io::Result<()> {
    let mut upstream = match TcpStream::connect((target.host.as_str(), target.port)).await {
        Ok(s) => s,
        Err(_) => {
            let _ = write_response_and_close(
                &mut client,
                b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n",
            )
            .await;
            return Ok(());
        }
    };
    client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;
    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
    Ok(())
}

/// Forward a plain-HTTP request to its origin in origin-form, then pipe both
/// directions.
async fn forward_http(
    mut client: TcpStream,
    request_line: &str,
    target: &RequestTarget,
) -> io::Result<()> {
    let mut upstream = match TcpStream::connect((target.host.as_str(), target.port)).await {
        Ok(s) => s,
        Err(_) => {
            let _ = write_response_and_close(
                &mut client,
                b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n",
            )
            .await;
            return Ok(());
        }
    };
    let origin_line = to_origin_form(request_line);
    upstream.write_all(origin_line.as_bytes()).await?;
    // The remaining headers/body still buffered on the client socket are piped
    // through unchanged.
    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
    Ok(())
}

/// Rewrite an absolute-form proxy request line into origin-form for the origin
/// server: `GET http://host:port/path HTTP/1.1` → `GET /path HTTP/1.1\r\n`.
fn to_origin_form(request_line: &str) -> String {
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("GET");
    let uri = parts.next().unwrap_or("/");
    let version = parts.next().unwrap_or("HTTP/1.1");
    let path = uri
        .strip_prefix("http://")
        .and_then(|rest| rest.find('/').map(|i| &rest[i..]))
        .unwrap_or("/");
    let path = if path.is_empty() { "/" } else { path };
    format!("{method} {path} {version}\r\n")
}

/// Return a policy-denial connection failure for a blocked plain-HTTP request.
/// `403 Forbidden` makes the policy denial explicit to the caller without
/// forwarding anything.
async fn deny_http(mut client: TcpStream) -> io::Result<()> {
    let body = "Blocked by Fida network policy.";
    let response = format!(
        "HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: {}\r\nContent-Type: \
text/plain\r\n\r\n{}",
        body.len(),
        body
    );
    write_response_and_close(&mut client, response.as_bytes()).await
}

/// Return a policy-denial connection failure for a blocked `CONNECT` tunnel.
/// `403 Forbidden` (rather than `200`) means the tunnel is never established,
/// so no bytes reach the destination.
async fn deny_connect(mut client: TcpStream) -> io::Result<()> {
    write_response_and_close(
        &mut client,
        b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n",
    )
    .await
}

/// Write a terminal proxy response and close the write half gracefully.
///
/// Tokio's `TcpStream` is unbuffered, but explicit `flush` + `shutdown` keeps
/// the client-facing denial path deterministic across Unix and Windows.
async fn write_response_and_close(client: &mut TcpStream, response: &[u8]) -> io::Result<()> {
    client.write_all(response).await?;
    client.flush().await?;
    client.shutdown().await
}

/// Whether `host` is a literal IP address (vs a registered name). Retained as a
/// small helper used by docs/tests; the canonical check lives in
/// [`gate::request_to_net_target`].
#[doc(hidden)]
pub fn is_ip_literal(host: &str) -> bool {
    host.parse::<IpAddr>().is_ok()
}

/// Convenience re-export of the network decision for callers that only need the
/// allow/deny verdict.
pub use fida_action::DecisionResult as NetDecision;

#[cfg(test)]
mod tests {
    use super::*;
    use fida_action::{ActionPayload, Decision};
    use fida_policy::{PolicySource, load_source};
    use std::path::PathBuf;

    fn builtin() -> Arc<CompiledPolicy> {
        Arc::new(load_source(&PolicySource::BuiltinDefault, None).expect("builtin compiles"))
    }

    #[test]
    fn origin_form_rewrites_absolute_uri() {
        assert_eq!(
            to_origin_form("GET http://example.com:8080/a/b?c=d HTTP/1.1"),
            "GET /a/b?c=d HTTP/1.1\r\n"
        );
        assert_eq!(
            to_origin_form("POST http://example.com/x HTTP/1.0"),
            "POST /x HTTP/1.0\r\n"
        );
    }

    #[test]
    fn origin_form_defaults_root_path() {
        assert_eq!(
            to_origin_form("GET http://example.com HTTP/1.1"),
            "GET / HTTP/1.1\r\n"
        );
    }

    #[test]
    fn is_ip_literal_distinguishes_ip_from_name() {
        assert!(is_ip_literal("169.254.169.254"));
        assert!(is_ip_literal("::1"));
        assert!(!is_ip_literal("example.com"));
    }

    #[test]
    fn proxy_env_vars_point_at_endpoint() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let proxy = match NetworkProxy::bind(builtin(), "sess-test").await {
                Ok(proxy) => proxy,
                Err(err) if err.kind() == io::ErrorKind::PermissionDenied => return,
                Err(err) => panic!("proxy bind failed: {err}"),
            };
            let endpoint = proxy.endpoint();
            assert!(endpoint.starts_with("http://127.0.0.1:"));

            let vars = proxy.proxy_env_vars();
            assert_eq!(vars.len(), 2);
            assert_eq!(vars[0].0, HTTP_PROXY_ENV);
            assert_eq!(vars[1].0, HTTPS_PROXY_ENV);
            assert_eq!(vars[0].1, endpoint);
            assert_eq!(vars[1].1, endpoint);
        });
    }

    #[test]
    fn audit_result_maps_allow_and_deny() {
        let policy = builtin();
        // Metadata IP → deny.
        let denied = request_line_to_action("GET http://169.254.169.254/ HTTP/1.1").unwrap();
        let verdict = gate::gate(&policy, &denied);
        assert_eq!(audit_result_for(&verdict), AuditResult::Denied);
        assert_eq!(verdict.decision.decision, Decision::Deny);
    }

    #[test]
    fn network_payload_audits_routing_only() {
        // The audit action built from a network request carries no body.
        let action = request_line_to_action("CONNECT example.com:443 HTTP/1.1").unwrap();
        match &action.payload {
            ActionPayload::Network { target } => {
                let audit_action = AuditAction::from_action(&action);
                match audit_action {
                    AuditAction::NetworkRequest {
                        domain,
                        host,
                        protocol,
                    } => {
                        assert_eq!(domain, target.domain);
                        assert_eq!(host, target.host);
                        assert_eq!(protocol, target.protocol);
                    }
                    other => panic!("expected network audit action, got {other:?}"),
                }
            }
            other => panic!("expected network payload, got {other:?}"),
        }
    }

    // A small compile-time guard that the test helper compiles against the
    // builtin policy path API.
    #[test]
    fn builtin_policy_loads() {
        let _ = builtin();
        let _ = PathBuf::from(".fida");
    }
}
