//! Pure request-gating core for the Network_Proxy (spec task 15.1).
//!
//! This module is deliberately free of any `tokio`/socket code so the gating
//! logic — parsing a proxied request, mapping it to a normalized
//! [`Action`], and turning a policy [`Decision`] into a forward/deny verdict —
//! can be unit- and property-tested in isolation (design "Network Proxy
//! Design", "Testing Strategy"). The async [`serve`](crate::NetworkProxy::serve)
//! loop is a thin shell over these functions.

use std::net::IpAddr;

use fida_action::{
    Action, ActionKind, ActionPayload, Actor, Decision, DecisionResult, NetTarget, Protocol,
};
use fida_policy::CompiledPolicy;

/// A proxied request reduced to the routing essentials the evaluator needs.
///
/// Both the plain-HTTP request line (`GET http://host:port/path HTTP/1.1`) and
/// the HTTPS `CONNECT host:port HTTP/1.1` line collapse to this shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestTarget {
    /// The destination host: a hostname (`example.com`) or IP literal
    /// (`169.254.169.254`), never including the port.
    pub host: String,
    /// The destination port (defaulted from the scheme when absent).
    pub port: u16,
    /// The wire protocol: `http` for an absolute-form request line, `https`
    /// for a `CONNECT` tunnel.
    pub protocol: Protocol,
}

/// Parse a plain-HTTP proxy request line of the form
/// `METHOD absolute-URI HTTP/x.y`, extracting the destination.
///
/// A proxy receives the request target in *absolute form* (RFC 7230 §5.3.2),
/// e.g. `GET http://example.com:8080/path HTTP/1.1`. Returns `None` for a
/// malformed line, a non-HTTP scheme, or an origin-form target (which a
/// correctly configured proxy client never sends). `CONNECT` is handled by
/// [`parse_connect_line`] instead.
pub fn parse_http_request_line(line: &str) -> Option<RequestTarget> {
    let mut parts = line.split_whitespace();
    let method = parts.next()?;
    let uri = parts.next()?;
    let version = parts.next()?;
    if !version.starts_with("HTTP/") || parts.next().is_some() {
        return None;
    }
    if method.eq_ignore_ascii_case("CONNECT") {
        // CONNECT is HTTPS tunneling — handled separately.
        return None;
    }
    // Absolute-form: scheme://host[:port]/path. Only http is plain-HTTP.
    let rest = uri.strip_prefix("http://")?;
    let authority = rest.split('/').next().unwrap_or(rest);
    // Strip any userinfo (`user@host`).
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    let (host, port) = split_host_port(authority, 80)?;
    Some(RequestTarget {
        host,
        port,
        protocol: Protocol::Http,
    })
}

/// Parse an HTTPS `CONNECT host:port HTTP/x.y` request line, extracting the
/// tunnel destination. Returns `None` for a non-`CONNECT` method or a malformed
/// authority.
pub fn parse_connect_line(line: &str) -> Option<RequestTarget> {
    let mut parts = line.split_whitespace();
    let method = parts.next()?;
    let authority = parts.next()?;
    let version = parts.next()?;
    if !method.eq_ignore_ascii_case("CONNECT") || !version.starts_with("HTTP/") {
        return None;
    }
    if parts.next().is_some() {
        return None;
    }
    let (host, port) = split_host_port(authority, 443)?;
    Some(RequestTarget {
        host,
        port,
        protocol: Protocol::Https,
    })
}

/// Split an `host[:port]` authority, applying `default_port` when no port is
/// present. Returns `None` if the host is empty or the port is not a number.
fn split_host_port(authority: &str, default_port: u16) -> Option<(String, u16)> {
    if authority.is_empty() {
        return None;
    }
    match authority.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() => {
            let port: u16 = port.parse().ok()?;
            Some((host.to_string(), port))
        }
        // No colon → bare host.
        None => Some((authority.to_string(), default_port)),
        // Leading colon or empty host.
        Some(_) => None,
    }
}

/// Build a redaction-safe [`NetTarget`] from a parsed request.
///
/// `host` is always the literal destination. `domain` is populated only when
/// the host is a registered name (not an IP literal); for an IP literal — such
/// as the metadata address or a private-CIDR address — `domain` is `None` so
/// the built-in hard denies match on `host`.
pub fn request_to_net_target(req: &RequestTarget) -> NetTarget {
    let is_ip = req.host.parse::<IpAddr>().is_ok();
    NetTarget {
        domain: if is_ip { None } else { Some(req.host.clone()) },
        host: req.host.clone(),
        protocol: req.protocol,
    }
}

/// Wrap a [`NetTarget`] in a normalized `network.request` [`Action`] originated
/// by the agent.
pub fn net_target_to_action(target: NetTarget) -> Action {
    Action {
        kind: ActionKind::NetworkRequest,
        actor: Actor::Agent,
        payload: ActionPayload::Network { target },
    }
}

/// Convenience: parse a request line and build the corresponding `Action`.
///
/// Tries the HTTPS `CONNECT` form first, then the plain-HTTP absolute form.
pub fn request_line_to_action(line: &str) -> Option<Action> {
    let target = parse_connect_line(line).or_else(|| parse_http_request_line(line))?;
    Some(net_target_to_action(request_to_net_target(&target)))
}

/// The proxy's verdict for one request: whether to forward it and the full
/// decision (retained for the audit record and the denial message).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GateVerdict {
    /// `true` only when the policy decision is `allow`;
    /// every other decision (`deny`, `ask`, `dry_run`) blocks forwarding
    pub forward: bool,
    /// The evaluator's decision, kept for auditing domain/host/protocol/decision
    /// and for the policy-denial connection failure.
    pub decision: DecisionResult,
}

/// Gate one `network.request` [`Action`] against the policy.
///
/// Evaluation is delegated to the pure [`fida_policy::evaluate`] pipeline, so
/// the metadata IP and private-CIDR hard denies hold
/// without any explicit rule. The proxy forwards **only** on `allow`.
pub fn gate(policy: &CompiledPolicy, action: &Action) -> GateVerdict {
    let decision = fida_policy::evaluate(policy, action);
    GateVerdict {
        forward: decision.decision == Decision::Allow,
        decision,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fida_policy::{PolicySource, load_source};

    fn builtin() -> CompiledPolicy {
        load_source(&PolicySource::BuiltinDefault, None).expect("builtin policy compiles")
    }

    // Request-line parsing -------------------------------------------------

    #[test]
    fn parses_http_absolute_form_with_explicit_port() {
        let req = parse_http_request_line("GET http://example.com:8080/path HTTP/1.1").unwrap();
        assert_eq!(req.host, "example.com");
        assert_eq!(req.port, 8080);
        assert_eq!(req.protocol, Protocol::Http);
    }

    #[test]
    fn parses_http_absolute_form_defaulting_port_80() {
        let req = parse_http_request_line("POST http://example.com/api HTTP/1.1").unwrap();
        assert_eq!(req.host, "example.com");
        assert_eq!(req.port, 80);
        assert_eq!(req.protocol, Protocol::Http);
    }

    #[test]
    fn http_parse_strips_userinfo() {
        let req = parse_http_request_line("GET http://user@example.com/x HTTP/1.1").unwrap();
        assert_eq!(req.host, "example.com");
    }

    #[test]
    fn http_parse_rejects_origin_form_and_connect() {
        // Origin-form (no scheme) — a proxy client never sends this.
        assert!(parse_http_request_line("GET /path HTTP/1.1").is_none());
        // CONNECT is not a plain-HTTP request.
        assert!(parse_http_request_line("CONNECT example.com:443 HTTP/1.1").is_none());
        // Garbage / missing fields.
        assert!(parse_http_request_line("nonsense").is_none());
        assert!(parse_http_request_line("GET http://example.com/x").is_none());
    }

    #[test]
    fn parses_connect_line() {
        let req = parse_connect_line("CONNECT example.com:443 HTTP/1.1").unwrap();
        assert_eq!(req.host, "example.com");
        assert_eq!(req.port, 443);
        assert_eq!(req.protocol, Protocol::Https);
    }

    #[test]
    fn connect_defaults_port_443_when_absent() {
        let req = parse_connect_line("CONNECT example.com HTTP/1.1").unwrap();
        assert_eq!(req.port, 443);
        assert_eq!(req.protocol, Protocol::Https);
    }

    #[test]
    fn connect_rejects_non_connect_method() {
        assert!(parse_connect_line("GET example.com:443 HTTP/1.1").is_none());
        assert!(parse_connect_line("CONNECT  HTTP/1.1").is_none());
    }

    // Target → Action mapping ---------------------------------------------

    #[test]
    fn hostname_target_populates_domain() {
        let target = request_to_net_target(&RequestTarget {
            host: "example.com".into(),
            port: 443,
            protocol: Protocol::Https,
        });
        assert_eq!(target.domain.as_deref(), Some("example.com"));
        assert_eq!(target.host, "example.com");
        assert_eq!(target.protocol, Protocol::Https);
    }

    #[test]
    fn ip_literal_target_has_no_domain() {
        let target = request_to_net_target(&RequestTarget {
            host: "169.254.169.254".into(),
            port: 80,
            protocol: Protocol::Http,
        });
        assert_eq!(target.domain, None, "IP literal must not be a domain");
        assert_eq!(target.host, "169.254.169.254");
    }

    #[test]
    fn request_line_to_action_builds_network_action() {
        let action = request_line_to_action("CONNECT example.com:443 HTTP/1.1").unwrap();
        assert_eq!(action.kind, ActionKind::NetworkRequest);
        match action.payload {
            ActionPayload::Network { target } => {
                assert_eq!(target.host, "example.com");
                assert_eq!(target.protocol, Protocol::Https);
            }
            other => panic!("expected network payload, got {other:?}"),
        }
    }

    // Gating decision ------------------------------------------------------

    #[test]
    fn metadata_ip_is_denied_and_not_forwarded() {
        let policy = builtin();
        let action = request_line_to_action("GET http://169.254.169.254/latest HTTP/1.1").unwrap();
        let verdict = gate(&policy, &action);
        assert!(!verdict.forward, "metadata IP must never be forwarded");
        assert_eq!(verdict.decision.decision, Decision::Deny);
    }

    #[test]
    fn private_cidr_is_denied_and_not_forwarded() {
        let policy = builtin();
        let action = request_line_to_action("CONNECT 10.0.0.5:443 HTTP/1.1").unwrap();
        let verdict = gate(&policy, &action);
        assert!(!verdict.forward, "private CIDR must never be forwarded");
        assert_eq!(verdict.decision.decision, Decision::Deny);
    }

    #[test]
    fn allow_decision_forwards() {
        // A policy that explicitly allows a public host.
        let raw = r#"
version: 1
default_decision: deny
commands: {}
files: {}
network:
  allow:
    - host: example.com
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
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fida.yaml");
        std::fs::write(&path, raw).unwrap();
        let policy = load_source(&PolicySource::Config(path), None).expect("compiles");

        let action = request_line_to_action("CONNECT example.com:443 HTTP/1.1").unwrap();
        let verdict = gate(&policy, &action);
        assert!(verdict.forward, "explicitly allowed host must forward");
        assert_eq!(verdict.decision.decision, Decision::Allow);
    }
}
