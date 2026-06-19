//! The append-only JSONL Audit_Store (spec task 7.1).
//!
//! Events are persisted one JSON object per line in `events.jsonl` inside each
//! session directory (`<sessions_dir>/<session_id>/events.jsonl`). [`append`] is
//! the sole writer: it opens the file in append mode and never rewrites prior
//! lines. [`read`] returns every event in append
//! order and [`filter`] returns only the events matching every supplied
//! [`AuditFilter`] field.
//!
//! [`append`]: AuditStore::append
//! [`read`]: AuditStore::read
//! [`filter`]: AuditStore::filter

use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use fida_action::{ActionKind, Decision, Risk};
use fida_secrets::{Scanner, SecretScanner};

use crate::event::{AuditAction, AuditEvent, AuditMetrics};

/// Selection criteria for [`AuditStore::filter`].
///
/// Every field is optional. An event is kept only when it satisfies *every*
/// supplied field (AND semantics); a [`AuditFilter::default`] (all `None`)
/// matches all events. When no recorded event matches, the result is empty.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuditFilter {
    /// `--kind`: keep only events whose action is of this kind.
    pub kind: Option<ActionKind>,
    /// `--decision`: keep only events with this decision.
    pub decision: Option<Decision>,
    /// `--risk`: keep only events at this risk level.
    pub risk: Option<Risk>,
    /// `--since`: keep only events whose time is at or after this instant.
    pub since: Option<DateTime<Utc>>,
}

impl AuditFilter {
    /// Returns `true` when `event` satisfies every supplied field of this
    /// filter (AND semantics). An empty filter matches everything.
    pub fn matches(&self, event: &AuditEvent) -> bool {
        if let Some(kind) = self.kind {
            if action_kind(&event.action) != kind {
                return false;
            }
        }
        if let Some(decision) = self.decision {
            if event.decision != decision {
                return false;
            }
        }
        if let Some(risk) = self.risk {
            if event.risk != risk {
                return false;
            }
        }
        if let Some(since) = self.since {
            if event.time < since {
                return false;
            }
        }
        true
    }
}

/// Map a redaction-safe [`AuditAction`] back to its [`ActionKind`] so events
/// can be filtered by `--kind`.
fn action_kind(action: &AuditAction) -> ActionKind {
    match action {
        AuditAction::CommandRun { .. }
        | AuditAction::CommandOutput { .. }
        | AuditAction::CommandRedactionFailure { .. } => ActionKind::CommandRun,
        AuditAction::FileRead { .. } => ActionKind::FileRead,
        AuditAction::FileWrite { .. } => ActionKind::FileWrite,
        AuditAction::FileDelete { .. } => ActionKind::FileDelete,
        AuditAction::NetworkRequest { .. } => ActionKind::NetworkRequest,
        AuditAction::McpToolCall { .. } => ActionKind::McpToolCall,
        AuditAction::SecretDetected { .. } => ActionKind::SecretDetected,
        AuditAction::SessionApplyChanges => ActionKind::SessionApplyChanges,
    }
}

/// The append-only event store interface (design "Audit_Store and
/// Report_Generator"). Sessions are addressed by their string id; the concrete
/// [`JsonlAuditStore`] resolves each id to a directory under its root.
pub trait AuditStore {
    /// Append exactly one event to the owning session's log, after all
    /// previously written events, without modifying any prior line. The
    /// destination is derived from the event's own `session_id`.
    fn append(&mut self, event: &AuditEvent) -> io::Result<()>;

    /// Read every event recorded for `session`, in append order. A session
    /// with no log yet yields an empty vector.
    fn read(&self, session: &str) -> io::Result<Vec<AuditEvent>>;

    /// Read `session`'s events and return only those matching every supplied
    /// field of `filter`.
    fn filter(&self, session: &str, filter: &AuditFilter) -> io::Result<Vec<AuditEvent>>;
}

/// A filesystem-backed [`AuditStore`] writing one JSONL file per session.
///
/// Given a root directory (typically `.fida/sessions`), a session's log
/// lives at `<root>/<session_id>/events.jsonl`.
#[derive(Debug, Clone)]
pub struct JsonlAuditStore {
    sessions_dir: PathBuf,
}

impl JsonlAuditStore {
    /// Create a store rooted at `sessions_dir` (e.g. `.fida/sessions`).
    pub fn new(sessions_dir: impl Into<PathBuf>) -> Self {
        Self {
            sessions_dir: sessions_dir.into(),
        }
    }

    /// The directory holding `session`'s artifacts.
    pub fn session_dir(&self, session: &str) -> PathBuf {
        self.sessions_dir.join(session)
    }

    /// The `events.jsonl` path for `session`.
    pub fn events_path(&self, session: &str) -> PathBuf {
        self.session_dir(session).join("events.jsonl")
    }

    /// Read every event for `session` resiliently, returning the parsed events
    /// plus the 1-based line numbers of any unparseable lines (R14.2). A session
    /// with no log yet yields an empty report.
    pub fn read_report(&self, session: &str) -> io::Result<ReadReport> {
        Self::read_report_path(&self.events_path(session))
    }

    /// Read and parse every event from an explicit `events.jsonl` path,
    /// preserving file order, tolerating unparseable lines and malformed
    /// metrics objects (R14.2, R5.7). A missing file yields an empty report.
    fn read_report_path(path: &Path) -> io::Result<ReadReport> {
        let file = match fs::File::open(path) {
            Ok(file) => file,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(ReadReport::default()),
            Err(err) => return Err(err),
        };
        let reader = BufReader::new(file);
        let mut events = Vec::new();
        let mut skipped_lines = Vec::new();
        for (idx, line) in reader.lines().enumerate() {
            let line = line?;
            let line_no = idx + 1; // 1-based (R14.2)
            // Tolerate incidental blank lines (e.g. a trailing newline); they
            // are not "unparseable" and are not reported as skipped.
            if line.trim().is_empty() {
                continue;
            }
            match parse_line_tolerant(&line) {
                Some(event) => events.push(event),
                None => skipped_lines.push(line_no),
            }
        }
        Ok(ReadReport {
            events,
            skipped_lines,
        })
    }
}

/// The outcome of a resilient JSONL read: every parsed event plus the 1-based
/// line numbers that could not be parsed (R14.2).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReadReport {
    /// Every successfully parsed event, in append order.
    pub events: Vec<AuditEvent>,
    /// 1-based line numbers of skipped (unparseable) lines.
    pub skipped_lines: Vec<usize>,
}

/// Parse one JSONL line into an [`AuditEvent`], tolerating a malformed or
/// out-of-bounds `metrics` object by normalizing it to absent (R5.7) rather
/// than failing the whole line. Returns `None` only when the rest of the line
/// cannot be parsed into an event.
fn parse_line_tolerant(line: &str) -> Option<AuditEvent> {
    let mut value: serde_json::Value = serde_json::from_str(line).ok()?;
    if let Some(obj) = value.as_object_mut() {
        if let Some(metrics) = obj.get("metrics") {
            // A present-but-invalid metrics object is dropped so the event
            // still parses with metrics absent; an explicit null already maps
            // to `None`.
            if !metrics.is_null() && !metrics_value_is_valid(metrics) {
                obj.remove("metrics");
            }
        }
    }
    serde_json::from_value(value).ok()
}

/// Whether a JSON `metrics` value deserializes into well-formed, in-bounds
/// [`AuditMetrics`].
fn metrics_value_is_valid(metrics: &serde_json::Value) -> bool {
    match serde_json::from_value::<AuditMetrics>(metrics.clone()) {
        Ok(m) => AuditMetrics::validated(
            m.duration_ms,
            m.input_bytes,
            m.output_bytes,
            m.estimated_tokens,
            m.model,
        )
        .is_some(),
        Err(_) => false,
    }
}

/// Apply the metrics secret-guard and safe-drop to an event before it is
/// written (R5.6, R5.7).
///
/// The whole metrics field is dropped when it is out of bounds, or when its
/// `model` carries a detected secret — in the latter case the event is recorded
/// as redacted. Every other field is preserved.
fn guard_metrics(mut event: AuditEvent) -> AuditEvent {
    let Some(metrics) = event.metrics.as_ref() else {
        return event;
    };

    // Re-validate bounds; drop the whole field if invalid (R5.7).
    if AuditMetrics::validated(
        metrics.duration_ms,
        metrics.input_bytes,
        metrics.output_bytes,
        metrics.estimated_tokens,
        metrics.model.clone(),
    )
    .is_none()
    {
        event.metrics = None;
        return event;
    }

    // Secret-guard the only free-text subfield. Fail closed on a redaction
    // error (R5.6).
    let model = metrics.model.clone();
    let scanner = Scanner::with_patterns(&[]);
    let secret_detected = match scanner.redact(&model) {
        Ok(redacted) => redacted != model,
        Err(_) => true,
    };
    if secret_detected {
        event.metrics = None;
        event.redacted = true;
    }
    event
}

impl AuditStore for JsonlAuditStore {
    fn append(&mut self, event: &AuditEvent) -> io::Result<()> {
        let path = self.events_path(&event.session_id);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        // Apply the metrics secret-guard / safe-drop before serialization
        // (R5.6, R5.7). Only the metrics-bearing path pays the clone cost.
        let guarded;
        let event = if event.metrics.is_some() {
            guarded = guard_metrics(event.clone());
            &guarded
        } else {
            event
        };
        // Serialize first so a serialization failure never opens/truncates the
        // log, and reject any embedded newline that would corrupt the JSONL
        // one-event-per-line invariant.
        let line = serde_json::to_string(event)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        if line.contains('\n') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "serialized audit event contains a newline",
            ));
        }
        // Append-only: never truncate, always write past existing content.
        let mut file = OpenOptions::new().create(true).append(true).open(&path)?;
        file.write_all(line.as_bytes())?;
        file.write_all(b"\n")?;
        file.flush()?;
        Ok(())
    }

    fn read(&self, session: &str) -> io::Result<Vec<AuditEvent>> {
        Ok(self.read_report(session)?.events)
    }

    fn filter(&self, session: &str, filter: &AuditFilter) -> io::Result<Vec<AuditEvent>> {
        let events = self.read(session)?;
        Ok(events.into_iter().filter(|e| filter.matches(e)).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use fida_action::{Actor, MatchedRule};

    use crate::event::AuditResult;

    fn event(id: &str, session: &str, time: DateTime<Utc>, action: AuditAction) -> AuditEvent {
        AuditEvent {
            id: id.to_string(),
            session_id: session.to_string(),
            time,
            actor: Actor::Agent,
            action,
            decision: Decision::Allow,
            result: AuditResult::Allowed,
            matched_rule: MatchedRule::NoExplicitRule,
            risk: Risk::Low,
            redacted: false,
            metrics: None,
        }
    }

    fn at(hour: u32, minute: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 6, 12, hour, minute, 0).unwrap()
    }

    fn tmp_root() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "fida-audit-test-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn read_of_unknown_session_is_empty() {
        let store = JsonlAuditStore::new(tmp_root());
        assert!(store.read("does-not-exist").unwrap().is_empty());
    }

    #[test]
    fn append_then_read_preserves_order() {
        let root = tmp_root();
        let mut store = JsonlAuditStore::new(&root);
        let session = "2026-06-12T070000Z-aaaa";
        let e1 = event(
            "evt_01",
            session,
            at(7, 0),
            AuditAction::CommandRun {
                command: "pnpm install".to_string(),
            },
        );
        let e2 = event(
            "evt_02",
            session,
            at(7, 1),
            AuditAction::FileWrite {
                path: "src/app.ts".to_string(),
            },
        );
        store.append(&e1).unwrap();
        store.append(&e2).unwrap();

        let read = store.read(session).unwrap();
        assert_eq!(read, vec![e1, e2]);
    }

    #[test]
    fn append_is_append_only_across_store_instances() {
        let root = tmp_root();
        let session = "s1";
        let e1 = event(
            "evt_01",
            session,
            at(7, 0),
            AuditAction::SessionApplyChanges,
        );
        let e2 = event(
            "evt_02",
            session,
            at(7, 5),
            AuditAction::SessionApplyChanges,
        );

        JsonlAuditStore::new(&root).append(&e1).unwrap();
        // A fresh store must not overwrite the existing file.
        JsonlAuditStore::new(&root).append(&e2).unwrap();

        let read = JsonlAuditStore::new(&root).read(session).unwrap();
        assert_eq!(read.len(), 2);
        assert_eq!(read[0].id, "evt_01");
        assert_eq!(read[1].id, "evt_02");
    }

    #[test]
    fn filter_applies_and_semantics() {
        let root = tmp_root();
        let mut store = JsonlAuditStore::new(&root);
        let session = "s1";

        let cmd = {
            let mut e = event(
                "evt_cmd",
                session,
                at(7, 0),
                AuditAction::CommandRun {
                    command: "ls".to_string(),
                },
            );
            e.decision = Decision::Allow;
            e.risk = Risk::Low;
            e
        };
        let deny_net = {
            let mut e = event(
                "evt_net",
                session,
                at(8, 0),
                AuditAction::NetworkRequest {
                    domain: None,
                    host: "169.254.169.254".to_string(),
                    protocol: fida_action::Protocol::Http,
                },
            );
            e.decision = Decision::Deny;
            e.risk = Risk::High;
            e
        };
        store.append(&cmd).unwrap();
        store.append(&deny_net).unwrap();

        // Empty filter matches everything.
        assert_eq!(
            store
                .filter(session, &AuditFilter::default())
                .unwrap()
                .len(),
            2
        );

        // Single field.
        let by_kind = AuditFilter {
            kind: Some(ActionKind::NetworkRequest),
            ..Default::default()
        };
        let got = store.filter(session, &by_kind).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].id, "evt_net");

        // Multiple fields are ANDed: high risk AND deny AND since 7:30.
        let combo = AuditFilter {
            decision: Some(Decision::Deny),
            risk: Some(Risk::High),
            since: Some(at(7, 30)),
            ..Default::default()
        };
        let got = store.filter(session, &combo).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].id, "evt_net");

        // No event matches -> empty.
        let none = AuditFilter {
            decision: Some(Decision::Deny),
            risk: Some(Risk::Low),
            ..Default::default()
        };
        assert!(store.filter(session, &none).unwrap().is_empty());
    }

    #[test]
    fn since_is_inclusive_lower_bound() {
        let root = tmp_root();
        let mut store = JsonlAuditStore::new(&root);
        let session = "s1";
        let e = event(
            "evt_01",
            session,
            at(7, 0),
            AuditAction::SessionApplyChanges,
        );
        store.append(&e).unwrap();

        let inclusive = AuditFilter {
            since: Some(at(7, 0)),
            ..Default::default()
        };
        assert_eq!(store.filter(session, &inclusive).unwrap().len(), 1);

        let after = AuditFilter {
            since: Some(at(7, 1)),
            ..Default::default()
        };
        assert!(store.filter(session, &after).unwrap().is_empty());
    }

    #[test]
    fn read_report_skips_bad_lines_and_normalizes_bad_metrics() {
        use crate::event::{AuditMetrics, MAX_SAFE_INT};
        let root = tmp_root();
        let session = "s_resilient";
        let dir = JsonlAuditStore::new(&root).session_dir(session);
        fs::create_dir_all(&dir).unwrap();

        // A valid event, a garbage line, a valid event whose metrics object is
        // out of bounds (must normalize to None, keeping the event), and a
        // blank line (tolerated, not counted as skipped).
        let mut good = event(
            "evt_01",
            session,
            at(7, 0),
            AuditAction::SessionApplyChanges,
        );
        good.metrics = AuditMetrics::validated(1, 2, 3, 4, "m".to_string());
        let good_line = serde_json::to_string(&good).unwrap();

        let mut bad_metrics = event(
            "evt_03",
            session,
            at(7, 2),
            AuditAction::SessionApplyChanges,
        );
        bad_metrics.metrics = None;
        let mut v: serde_json::Value = serde_json::to_value(&bad_metrics).unwrap();
        // Inject an out-of-bounds metrics object directly on the wire.
        v.as_object_mut().unwrap().insert(
            "metrics".to_string(),
            serde_json::json!({
                "duration_ms": MAX_SAFE_INT + 1,
                "input_bytes": 0, "output_bytes": 0, "estimated_tokens": 0, "model": "m"
            }),
        );
        let bad_metrics_line = serde_json::to_string(&v).unwrap();

        let contents = format!("{good_line}\nnot json at all\n\n{bad_metrics_line}\n");
        fs::write(dir.join("events.jsonl"), contents).unwrap();

        let report = JsonlAuditStore::new(&root).read_report(session).unwrap();
        // Two events retained in order; the garbage line (line 2) is reported.
        assert_eq!(report.events.len(), 2);
        assert_eq!(report.events[0].id, "evt_01");
        assert_eq!(report.events[1].id, "evt_03");
        // The out-of-bounds metrics object was normalized to absent.
        assert!(report.events[1].metrics.is_none());
        assert_eq!(report.skipped_lines, vec![2]);
    }

    #[test]
    fn append_drops_secret_bearing_metrics_and_marks_redacted() {
        use crate::event::AuditMetrics;
        let root = tmp_root();
        let mut store = JsonlAuditStore::new(&root);
        let session = "s_guard";
        let mut e = event(
            "evt_01",
            session,
            at(7, 0),
            AuditAction::SessionApplyChanges,
        );
        // A model carrying a `KEY=value` secret triggers the secret guard.
        e.metrics = Some(AuditMetrics {
            duration_ms: 1,
            input_bytes: 1,
            output_bytes: 1,
            estimated_tokens: 1,
            model: "API_KEY=super-secret".to_string(),
        });
        store.append(&e).unwrap();

        let read = store.read(session).unwrap();
        assert_eq!(read.len(), 1);
        // Metrics dropped, event recorded as redacted, every other field kept.
        assert!(read[0].metrics.is_none());
        assert!(read[0].redacted);
        assert_eq!(read[0].id, "evt_01");
    }
}
