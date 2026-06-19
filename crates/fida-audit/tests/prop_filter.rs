// Feature: fida-mvp, Property 15: Audit filter soundness and completeness
//
// Property 15: Audit filter soundness and completeness — for any events and any
// `--kind`/`--decision`/`--risk`/`--since` combination, the result is exactly
// the events matching every supplied filter (AND semantics). This proves
// soundness (no extra events) and completeness (no missing events), preserving
// append order.
//

use chrono::{DateTime, TimeZone, Utc};
use fida_action::{ActionKind, Actor, Decision, MatchedRule, Protocol, Risk};
use fida_audit::{AuditAction, AuditEvent, AuditFilter, AuditResult, AuditStore, JsonlAuditStore};
use proptest::prelude::*;

/// Bounded epoch-seconds range so generated times stay representable and vary
/// across a meaningful window (2020-01-01 .. ~2035).
const MIN_SECS: i64 = 1_577_836_800;
const MAX_SECS: i64 = 2_051_222_400;

fn time_strategy() -> impl Strategy<Value = DateTime<Utc>> {
    (MIN_SECS..MAX_SECS).prop_map(|secs| Utc.timestamp_opt(secs, 0).unwrap())
}

fn actor_strategy() -> impl Strategy<Value = Actor> {
    prop_oneof![Just(Actor::Agent), Just(Actor::User)]
}

fn decision_strategy() -> impl Strategy<Value = Decision> {
    prop_oneof![
        Just(Decision::Allow),
        Just(Decision::Ask),
        Just(Decision::Deny),
        Just(Decision::DryRun),
    ]
}

fn risk_strategy() -> impl Strategy<Value = Risk> {
    prop_oneof![Just(Risk::Low), Just(Risk::Medium), Just(Risk::High)]
}

fn result_strategy() -> impl Strategy<Value = AuditResult> {
    prop_oneof![
        Just(AuditResult::Allowed),
        Just(AuditResult::AllowedOnce),
        Just(AuditResult::AllowedRemembered),
        Just(AuditResult::Denied),
        Just(AuditResult::Blocked),
        Just(AuditResult::WouldRun),
        Just(AuditResult::TimedOut),
    ]
}

fn matched_rule_strategy() -> impl Strategy<Value = MatchedRule> {
    prop_oneof![
        "[a-zA-Z0-9_.\\[\\]-]{1,24}".prop_map(MatchedRule::Rule),
        Just(MatchedRule::NoExplicitRule),
    ]
}

/// Generate a redaction-safe action spanning every kind so `--kind` filtering
/// is exercised across all variants. Text fields exclude newlines to keep the
/// one-event-per-line JSONL invariant intact.
fn action_strategy() -> impl Strategy<Value = AuditAction> {
    let text = "[a-zA-Z0-9_./ -]{0,32}";
    prop_oneof![
        text.prop_map(|command| AuditAction::CommandRun { command }),
        text.prop_map(|path| AuditAction::FileRead { path }),
        text.prop_map(|path| AuditAction::FileWrite { path }),
        text.prop_map(|path| AuditAction::FileDelete { path }),
        (
            proptest::option::of("[a-zA-Z0-9.-]{1,24}"),
            "[a-zA-Z0-9.:-]{1,24}",
            prop_oneof![Just(Protocol::Http), Just(Protocol::Https)],
        )
            .prop_map(|(domain, host, protocol)| AuditAction::NetworkRequest {
                domain,
                host,
                protocol,
            }),
        "[a-zA-Z0-9_.]{1,24}".prop_map(|tool| AuditAction::McpToolCall { tool }),
        ("[a-z_]{1,16}", "[a-zA-Z0-9 ]{0,32}").prop_map(|(pattern_id, reason)| {
            AuditAction::SecretDetected { pattern_id, reason }
        }),
        Just(AuditAction::SessionApplyChanges),
    ]
}

fn event_strategy(session: String, id: String) -> impl Strategy<Value = AuditEvent> {
    (
        time_strategy(),
        actor_strategy(),
        action_strategy(),
        decision_strategy(),
        result_strategy(),
        matched_rule_strategy(),
        risk_strategy(),
        any::<bool>(),
    )
        .prop_map(
            move |(time, actor, action, decision, result, matched_rule, risk, redacted)| {
                AuditEvent {
                    id: id.clone(),
                    session_id: session.clone(),
                    time,
                    actor,
                    action,
                    decision,
                    result,
                    matched_rule,
                    risk,
                    redacted,
                    metrics: None,
                }
            },
        )
}

/// A possibly-empty sequence of events for a single session, each carrying a
/// distinct, order-tagged id (`evt_0000`, `evt_0001`, ...). Empty sequences are
/// allowed so the zero-event case is covered.
fn sequence_strategy() -> impl Strategy<Value = Vec<AuditEvent>> {
    (0usize..=40).prop_flat_map(|len| {
        let session = "2026-06-12T070000Z-prop".to_string();
        (0..len)
            .map(|i| event_strategy(session.clone(), format!("evt_{i:04}")))
            .collect::<Vec<_>>()
    })
}

/// Map every [`ActionKind`] so `--kind` can filter on any variant.
fn action_kind_strategy() -> impl Strategy<Value = ActionKind> {
    prop_oneof![
        Just(ActionKind::CommandRun),
        Just(ActionKind::FileRead),
        Just(ActionKind::FileWrite),
        Just(ActionKind::FileDelete),
        Just(ActionKind::NetworkRequest),
        Just(ActionKind::McpToolCall),
        Just(ActionKind::SecretDetected),
        Just(ActionKind::SessionApplyChanges),
    ]
}

/// Generate an [`AuditFilter`] where each field is independently `Some`/`None`,
/// so every combination of the four `--kind`/`--decision`/`--risk`/`--since`
/// filters is reachable, including the empty (match-all) filter.
fn filter_strategy() -> impl Strategy<Value = AuditFilter> {
    (
        proptest::option::of(action_kind_strategy()),
        proptest::option::of(decision_strategy()),
        proptest::option::of(risk_strategy()),
        // Use the same time window (plus the exact boundaries) so generated
        // `since` values land before, within, and after the event span.
        proptest::option::of(time_strategy()),
    )
        .prop_map(|(kind, decision, risk, since)| AuditFilter {
            kind,
            decision,
            risk,
            since,
        })
}

/// Reference predicate computed entirely in memory, independent of the store,
/// so the assertion compares the store result against an oracle that does not
/// reuse `AuditFilter::matches`.
fn expected_matches(event: &AuditEvent, filter: &AuditFilter) -> bool {
    if let Some(kind) = filter.kind {
        let event_kind = match &event.action {
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
        };
        if event_kind != kind {
            return false;
        }
    }
    if let Some(decision) = filter.decision {
        if event.decision != decision {
            return false;
        }
    }
    if let Some(risk) = filter.risk {
        if event.risk != risk {
            return false;
        }
    }
    if let Some(since) = filter.since {
        if event.time < since {
            return false;
        }
    }
    true
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 100, ..ProptestConfig::default() })]

    /// For any events appended to a session and any filter combination, the
    /// store returns exactly the events matching every supplied field — same
    /// events, same append order — with no extras (soundness) and none missing
    /// (completeness).
    #[test]
    fn filter_soundness_and_completeness(
        events in sequence_strategy(),
        filter in filter_strategy(),
    ) {
        let root = tempfile::tempdir().unwrap();
        let session = "2026-06-12T070000Z-prop".to_string();

        let mut store = JsonlAuditStore::new(root.path());
        for event in &events {
            store.append(event).unwrap();
        }

        // Oracle: independently filter the in-memory list with the same AND
        // predicate, preserving append order.
        let expected: Vec<AuditEvent> = events
            .iter()
            .filter(|e| expected_matches(e, &filter))
            .cloned()
            .collect();

        let got = JsonlAuditStore::new(root.path())
            .filter(&session, &filter)
            .unwrap();

        // Exactly the expected subset, in the same order (soundness + completeness).
        prop_assert_eq!(got.len(), expected.len());
        prop_assert_eq!(&got, &expected);

        // Every returned event genuinely satisfies every supplied field (no extras).
        for event in &got {
            prop_assert!(expected_matches(event, &filter));
        }

        // Every appended event matching the filter is present (none missing).
        for event in &events {
            if expected_matches(event, &filter) {
                let occurrences = got.iter().filter(|e| e.id == event.id).count();
                prop_assert_eq!(occurrences, 1);
            } else {
                prop_assert!(!got.iter().any(|e| e.id == event.id));
            }
        }
    }
}
