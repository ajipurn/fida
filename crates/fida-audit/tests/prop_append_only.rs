// Feature: fida-mvp, Property 14: Audit append-only ordering
//
// Property 14: Audit append-only ordering — reading back yields events in
// append order, each present exactly once, with no prior event modified or
// removed.
//

use chrono::{DateTime, TimeZone, Utc};
use fida_action::{Actor, Decision, MatchedRule, Protocol, Risk};
use fida_audit::{AuditAction, AuditEvent, AuditResult, AuditStore, JsonlAuditStore};
use proptest::prelude::*;

/// Generate a UTC timestamp from a bounded epoch-seconds range so times stay
/// well within chrono's representable bounds while still varying.
fn time_strategy() -> impl Strategy<Value = DateTime<Utc>> {
    // 2020-01-01 .. ~2035 worth of seconds.
    (1_577_836_800i64..2_051_222_400i64).prop_map(|secs| Utc.timestamp_opt(secs, 0).unwrap())
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
        // Rule ids never contain newlines (which the store rejects).
        "[a-zA-Z0-9_.\\[\\]-]{1,24}".prop_map(MatchedRule::Rule),
        Just(MatchedRule::NoExplicitRule),
    ]
}

/// Generate a redaction-safe action of a varied kind. Text fields exclude
/// newlines so they never violate the one-event-per-line JSONL invariant.
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

/// Generate a single event for a fixed session. The id is supplied by the
/// caller so generated sequences carry unique, position-tagged ids.
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

/// Generate a non-empty sequence of events all belonging to one session, each
/// with a distinct, order-tagged id (`evt_0000`, `evt_0001`, ...).
fn sequence_strategy() -> impl Strategy<Value = Vec<AuditEvent>> {
    (1usize..=40).prop_flat_map(|len| {
        let session = "2026-06-12T070000Z-prop".to_string();
        let per_event: Vec<_> = (0..len)
            .map(|i| event_strategy(session.clone(), format!("evt_{i:04}")))
            .collect();
        per_event
    })
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 100, ..ProptestConfig::default() })]

    /// Appending a sequence and reading it back yields exactly those events,
    /// in append order, each present exactly once — with no prior event lost or
    /// mutated, even across fresh store instances.
    #[test]
    fn append_only_ordering(events in sequence_strategy()) {
        let root = tempfile::tempdir().unwrap();
        let session = events[0].session_id.clone();

        // Append in order, using a fresh store instance for each event so the
        // append-only guarantee is exercised across independent openings (no
        // prior line may be modified or removed).
        for event in &events {
            let mut store = JsonlAuditStore::new(root.path());
            store.append(event).unwrap();

            // After each append the prefix written so far must be intact and
            // unchanged — every earlier event survives exactly as written.
            let so_far = JsonlAuditStore::new(root.path()).read(&session).unwrap();
            let written = &events[..so_far.len()];
            prop_assert_eq!(so_far.len(), written.len());
            prop_assert_eq!(&so_far[..], written);
        }

        // Full read-back equals the appended sequence, in the same order.
        let read = JsonlAuditStore::new(root.path()).read(&session).unwrap();
        prop_assert_eq!(read.len(), events.len());
        prop_assert_eq!(&read, &events);

        // Each appended event is present exactly once (ids are unique by
        // construction; confirm the read-back preserves that one-to-one).
        for (i, event) in events.iter().enumerate() {
            let occurrences = read.iter().filter(|e| e.id == event.id).count();
            prop_assert_eq!(occurrences, 1);
            // Same position => no reordering.
            prop_assert_eq!(&read[i], event);
        }
    }
}
