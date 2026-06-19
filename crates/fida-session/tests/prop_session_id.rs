// Feature: fida-mvp, Property 18: Session id uniqueness and latest resolution
//
//! Property-based test for Session_Manager id assignment and `latest`
//! resolution.
//!
//! **Property 18: Session id uniqueness and latest resolution** — every
//! assigned id is distinct across all sessions in a repository, and `latest`
//! resolves to the session with the most recently started time.
//!
//!
//! - each created session is assigned a Session_ID that is
//!   unique across all sessions in the repository.
//! - `latest` resolves to the session with the most recent
//!   start time.
//!
//! Strategy notes:
//! - Sessions are created with *distinct* start times (strictly increasing by
//!   at least one second) so that the second-resolution id timestamp prefix is
//!   itself distinct; this makes the uniqueness claim hold deterministically
//!   rather than relying on the random suffix avoiding a collision.
//! - Creation order is decoupled from time order via a random sort key, so the
//!   `latest` assertion verifies resolution is by start time and not by
//!   creation order.

use std::collections::HashSet;
use std::path::Path;

use chrono::{DateTime, Utc};
use fida_action::Mode;
use fida_session::{Baseline, CreateSessionParams, create_session, latest, list_sessions};
use proptest::prelude::*;

/// One generated session: a gap (seconds added on top of the previous start
/// time, guaranteeing strictly increasing distinct times) and an opaque sort
/// key used to shuffle creation order independently of time order.
fn entries_strategy() -> impl Strategy<Value = Vec<(u32, u64)>> {
    // 2..=25 sessions per case; gaps bounded so the cumulative timestamp stays
    // comfortably within the valid `DateTime` range.
    proptest::collection::vec((0u32..3600, any::<u64>()), 2..25)
}

/// Build strictly increasing, distinct UTC start times from per-entry gaps.
///
/// `t_0 = base`, `t_i = t_{i-1} + gap_i + 1`, so consecutive times differ by at
/// least one second and every timestamp (to second resolution) is distinct.
fn build_start_times(base_secs: i64, entries: &[(u32, u64)]) -> Option<Vec<DateTime<Utc>>> {
    let mut times = Vec::with_capacity(entries.len());
    let mut secs = base_secs;
    for (i, (gap, _)) in entries.iter().enumerate() {
        if i > 0 {
            secs = secs.checked_add(i64::from(*gap) + 1)?;
        }
        times.push(DateTime::<Utc>::from_timestamp(secs, 0)?);
    }
    Some(times)
}

fn params(repo: &Path, start: DateTime<Utc>) -> CreateSessionParams {
    CreateSessionParams {
        repo_path: repo.to_path_buf(),
        git_sha: "deadbeefcafe".to_string(),
        profile: Some("careful".to_string()),
        mode: Mode::Enforce,
        workspace_mode: "current".to_string(),
        agent_command: vec!["codex".to_string()],
        start_time: start,
        baseline: Baseline {
            head_sha: "deadbeefcafe".to_string(),
            dirty: false,
        },
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 100, ..ProptestConfig::default() })]

    /// All assigned ids are distinct, and `latest` resolves to the session with
    /// the most recent start time regardless of the order sessions were created.
    #[test]
    fn session_ids_unique_and_latest_resolves_to_most_recent(
        // A base instant well inside the representable range (≈2001..2033).
        base_secs in 1_000_000_000i64..2_000_000_000i64,
        entries in entries_strategy(),
    ) {
        let start_times = match build_start_times(base_secs, &entries) {
            Some(times) => times,
            // Discard the (vanishingly rare) overflow/out-of-range draw.
            None => return Err(TestCaseError::reject("start times out of range")),
        };

        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path();

        // Decouple creation order from time order: pair each start time with its
        // generated sort key and create sessions in key order.
        let mut creation_order: Vec<(u64, DateTime<Utc>)> = entries
            .iter()
            .map(|(_, key)| *key)
            .zip(start_times.iter().copied())
            .collect();
        creation_order.sort_by_key(|(key, _)| *key);

        let mut assigned_ids = HashSet::new();
        for (_, start) in &creation_order {
            let created = create_session(params(repo, *start)).expect("create session");
            // each id is unique across the repository.
            prop_assert!(
                assigned_ids.insert(created.id.clone()),
                "duplicate session id assigned: {}",
                created.id
            );
        }

        // Every created session is on disk and listed exactly once.
        let listed = list_sessions(repo).expect("list sessions");
        prop_assert_eq!(listed.len(), start_times.len());

        // The expected latest is the session with the maximum (distinct) start
        // time; ids are derived from start time so the max start time maps to a
        // single, known id.
        let max_start = *start_times.iter().max().unwrap();
        let expected_latest = list_sessions(repo)
            .expect("list sessions")
            .into_iter()
            .find(|m| m.start_time == max_start)
            .map(|m| m.session_id)
            .expect("a session at the max start time");

        let resolved = latest(repo).expect("resolve latest");
        // `latest` is the most recently started session.
        prop_assert_eq!(resolved, Some(expected_latest));
    }
}
