//! In-memory audit collaborators for unit tests.
//!
//! [`MemoryAuditStore`] is an [`AuditStore`] backed by a per-session `Vec`, so
//! tests can read back the exactly-one-event-per-action trail and assert on its
//! order, decision, and result without touching the filesystem.

use std::collections::HashMap;

use crate::{AuditEvent, AuditFilter, AuditStore};

/// An append-only [`AuditStore`] that keeps events in memory, grouped by
/// session id, preserving append order.
#[derive(Debug, Default, Clone)]
pub struct MemoryAuditStore {
    by_session: HashMap<String, Vec<AuditEvent>>,
}

impl MemoryAuditStore {
    /// An empty store.
    pub fn new() -> Self {
        MemoryAuditStore::default()
    }

    /// Total number of events recorded across all sessions.
    pub fn total(&self) -> usize {
        self.by_session.values().map(Vec::len).sum()
    }
}

impl AuditStore for MemoryAuditStore {
    fn append(&mut self, event: &AuditEvent) -> std::io::Result<()> {
        self.by_session
            .entry(event.session_id.clone())
            .or_default()
            .push(event.clone());
        Ok(())
    }

    fn read(&self, session: &str) -> std::io::Result<Vec<AuditEvent>> {
        Ok(self.by_session.get(session).cloned().unwrap_or_default())
    }

    fn filter(&self, session: &str, filter: &AuditFilter) -> std::io::Result<Vec<AuditEvent>> {
        Ok(self
            .read(session)?
            .into_iter()
            .filter(|event| filter.matches(event))
            .collect())
    }
}
