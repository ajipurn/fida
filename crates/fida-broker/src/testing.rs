//! In-memory broker collaborators for unit and property tests.
//!
//! These let the broker's orchestration be exercised without real process
//! execution or audit-file I/O (design "Testing Strategy", "I/O isolation"):
//!
//! * [`MemoryAuditStore`] — an [`AuditStore`] backed by a per-session `Vec`, so
//!   tests can read back the exactly-one-event-per-action trail and assert on
//!   its order, decision, and result.
//! * [`RecordingDispatcher`] — an [`ActionDispatcher`] that records every action
//!   it is asked to perform and returns a configurable exit code, so tests can
//!   assert *whether* and *how often* dispatch happened (e.g. never, in
//!   dry-run — Property 20).
//! * [`ScriptedApprovalUi`] — an [`ApprovalUi`] that returns a pre-scripted
//!   queue of [`ApprovalOutcome`]s and counts prompts.

use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};

use fida_action::Action;
use fida_approval::{ApprovalOutcome, ApprovalPresentation, ApprovalUi};
use fida_audit::{AuditEvent, AuditFilter, AuditStore};

use crate::{ActionDispatcher, DispatchOutcome};

// ---------------------------------------------------------------------------
// In-memory audit store
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Recording dispatcher
// ---------------------------------------------------------------------------

/// An [`ActionDispatcher`] that records every dispatched action and returns a
/// fixed exit code.
#[derive(Debug, Clone)]
pub struct RecordingDispatcher {
    exit_code: u8,
    /// Every action the broker asked this dispatcher to perform, in order.
    pub dispatched: Vec<Action>,
}

impl RecordingDispatcher {
    /// A dispatcher that reports `exit_code` for every action.
    pub fn new(exit_code: u8) -> Self {
        RecordingDispatcher {
            exit_code,
            dispatched: Vec::new(),
        }
    }

    /// A dispatcher that always reports success (exit code 0).
    pub fn succeeding() -> Self {
        RecordingDispatcher::new(0)
    }

    /// How many actions were dispatched.
    pub fn count(&self) -> usize {
        self.dispatched.len()
    }
}

impl Default for RecordingDispatcher {
    fn default() -> Self {
        RecordingDispatcher::succeeding()
    }
}

impl ActionDispatcher for RecordingDispatcher {
    fn dispatch(&mut self, action: &Action) -> DispatchOutcome {
        self.dispatched.push(action.clone());
        DispatchOutcome {
            exit_code: self.exit_code,
        }
    }
}

// ---------------------------------------------------------------------------
// Scripted approval UI
// ---------------------------------------------------------------------------

/// An [`ApprovalUi`] that returns a pre-scripted sequence of outcomes.
///
/// Each call to [`prompt`](ApprovalUi::prompt) pops the next outcome from the
/// script and increments the prompt counter. If the script is exhausted it
/// fails closed by returning [`ApprovalOutcome::Denied`], mirroring the
/// production UI's EOF behavior.
#[derive(Debug, Default)]
pub struct ScriptedApprovalUi {
    outcomes: RefCell<VecDeque<ApprovalOutcome>>,
    prompts: RefCell<usize>,
}

impl ScriptedApprovalUi {
    /// Build a UI that returns `outcomes` in order, one per prompt.
    pub fn new(outcomes: impl IntoIterator<Item = ApprovalOutcome>) -> Self {
        ScriptedApprovalUi {
            outcomes: RefCell::new(outcomes.into_iter().collect()),
            prompts: RefCell::new(0),
        }
    }

    /// A UI that always denies (and never runs out of script).
    pub fn always_denying() -> Self {
        ScriptedApprovalUi::default()
    }

    /// How many times the broker prompted this UI.
    pub fn prompt_count(&self) -> usize {
        *self.prompts.borrow()
    }
}

impl ApprovalUi for ScriptedApprovalUi {
    fn prompt(&self, _presentation: &ApprovalPresentation) -> ApprovalOutcome {
        *self.prompts.borrow_mut() += 1;
        self.outcomes
            .borrow_mut()
            .pop_front()
            .unwrap_or(ApprovalOutcome::Denied)
    }
}

/// Lets tests build a [`crate::Broker`] over a borrowed [`ScriptedApprovalUi`]
/// so they can inspect [`ScriptedApprovalUi::prompt_count`] after driving the
/// broker, without moving the UI into the broker.
impl ApprovalUi for &ScriptedApprovalUi {
    fn prompt(&self, presentation: &ApprovalPresentation) -> ApprovalOutcome {
        (**self).prompt(presentation)
    }
}
