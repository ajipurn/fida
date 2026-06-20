//! `fida-audit` — Audit_Store (append-only JSONL) and Report_Generator
//! (see spec tasks 7.x).
//!
//! Task 7.2 defines the redaction-safe [`AuditEvent`] schema; the append-only
//! store (task 7.1) and report generator (task 7.5) build on it.

mod event;
mod report;
mod store;
pub mod testing;

pub use event::{AuditAction, AuditEvent, AuditMetrics, AuditResult, MAX_SAFE_INT};
pub use report::{DefaultReportGenerator, ReportError, ReportFormat, ReportGenerator};
pub use store::{AuditFilter, AuditStore, JsonlAuditStore, ReadReport};
