//! Per-kind matching primitives invoked by the evaluator pipeline.
//!
//! These are the **seams** the staged evaluator (task 4.1) calls into. The
//! detailed matcher behavior is owned by later tasks:
//!
//! * [`command`] — command exact/prefix/regex/binary matching plus the
//!   working-directory condition (**task 4.2**).
//! * [`resource`] — file glob, network domain/host/CIDR, MCP tool-name
//!   matching, and the built-in hard-deny materialized rules (**task 4.3**).
//!
//! Task 4.1 ships minimal-but-working implementations here so the pipeline
//! compiles and is testable end to end; tasks 4.2 and 4.3 refine them (e.g.
//! token-boundary prefix matching, repo-relative path normalization). Keeping
//! commands and resources in separate files avoids edit collisions between the
//! two follow-up tasks.

pub mod command;
pub mod resource;
