//! Command handler modules — the dispatch table's leaves.
//!
//! Each module owns one top-level command (or command family): its clap
//! argument struct(s) **and** its handler.
//!
//! | Module      | Command(s)                                   |
//! |-------------|----------------------------------------------|
//! | [`root`]    | `fida` (install / update)                    |
//! | [`toggle`]  | `fida on` / `fida off`                        |
//! | [`status`]  | `fida status`                                |
//! | [`scan`]    | `fida scan`                                  |
//! | [`exec`]    | `fida exec -- <cmd>` (hidden)                |
//! | [`guard`]   | `fida guard -- <cmd>` (hidden)               |
//! | [`hook`]    | `fida hook` (hidden)                         |
//! | [`mcp`]     | `fida mcp …` (hidden)                        |
//!
//! [`integrations`], [`setup_state`], [`protection`], and [`shell_hook`] are
//! shared helpers, not commands.

pub mod exec;
pub mod guard;
pub mod hook;
pub mod integrations;
pub mod mcp;
pub mod protection;
pub mod root;
pub mod scan;
pub mod setup_state;
pub mod shell_hook;
pub mod status;
pub mod toggle;
