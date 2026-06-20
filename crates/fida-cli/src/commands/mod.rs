//! Command handler modules — the dispatch table's leaves.
//!
//! Each module owns one top-level command (or command family): its clap
//! argument struct(s) **and** its async `run` handler.
//!
//! | Module      | Command(s)                                   |
//! |-------------|----------------------------------------------|
//! | [`init`]    | `fida init` / `fida init --policy`           |
//! | [`policy`]  | `fida policy {check,explain,test,schema,list-presets}` |
//! | [`exec`]    | `fida exec -- <cmd>`                         |
//! | [`run`]     | `fida run -- <agent>`                        |
//! | [`session`] | `fida session {list,show,diff,export,apply,clean}` |
//! | [`audit`]   | `fida audit {tail,list,show,export}`         |
//! | [`report`]  | `fida report <session>`                      |
//! | [`mcp`]     | `fida mcp {inspect,list-tools,explain-tool,proxy}` |
//! | [`doctor`]  | `fida doctor`                                |
//! | [`status`]  | `fida status`                                |
//! | [`guard`]   | `fida guard -- <cmd>`                        |

pub mod audit;
pub mod doctor;
pub mod exec;
pub mod guard;
pub mod hook;
pub mod init;
pub mod install;
pub mod integrations;
pub mod mcp;
pub mod protection;
pub mod report;
pub mod scan;
pub mod setup_state;
pub mod shell_hook;
pub mod status;
pub mod uninstall;
