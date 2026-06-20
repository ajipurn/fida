//! The single typed CLI error and its mapping to the documented exit-code
//! table (design "Error Handling").
//!
//! `fida-cli` is the only place that turns subsystem outcomes into process
//! exit codes. Every command module returns [`CliResult`]; `main` converts the
//! terminal [`CliError`] into a `u8` via [`CliError::exit_code`] and calls
//! `std::process::exit`.
//!
//! `fida-cli` owns the exit-code table directly. Each value has exactly one
//! definition here:
//!
//! | Code | Meaning                                            |
//! |------|----------------------------------------------------|
//! | 0    | success                                             |
//! | 1    | [`EXIT_GENERAL`] — usage / generic failure         |
//! | 2    | [`EXIT_DENY`] — policy deny                         |
//! | 3    | [`EXIT_APPROVAL_REQUIRED`] — non-interactive `ask`  |
//! | 4    | [`EXIT_INVALID_POLICY`] — invalid / unresolvable policy |
//! | 6    | [`EXIT_SECRET_BLOCKED`] — secret exposure blocked   |

use std::fmt;

/// Successful completion.
const EXIT_SUCCESS: u8 = 0;
/// A mediated action resolved to `deny`.
const EXIT_DENY: u8 = 2;
/// `ask` required while non-interactive with no remembered decision.
const EXIT_APPROVAL_REQUIRED: u8 = 3;
/// A secret exposure was blocked.
const EXIT_SECRET_BLOCKED: u8 = 6;

/// Successful completion.
pub const EXIT_SUCCESS_CODE: u8 = EXIT_SUCCESS;

/// General/usage error. CLI-owned; no
/// subsystem constant exists for the generic bucket.
pub const EXIT_GENERAL: u8 = 1;

/// Invalid/unresolvable policy. Mirrors
/// [`fida_policy::LoadError::exit_code`], which always returns `4`.
pub const EXIT_INVALID_POLICY: u8 = 4;

/// Convenience alias for command modules. Every command handler returns this.
pub type CliResult<T = ()> = Result<T, CliError>;

/// The single typed CLI error. Each variant carries enough context to print an
/// actionable message to stderr and maps to exactly one exit code.
///
/// Several variants are constructed only by the per-command handlers added in
/// tasks 19.2–19.10; they are part of the scaffold's stable surface now.
#[derive(Debug)]
#[allow(dead_code)]
pub enum CliError {
    /// Bad invocation, conflicting flags (e.g. `--quiet` + `--verbose`), or any
    /// other generic failure -> exit 1.
    Usage(String),
    /// A non-usage failure that still maps to the generic bucket → exit 1
    /// Doctor failures, malformed test/cases files, etc.
    General(String),
    /// A mediated action resolved to `deny` -> exit 2.
    PolicyDenied { reason: String },
    /// `ask` required while non-interactive with no remembered decision →
    /// exit 3.
    ApprovalRequired { reason: String },
    /// The resolved policy is invalid or unreadable → exit 4
    InvalidPolicy(String),
    /// A secret exposure was blocked -> exit 6.
    SecretBlocked { reason: String },
    /// A permitted `command.run` exited with a non-zero code; the CLI must
    /// surface that exact code. Unlike the other variants
    /// this does not map to a fixed slot in the 0–7 table — it carries the
    /// process's own exit code (which may exceed 7), because `fida exec`
    /// is a transparent wrapper around the executed command.
    CommandExit(u8),
}

impl CliError {
    /// Shorthand for a usage error (conflicting/invalid flags).
    pub fn usage(message: impl Into<String>) -> Self {
        CliError::Usage(message.into())
    }

    /// Shorthand for a generic error.
    pub fn general(message: impl Into<String>) -> Self {
        CliError::General(message.into())
    }

    /// The process exit code for this error per the documented table.
    pub fn exit_code(&self) -> u8 {
        match self {
            CliError::Usage(_) | CliError::General(_) => EXIT_GENERAL,
            CliError::PolicyDenied { .. } => EXIT_DENY,
            CliError::ApprovalRequired { .. } => EXIT_APPROVAL_REQUIRED,
            CliError::InvalidPolicy(_) => EXIT_INVALID_POLICY,
            CliError::SecretBlocked { .. } => EXIT_SECRET_BLOCKED,
            // Transparent passthrough of the executed command's own exit code.
            CliError::CommandExit(code) => *code,
        }
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CliError::Usage(m) => write!(f, "{m}"),
            CliError::General(m) => write!(f, "{m}"),
            CliError::PolicyDenied { reason } => write!(f, "denied by policy: {reason}"),
            CliError::ApprovalRequired { reason } => {
                write!(f, "approval required (non-interactive): {reason}")
            }
            CliError::InvalidPolicy(m) => write!(f, "invalid policy: {m}"),
            CliError::SecretBlocked { reason } => write!(f, "secret exposure blocked: {reason}"),
            CliError::CommandExit(code) => write!(f, "command exited with status {code}"),
        }
    }
}

impl std::error::Error for CliError {}

/// Policy load failures always surface as invalid-policy (exit 4), reusing the
/// loader's own classification.
impl From<fida_policy::LoadError> for CliError {
    fn from(err: fida_policy::LoadError) -> Self {
        // `LoadError::exit_code()` is contractually always 4; mirror it here.
        debug_assert_eq!(err.exit_code(), EXIT_INVALID_POLICY as i32);
        CliError::InvalidPolicy(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes_match_documented_table() {
        assert_eq!(EXIT_SUCCESS_CODE, 0);
        assert_eq!(CliError::usage("x").exit_code(), 1);
        assert_eq!(CliError::general("x").exit_code(), 1);
        assert_eq!(CliError::PolicyDenied { reason: "x".into() }.exit_code(), 2);
        assert_eq!(
            CliError::ApprovalRequired { reason: "x".into() }.exit_code(),
            3
        );
        assert_eq!(CliError::InvalidPolicy("x".into()).exit_code(), 4);
        assert_eq!(
            CliError::SecretBlocked { reason: "x".into() }.exit_code(),
            6
        );
    }

    #[test]
    fn cli_codes_agree_with_documented_table() {
        assert_eq!(EXIT_DENY, 2);
        assert_eq!(EXIT_APPROVAL_REQUIRED, 3);
        assert_eq!(EXIT_INVALID_POLICY, 4);
        assert_eq!(EXIT_SECRET_BLOCKED, 6);
    }

    #[test]
    fn every_code_is_in_range_zero_to_seven() {
        for err in [
            CliError::usage("x"),
            CliError::general("x"),
            CliError::PolicyDenied { reason: "x".into() },
            CliError::ApprovalRequired { reason: "x".into() },
            CliError::InvalidPolicy("x".into()),
            CliError::SecretBlocked { reason: "x".into() },
        ] {
            assert!(err.exit_code() <= 7);
        }
    }
}
