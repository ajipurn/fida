//! Command matching seam (design "Command Matching").
//!
//! **Owner: task 4.2.** The matchers implement the full command-matching
//! semantics:
//!
//! * exact — full command string equality,
//! * prefix — begins-with on a **token boundary** (not a bare `starts_with`),
//! * regex — compiled-regex match,
//! * binary — first argv token's basename equals the rule binary,
//! * working-directory condition — the rule applies only when the action cwd
//!   equals or nests under the rule directory.

use std::path::Path;

use crate::compiled::{CompiledCommandMatcher, CompiledCommandRule};

/// Whether a compiled command rule matches the given argv/cwd.
///
/// Applies the working-directory condition first: when the
/// rule declares a `working_dir`, it is inapplicable unless the action cwd
/// equals or nests under that directory, in which case the caller continues to
/// the next rule.
pub fn command_rule_matches(rule: &CompiledCommandRule, argv: &[String], cwd: &Path) -> bool {
    if let Some(dir) = &rule.working_dir {
        if !working_dir_satisfied(dir, cwd) {
            return false;
        }
    }
    matcher_matches(&rule.matcher, argv)
}

/// Whether `action_cwd` equals or nests under `rule_dir`.
pub fn working_dir_satisfied(rule_dir: &Path, action_cwd: &Path) -> bool {
    action_cwd == rule_dir || action_cwd.starts_with(rule_dir)
}

/// Match a single compiled matcher against the action's argv.
///
/// The argv tokens are joined with single spaces to form the command string the
/// `Exact`, `Prefix`, and `Regex` matchers test against.
pub fn matcher_matches(matcher: &CompiledCommandMatcher, argv: &[String]) -> bool {
    let command = argv.join(" ");
    match matcher {
        CompiledCommandMatcher::Exact(s) => command == *s,
        CompiledCommandMatcher::Prefix(s) => prefix_matches(&command, s),
        CompiledCommandMatcher::Regex(re) => re.is_match(&command),
        CompiledCommandMatcher::Binary(b) => {
            first_binary(argv).is_some_and(|name| name == b.as_str())
        }
    }
}

/// Whether `command` begins with `prefix` on a **token boundary**: the command
/// either equals the prefix exactly or continues with a whitespace character.
///
/// This is stricter than a bare `starts_with`, so the prefix `git push` matches
/// `git push` and `git push origin` but not `git pushy`.
fn prefix_matches(command: &str, prefix: &str) -> bool {
    command
        .strip_prefix(prefix)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with(char::is_whitespace))
}

/// The basename of the first argv token (the invoked binary), if any.
fn first_binary(argv: &[String]) -> Option<&str> {
    argv.first()
        .and_then(|arg| Path::new(arg).file_name())
        .and_then(|name| name.to_str())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn exact_matches_full_string_only() {
        let m = CompiledCommandMatcher::Exact("git status".to_string());
        assert!(matcher_matches(&m, &argv(&["git", "status"])));
        assert!(!matcher_matches(&m, &argv(&["git", "status", "-s"])));
    }

    #[test]
    fn binary_matches_basename_of_first_token() {
        let m = CompiledCommandMatcher::Binary("rm".to_string());
        assert!(matcher_matches(&m, &argv(&["/bin/rm", "-rf", "build"])));
        assert!(!matcher_matches(&m, &argv(&["git", "rm"])));
    }

    #[test]
    fn prefix_matches_command_equal_to_prefix() {
        let m = CompiledCommandMatcher::Prefix("git push".to_string());
        assert!(matcher_matches(&m, &argv(&["git", "push"])));
    }

    #[test]
    fn prefix_matches_only_on_token_boundary() {
        let m = CompiledCommandMatcher::Prefix("git push".to_string());
        // Continues with a whitespace boundary -> matches.
        assert!(matcher_matches(&m, &argv(&["git", "push", "origin"])));
        assert!(matcher_matches(
            &m,
            &argv(&["git", "push", "origin", "main"])
        ));
        // Continues mid-token -> must NOT match.
        assert!(!matcher_matches(&m, &argv(&["git", "pushy"])));
        assert!(!matcher_matches(&m, &argv(&["git", "pushy", "origin"])));
    }

    #[test]
    fn prefix_does_not_match_shorter_command() {
        let m = CompiledCommandMatcher::Prefix("git push".to_string());
        assert!(!matcher_matches(&m, &argv(&["git"])));
        assert!(!matcher_matches(&m, &argv(&["gi"])));
    }

    #[test]
    fn prefix_single_token_respects_boundary() {
        let m = CompiledCommandMatcher::Prefix("rm".to_string());
        assert!(matcher_matches(&m, &argv(&["rm"])));
        assert!(matcher_matches(&m, &argv(&["rm", "-rf", "build"])));
        // `rmdir` shares the leading bytes but is a different token.
        assert!(!matcher_matches(&m, &argv(&["rmdir", "build"])));
    }

    #[test]
    fn prefix_helper_token_boundary_rules() {
        assert!(prefix_matches("git push", "git push"));
        assert!(prefix_matches("git push origin", "git push"));
        assert!(!prefix_matches("git pushy", "git push"));
        assert!(!prefix_matches("git", "git push"));
    }

    #[test]
    fn command_rule_matches_applies_working_dir_condition() {
        let rule = CompiledCommandRule {
            rule_id: "commands.allow[0]".to_string(),
            matcher: CompiledCommandMatcher::Prefix("git push".to_string()),
            working_dir: Some(PathBuf::from("/repo")),
            reason: None,
            auto_approve: false,
        };
        // cwd nested under rule dir + command matches -> applies.
        assert!(command_rule_matches(
            &rule,
            &argv(&["git", "push", "origin"]),
            Path::new("/repo/crates")
        ));
        // command matches but cwd is outside the rule dir -> inapplicable.
        assert!(!command_rule_matches(
            &rule,
            &argv(&["git", "push", "origin"]),
            Path::new("/other")
        ));
        // cwd satisfies but command is a different token -> inapplicable.
        assert!(!command_rule_matches(
            &rule,
            &argv(&["git", "pushy"]),
            Path::new("/repo")
        ));
    }

    #[test]
    fn working_dir_requires_equal_or_nested() {
        let dir = PathBuf::from("/repo/crates");
        assert!(working_dir_satisfied(&dir, Path::new("/repo/crates")));
        assert!(working_dir_satisfied(&dir, Path::new("/repo/crates/cli")));
        assert!(!working_dir_satisfied(&dir, Path::new("/repo")));
    }
}
