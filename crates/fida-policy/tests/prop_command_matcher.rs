// Feature: fida-mvp, Property 7: Command matcher correctness
//
// Property 7: for any command string and rule set:
//   * an exact rule matches iff the joined argv equals the rule string,
//   * a prefix rule matches iff the command begins with the rule on a token
//     boundary (the command equals the prefix, or continues with whitespace),
//   * a binary rule matches iff the first argv token's basename equals the rule
//     binary,
//   * a working-directory-conditioned rule applies only when the action cwd is
//     equal to or nested under the rule directory.
//
//
// The command matchers (`command_rule_matches`, `matcher_matches`,
// `working_dir_satisfied`) are part of the crate's public surface
// (`fida_policy::matchers::command::*`), so we exercise them directly. Each
// sub-property compares the matcher's result against an independent oracle that
// restates the design's "Command Matching" specification.

use std::path::{Path, PathBuf};

use fida_policy::matchers::command::{
    command_rule_matches, matcher_matches, working_dir_satisfied,
};
use fida_policy::{CompiledCommandMatcher, CompiledCommandRule};
use proptest::prelude::*;

// ---------------------------------------------------------------------------
// Oracles — independent restatements of the design's command-matching spec
// ---------------------------------------------------------------------------

/// Spec: a prefix rule matches iff the command equals the prefix, or begins
/// with the prefix followed by a whitespace token boundary.
fn oracle_prefix(command: &str, prefix: &str) -> bool {
    match command.strip_prefix(prefix) {
        Some(rest) => rest.is_empty() || rest.chars().next().is_some_and(char::is_whitespace),
        None => false,
    }
}

/// Spec: a binary rule matches iff the first argv token's basename equals the
/// rule binary.
fn oracle_binary(argv: &[String], binary: &str) -> bool {
    argv.first()
        .and_then(|arg| Path::new(arg).file_name())
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == binary)
}

fn exact_rule(s: &str) -> CompiledCommandRule {
    rule_with(CompiledCommandMatcher::Exact(s.to_string()), None)
}

fn rule_with(matcher: CompiledCommandMatcher, working_dir: Option<PathBuf>) -> CompiledCommandRule {
    CompiledCommandRule {
        rule_id: "commands.allow[0]".to_string(),
        matcher,
        working_dir,
        reason: None,
        auto_approve: false,
    }
}

// ---------------------------------------------------------------------------
// Generators — constrained to safe, whitespace-free argv tokens
// ---------------------------------------------------------------------------

/// A whitespace-free command token (e.g. `git`, `push`, `abc12`).
fn token() -> impl Strategy<Value = String> {
    "[a-z][a-z0-9]{0,4}".prop_map(|s| s)
}

fn argv() -> impl Strategy<Value = Vec<String>> {
    prop::collection::vec(token(), 0..=4)
}

/// A command string built from 1–3 tokens joined by single spaces.
fn command_string() -> impl Strategy<Value = String> {
    prop::collection::vec(token(), 1..=3).prop_map(|ws| ws.join(" "))
}

/// A prefix (1–3 tokens) paired with an argv constructed to exercise both the
/// matching and non-matching branches of the token-boundary rule.
fn prefix_and_argv() -> impl Strategy<Value = (String, Vec<String>)> {
    prop::collection::vec(token(), 1..=3).prop_flat_map(|prefix_tokens| {
        let prefix = prefix_tokens.join(" ");
        let pt = prefix_tokens.clone();
        let variants = prop_oneof![
            // (a) exactly the prefix tokens -> matches.
            Just(pt.clone()),
            // (b) prefix tokens + extra tokens -> matches (token boundary).
            prop::collection::vec(token(), 1..=2).prop_map({
                let pt = pt.clone();
                move |extra| {
                    let mut a = pt.clone();
                    a.extend(extra);
                    a
                }
            }),
            // (c) last token extended -> mid-token, must NOT match.
            token().prop_map({
                let pt = pt.clone();
                move |suffix| {
                    let mut a = pt.clone();
                    let last = a.len() - 1;
                    a[last] = format!("{}{suffix}", a[last]);
                    a
                }
            }),
            // (d) one fewer token -> shorter, must NOT match.
            Just(pt[..pt.len().saturating_sub(1)].to_vec()),
            // (e) entirely unrelated argv -> usually no match.
            argv(),
        ];
        variants.prop_map(move |argv| (prefix.clone(), argv))
    })
}

/// A rule-binary paired with an argv whose first token sometimes shares the
/// binary's basename (with an optional leading directory) and sometimes does
/// not.
fn binary_and_argv() -> impl Strategy<Value = (String, Vec<String>)> {
    let dir_prefix = prop_oneof![
        Just(String::new()),
        Just("/bin/".to_string()),
        Just("/usr/local/bin/".to_string()),
        Just("./".to_string()),
        token().prop_map(|d| format!("/{d}/")),
    ];
    (token(), dir_prefix, prop::collection::vec(token(), 0..=2)).prop_flat_map(
        |(base, dir, rest)| {
            // Bias toward equal-basename cases so the `true` branch is hit.
            let binary = prop_oneof![Just(base.clone()), token()];
            let base = base.clone();
            binary.prop_map(move |b| {
                let mut argv = vec![format!("{dir}{base}")];
                argv.extend(rest.clone());
                (b, argv)
            })
        },
    )
}

/// An absolute rule directory paired with a cwd and the expected
/// equal-or-nested result.
fn rule_dir_and_cwd() -> impl Strategy<Value = (PathBuf, PathBuf, bool)> {
    prop::collection::vec(token(), 1..=3).prop_flat_map(|segs| {
        let rule_dir = PathBuf::from(format!("/{}", segs.join("/")));
        let rd = rule_dir.clone();
        let cases = prop_oneof![
            // Equal -> satisfied.
            Just((rd.clone(), true)),
            // Nested under -> satisfied.
            prop::collection::vec(token(), 1..=2).prop_map({
                let rd = rd.clone();
                move |extra| (rd.join(extra.join("/")), true)
            }),
            // Disjoint root -> not satisfied.
            prop::collection::vec(token(), 1..=2).prop_map(|p| (
                PathBuf::from(format!("/__outside__/{}", p.join("/"))),
                false
            )),
            // Parent of the rule dir -> not satisfied (parent never nests).
            Just((
                rd.parent()
                    .map(Path::to_path_buf)
                    .unwrap_or_else(|| PathBuf::from("/")),
                rd.parent().is_none(),
            )),
        ];
        cases.prop_map(move |(cwd, expected)| (rule_dir.clone(), cwd, expected))
    })
}

// ---------------------------------------------------------------------------
// Property 7
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig { cases: 100, ..ProptestConfig::default() })]

    // Feature: fida-mvp, Property 7: Command matcher correctness — exact
    #[test]
    fn exact_matches_iff_joined_argv_equals_rule(
        rule_str in command_string(),
        argv in argv(),
    ) {
        let m = CompiledCommandMatcher::Exact(rule_str.clone());
        let expected = argv.join(" ") == rule_str;
        prop_assert_eq!(matcher_matches(&m, &argv), expected);

        // An exact rule built from the argv's own joined form always matches it.
        let self_rule = CompiledCommandMatcher::Exact(argv.join(" "));
        prop_assert!(matcher_matches(&self_rule, &argv));
    }

    // Feature: fida-mvp, Property 7: Command matcher correctness — prefix
    #[test]
    fn prefix_matches_iff_begins_with_on_token_boundary(
        (prefix, argv) in prefix_and_argv(),
    ) {
        let m = CompiledCommandMatcher::Prefix(prefix.clone());
        let expected = oracle_prefix(&argv.join(" "), &prefix);
        prop_assert_eq!(matcher_matches(&m, &argv), expected);
    }

    // Feature: fida-mvp, Property 7: Command matcher correctness — binary
    #[test]
    fn binary_matches_iff_first_token_basename_equals_rule(
        (binary, argv) in binary_and_argv(),
    ) {
        let m = CompiledCommandMatcher::Binary(binary.clone());
        prop_assert_eq!(matcher_matches(&m, &argv), oracle_binary(&argv, &binary));
    }

    // Feature: fida-mvp, Property 7: Command matcher correctness — working dir
    #[test]
    fn working_dir_conditioned_rule_applies_only_when_equal_or_nested(
        (rule_dir, cwd, nested) in rule_dir_and_cwd(),
        extra in prop::collection::vec(token(), 0..=2),
    ) {
        // `working_dir_satisfied` agrees with the equal-or-nested expectation.
        prop_assert_eq!(working_dir_satisfied(&rule_dir, &cwd), nested);

        // A rule whose matcher would otherwise match applies iff the cwd is
        // equal to or nested under the rule directory.
        let mut argv = vec!["git".to_string(), "push".to_string()];
        argv.extend(extra);
        let matching = exact_rule_for(&argv);
        let rule = rule_with(matching.matcher, Some(rule_dir.clone()));
        prop_assert_eq!(command_rule_matches(&rule, &argv, &cwd), nested);

        // A rule whose matcher does NOT match is inapplicable regardless of cwd.
        let non_matching = rule_with(
            CompiledCommandMatcher::Exact(format!("{} zzz", argv.join(" "))),
            Some(rule_dir.clone()),
        );
        prop_assert!(!command_rule_matches(&non_matching, &argv, &cwd));
    }
}

/// An exact rule that matches exactly the given argv.
fn exact_rule_for(argv: &[String]) -> CompiledCommandRule {
    exact_rule(&argv.join(" "))
}
