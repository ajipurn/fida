//! Property-based tests for Secret_Scanner redaction (spec task 6.2).
//!
//! Feature: fida-mvp, Property 11: Secret redaction hides value and length

use fida_policy::CompiledSecretPattern;
use fida_secrets::{REDACTION_MARKER, Scanner, SecretScanner};
use proptest::prelude::*;
use regex::Regex;

/// A scanner whose single policy pattern detects values of the form
/// `FIDA<alphanumerics>`. This lets the proptest-generated secret align with
/// a pattern the scanner actually matches.
fn scanner() -> Scanner {
    Scanner::with_patterns(&[CompiledSecretPattern {
        name: "fida_token".to_string(),
        regex: Regex::new(r"FIDA[0-9A-Za-z]+").unwrap(),
    }])
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 100, ..ProptestConfig::default() })]

    // Feature: fida-mvp, Property 11: Secret redaction hides value and length
    //
    // The redacted output contains none of the original secret value as a
    // substring. The secret is a `FIDA`-prefixed alphanumeric token of
    // varying length; the surrounding text is lowercase letters and spaces, so
    // it can never contain the uppercase-prefixed secret. After redaction the
    // value must be gone and the fixed marker present.
    #[test]
    fn redaction_hides_secret_value(
        prefix in "[a-z ]{0,50}",
        token in "FIDA[0-9A-Za-z]{1,200}",
        suffix in "[a-z ]{0,50}",
    ) {
        let content = format!("{prefix} {token} {suffix}");
        let out = scanner().redact(&content).expect("redaction succeeds for clean utf-8");

        // (1) The original secret value does not survive as a substring.
        prop_assert!(
            !out.contains(&token),
            "redacted output still contains the secret value"
        );
        // The fixed marker stands in its place.
        prop_assert!(
            out.contains(REDACTION_MARKER),
            "redacted output is missing the redaction marker"
        );
    }

    // Feature: fida-mvp, Property 11: Secret redaction hides value and length
    //
    // The marker substituted in place of a secret is identical regardless of
    // the secret's content or length: redacting two arbitrary secrets embedded
    // in the same fixed template yields byte-identical output (the constant
    // marker), so the marker leaks neither value nor length.
    #[test]
    fn marker_is_identical_regardless_of_content_and_length(
        token_a in "FIDA[0-9A-Za-z]{1,200}",
        token_b in "FIDA[0-9A-Za-z]{1,200}",
    ) {
        let s = scanner();
        let out_a = s.redact(&format!("head {token_a} tail")).unwrap();
        let out_b = s.redact(&format!("head {token_b} tail")).unwrap();

        let expected = format!("head {REDACTION_MARKER} tail");
        // (2) The marker text in place is identical regardless of content/length.
        prop_assert_eq!(&out_a, &expected);
        prop_assert_eq!(&out_b, &expected);
        prop_assert_eq!(&out_a, &out_b);
    }
}
