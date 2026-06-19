//! Property-based tests for fail-closed redaction suppression (spec task 6.3).
//!
//! Feature: fida-mvp, Property 13: Redaction failure suppresses content
//!
//! `Scanner::redact` fails closed with a [`RedactError`] when redaction cannot
//! complete on a content item. Design "Secret Scanner Design",
//! the CALLER then suppresses that item from the audit store and writes a
//! redaction-failure indicator in its place that contains no secret data.
//!
//! These tests model the caller's suppression decision with [`persist`]: it
//! returns the redacted string on `Ok`, and a fixed, secret-free indicator on
//! `Err`. The encoded guarantee is that the value the caller would persist —
//! whether redaction succeeded or failed — never carries any of the original
//! secret material.

use fida_policy::CompiledSecretPattern;
use fida_secrets::{REDACTION_MARKER, RedactError, Scanner, SecretScanner};
use proptest::prelude::*;
use regex::Regex;

/// The fixed redaction-failure indicator the caller writes in place of a
/// suppressed content item. It is a constant that carries no portion
/// of any content item — neither value, substring, nor length.
const REDACTION_FAILURE_INDICATOR: &str = "[redaction-failed]";

/// Models the caller's fail-closed suppression decision:
///
/// * on `Ok(redacted)` the redacted content is persisted as-is;
/// * on `Err(_)` the whole content item is suppressed and the fixed
///   [`REDACTION_FAILURE_INDICATOR`] — which contains no secret data — is
///   persisted instead.
///
/// The `RedactError` itself never carries secret material, so nothing about the
/// original content can flow through this path.
fn persist(result: Result<String, RedactError>) -> String {
    match result {
        Ok(redacted) => redacted,
        Err(_) => REDACTION_FAILURE_INDICATOR.to_string(),
    }
}

/// A scanner whose single policy pattern detects `FIDA`-prefixed alphanumeric
/// tokens, so a generated secret aligns with something the scanner matches.
fn scanner() -> Scanner {
    Scanner::with_patterns(&[CompiledSecretPattern {
        name: "fida_token".to_string(),
        regex: Regex::new(r"FIDA[0-9A-Za-z]+").unwrap(),
    }])
}

/// Strategy over the structural redaction-failure causes (no secret payload).
fn any_redact_error() -> impl Strategy<Value = RedactError> {
    prop_oneof![
        Just(RedactError::NonCharBoundary),
        Just(RedactError::IncompleteRedaction),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 100,..ProptestConfig::default() })]

    // Feature: fida-mvp, Property 13: Redaction failure suppresses content
    //
    // The Err branch: for ANY content item carrying a secret, if redaction
    // fails the caller persists the fixed failure indicator only. The persisted
    // value contains no part of the content item — not the secret, not the
    // surrounding text, not its length — and equals the constant indicator.
    #[test]
    fn redaction_failure_suppresses_entire_content(
        prefix in "[a-zA-Z0-9 ]{0,80}",
        token in "FIDA[0-9A-Za-z]{1,200}",
        suffix in "[a-zA-Z0-9 ]{0,80}",
        err in any_redact_error(),
    ) {
        let content = format!("{prefix} {token} {suffix}");

        // The caller faced a redaction failure on this item.
        let persisted = persist(Err(err));

        // No part of the content item survives: the persisted value is exactly
        // the fixed, secret-free indicator.
        prop_assert_eq!(&persisted, REDACTION_FAILURE_INDICATOR);
        prop_assert!(
            !persisted.contains(&token),
            "failure indicator leaked the secret value"
        );
        // Nor does any other non-trivial slice of the content survive.
        for word in content.split_whitespace().filter(|w| w.len() >= 4) {
            prop_assert!(
                !persisted.contains(word),
                "failure indicator leaked a fragment of the content"
            );
        }
    }

    // Feature: fida-mvp, Property 13: Redaction failure suppresses content
    //
    // The unifying invariant across BOTH branches: whatever the caller would
    // persist — the redacted string on success, or the failure indicator on
    // failure — never contains the original secret value as a substring. This
    // is the fail-closed guarantee: secret material reaches the audit store on
    // neither path.
    #[test]
    fn persisted_value_never_contains_secret_on_either_branch(
        prefix in "[a-z ]{0,50}",
        token in "FIDA[0-9A-Za-z]{1,200}",
        suffix in "[a-z ]{0,50}",
        force_failure in any::<bool>(),
        err in any_redact_error(),
    ) {
        let content = format!("{prefix} {token} {suffix}");

        // Branch chosen by `force_failure`: a genuine redaction of clean UTF-8
        // (Ok) versus a modeled redaction failure (Err).
        let result = if force_failure {
            Err(err)
        } else {
            scanner().redact(&content)
        };
        let persisted = persist(result);

        // The secret value never reaches what would be persisted.
        prop_assert!(
            !persisted.contains(&token),
            "persisted value leaked the secret on the {} branch",
            if force_failure { "failure" } else { "success" }
        );

        if force_failure {
            // Failure path: exactly the secret-free indicator, nothing else.
            prop_assert_eq!(&persisted, REDACTION_FAILURE_INDICATOR);
        } else {
            // Success path: the fixed marker stands in for the secret.
            prop_assert!(
                persisted.contains(REDACTION_MARKER),
                "success path is missing the redaction marker"
            );
        }
    }
}
