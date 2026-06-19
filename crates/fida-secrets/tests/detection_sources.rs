//! Unit/integration tests for the Secret_Scanner's three detection sources
//! (spec task 6.4; design "Secret Scanner Design").
//!
//! Covers each source — policy-defined named patterns, `.env` key=value
//! contents, and private-key headers — and asserts the strong leak-safety
//! property shared by all of them: a [`Finding`] NEVER includes the secret
//! value, any substring of it (length >= 4), or its length.
//!

use fida_action::Finding;
use fida_policy::CompiledSecretPattern;
use fida_secrets::{DOTENV_PATTERN_ID, PRIVATE_KEY_PATTERN_ID, Scanner, SecretScanner};
use regex::Regex;

/// Builds a compiled named policy pattern.
fn pattern(name: &str, re: &str) -> CompiledSecretPattern {
    CompiledSecretPattern {
        name: name.to_string(),
        regex: Regex::new(re).unwrap(),
    }
}

/// Asserts the core leak-safety invariant for a single finding:
/// neither `pattern_id` nor `reason` reveals the secret value, any substring of
/// it of length >= 4, or its length expressed as a decimal number.
fn assert_no_secret_leak(finding: &Finding, secret: &str) {
    // The whole value never appears.
    assert!(
        !finding.pattern_id.contains(secret),
        "pattern_id leaked the whole secret value"
    );
    assert!(
        !finding.reason.contains(secret),
        "reason leaked the whole secret value"
    );

    // No substring of the secret of length >= 4 appears in either field.
    let bytes = secret.as_bytes();
    for len in 4..=bytes.len() {
        for win in bytes.windows(len) {
            // Only consider windows that are valid UTF-8 fragments.
            if let Ok(frag) = std::str::from_utf8(win) {
                assert!(
                    !finding.pattern_id.contains(frag),
                    "pattern_id leaked secret fragment {frag:?}"
                );
                assert!(
                    !finding.reason.contains(frag),
                    "reason leaked secret fragment {frag:?}"
                );
            }
        }
    }

    // The secret's length is never revealed numerically.
    let len_str = secret.len().to_string();
    assert!(
        !finding.reason.contains(&len_str),
        "reason leaked the secret length {len_str}"
    );
    assert!(
        !finding.pattern_id.contains(&len_str),
        "pattern_id leaked the secret length {len_str}"
    );
}

// ---------------------------------------------------------------------------
// Source 1: policy-defined named patterns
// ---------------------------------------------------------------------------

#[test]
fn policy_named_pattern_detects_and_reports_pattern_name() {
    // Synthetic shape (not in the built-in catalog) so this isolates a
    // *policy-defined* pattern.
    let scanner = Scanner::with_patterns(&[pattern("acme_token", r"ACME[0-9A-Z]{16}")]);
    let secret = "ACME0123456789ABCDEF";

    let findings = scanner.scan(&format!("prefix {secret} suffix"));

    assert_eq!(findings.len(), 1, "exactly one policy match expected");
    // The finding's pattern_id is the policy pattern's name, not the value.
    assert_eq!(findings[0].pattern_id, "acme_token");
    assert!(!findings[0].reason.is_empty());
}

#[test]
fn policy_named_pattern_finding_never_leaks_secret() {
    let scanner = Scanner::with_patterns(&[pattern("acme_key", r"ACMEKEY-[0-9A-Za-z]{24}")]);
    let secret = "ACMEKEY-ABCDEFGH01234567IJKLMNOP";

    let findings = scanner.scan(&format!("config key={secret};"));

    assert_eq!(findings.len(), 1);
    assert_no_secret_leak(&findings[0], secret);
}

#[test]
fn policy_multiple_named_patterns_each_report_their_own_name() {
    let scanner = Scanner::with_patterns(&[
        pattern("acme_token", r"ACME[0-9A-Z]{16}"),
        pattern("zk_pat", r"ZkPat_[0-9A-Za-z]{20}"),
    ]);
    let acme = "ACME0000111122223333";
    let zk = "ZkPat_ABCDEFGH01234567WXYZ";

    let findings = scanner.scan(&format!("{acme} and {zk}"));

    let ids: Vec<&str> = findings.iter().map(|f| f.pattern_id.as_str()).collect();
    assert!(ids.contains(&"acme_token"));
    assert!(ids.contains(&"zk_pat"));
    for f in &findings {
        assert_no_secret_leak(f, acme);
        assert_no_secret_leak(f, zk);
    }
}

// ---------------------------------------------------------------------------
// Source 2: `.env` key=value contents
// ---------------------------------------------------------------------------

#[test]
fn dotenv_value_is_detected_under_dotenv_pattern_id() {
    let scanner = Scanner::with_patterns(&[]);
    // Only the value side of the assignment is the secret; the key is preserved.
    let value = "Sup3rSecretToken";
    let findings = scanner.scan(&format!("DATABASE_PASSWORD={value}"));

    assert_eq!(findings.len(), 1, "one.env assignment value expected");
    assert_eq!(findings[0].pattern_id, DOTENV_PATTERN_ID);
}

#[test]
fn dotenv_finding_never_leaks_value() {
    let scanner = Scanner::with_patterns(&[]);
    let value = "Sup3rSecretToken";

    let findings = scanner.scan(&format!("DATABASE_PASSWORD={value}"));

    assert_eq!(findings.len(), 1);
    assert_no_secret_leak(&findings[0], value);
}

#[test]
fn dotenv_export_prefixed_value_is_detected_without_leak() {
    let scanner = Scanner::with_patterns(&[]);
    let value = "XyZ9876AbCdToken";

    let findings = scanner.scan(&format!("export API_TOKEN={value}"));

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].pattern_id, DOTENV_PATTERN_ID);
    assert_no_secret_leak(&findings[0], value);
}

#[test]
fn dotenv_multiple_assignments_detected_without_leak() {
    let scanner = Scanner::with_patterns(&[]);
    let first = "AbCdEfGh12345678";
    let second = "Zyxw98765432Mnop";
    let content = format!("API_KEY={first}\nDB_PASSWORD={second}");

    let findings = scanner.scan(&content);

    assert_eq!(findings.len(), 2, "two.env assignments expected");
    assert!(findings.iter().all(|f| f.pattern_id == DOTENV_PATTERN_ID));
    for f in &findings {
        assert_no_secret_leak(f, first);
        assert_no_secret_leak(f, second);
    }
}

// ---------------------------------------------------------------------------
// Source 3: private-key headers / PEM blocks
// ---------------------------------------------------------------------------

#[test]
fn private_key_block_is_detected_under_private_key_pattern_id() {
    let scanner = Scanner::with_patterns(&[]);
    // Uppercase/digit body so no lowercase structural word collides with the
    // reason text in the leak assertion below.
    let block = "-----BEGIN RSA PRIVATE KEY-----\nMIIBVQABCDEF0123456789GHIJ\n-----END RSA PRIVATE KEY-----";

    let findings = scanner.scan(block);

    assert_eq!(findings.len(), 1, "one private-key block expected");
    assert_eq!(findings[0].pattern_id, PRIVATE_KEY_PATTERN_ID);
}

#[test]
fn private_key_block_finding_never_leaks_key_material() {
    let scanner = Scanner::with_patterns(&[]);
    let block = "-----BEGIN RSA PRIVATE KEY-----\nMIIBVQABCDEF0123456789GHIJ\n-----END RSA PRIVATE KEY-----";

    let findings = scanner.scan(&format!("noise {block} noise"));

    assert_eq!(findings.len(), 1);
    assert_no_secret_leak(&findings[0], block);
}

#[test]
fn private_key_bare_header_is_detected_without_leak() {
    let scanner = Scanner::with_patterns(&[]);
    // A bare header with no closing END line still counts as a private-key
    // header.
    let header = "-----BEGIN OPENSSH PRIVATE KEY-----";

    let findings = scanner.scan(&format!("junk {header} more"));

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].pattern_id, PRIVATE_KEY_PATTERN_ID);
    assert_no_secret_leak(&findings[0], header);
}
