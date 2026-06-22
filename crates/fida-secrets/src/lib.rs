//! `fida-secrets` — Secret_Scanner: detection + fixed-marker redaction
//! (spec task 6.1; design "Secret Scanner Design").
//!
//! The scanner detects secrets from three sources:
//!
//! 1. **Policy-defined named patterns** — the compiled named regexes carried by
//!    [`CompiledSecretSection`].
//! 2. **`.env` key=value contents** — the *value* side of `KEY=value`
//!    assignments (optionally `export`-prefixed, optionally quoted).
//! 3. **Private-key headers** — PEM blocks opened by
//!    `-----BEGIN ... PRIVATE KEY-----` (with or without a closing `END`).
//!
//! Two operations are exposed through the [`SecretScanner`] trait:
//!
//! * [`SecretScanner::scan`] returns a [`Finding`] per detected occurrence. A
//!   finding records only the `pattern_id` and a `reason` — never the secret
//!   value, a substring of it, or its length.
//! * [`SecretScanner::redact`] replaces every detected value with the fixed
//!   marker [`REDACTION_MARKER`] (`«redacted»`), identical regardless of the
//!   secret's content or length. On [`RedactError`] the caller
//!   suppresses the content item and writes a redaction-failure indicator
//!   instead.

use std::sync::OnceLock;

use fida_action::Finding;
use fida_policy::{CompiledSecretPattern, CompiledSecretSection};
use regex::Regex;

/// The fixed redaction marker substituted for every detected secret value.
///
/// It is a single constant independent of the secret's content or length
/// A 5-byte value and a 5000-byte value both become this exact string, so the
/// marker leaks neither value nor length.
pub const REDACTION_MARKER: &str = "«redacted»";

/// Pattern id recorded for `.env` `KEY=value` detections.
pub const DOTENV_PATTERN_ID: &str = "dotenv_value";
/// Pattern id recorded for PEM private-key detections.
pub const PRIVATE_KEY_PATTERN_ID: &str = "private_key";

/// The reason for redacting an item could not be completed and the item must be
/// suppressed from the audit store in favor of a redaction-failure indicator
///
/// The error never carries any portion of the secret — only the structural
/// cause — so it is safe to surface and log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RedactError {
    /// A detected span did not fall on UTF-8 character boundaries, so the bytes
    /// could not be safely excised. Defensive: regex matches over `&str` are
    /// always boundary-aligned, but redaction fails closed rather than risk a
    /// partial leak.
    NonCharBoundary,
    /// Post-redaction verification found that a detected secret value still
    /// survives in the output beyond its legitimate (non-secret) occurrences.
    /// Redaction is rejected so the caller can suppress the whole item.
    IncompleteRedaction,
}

impl std::fmt::Display for RedactError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RedactError::NonCharBoundary => {
                f.write_str("redaction failed: detected span is not on a character boundary")
            }
            RedactError::IncompleteRedaction => {
                f.write_str("redaction failed: detected secret value survived redaction")
            }
        }
    }
}

impl std::error::Error for RedactError {}

/// Detection + redaction contract (design "Secret_Scanner").
pub trait SecretScanner {
    /// Detects secrets in `content`, returning one [`Finding`] per occurrence
    /// in order of appearance. Findings never reveal the secret value, a
    /// substring, or its length.
    fn scan(&self, content: &str) -> Vec<Finding>;

    /// Replaces every detected value with the fixed [`REDACTION_MARKER`],
    /// independent of value/length. Fails closed with a [`RedactError`] when
    /// redaction cannot be completed safely.
    fn redact(&self, content: &str) -> Result<String, RedactError>;
}

/// A named regex with the `pattern_id` surfaced in findings.
#[derive(Debug, Clone)]
struct NamedPattern {
    pattern_id: String,
    regex: Regex,
}

/// A detected secret occurrence: a byte range plus the metadata reported in a
/// [`Finding`]. The covered bytes are the secret value and are never copied
/// into the finding.
#[derive(Debug, Clone)]
struct Span {
    start: usize,
    end: usize,
    pattern_id: String,
    reason: String,
}

/// Built-in, always-on detectors for common provider credential formats. These
/// run in addition to any policy-defined patterns, so a default install — and
/// the MCP gateway redactor, which shares this scanner — recognizes real-world
/// keys without the user authoring a single regex.
///
/// Precision over recall: every pattern is anchored (`\b`) and shaped to its
/// provider's known format to keep false positives low. The whole match is the
/// secret value, so it is detected and redacted exactly like a policy pattern.
///
/// ponytail: this catalog detects *formatted* provider tokens only. Free-form
/// assigned secrets in source (e.g. `password = "hunter2longvalue"`) are caught
/// only when they match the `.env` `KEY=value` detector or one of the shapes
/// below; the upgrade path is an entropy-scored assignment detector keyed on
/// secret-ish identifiers (`*_TOKEN`, `*_SECRET`, `*_KEY`).
fn builtin_catalog() -> &'static [NamedPattern] {
    static CATALOG: OnceLock<Vec<NamedPattern>> = OnceLock::new();
    CATALOG.get_or_init(|| {
        // (pattern_id, regex). Each compiles once. A bad regex here is a bug
        // (covered by `builtin_catalog_is_valid_and_precise`), never user input.
        const ENTRIES: &[(&str, &str)] = &[
            // AWS access key id (long-term AKIA / temporary ASIA). ponytail: the
            // 40-char secret access key has no fixed shape and is caught only via
            // the `.env`/assignment path, not here.
            ("aws_access_key_id", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
            // GitHub PAT / OAuth / server / refresh tokens: ghp_/gho_/ghu_/ghs_/ghr_ + 36.
            ("github_token", r"\bgh[pousr]_[A-Za-z0-9]{36}\b"),
            (
                "github_fine_grained_pat",
                r"\bgithub_pat_[A-Za-z0-9_]{30,}\b",
            ),
            ("google_api_key", r"\bAIza[0-9A-Za-z_\-]{35,}\b"),
            ("slack_token", r"\bxox[baprs]-[0-9A-Za-z-]{10,48}\b"),
            ("stripe_secret_key", r"\b(?:sk|rk)_live_[0-9A-Za-z]{24,}\b"),
            // OpenAI: legacy `sk-` keys are alphanumeric; project keys use a
            // base64url-like tail, so `_` and `-` must be accepted after the
            // distinctive `sk-proj-` prefix. The final alphanumeric keeps the
            // trailing word boundary meaningful.
            (
                "openai_api_key",
                r"\bsk-(?:[A-Za-z0-9]{20,}|proj-[A-Za-z0-9_-]{19,}[A-Za-z0-9])\b",
            ),
            // Anthropic: the `sk-ant-` prefix is distinctive enough to allow
            // hyphens in the tail without false positives.
            ("anthropic_api_key", r"\bsk-ant-[A-Za-z0-9-]{20,}\b"),
            // JWT: three base64url segments, header opens with `eyJ` (`{"`).
            (
                "jwt",
                r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b",
            ),
        ];
        ENTRIES
            .iter()
            .map(|(id, re)| NamedPattern {
                pattern_id: (*id).to_string(),
                regex: Regex::new(re).expect("built-in catalog regex is valid"),
            })
            .collect()
    })
}

/// The concrete Secret_Scanner.
///
/// Holds the policy-defined named patterns plus the built-in `.env` and
/// private-key detectors. Construct with [`Scanner::new`] from a compiled
/// policy secret section, or [`Scanner::with_patterns`] from a bare pattern
/// list.
#[derive(Debug, Clone)]
pub struct Scanner {
    policy_patterns: Vec<NamedPattern>,
    env_regex: Regex,
    private_key_regex: Regex,
}

impl Scanner {
    /// Builds a scanner from a compiled policy secret section, using its
    /// `patterns` as the policy-defined named detectors.
    pub fn new(section: &CompiledSecretSection) -> Self {
        Self::with_patterns(&section.patterns)
    }

    /// Builds a scanner from an explicit list of compiled named patterns. The
    /// built-in `.env` and private-key detectors are always present.
    pub fn with_patterns(patterns: &[CompiledSecretPattern]) -> Self {
        let policy_patterns = patterns
            .iter()
            .map(|p| NamedPattern {
                pattern_id: p.name.clone(),
                regex: p.regex.clone(),
            })
            .collect();

        // `.env` assignment: optional leading whitespace, optional `export`,
        // an identifier key, `=`, then a non-empty value (capture group 1).
        // Multiline so each line is matched independently; the value is the
        // detected secret, the key is preserved.
        let env_regex = Regex::new(
            r"(?m)^[ \t]*(?:export[ \t]+)?[A-Za-z_][A-Za-z0-9_]*[ \t]*=[ \t]*(\S.*?)[ \t]*$",
        )
        .expect("static .env regex is valid");

        // PEM private-key block. The closing `END` line is optional so a bare
        // header still matches; when present,
        // the whole block — the key material — is captured.
        let private_key_regex = Regex::new(
            r"(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----(?:.*?-----END [A-Z0-9 ]*PRIVATE KEY-----)?",
        )
        .expect("static private-key regex is valid");

        Scanner {
            policy_patterns,
            env_regex,
            private_key_regex,
        }
    }

    /// Collects every detected span across all sources, ordered by start
    /// offset. Spans may overlap; redaction merges them before replacing.
    ///
    /// `include_env_heuristic` toggles the broad `.env` `KEY=value` detector
    /// (Source 2). It is correct for `.env`-style files and for redaction (max
    /// recall), but matches any `key = value` line, so [`Scanner::scan_code`]
    /// disables it when scanning arbitrary source.
    fn detect_spans(&self, content: &str, include_env_heuristic: bool) -> Vec<Span> {
        let mut spans = Vec::new();

        // Source 1: policy-defined named patterns. The whole match is the value.
        for pat in &self.policy_patterns {
            for m in pat.regex.find_iter(content) {
                // Skip empty matches: a zero-width match is not a secret value
                // and would otherwise produce noise.
                if m.start() == m.end() {
                    continue;
                }
                spans.push(Span {
                    start: m.start(),
                    end: m.end(),
                    pattern_id: pat.pattern_id.clone(),
                    reason: format!("matched policy secret pattern '{}'", pat.pattern_id),
                });
            }
        }

        // Source 1b: built-in provider catalog (always on). The whole match is
        // the secret value, exactly like a policy pattern.
        for pat in builtin_catalog() {
            for m in pat.regex.find_iter(content) {
                if m.start() == m.end() {
                    continue;
                }
                spans.push(Span {
                    start: m.start(),
                    end: m.end(),
                    pattern_id: pat.pattern_id.clone(),
                    reason: format!("matched built-in secret pattern '{}'", pat.pattern_id),
                });
            }
        }

        // Source 2: `.env` key=value contents. Only the value (group 1) is the
        // secret; the key stays intact. Skipped for source-code scans, where a
        // bare `KEY=value` heuristic would flag ordinary assignments.
        if include_env_heuristic {
            for caps in self.env_regex.captures_iter(content) {
                if let Some(value) = caps.get(1) {
                    if value.start() == value.end() {
                        continue;
                    }
                    // The `KEY=value` shape is blind to whether the value is a
                    // credential, so an ordinary code assignment like
                    // `last_name = "Doe"` matches too. Gate on the value being
                    // substantial/token-shaped to drop those false positives;
                    // real `.env` secrets (and the redteam planted values) stay
                    // flagged. See `is_secretish_env_value`.
                    if !is_secretish_env_value(value.as_str()) {
                        continue;
                    }
                    spans.push(Span {
                        start: value.start(),
                        end: value.end(),
                        pattern_id: DOTENV_PATTERN_ID.to_string(),
                        reason: "matched .env key=value assignment".to_string(),
                    });
                }
            }
        }

        // Source 3: private-key headers/blocks. The whole block is the secret.
        for m in self.private_key_regex.find_iter(content) {
            if m.start() == m.end() {
                continue;
            }
            spans.push(Span {
                start: m.start(),
                end: m.end(),
                pattern_id: PRIVATE_KEY_PATTERN_ID.to_string(),
                reason: "matched PEM private key block".to_string(),
            });
        }

        spans.sort_by(|a, b| a.start.cmp(&b.start).then(a.end.cmp(&b.end)));
        spans
    }

    /// Scans source code for embedded secrets, returning one [`Finding`] per
    /// occurrence. Unlike [`SecretScanner::scan`], this excludes the broad
    /// `.env` `KEY=value` heuristic so ordinary assignments (`version = "1.0"`,
    /// `const port = 8080`) are not flagged. Policy patterns, the built-in
    /// provider catalog, and PEM private-key blocks still apply — so a
    /// hardcoded `sk_live_…`, `ghp_…`, etc. is detected. Findings never reveal
    /// the secret value, a substring, or its length.
    pub fn scan_code(&self, content: &str) -> Vec<Finding> {
        self.detect_spans(content, false)
            .into_iter()
            .map(|s| Finding {
                pattern_id: s.pattern_id,
                reason: s.reason,
            })
            .collect()
    }
}

/// Whether an `.env` `KEY=value` *value* is substantial enough to treat as a
/// secret. The `KEY=value` heuristic is shape-blind, so without this gate it
/// flags ordinary code assignments (`last_name = "Doe"`, `port = 8080`,
/// `version = "1.2.3"`). A value qualifies when it is long (>= `LONG` bytes) or
/// medium-length with at least two character classes (lower/upper/digit) — the
/// shape of a token, not a word, number, or version string. Quotes and
/// punctuation don't count as a class, so `"Doe"`, `"1.2.3"`, and `8080` are
/// skipped while `abc123`, `super-secret-value`, and 32-char keys are kept.
///
/// Erring toward over-detection keeps leak-prevention-first: any uncertainty at
/// or above the length floor stays flagged.
fn is_secretish_env_value(value: &str) -> bool {
    const LONG: usize = 12;
    const MED: usize = 6;
    let len = value.len();
    if len >= LONG {
        return true;
    }
    if len < MED {
        return false;
    }
    let (mut lower, mut upper, mut digit) = (false, false, false);
    for b in value.bytes() {
        match b {
            b'a'..=b'z' => lower = true,
            b'A'..=b'Z' => upper = true,
            b'0'..=b'9' => digit = true,
            _ => {}
        }
    }
    u8::from(lower) + u8::from(upper) + u8::from(digit) >= 2
}

/// Merges overlapping/touching byte ranges so each region of secret material is
/// replaced exactly once, leaving no partial-overlap remnant.
fn merge_ranges(spans: &[Span]) -> Vec<(usize, usize)> {
    let mut merged: Vec<(usize, usize)> = Vec::new();
    for s in spans {
        match merged.last_mut() {
            Some(last) if s.start <= last.1 => {
                if s.end > last.1 {
                    last.1 = s.end;
                }
            }
            _ => merged.push((s.start, s.end)),
        }
    }
    merged
}

impl SecretScanner for Scanner {
    fn scan(&self, content: &str) -> Vec<Finding> {
        self.detect_spans(content, true)
            .into_iter()
            .map(|s| Finding {
                pattern_id: s.pattern_id,
                reason: s.reason,
            })
            .collect()
    }

    fn redact(&self, content: &str) -> Result<String, RedactError> {
        let spans = self.detect_spans(content, true);
        if spans.is_empty() {
            return Ok(content.to_string());
        }

        let ranges = merge_ranges(&spans);

        // Build the redacted output, replacing each merged range with the fixed
        // marker. Verify every range is char-boundary aligned first; fail
        // closed rather than risk a partial leak.
        let mut out = String::with_capacity(content.len());
        let mut cursor = 0usize;
        for &(start, end) in &ranges {
            if !content.is_char_boundary(start) || !content.is_char_boundary(end) {
                return Err(RedactError::NonCharBoundary);
            }
            out.push_str(&content[cursor..start]);
            out.push_str(REDACTION_MARKER);
            cursor = end;
        }
        out.push_str(&content[cursor..]);

        verify_no_leak(content, &ranges, &out)?;
        Ok(out)
    }
}

/// Verifies that no detected secret value survives in `out` beyond its
/// legitimate (non-secret) occurrences in `content`. Fails closed
/// ([`RedactError::IncompleteRedaction`]) if a secret leaked.
fn verify_no_leak(content: &str, ranges: &[(usize, usize)], out: &str) -> Result<(), RedactError> {
    for &(start, end) in ranges {
        let secret = &content[start..end];
        if secret.is_empty() {
            continue;
        }
        // How many times does this exact value legitimately appear outside any
        // redacted range? Those occurrences are allowed to remain.
        let legitimate = count_outside(content, ranges, secret);
        let surviving = out.matches(secret).count();
        if surviving > legitimate {
            return Err(RedactError::IncompleteRedaction);
        }
    }
    Ok(())
}

/// Counts non-overlapping occurrences of `needle` in `content` that lie wholly
/// outside every redacted range.
fn count_outside(content: &str, ranges: &[(usize, usize)], needle: &str) -> usize {
    if needle.is_empty() {
        return 0;
    }
    let mut count = 0;
    let mut from = 0usize;
    while let Some(rel) = content[from..].find(needle) {
        let abs = from + rel;
        let occ_end = abs + needle.len();
        let overlaps = ranges.iter().any(|&(s, e)| abs < e && occ_end > s);
        if !overlaps {
            count += 1;
        }
        from = abs + needle.len();
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;
    use fida_policy::CompiledSecretPattern;

    fn pattern(name: &str, re: &str) -> CompiledSecretPattern {
        CompiledSecretPattern {
            name: name.to_string(),
            regex: Regex::new(re).unwrap(),
        }
    }

    fn scanner_with(patterns: Vec<CompiledSecretPattern>) -> Scanner {
        Scanner::with_patterns(&patterns)
    }

    #[test]
    fn scan_detects_policy_pattern() {
        // Synthetic, non-catalog shape so this exercises a *policy* pattern
        // without the built-in catalog also matching.
        let s = scanner_with(vec![pattern("acme_key", r"ACME[0-9A-Z]{16}")]);
        let findings = s.scan("token ACME0123456789ABCDEF end");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].pattern_id, "acme_key");
        assert!(!findings[0].reason.is_empty());
    }

    #[test]
    fn finding_never_contains_value_or_length() {
        let secret = "ACME0123456789ABCDEF";
        let s = scanner_with(vec![pattern("acme_key", r"ACME[0-9A-Z]{16}")]);
        let findings = s.scan(&format!("x {secret} y"));
        let f = &findings[0];
        assert!(!f.pattern_id.contains(secret));
        assert!(!f.reason.contains(secret));
        // No substring of the secret of length >= 4 leaks into the finding.
        for win in secret.as_bytes().windows(4) {
            let frag = std::str::from_utf8(win).unwrap();
            assert!(!f.reason.contains(frag), "reason leaked fragment {frag}");
        }
        // The length must not be revealed numerically.
        assert!(!f.reason.contains(&secret.len().to_string()));
    }

    #[test]
    fn scan_code_detects_hardcoded_provider_key_but_not_plain_assignments() {
        let s = scanner_with(vec![]);
        // A hardcoded Stripe key in source must be detected by the catalog.
        let secret = ["sk", "_live_", "1234567890abcdefghijklmnopqrstuv"].concat();
        let src = format!(r#"const key = "{secret}";"#);
        let findings = s.scan_code(&src);
        assert!(
            findings.iter().any(|f| f.pattern_id == "stripe_secret_key"),
            "hardcoded provider key should be detected in source"
        );

        // Ordinary `key = value` lines must NOT be flagged (no env heuristic).
        for benign in [
            "version = \"1.2.3\"",
            "const port = 8080",
            "name = \"fida-secrets\"",
            "export const TIMEOUT = 30",
        ] {
            assert!(
                s.scan_code(benign).is_empty(),
                "scan_code false-positived on benign assignment: {benign}"
            );
        }

        // The full scan() (env heuristic on) still flags a real .env-style
        // secret line that scan_code() suppresses, proving the narrowing.
        let env_line = "API_KEY=abcdef0123456789ABCDEF";
        assert!(!s.scan(env_line).is_empty());
        assert!(s.scan_code(env_line).is_empty());
    }

    #[test]
    fn scan_code_redacts_openai_project_key_with_base64url_tail() {
        let s = scanner_with(vec![]);
        let secret = [
            "sk",
            "-proj-",
            "0123456789abcdefghijklmnopqrstuv",
            "_",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcd",
            "-",
            "efghijklmnopqrstuvwxyz012345",
        ]
        .concat();
        let src = format!(r#"export const firstName = "{secret}";"#);

        let findings = s.scan_code(&src);
        assert!(
            findings.iter().any(|f| f.pattern_id == "openai_api_key"),
            "OpenAI project key should be detected in source"
        );
        let redacted = s.redact(&src).unwrap();
        assert!(!redacted.contains(&secret));
        assert!(redacted.contains(REDACTION_MARKER));
    }

    #[test]
    fn redact_replaces_with_fixed_marker() {
        let s = scanner_with(vec![pattern("acme_key", r"ACME[0-9A-Z]{16}")]);
        let out = s.redact("token ACME0123456789ABCDEF end").unwrap();
        assert_eq!(out, format!("token {REDACTION_MARKER} end"));
        assert!(!out.contains("ACME0123456789ABCDEF"));
    }

    #[test]
    fn deprecated_redact_false_cannot_disable_model_bound_redaction() {
        let section = fida_policy::CompiledSecretSection {
            redact: false,
            block_in_diffs: false,
            patterns: Vec::new(),
        };
        let scanner = Scanner::new(&section);
        let secret = "synthetic-secret-value-0123456789";
        let output = scanner
            .redact(&format!("API_KEY={secret}\n"))
            .expect("redaction remains mandatory");
        assert!(!output.contains(secret));
        assert!(output.contains(REDACTION_MARKER));
    }

    #[test]
    fn marker_is_independent_of_value_and_length() {
        let s = scanner_with(vec![pattern("k", r"SECRET[0-9A-Z]*")]);
        let short = s.redact("a SECRET1 b").unwrap();
        let long = s.redact("a SECRET0123456789ABCDEFGHIJ b").unwrap();
        assert_eq!(short, format!("a {REDACTION_MARKER} b"));
        assert_eq!(long, format!("a {REDACTION_MARKER} b"));
        assert_eq!(short, long);
    }

    #[test]
    fn detects_and_redacts_env_value_keeping_key() {
        let s = scanner_with(vec![]);
        let content = "API_KEY=super-secret-value\nPORT=8080-not-secret";
        let findings = s.scan(content);
        // Both lines are key=value assignments → both detected.
        assert_eq!(findings.len(), 2);
        assert!(findings.iter().all(|f| f.pattern_id == DOTENV_PATTERN_ID));
        let out = s.redact(content).unwrap();
        assert!(out.starts_with("API_KEY="));
        assert!(out.contains(&format!("API_KEY={REDACTION_MARKER}")));
        assert!(!out.contains("super-secret-value"));
    }

    #[test]
    fn detects_export_prefixed_env_value() {
        let s = scanner_with(vec![]);
        let out = s.redact("export TOKEN=abc123").unwrap();
        assert_eq!(out, format!("export TOKEN={REDACTION_MARKER}"));
    }

    #[test]
    fn env_heuristic_skips_trivial_values_but_keeps_token_shaped_ones() {
        let s = scanner_with(vec![]);
        // Ordinary code assignments with short / single-class values must NOT
        // trip the shape-blind KEY=value heuristic (the `last_name = "Doe"`
        // false positive from the report).
        for benign in ["last_name = \"Doe\"", "version = \"1.2.3\"", "port = 8080"] {
            assert!(s.scan(benign).is_empty(), "false positive on: {benign}");
        }
        // Substantial / token-shaped values stay flagged (leak-prevention-first):
        // short-but-multi-class, long single-class, and a 32-char key.
        for secret in [
            "export TOKEN=abc123",
            "API_KEY=super-secret-value",
            "PASSWORD=abcdefghijklmnopqrstuvwxyz012345",
        ] {
            assert!(!s.scan(secret).is_empty(), "missed secret in: {secret}");
        }
    }

    #[test]
    fn detects_private_key_block() {
        let s = scanner_with(vec![]);
        let content =
            "-----BEGIN RSA PRIVATE KEY-----\nMIIBxxxxxxxx\n-----END RSA PRIVATE KEY-----";
        let findings = s.scan(content);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].pattern_id, PRIVATE_KEY_PATTERN_ID);
        let out = s.redact(content).unwrap();
        assert_eq!(out, REDACTION_MARKER);
        assert!(!out.contains("MIIBxxxxxxxx"));
    }

    #[test]
    fn detects_bare_private_key_header() {
        let s = scanner_with(vec![]);
        let content = "junk -----BEGIN OPENSSH PRIVATE KEY----- more";
        let findings = s.scan(content);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].pattern_id, PRIVATE_KEY_PATTERN_ID);
        let out = s.redact(content).unwrap();
        assert_eq!(out, format!("junk {REDACTION_MARKER} more"));
    }

    #[test]
    fn clean_content_is_unchanged_and_has_no_findings() {
        let s = scanner_with(vec![pattern("k", r"AKIA[0-9A-Z]{16}")]);
        let content = "just a normal line of text";
        assert!(s.scan(content).is_empty());
        assert_eq!(s.redact(content).unwrap(), content);
    }

    #[test]
    fn overlapping_detections_redact_once_without_remnant() {
        // A private-key block whose body also looks like an env assignment.
        let s = scanner_with(vec![pattern("whole", r"BEGIN[\s\S]*END")]);
        let content = "-----BEGIN RSA PRIVATE KEY-----\nKEY=abc\n-----END RSA PRIVATE KEY-----";
        let out = s.redact(content).unwrap();
        // Whole region collapses to a single marker; no leftover key material.
        assert!(!out.contains("KEY=abc"));
        assert!(!out.contains("BEGIN"));
        assert!(out.contains(REDACTION_MARKER));
    }

    #[test]
    fn multiple_findings_reported_in_order() {
        let s = scanner_with(vec![pattern("acme_key", r"ACME[0-9A-Z]{16}")]);
        let content = "ACME0000000000000000 then ACME1111111111111111";
        let findings = s.scan(content);
        assert_eq!(findings.len(), 2);
        let out = s.redact(content).unwrap();
        assert_eq!(out, format!("{REDACTION_MARKER} then {REDACTION_MARKER}"));
    }

    /// Leave-behind check for the built-in catalog (Phase 1.1): every shipped
    /// pattern must detect a canonical positive, redact it to the fixed marker
    /// with the value gone, and reject a near-miss it should not claim.
    #[test]
    fn builtin_catalog_detects_providers_rejects_near_misses_and_redacts() {
        // (expected pattern_id, positive sample, near-miss that must NOT match it)
        let cases: &[(&str, &str, &str)] = &[
            ("aws_access_key_id", "AKIA0123456789ABCDEF", "AKIA0123"),
            (
                "github_token",
                "ghp_0123456789abcdefghijABCDEFGHIJklmnop",
                "ghp_tooshort",
            ),
            (
                "github_fine_grained_pat",
                "github_pat_0123456789abcdefghijABCDEFGHIJ",
                "github_pat_short",
            ),
            (
                "google_api_key",
                "AIzaSyA0123456789abcdefghijklmnopqrstuv0",
                "AIzaShort",
            ),
            ("slack_token", "xoxb-012345678901", "xoxb-1"),
            (
                "stripe_secret_key",
                concat!("sk", "_live_", "0123456789abcdefABCDEFGH"),
                "sk_live_short",
            ),
            ("openai_api_key", "sk-0123456789abcdefABCDEFGH", "sk-short"),
            (
                "anthropic_api_key",
                "sk-ant-0123456789abcdef-ABCDEFGH",
                "sk-ant-x",
            ),
            (
                "jwt",
                "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.dozjgNryP4J3jVmNHl0w5N",
                "eyJonly",
            ),
        ];
        // No policy patterns: detections here come solely from the built-in catalog.
        let s = scanner_with(vec![]);
        for (id, positive, near_miss) in cases {
            let content = format!("lead {positive} trail");
            let findings = s.scan(&content);
            assert!(
                findings.iter().any(|f| &f.pattern_id == id),
                "catalog pattern {id} failed to detect its positive sample"
            );
            let redacted = s.redact(&content).unwrap();
            assert!(
                !redacted.contains(positive),
                "catalog pattern {id} left its secret in the redacted output"
            );
            assert!(redacted.contains(REDACTION_MARKER));
            assert!(
                !s.scan(near_miss).iter().any(|f| &f.pattern_id == id),
                "catalog pattern {id} matched a near-miss it should reject"
            );
        }
    }
}
