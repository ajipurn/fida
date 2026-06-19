//! Built-in policy presets shared by `fida init --policy` (task 19.2) and
//! `fida policy list-presets`.
//!
//! Each preset is a complete version-1 policy document that passes
//! [`fida_policy::validate_raw`]. The `starter` preset
//! mirrors the loader's built-in default so `init` with no options writes the
//! same balanced baseline Fida falls back to when no policy exists. `relaxed`
//! is the loosest (allow common commands, deny only the dangerous); `careful`,
//! `oss-maintainer`, and `ci-readonly` are progressively stricter variants.
//! `strict-firewall` restores path-based blocking for sensitive reads.

/// The supported preset names, in display order.
///
/// `init` validates `--preset` against this list and `list-presets` prints it.
pub const PRESET_NAMES: &[&str] = &[
    "secret-safe",
    "starter",
    "relaxed",
    "careful",
    "oss-maintainer",
    "ci-readonly",
    "strict-firewall",
];

/// Return the YAML contents for the named preset, or `None` if `name` does not
/// exactly match a supported preset.
pub fn preset_contents(name: &str) -> Option<&'static str> {
    match name {
        "secret-safe" => Some(SECRET_SAFE),
        "starter" => Some(STARTER),
        "relaxed" => Some(RELAXED),
        "careful" => Some(CAREFUL),
        "oss-maintainer" => Some(OSS_MAINTAINER),
        "ci-readonly" => Some(CI_READONLY),
        "strict-firewall" => Some(STRICT_FIREWALL),
        _ => None,
    }
}

/// `starter` — the conservative baseline. Mirrors the loader's built-in default
/// policy so `fida init --policy` writes exactly what Fida would use implicitly.
pub const STARTER: &str = fida_policy::BUILTIN_DEFAULT_POLICY;

/// `secret-safe` — the product default. It intentionally reuses the built-in
/// redaction-first policy: broad reads remain useful, while model-bound content
/// is always passed through Fida's fail-closed secret redactor.
pub const SECRET_SAFE: &str = fida_policy::BUILTIN_DEFAULT_POLICY;

/// `relaxed` — lowest friction: run anything that is not explicitly dangerous,
/// with no prompt. The deny list still hard-stops destructive/trust-breaking
/// commands (deny is evaluated before allow). File writes, network egress, and
/// sensitive writes stay gated, so "relaxed" means relaxed *commands*, not a
/// free-for-all. Reads still pass through Fida's redaction path. Good for a
/// trusted local repo where the curated `starter` allow list still nags.
pub const RELAXED: &str = r#"version: 1
default_decision: ask

commands:
  deny:
    - regex: "rm\\s+-rf\\s+(/|~|\\.)"
      reason: destructive recursive delete of root, home, or cwd
    - binary: sudo
      reason: privilege escalation runs outside the policy trust boundary
    - binary: shutdown
      reason: host power control
    - binary: reboot
      reason: host power control
    - binary: mkfs
      reason: formatting a filesystem destroys data
    - binary: dd
      reason: raw block writes can destroy data
    - regex: "\\bgit\\s+push\\b.*--force"
      reason: force-push can clobber published history
    - regex: "curl\\s+.*\\|\\s*(sh|bash)"
      reason: piping a remote script straight into a shell is unsafe
    - regex: "wget\\s+.*\\|\\s*(sh|bash)"
      reason: piping a remote script straight into a shell is unsafe
    - regex: "chmod\\s+.*777"
      reason: world-writable permissions
  allow:
    - regex: ".*"

files:
  read:
    allow:
      - "**/*"
  write:
    allow:
      - src/**
      - tests/**
      - docs/**
      - README.md
    deny:
      - .env
      - .env.*
      - "**/*.pem"
      - "**/*.key"

network:
  ask:
    - domain: "*"
      reason: arbitrary network access can transmit code or local data
  deny:
    - host: 169.254.169.254
      reason: cloud metadata service

secrets:
  redact: true
  block_in_diffs: true

audit:
  path: .fida/sessions
  format: jsonl
"#;

/// `careful` — gate writes and test commands behind approval, deny all network.
pub const CAREFUL: &str = r#"version: 1
default_decision: ask

commands:
  allow:
    - exact: git status
    - exact: git diff
  ask:
    - prefix: cargo test
    - prefix: npm test
    - prefix: pnpm test
  deny:
    - regex: "rm\\s+-rf\\s+(/|~|\\.)"
      reason: destructive remove command

files:
  read:
    allow:
      - "**/*"
  write:
    ask:
      - src/**
      - tests/**
      - docs/**
    deny:
      - .env
      - .env.*
      - "**/*.pem"
      - "**/*.key"

network:
  deny:
    - domain: "*"
      reason: network access is disabled in the careful preset

secrets:
  redact: true
  block_in_diffs: true

audit:
  path: .fida/sessions
  format: jsonl
"#;

/// `oss-maintainer` — allow common build/test, ask before touching project
/// metadata and CI config, gate pushes and arbitrary network access.
pub const OSS_MAINTAINER: &str = r#"version: 1
default_decision: ask

commands:
  allow:
    - exact: git status
    - exact: git diff
    - prefix: git log
    - prefix: cargo build
    - prefix: cargo test
    - prefix: npm test
    - prefix: npm run build
  deny:
    - regex: "rm\\s+-rf\\s+(/|~|\\.)"
      reason: destructive remove command
    - prefix: git push
      reason: publishing is a maintainer-gated action

files:
  read:
    allow:
      - "**/*"
  write:
    allow:
      - src/**
      - tests/**
      - docs/**
      - examples/**
      - README.md
    ask:
      - .github/**
      - Cargo.toml
      - package.json
    deny:
      - .env
      - .env.*
      - "**/*.pem"
      - "**/*.key"

network:
  ask:
    - domain: "*"
      reason: arbitrary network access can transmit code or local data

secrets:
  redact: true
  block_in_diffs: true

audit:
  path: .fida/sessions
  format: jsonl
"#;

/// `ci-readonly` — deny by default, permit only read-only inspection and
/// build/test commands, forbid all writes and network access.
pub const CI_READONLY: &str = r#"version: 1
default_decision: deny

commands:
  allow:
    - exact: git status
    - exact: git diff
    - prefix: cargo build
    - prefix: cargo test
    - prefix: npm test
  deny:
    - regex: "rm\\s+-rf\\s+(/|~|\\.)"
      reason: destructive remove command

files:
  read:
    allow:
      - "**/*"
  write:
    deny:
      - "**/*"

network:
  deny:
    - domain: "*"
      reason: no network access in the CI read-only preset

secrets:
  redact: true
  block_in_diffs: true

audit:
  path: .fida/sessions
  format: jsonl
"#;

/// `strict-firewall` — opt-in path lockdown for users who prefer sensitive
/// reads to be denied instead of returned as a redacted safe view.
pub const STRICT_FIREWALL: &str = r#"version: 1
default_decision: ask

commands:
  allow:
    - binary: ls
    - binary: pwd
    - binary: echo
    - binary: cat
    - binary: head
    - binary: tail
    - binary: rg
    - prefix: git status
    - prefix: git diff
    - prefix: cargo build
    - prefix: cargo check
    - prefix: cargo test
    - prefix: npm test
    - prefix: npm run
  deny:
    - regex: "rm\\s+-rf\\s+(/|~|\\.)"
      reason: destructive recursive delete of root, home, or cwd
    - regex: "curl\\s+.*\\|\\s*(sh|bash)"
      reason: piping a remote script straight into a shell is unsafe
    - regex: "wget\\s+.*\\|\\s*(sh|bash)"
      reason: piping a remote script straight into a shell is unsafe

files:
  read:
    allow:
      - "**/*"
    deny:
      - .env
      - .env.*
      - "**/*.pem"
      - "**/*.key"
      - "**/id_rsa"
      - "**/id_ed25519"
  write:
    allow:
      - src/**
      - tests/**
      - docs/**
      - README.md
    deny:
      - .env
      - .env.*
      - "**/*.pem"
      - "**/*.key"
      - "**/id_rsa"
      - "**/id_ed25519"

network:
  ask:
    - domain: "*"
      reason: arbitrary network access can transmit code or local data
  deny:
    - host: 169.254.169.254
      reason: cloud metadata service

secrets:
  redact: true
  block_in_diffs: true

audit:
  path: .fida/sessions
  format: jsonl
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use fida_action::{Action, ActionKind, ActionPayload, Actor, Decision};
    use fida_policy::{PolicySource, evaluate, load_source, validate_raw};

    #[test]
    fn every_builtin_preset_is_valid() {
        for name in PRESET_NAMES {
            let raw = preset_contents(name).expect("listed preset exists");
            assert!(validate_raw(raw).is_ok(), "preset {name} must validate");
        }
    }

    #[test]
    fn strict_firewall_denies_sensitive_read_paths() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("strict.yaml");
        std::fs::write(&path, STRICT_FIREWALL).unwrap();
        let policy =
            load_source(&PolicySource::Config(path), None).expect("strict preset compiles");
        let action = Action {
            kind: ActionKind::FileRead,
            actor: Actor::Agent,
            payload: ActionPayload::File {
                path: ".env".into(),
            },
        };

        assert_eq!(evaluate(&policy, &action).decision, Decision::Deny);
    }
}
