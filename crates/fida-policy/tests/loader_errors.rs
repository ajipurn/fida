//! Integration tests for `fida-policy` loader error cases (spec task 3.5).
//!
//! Each loader failure surfaces as CLI exit code 4. These tests drive the
//! **public** loader API
//! (`FsPolicyLoader`, `load_source`, `resolve_source_in`, `PolicySource`,
//! `LoadError`, `ProfileError`) and assert that every distinct error variant
//! reports `exit_code() == 4`.

use std::fs;
use std::path::{Path, PathBuf};

use fida_policy::loader::{
    FsPolicyLoader, LoadError, MAX_POLICY_BYTES, PolicyLoader, PolicySource, ProfileError,
    load_source, resolve_source_in,
};

/// Write `contents` to `root/rel`, creating parent dirs, and return the path.
fn write(root: &Path, rel: &str, contents: &str) -> PathBuf {
    let path = root.join(rel);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(&path, contents).unwrap();
    path
}

/// Load a freshly written policy file as an explicit `--config` source.
fn load_file(root: &Path, rel: &str, contents: &str, profile: Option<&str>) -> LoadError {
    let path = write(root, rel, contents);
    load_source(&PolicySource::Config(path), profile).expect_err("expected a load failure")
}

// 1. Unparseable YAML reports line/column.
#[test]
fn unparseable_yaml_reports_location_with_exit_code_4() {
    let dir = tempfile::tempdir().unwrap();
    let err = load_file(dir.path(), "bad.yaml", "version: 1\n  : : bad", None);
    match &err {
        LoadError::Parse { line, path, .. } => {
            assert!(line.is_some(), "parse error should carry a 1-based line");
            assert!(
                path.is_some(),
                "file-backed parse error should carry a path"
            );
        }
        other => panic!("expected parse error, got {other:?}"),
    }
    assert_eq!(err.exit_code(), 4);
}

// 2. Oversize (>1 MB) file is rejected.
#[test]
fn oversize_file_rejected_with_exit_code_4() {
    let dir = tempfile::tempdir().unwrap();
    let mut big = String::from("version: 1\ndefault_decision: ask\n# ");
    big.push_str(&"x".repeat(MAX_POLICY_BYTES));
    let err = load_file(dir.path(), "big.yaml", &big, None);
    match &err {
        LoadError::Size { size, max, .. } => {
            assert!(size > max, "reported size must exceed the cap");
            assert_eq!(*max, MAX_POLICY_BYTES);
        }
        other => panic!("expected size error, got {other:?}"),
    }
    assert_eq!(err.exit_code(), 4);
}

// 3. Missing `--config` path is a hard error — no fallthrough to a repo file
//    that happens to exist.
#[test]
fn missing_config_no_fallthrough_with_exit_code_4() {
    let dir = tempfile::tempdir().unwrap();
    // A valid repo policy exists, but --config must NOT fall back to it.
    write(
        dir.path(),
        "fida.yaml",
        "version: 1\ndefault_decision: ask\n",
    );
    let missing = dir.path().join("nope.yaml");
    let err = resolve_source_in(dir.path(), Some(&missing)).expect_err("missing --config is fatal");
    match &err {
        LoadError::Io { path, .. } => assert_eq!(path, &missing),
        other => panic!("expected io error, got {other:?}"),
    }
    assert_eq!(err.exit_code(), 4);

    // The repo file is never consulted: it would only be reached with no --config.
    let fallback = resolve_source_in(dir.path(), None).unwrap();
    assert!(matches!(fallback, PolicySource::FidaYaml(_)));
}

// 4. Unknown profile named by `--profile`.
#[test]
fn unknown_profile_with_exit_code_4() {
    let dir = tempfile::tempdir().unwrap();
    let err = load_file(
        dir.path(),
        "p.yaml",
        "version: 1\ndefault_decision: ask\n",
        Some("ghost"),
    );
    match &err {
        LoadError::Profile(ProfileError::Unknown(name)) => assert_eq!(name, "ghost"),
        other => panic!("expected unknown-profile error, got {other:?}"),
    }
    assert_eq!(err.exit_code(), 4);
}

// 5. Undefined parent profile.
#[test]
fn undefined_parent_with_exit_code_4() {
    let dir = tempfile::tempdir().unwrap();
    let yaml = "version: 1\ndefault_decision: ask\nprofiles:\n  child:\n    parent: missing\n";
    let err = load_file(dir.path(), "p.yaml", yaml, Some("child"));
    match &err {
        LoadError::Profile(ProfileError::UndefinedParent { profile, parent }) => {
            assert_eq!(profile, "child");
            assert_eq!(parent, "missing");
        }
        other => panic!("expected undefined-parent error, got {other:?}"),
    }
    assert_eq!(err.exit_code(), 4);
}

// 6. Cyclic parent profile.
#[test]
fn cyclic_parent_with_exit_code_4() {
    let dir = tempfile::tempdir().unwrap();
    let yaml =
        "version: 1\ndefault_decision: ask\nprofiles:\n  a:\n    parent: b\n  b:\n    parent: a\n";
    let err = load_file(dir.path(), "p.yaml", yaml, Some("a"));
    match &err {
        LoadError::Profile(ProfileError::Cycle(chain)) => {
            assert!(chain.contains(&"a".to_string()) && chain.contains(&"b".to_string()));
        }
        other => panic!("expected cycle error, got {other:?}"),
    }
    assert_eq!(err.exit_code(), 4);
}

// 7a. Glob/matcher compile failure: a bad command regex.
#[test]
fn bad_command_regex_compile_failure_with_exit_code_4() {
    let dir = tempfile::tempdir().unwrap();
    let yaml = "version: 1\ndefault_decision: ask\ncommands:\n  deny:\n    - regex: \"([\"\n";
    let err = load_file(dir.path(), "p.yaml", yaml, None);
    match &err {
        LoadError::Compile { field_path, .. } => {
            assert_eq!(field_path, "commands.deny[0].regex");
        }
        other => panic!("expected compile error, got {other:?}"),
    }
    assert_eq!(err.exit_code(), 4);
}

// 7b. Glob/matcher compile failure: a malformed file glob.
#[test]
fn bad_file_glob_compile_failure_with_exit_code_4() {
    let dir = tempfile::tempdir().unwrap();
    // An unclosed character class is not a valid glob.
    let yaml =
        "version: 1\ndefault_decision: ask\nfiles:\n  write:\n    allow:\n      - \"src/[a\"\n";
    let err = load_file(dir.path(), "p.yaml", yaml, None);
    match &err {
        LoadError::Compile { field_path, .. } => {
            assert_eq!(field_path, "files.write.allow[0]");
        }
        other => panic!("expected compile error, got {other:?}"),
    }
    assert_eq!(err.exit_code(), 4);
}

// 7c. Glob/matcher compile failure: a malformed CIDR.
#[test]
fn bad_cidr_compile_failure_with_exit_code_4() {
    let dir = tempfile::tempdir().unwrap();
    let yaml = "version: 1\ndefault_decision: ask\nnetwork:\n  deny:\n    - cidr: \"not-a-cidr\"\n";
    let err = load_file(dir.path(), "p.yaml", yaml, None);
    match &err {
        LoadError::Compile { field_path, .. } => {
            assert_eq!(field_path, "network.deny[0].cidr");
        }
        other => panic!("expected compile error, got {other:?}"),
    }
    assert_eq!(err.exit_code(), 4);
}

// 8a. Unsupported version is a schema violation.
#[test]
fn unsupported_version_schema_violation_with_exit_code_4() {
    let dir = tempfile::tempdir().unwrap();
    let err = load_file(
        dir.path(),
        "p.yaml",
        "version: 2\ndefault_decision: ask\n",
        None,
    );
    match &err {
        LoadError::Schema { violations } => {
            assert!(violations.iter().any(|v| v.field_path == "version"));
        }
        other => panic!("expected schema error, got {other:?}"),
    }
    assert_eq!(err.exit_code(), 4);
}

// 8b. Invalid `default_decision` is a schema violation.
#[test]
fn invalid_default_decision_schema_violation_with_exit_code_4() {
    let dir = tempfile::tempdir().unwrap();
    let err = load_file(
        dir.path(),
        "p.yaml",
        "version: 1\ndefault_decision: dry_run\n",
        None,
    );
    match &err {
        LoadError::Schema { violations } => {
            assert!(
                violations
                    .iter()
                    .any(|v| v.field_path == "default_decision")
            );
        }
        other => panic!("expected schema error, got {other:?}"),
    }
    assert_eq!(err.exit_code(), 4);
}

// Cross-check: the public `FsPolicyLoader` reports the same exit code 4 for a
// missing `--config` path (exercises the trait surface).
#[test]
fn fs_loader_missing_config_exit_code_4() {
    let dir = tempfile::tempdir().unwrap();
    let loader = FsPolicyLoader::new(dir.path());
    let missing = dir.path().join("absent.yaml");
    let err = loader
        .resolve_source(Some(&missing))
        .expect_err("missing --config is fatal");
    assert!(matches!(err, LoadError::Io { .. }));
    assert_eq!(err.exit_code(), 4);
}
