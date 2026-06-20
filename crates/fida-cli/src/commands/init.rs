//! `fida init` — initialize Fida for agents, or scaffold a starter policy.
//!
//! By default this is the interactive agent setup flow (the modern spelling for
//! the legacy `fida install` command). Policy scaffolding remains available via
//! `--policy` or any policy-specific flag (`--preset`, `--path`, `--force`).
//!
//! The policy path implements `--preset`/`--path`/`--force`, parent-dir creation,
//! write-failure cleanup (no partial file at the target), the
//! created-path/preset/next-steps report, and self-validation of the generated
//! file.

use std::path::{Path, PathBuf};

use clap::Args;

use crate::commands::install;
use crate::commands::presets;
use crate::context::GlobalContext;
use crate::error::{CliError, CliResult};

/// Default policy location when `--path` is not supplied.
const DEFAULT_POLICY_PATH: &str = ".fida/policy.yaml";

/// The preset used when `--preset` is omitted.
const DEFAULT_PRESET: &str = "secret-safe";

/// Arguments for `fida init`.
///
/// With no policy-specific flags, `fida init` wires agent integrations. Supplying
/// `--policy` or one of the policy scaffold flags routes to the original policy
/// creation behavior.
#[derive(Debug, Args)]
pub struct InitArgs {
    #[command(flatten)]
    pub install: install::InstallArgs,

    /// Create a starter policy file instead of wiring agent integrations.
    #[arg(long, hide = true)]
    pub policy: bool,

    #[command(flatten)]
    pub policy_args: PolicyInitArgs,
}

#[derive(Debug, Args)]
pub struct PolicyInitArgs {
    /// Preset to scaffold. Defaults to `secret-safe`; policy-oriented presets
    /// remain available for advanced use.
    #[arg(long, hide = true)]
    pub preset: Option<String>,

    /// Output path for the generated policy file.
    #[arg(long, hide = true)]
    pub path: Option<std::path::PathBuf>,

    /// Overwrite an existing policy file.
    #[arg(long, hide = true)]
    pub force: bool,
}

/// The policy path used when `--path` is not supplied. Exposed so `onboard`
/// can scaffold the same default location.
pub fn default_policy_path() -> PathBuf {
    PathBuf::from(DEFAULT_POLICY_PATH)
}

/// Initialize Fida. Agent setup is the default; policy scaffolding is opt-in.
pub async fn run(args: &InitArgs, ctx: &GlobalContext) -> CliResult {
    if args.wants_policy_scaffold() {
        if args.has_install_flags() {
            return Err(CliError::usage(
                "`fida init` agent flags cannot be combined with policy scaffold flags",
            ));
        }
        return run_policy(&args.policy_args, ctx).await;
    }

    install::run(&args.install, ctx).await
}

impl InitArgs {
    fn wants_policy_scaffold(&self) -> bool {
        self.policy
            || self.policy_args.preset.is_some()
            || self.policy_args.path.is_some()
            || self.policy_args.force
    }

    fn has_install_flags(&self) -> bool {
        self.install.workspace.is_some()
            || self.install.project
            || !self.install.agents.is_empty()
            || self.install.all
            || self.install.yes
            || self.install.uninstall
    }
}

/// Create a starter policy file from a preset.
pub async fn run_policy(args: &PolicyInitArgs, ctx: &GlobalContext) -> CliResult {
    // Resolve the preset name (default `starter`). An unknown name must create
    // nothing and list the supported names.
    let preset_name = args.preset.as_deref().unwrap_or(DEFAULT_PRESET);
    let target = args.path.clone().unwrap_or_else(default_policy_path);

    scaffold_policy(preset_name, &target, args.force)?;

    report_success(ctx, &target, preset_name);
    Ok(())
}

/// Write the `preset_name` policy to `target`, validating before and after the
/// write. Reusable by `fida init --policy` and `fida onboard`.
///
/// Errors when the preset name is unknown, when `target` exists and `force` is
/// false, or when the write/validation fails. On a validation failure after
/// writing, the partial file is removed.
pub fn scaffold_policy(preset_name: &str, target: &Path, force: bool) -> CliResult {
    let contents = presets::preset_contents(preset_name).ok_or_else(|| {
        CliError::usage(format!(
            "unknown preset `{preset_name}`; supported presets are: {}",
            presets::PRESET_NAMES.join(", ")
        ))
    })?;

    // The generated content must pass schema validation.
    // Validate before writing so a malformed preset never lands on disk.
    self_validate(preset_name, contents)?;

    // Existing file without `force`: leave it unchanged and exit 1.
    if target.exists() && !force {
        return Err(CliError::general(format!(
            "a policy file already exists at {}; pass --force to overwrite it",
            target.display()
        )));
    }

    // Create any missing parent directories.
    if let Some(parent) = target.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| {
                CliError::general(format!(
                    "failed to create parent directories for {}: {e}",
                    target.display()
                ))
            })?;
        }
    }

    // Write atomically (temp file + rename) so a write failure never leaves a
    // partial file at the target.
    write_atomic(target, contents).map_err(|e| {
        CliError::general(format!(
            "failed to write policy file to {}: {e}",
            target.display()
        ))
    })?;

    // Self-validate the bytes actually on disk. If the file
    // somehow does not validate, remove it so no invalid policy is left behind.
    if let Err(err) = validate_on_disk(preset_name, target) {
        let _ = std::fs::remove_file(target);
        return Err(err);
    }

    Ok(())
}

/// Validate generated preset contents, mapping any failure to a general error.
/// A built-in preset failing validation is an internal invariant violation.
fn self_validate(preset_name: &str, contents: &str) -> CliResult {
    fida_policy::validate_raw(contents).map_err(|violations| {
        let detail = violations
            .iter()
            .map(|v| v.to_string())
            .collect::<Vec<_>>()
            .join("; ");
        CliError::general(format!(
            "internal error: the `{preset_name}` preset failed schema validation: {detail}"
        ))
    })
}

/// Read the file back from disk and re-run schema validation.
fn validate_on_disk(preset_name: &str, target: &Path) -> CliResult {
    let written = std::fs::read_to_string(target).map_err(|e| {
        CliError::general(format!(
            "failed to read back generated policy at {} for validation: {e}",
            target.display()
        ))
    })?;
    self_validate(preset_name, &written)
}

/// Write `contents` to `target` atomically: write a sibling temp file, fsync it,
/// then rename it over the target. On any failure the temp file is removed so no
/// partial file is left at the target.
fn write_atomic(target: &Path, contents: &str) -> std::io::Result<()> {
    let tmp = temp_path(target);

    if let Err(e) = std::fs::write(&tmp, contents) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }

    if let Err(e) = std::fs::rename(&tmp, target) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }

    Ok(())
}

/// Build a unique sibling temp path next to `target` (same directory so the
/// final rename stays on one filesystem and is therefore atomic).
fn temp_path(target: &Path) -> PathBuf {
    let file_name = target
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "policy.yaml".to_string());
    let unique = std::process::id();
    let tmp_name = format!(".{file_name}.fida-tmp.{unique}");
    match target.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.join(tmp_name),
        _ => PathBuf::from(tmp_name),
    }
}

/// Report the created path, preset name, and suggested next commands
/// Honors `--json` for a machine-readable result.
fn report_success(ctx: &GlobalContext, target: &Path, preset_name: &str) {
    if ctx.json {
        // Minimal hand-rolled JSON keeps the CLI free of a serde dependency
        // here; the strings below contain no characters needing escaping.
        println!(
            "{{\"created\":\"{}\",\"preset\":\"{}\",\"next_commands\":[\"fida policy check\",\"fida init\",\"fida status\",\"fida run -- <agent>\"]}}",
            target.display(),
            preset_name
        );
        return;
    }

    if ctx.is_quiet() {
        return;
    }

    println!("Created {} ({preset_name} preset).", target.display());
    println!();
    println!("Next steps:");
    println!("  fida policy check       # validate the policy");
    println!("  fida init               # wire agent integrations");
    println!("  fida status             # inspect effective setup");
    println!("  fida run -- <agent>     # run an agent under Fida");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::Verbosity;
    use std::fs;
    use tempfile::tempdir;

    fn ctx() -> GlobalContext {
        GlobalContext {
            json: false,
            no_color: false,
            verbosity: Verbosity::Normal,
            config: None,
        }
    }

    fn args(preset: Option<&str>, path: Option<PathBuf>, force: bool) -> PolicyInitArgs {
        PolicyInitArgs {
            preset: preset.map(str::to_string),
            path,
            force,
        }
    }

    #[tokio::test]
    async fn default_preset_writes_validating_secret_safe_policy() {
        let dir = tempdir().unwrap();
        let target = dir.path().join(".fida/policy.yaml");
        run_policy(&args(None, Some(target.clone()), false), &ctx())
            .await
            .expect("default init succeeds");

        assert!(target.exists(), "policy file should be created");
        let written = fs::read_to_string(&target).unwrap();
        assert_eq!(written, presets::SECRET_SAFE);
        assert!(fida_policy::validate_raw(&written).is_ok());
    }

    #[tokio::test]
    async fn each_preset_selection_writes_that_preset_and_validates() {
        for name in presets::PRESET_NAMES {
            let dir = tempdir().unwrap();
            let target = dir.path().join("policy.yaml");
            run_policy(&args(Some(name), Some(target.clone()), false), &ctx())
                .await
                .unwrap_or_else(|e| panic!("preset `{name}` should init: {e}"));

            let written = fs::read_to_string(&target).unwrap();
            assert_eq!(written, presets::preset_contents(name).unwrap());
            assert!(
                fida_policy::validate_raw(&written).is_ok(),
                "preset `{name}` must pass schema validation"
            );
        }
    }

    #[tokio::test]
    async fn unknown_preset_creates_nothing_and_errors() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("policy.yaml");
        let err = run_policy(&args(Some("nope"), Some(target.clone()), false), &ctx())
            .await
            .expect_err("unknown preset must error");

        assert_eq!(err.exit_code(), 1);
        let msg = err.to_string();
        for name in presets::PRESET_NAMES {
            assert!(
                msg.contains(name),
                "error should list supported preset `{name}`"
            );
        }
        assert!(!target.exists(), "no policy file should be created");
    }

    #[tokio::test]
    async fn existing_file_without_force_is_left_unchanged() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("policy.yaml");
        fs::write(&target, "pre-existing contents").unwrap();

        let err = run_policy(&args(None, Some(target.clone()), false), &ctx())
            .await
            .expect_err("existing file without --force must error");

        assert_eq!(err.exit_code(), 1);
        assert_eq!(
            fs::read_to_string(&target).unwrap(),
            "pre-existing contents",
            "existing file must be left untouched"
        );
    }

    #[tokio::test]
    async fn force_overwrites_existing_file_entirely() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("policy.yaml");
        fs::write(&target, "old contents that should be gone").unwrap();

        run_policy(&args(Some("careful"), Some(target.clone()), true), &ctx())
            .await
            .expect("--force should overwrite");

        let written = fs::read_to_string(&target).unwrap();
        assert_eq!(written, presets::CAREFUL);
        assert!(!written.contains("old contents"));
    }

    #[tokio::test]
    async fn missing_parent_directories_are_created() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("nested/deeper/policy.yaml");
        run_policy(&args(None, Some(target.clone()), false), &ctx())
            .await
            .expect("init should create parent dirs");

        assert!(target.exists());
        assert!(target.parent().unwrap().is_dir());
    }
}
