//! Managed shell-rc block writer (legacy).
//!
//! Previously, `fida onboard` added a small, clearly delimited block to the user's
//! shell startup file. Now, this module is only retained so `fida uninstall` can
//! cleanly remove those legacy blocks.
//!
//! ```sh
//! # >>> fida initialize >>>
//! eval "$(/abs/path/to/fida activate)"
//! # <<< fida initialize <<<
//! ```
//!
//! The block is removable as a single unit (`remove`), so uninstall leaves the
//! rc file clean.

use std::path::{Path, PathBuf};

use crate::error::{CliError, CliResult};

/// First line of the managed block.
pub const BEGIN_MARKER: &str = "# >>> fida initialize >>>";
/// Last line of the managed block.
pub const END_MARKER: &str = "# <<< fida initialize <<<";

/// A supported login shell whose startup file Fida can manage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellKind {
    Zsh,
    Bash,
    Fish,
}

impl ShellKind {
    /// The startup file this shell sources, rooted at `home`.
    pub fn rc_path(self, home: &Path) -> PathBuf {
        match self {
            ShellKind::Zsh => home.join(".zshrc"),
            ShellKind::Bash => home.join(".bashrc"),
            ShellKind::Fish => home.join(".config/fish/config.fish"),
        }
    }
}

/// Resolve the user home directory from `$HOME`.
pub fn home_dir() -> CliResult<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| CliError::general("cannot resolve home directory: set HOME"))
}

/// Remove the managed block from `rc`. Returns `true` if a block was removed.
pub fn remove(rc: &Path) -> CliResult<bool> {
    let Some(content) = read_existing(rc)? else {
        return Ok(false);
    };
    let Some((start, end)) = find_block_bounds(&content) else {
        return Ok(false);
    };

    let mut next = String::with_capacity(content.len());
    next.push_str(&content[..start]);
    // Drop one blank separator line left dangling before the block, if any.
    if next.ends_with("\n\n") {
        next.pop();
    }
    next.push_str(&content[end..]);

    write_atomic(rc, &next)?;
    Ok(true)
}

/// Read the rc file if it exists; `Ok(None)` when absent.
fn read_existing(rc: &Path) -> CliResult<Option<String>> {
    match std::fs::read_to_string(rc) {
        Ok(s) => Ok(Some(s)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(CliError::general(format!(
            "failed to read shell rc {}: {e}",
            rc.display()
        ))),
    }
}

/// Byte range `[start, end)` covering the managed block including both marker
/// lines and the newline after the end marker. `None` when no block is present.
fn find_block_bounds(content: &str) -> Option<(usize, usize)> {
    let start = line_start_of(content, BEGIN_MARKER)?;
    // Search for the end marker at or after the begin marker.
    let end_line = line_start_of(&content[start..], END_MARKER)? + start;
    // Advance past the end marker line (through its trailing newline if present).
    let after = content[end_line..]
        .find('\n')
        .map(|nl| end_line + nl + 1)
        .unwrap_or(content.len());
    Some((start, after))
}

/// Byte offset of the start of the line that is exactly `marker` (ignoring
/// surrounding whitespace on that line). `None` if not found.
fn line_start_of(content: &str, marker: &str) -> Option<usize> {
    let mut offset = 0;
    for line in content.split_inclusive('\n') {
        if line.trim_end_matches(['\n', '\r']).trim() == marker {
            return Some(offset);
        }
        offset += line.len();
    }
    None
}

/// Write `contents` to `target` atomically (temp sibling + rename), creating
/// parent directories as needed.
fn write_atomic(target: &Path, contents: &str) -> CliResult {
    if let Some(parent) = target.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| {
                CliError::general(format!(
                    "failed to create directory {}: {e}",
                    parent.display()
                ))
            })?;
        }
    }
    let file_name = target
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "rc".to_string());
    let tmp = match target.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => {
            parent.join(format!(".{file_name}.fida-tmp.{}", std::process::id()))
        }
        _ => PathBuf::from(format!(".{file_name}.fida-tmp.{}", std::process::id())),
    };

    if let Err(e) = std::fs::write(&tmp, contents) {
        let _ = std::fs::remove_file(&tmp);
        return Err(CliError::general(format!(
            "failed to write {}: {e}",
            tmp.display()
        )));
    }
    if let Err(e) = std::fs::rename(&tmp, target) {
        let _ = std::fs::remove_file(&tmp);
        return Err(CliError::general(format!(
            "failed to update {}: {e}",
            target.display()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    // fn bin() -> PathBuf {
    //     PathBuf::from("/usr/local/bin/fida")
    // }

    #[test]
    fn remove_strips_block_and_preserves_rest() {
        let dir = tempdir().unwrap();
        let rc = dir.path().join(".zshrc");
        let content =
            format!("line A\n{BEGIN_MARKER}\neval \"$(fida activate)\"\n{END_MARKER}\nline B\n");
        std::fs::write(&rc, content).unwrap();

        assert!(remove(&rc).unwrap());
        let final_content = std::fs::read_to_string(&rc).unwrap();
        assert!(final_content.contains("line A"));
        assert!(final_content.contains("line B"));
        assert!(!final_content.contains(BEGIN_MARKER));
        assert!(!final_content.contains(END_MARKER));
    }

    #[test]
    fn remove_is_noop_without_block() {
        let dir = tempdir().unwrap();
        let rc = dir.path().join(".zshrc");
        std::fs::write(&rc, "just user config\n").unwrap();
        assert!(!remove(&rc).unwrap());
        assert_eq!(std::fs::read_to_string(&rc).unwrap(), "just user config\n");

        let missing = dir.path().join(".nope");
        assert!(!remove(&missing).unwrap());
    }
}
