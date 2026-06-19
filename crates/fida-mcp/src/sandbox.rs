//! OS-level sandboxing for commands the gateway runs on the agent's behalf.
//!
//! [`crate::server::GatewayServer`] already gates `fida_shell` by policy and
//! confines its working directory with PathJail. This module adds optional
//! defense-in-depth at the OS level by *wrapping* the command's argv so the
//! spawned process itself is restricted — the same idea as lean-ctx's
//! `sandbox_level = 1` (Seatbelt on macOS, Landlock on Linux).
//!
//! It is **opt-in** (`FIDA_SANDBOX=1`): a strict profile can break legitimate
//! commands, so Fida never imposes it silently.
//!
//! Backends, in order of how well Fida can lock things down today:
//! * **macOS** — wrap with the built-in `sandbox-exec` (Seatbelt). The profile
//!   denies outbound network (anti-exfiltration) and denies reads of common
//!   secret stores (`~/.ssh`, `~/.aws`, `.env`, …). No dependency, no root.
//! * **Linux** — if `bwrap` (bubblewrap) is on `PATH`, wrap with it and
//!   `--unshare-net` to block network. ponytail: this blocks exfiltration but
//!   not secret reads; the upgrade path is the Linux Landlock LSM (filesystem
//!   path restriction) via a `pre_exec` ruleset, which needs kernel ≥5.13.
//! * **Other / no backend** — return the command unchanged (the policy + skill
//!   + PathJail layers still apply).

use std::path::Path;

/// Wrap `argv` so the spawned process runs under an OS sandbox, or return it
/// unchanged when no backend is available. `argv[0]` is the program.
pub fn wrap(argv: &[String], _workspace: &Path) -> Vec<String> {
    #[cfg(target_os = "macos")]
    {
        if let Some(home) = std::env::var_os("HOME") {
            return wrap_seatbelt(argv, Path::new(&home));
        }
        argv.to_vec()
    }
    #[cfg(target_os = "linux")]
    {
        match which_bwrap() {
            Some(bwrap) => wrap_bwrap(&bwrap, argv),
            None => argv.to_vec(),
        }
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        // ponytail: no native sandbox wired for this OS (e.g. Windows).
        // Upgrade path: Windows AppContainer / job objects.
        argv.to_vec()
    }
}

/// Whether an OS sandbox backend is actually available on this platform.
pub fn available() -> bool {
    #[cfg(target_os = "macos")]
    {
        Path::new("/usr/bin/sandbox-exec").exists()
    }
    #[cfg(target_os = "linux")]
    {
        which_bwrap().is_some()
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        false
    }
}

// ---------------------------------------------------------------------------
// macOS — Seatbelt via sandbox-exec
// ---------------------------------------------------------------------------

#[cfg(any(target_os = "macos", test))]
fn wrap_seatbelt(argv: &[String], home: &Path) -> Vec<String> {
    let mut wrapped = vec![
        "sandbox-exec".to_string(),
        "-p".to_string(),
        seatbelt_profile(home),
    ];
    wrapped.extend(argv.iter().cloned());
    wrapped
}

/// Build a Seatbelt (SBPL) profile: allow by default, but deny outbound network
/// and reads of well-known secret locations. Allow-default keeps ordinary
/// commands working; the explicit denies serve Fida's goal (no exfiltration, no
/// reading credentials).
///
/// ponytail: allow-default profile (robust, won't break builds). The stricter
/// upgrade path is a deny-default profile confining all reads to the workspace.
#[cfg(any(target_os = "macos", test))]
fn seatbelt_profile(home: &Path) -> String {
    let h = home.to_string_lossy();
    let p = |suffix: &str| sbpl_quoted(&format!("{h}{suffix}"));
    format!(
        "(version 1)\n\
         (allow default)\n\
         (deny network-outbound)\n\
         (deny file-read*\n\
         \x20\x20(subpath {ssh})\n\
         \x20\x20(subpath {aws})\n\
         \x20\x20(subpath {gnupg})\n\
         \x20\x20(subpath {gh})\n\
         \x20\x20(subpath {kube})\n\
         \x20\x20(subpath {docker})\n\
         \x20\x20(literal {netrc}))\n\
         (deny file-read* (regex #\"/\\.env(\\.[^/]*)?$\"))\n",
        ssh = p("/.ssh"),
        aws = p("/.aws"),
        gnupg = p("/.gnupg"),
        gh = p("/.config/gh"),
        kube = p("/.kube"),
        docker = p("/.docker"),
        netrc = p("/.netrc"),
    )
}

/// Render `s` as a complete SBPL double-quoted string literal, escaping
/// backslashes and quotes.
#[cfg(any(target_os = "macos", test))]
fn sbpl_quoted(s: &str) -> String {
    let escaped = s.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

// ---------------------------------------------------------------------------
// Linux — bubblewrap (network isolation)
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
fn which_bwrap() -> Option<String> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|d| d.join("bwrap"))
        .find(|p| p.is_file())
        .map(|p| p.to_string_lossy().into_owned())
}

/// Bind the existing filesystem and block the network. ponytail: this is
/// network-isolation only; confining reads needs Landlock (see module docs).
#[cfg(target_os = "linux")]
fn wrap_bwrap(bwrap: &str, argv: &[String]) -> Vec<String> {
    let mut wrapped = vec![
        bwrap.to_string(),
        "--dev-bind".to_string(),
        "/".to_string(),
        "/".to_string(),
        "--unshare-net".to_string(),
        "--die-with-parent".to_string(),
        "--".to_string(),
    ];
    wrapped.extend(argv.iter().cloned());
    wrapped
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sbpl_string_escapes_quotes_and_backslashes() {
        assert_eq!(sbpl_quoted("/a/b"), "\"/a/b\"");
        assert_eq!(sbpl_quoted("a\"b"), "\"a\\\"b\"");
        assert_eq!(sbpl_quoted("a\\b"), "\"a\\\\b\"");
    }

    #[test]
    fn seatbelt_wrap_prepends_sandbox_exec() {
        let argv = vec!["echo".to_string(), "hi".to_string()];
        let wrapped = wrap_seatbelt(&argv, Path::new("/Users/x"));
        assert_eq!(wrapped[0], "sandbox-exec");
        assert_eq!(wrapped[1], "-p");
        assert_eq!(&wrapped[3..], &["echo".to_string(), "hi".to_string()]);
        assert!(wrapped[2].contains("(deny network-outbound)"));
        assert!(wrapped[2].contains("(subpath \"/Users/x/.ssh\")"));
    }

    /// The one runnable check: on macOS the generated profile must actually
    /// (a) let an allowed read through and (b) deny a secret-store read.
    #[cfg(target_os = "macos")]
    #[test]
    fn seatbelt_profile_blocks_secret_read_but_allows_workspace_read() {
        use std::process::Command;

        if !Path::new("/usr/bin/sandbox-exec").exists() {
            return; // environment without Seatbelt; skip.
        }
        let seatbelt_usable = Command::new("/usr/bin/sandbox-exec")
            .args(["-p", "(version 1)\n(allow default)", "/usr/bin/true"])
            .output()
            .map(|out| out.status.success())
            .unwrap_or(false);
        if !seatbelt_usable {
            return; // Seatbelt exists but cannot be applied in this host sandbox.
        }

        let home = tempfile::tempdir().unwrap();
        // Canonicalize: macOS temp dirs live under /var → /private/var, and the
        // Seatbelt profile must match the path the kernel actually resolves.
        let home = std::fs::canonicalize(home.path()).unwrap();
        // A fake secret store that the profile should block.
        std::fs::create_dir_all(home.join(".ssh")).unwrap();
        std::fs::write(home.join(".ssh/id_rsa"), b"TOPSECRET").unwrap();
        // An ordinary workspace file that must remain readable.
        let ws = tempfile::tempdir().unwrap();
        std::fs::write(ws.path().join("ok.txt"), b"hello").unwrap();

        let run = |target: &Path| {
            let argv = wrap_seatbelt(
                &["/bin/cat".to_string(), target.display().to_string()],
                &home,
            );
            Command::new(&argv[0])
                .args(&argv[1..])
                .output()
                .expect("sandbox-exec runs")
        };

        let secret = run(&home.join(".ssh/id_rsa"));
        assert!(
            !secret.status.success(),
            "reading the secret store must be denied by the sandbox"
        );
        assert!(!String::from_utf8_lossy(&secret.stdout).contains("TOPSECRET"));

        let ok = run(&ws.path().join("ok.txt"));
        assert!(ok.status.success(), "workspace read must still succeed");
        assert_eq!(String::from_utf8_lossy(&ok.stdout), "hello");
    }
}
