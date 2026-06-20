<p align="center">
  <img src="assets/fida-logo.png" alt="Fida logo" width="220">
</p>

<h1 align="center">Fida</h1>

<p align="center">
  <a href="https://github.com/ajipurn/fida/actions/workflows/ci.yml"><img alt="CI" src="https://img.shields.io/github/actions/workflow/status/ajipurn/fida/ci.yml?branch=main&amp;style=flat-square&amp;label=CI"></a>
  <a href="https://github.com/ajipurn/fida/releases/latest"><img alt="Latest release" src="https://img.shields.io/github/v/release/ajipurn/fida?style=flat-square&amp;label=release"></a>
  <a href="https://www.rust-lang.org/"><img alt="Rust 1.85+" src="https://img.shields.io/badge/rust-1.85%2B-000000?style=flat-square&amp;logo=rust"></a>
  <a href="LICENSE"><img alt="MIT License" src="https://img.shields.io/badge/license-MIT-blue?style=flat-square"></a>
  <img alt="Local-first" src="https://img.shields.io/badge/security-local--first-0b8f6a?style=flat-square">
</p>

**Keep secret values out of AI coding agents.**

Fida is a local-first secret leak prevention layer for AI coding agents. It finds exposed credentials, gives agents redacted safe views of sensitive files and command output, and shows whether your installed agent integrations can still expose a raw value.

It is deliberately **not** a general agent policy engine, approval system, or developer workflow firewall. Fida does not decide which ordinary commands an agent may run, which files it may edit, or whether you may use `curl | sh`. Its one job is simple: a detected secret must not reach model context.

> Project status: MVP implemented. Fida installs local integrations, verifies its redaction path with a synthetic credential, scans repo risk, and records redaction-safe audit events.

## Quick start

```bash
# Install the binary.
curl -fsSL https://raw.githubusercontent.com/ajipurn/fida/main/install.sh | sh

# Opt in to agent protection when you are ready.
fida init

# Check coverage and scan the current repository.
fida status
fida scan
```

The installer only installs `fida`; it never launches an interactive setup. It prints the exact `fida init` command to run next.

## What Fida does

When an agent needs content that may contain a credential, Fida provides a sanitized view instead of the raw bytes:

```text
Agent -> fida_read .env -> scan -> redact -> agent

API_URL=https://example.test
API_KEY=[REDACTED]
```

Its integrations combine three layers:

1. **Redacting MCP gateway** — `fida_read` and `fida_shell` return redacted file content and captured command output. `fida_shell` still runs the real command — the child process keeps the true credential, so the work succeeds — and redacts only the output handed back to the model: the agent *uses* a secret without *seeing* it. File reads are confined to the workspace by default, including symlink and `..` escape checks; secrets outside the workspace (e.g. `~/.aws`) are covered only by the native-read hook on `enforced` agents.
2. **Agent steering** — a managed instruction tells the agent to use those redacting tools whenever it needs sensitive content.
3. **Native-read hook, where supported** — Codex and Claude Code can block a native read only when Fida detects secret content that the native tool cannot redact, then direct the agent to the gateway.

Normal clean reads, edits, commands, installs, network access, and approvals remain the agent's and developer's concern. Fida's gateway follows the same low-friction rule: it captures and redacts output; it does not apply a command allowlist or repository approval policy.

## What Fida detects

The built-in detector catalog recognizes dotenv assignments, PEM private keys, and high-precision formats for AWS, GitHub, Google, Slack, Stripe, OpenAI, Anthropic, and JWT credentials. It favors precision over recall: a credential in a format Fida does not recognize passes through unredacted. This is best-effort protection against accidental exposure, not a guarantee of zero leakage. Use a dedicated history scanner such as gitleaks or GitGuardian alongside Fida.

Fida fails closed on redaction: if it cannot prove a response is clean, it suppresses that response rather than returning a partial secret.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/ajipurn/fida/main/install.sh | sh
```

The binary is installed to `~/.local/bin` by default and then exits. Start interactive setup separately:

```bash
fida init
```

Pin a version or choose another install directory:

```bash
FIDA_VERSION=v0.1.0 FIDA_INSTALL_DIR=/usr/local/bin \
  curl -fsSL https://raw.githubusercontent.com/ajipurn/fida/main/install.sh | sh
```

Other options:

```bash
cargo install --git https://github.com/ajipurn/fida fida-cli

git clone https://github.com/ajipurn/fida
cd fida
./install.sh
```

## Everyday commands

```bash
fida init             # wire selected agent integrations and verify redaction
fida status           # show enforced, best-effort, or incomplete coverage
fida scan             # find secret risk without printing secret values
fida scan --fail-on high
fida doctor           # diagnose setup and redaction verification
fida audit tail       # inspect redaction-safe gateway activity
fida uninstall        # remove only Fida-managed integrations
```

`fida scan` reports whether a raw secret could reach a detected agent. It never prints a secret value, its length, or a fragment of it.

## Agent coverage

| Agent | Coverage |
| --- | --- |
| Codex, Claude Code | `enforced` when the hook and gateway self-test pass |
| Cursor, OpenCode, GitHub Copilot, Windsurf, Antigravity, Kiro | `best_effort` gateway + steering |

`fida status` and `fida doctor` report the actual state for each detected agent: `enforced`, `best_effort`, `incomplete`, or `inactive`.

## Scope and limits

Fida protects model-bound content on its installed integration paths. It is not an OS sandbox or a complete data-loss-prevention product. An agent that can ignore steering, bypass a hook, or access a file through an unmediated native tool may still need OS-level containment. Fida names that coverage honestly instead of turning ordinary development into a permission maze.

## Development

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## Security

Please report security-sensitive issues privately when they could expose a secret, bypass redaction, or misrepresent protection coverage. See [SECURITY.md](SECURITY.md).

## License

Licensed under the terms in [LICENSE](LICENSE).
