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

**Prevent AI coding agents from reading or leaking your secrets.**

Fida is a local-first secret leak prevention layer for AI coding agents. It
scans your repo for exposed secrets, inspects mediated reads and command output,
redacts secret material before it reaches an LLM, and gives you a local audit
trail across projects and agents.

In Latin, *fida* carries the sense of being faithful, trustworthy, and true to a
duty. That is the product promise: your secrets stay safe while agents move fast.

> Project status: MVP implemented. Fida installs agent integrations, verifies
> redaction end-to-end, scans local secret risk, and records redaction-safe
> audit events. Policy and session controls remain available for advanced use.

## Quick Start

```bash
# 1. Install protection, verify redaction, and scan the repo
fida init

# 2. Inspect protection strength per agent
fida status

# 3. Re-scan whenever credentials or integrations change
fida scan
```

### What happens when an agent reads `.env`

```
$ cat .env                         # agent attempts to read secrets
AWS_ACCESS_KEY_ID=AKIA...          # ← what the agent would see without Fida

$ fida_read .env                   # through the Fida gateway
API_KEY=[REDACTED]
   file structure remains useful; the secret value never reaches the agent
```

Reproduce it locally (sets up a throwaway repo, no real secrets):

```bash
bash examples/demo.sh
```

## Three Pillars

- **Secret Guard** (`fida init`, gateway, hooks) — install protection and verify that raw values do not reach the model.
- **Secret Scan** (`fida scan`) — find credentials and report whether any detected agent still has a raw-secret path.
- **Audit** (`fida audit`, `fida report`) — answer "what did the agent do?" with structured, append-only event logs.

## Why Fida?

AI coding agents are useful because they can inspect code, edit files, run
commands, install packages, and call external tools. Those same powers deserve
clear boundaries.

Fida makes agent work:

- **Secret-safe** - `.env`, keys, and credentials are redacted by default before
  they reach an agent; strict policies can block the path entirely.
- **Reviewable** - sessions produce structured audit events and human-readable
  reports.
- **Local-first** - enforcement and audit data stay on your machine.
- **Agent-agnostic** - works with Codex, Claude Code, Cursor, OpenCode, Windsurf,
  GitHub Copilot, Antigravity, MCP servers, and future adapters.

Fida is not trying to sell you a perfect OS sandbox. Its MVP promise is narrower:
secret values are redacted or blocked before they reach the model. General
policy controls remain an advanced capability.

## Guarding IDE-embedded agents

Fida's shell wrappers (`guard`, `exec`, `run`) mediate agents that act through
the shell. IDE-embedded agents — OpenCode, Cursor, Copilot, Windsurf — are different:
they read and write files through their *own* internal tools, which never pass
through a shell shim. Fida cannot inspect or redact output from a tool it never
sees.

Fida closes most of that gap with three complementary layers (no OS sandbox
required), following the approach proven by tools like lean-ctx — a strong skill
plus a policy-enforcing gateway:

1. **Gateway MCP tools** — `fida mcp serve` exposes `fida_read` and `fida_shell`
   over MCP. Every call runs through policy → execute → redact → audit, and a
   **PathJail** confines file access to the workspace root: symlinks and `..`
   traversal are resolved first, so `/etc/passwd`, `~/.ssh/id_rsa`, and
   `../../secrets/.env` are blocked even before policy runs. Inside the workspace,
   the default policy allows reads to continue through a built-in detector catalog
   (AWS, GitHub, Google, Slack, Stripe, OpenAI, Anthropic, JWT, dotenv values,
   and private keys), which redacts matches before returning content.
2. **Skill (steering)** — an always-included, assertive rules file that tells the
   agent it MUST route reads/commands through Fida and must not bypass redaction.
3. **preToolUse hook** — a backstop that fires before the agent's *native*
   read/write tools and forces a policy check. On **Claude Code**, **Codex**,
   and **GitHub Copilot in VS Code** it is a real **hard block**: `fida hook`
   denies a native read when secret content is detected because the native tool
   cannot return a redacted view, then directs the agent to `fida_read` or
   `fida_shell`.
4. **OS sandbox (opt-in)** — `FIDA_SANDBOX=1` wraps `fida_shell` commands in
   Seatbelt (macOS) or bubblewrap (Linux) so even an allowed command cannot
   exfiltrate over the network or read secret stores like `~/.ssh`.

One interactive command installs integrations, runs a synthetic end-to-end
redaction self-test, scans the repository, and records each agent's protection
level. It installs **globally by default** — once, for every repo:

```bash
fida init               # detect agents, choose from a checklist, wire globally
```

`fida init` auto-detects every coding agent present on your machine — by its
config directory in your home (e.g. `~/.cursor`, `~/.claude`, `~/.codex`), its
project marker files, its CLI on `PATH`, or (on macOS) its app bundle in
`/Applications` — and pre-checks them. The picker is an arrow-key checklist
(↑/↓ to move, space to toggle, enter to confirm). Because the global gateway
resolves policy per-repo at runtime (and falls back to the built-in
redaction-first policy), every repository is protected with no per-project setup. It is
scriptable too:

```bash
fida init --yes                     # auto-detect and wire every detected agent
fida init --agents opencode,cursor    # specific agents, no prompt
fida init --all                     # every supported agent (even undetected)
fida init --project                 # scope to the current repo instead of global
fida uninstall                      # remove Fida from every supported agent
fida uninstall --project            # remove project-scoped Fida integrations
```

Supported agents and where Fida writes (global scope shown):

| Agent | Protection | Gateway MCP | Skill / rules | Hook |
| --- | --- | --- | --- | --- |
| Codex | enforced | (config.toml — TOML) | `~/.codex/AGENTS.md` (managed block) | `~/.codex/hooks.json` (hard block) |
| Claude Code | enforced | `~/.claude.json` | `~/.claude/CLAUDE.md` (managed block) | `~/.claude/settings.json` (hard block) |
| Antigravity | best-effort | `~/.gemini/config/mcp_config.json` | `AGENTS.md` (project) · `~/.gemini/GEMINI.md` (global) | — |
| Kiro | best-effort | `~/.kiro/settings/mcp.json` | `~/.kiro/steering/fida.md` | soft prompt |
| OpenCode | best-effort | `~/.config/opencode/opencode.json` | `~/.config/opencode/OPENCODE.md` | — |
| Cursor | best-effort | `~/.cursor/mcp.json` | `.cursor/rules/fida.mdc` (project) | — |
| GitHub Copilot | enforced | VS Code user-profile `mcp.json` · `.vscode/mcp.json` (project) | `~/.copilot/instructions/fida.instructions.md` · `.github/copilot-instructions.md` (project) | `~/.copilot/hooks/fida.json` · `.github/hooks/fida.json` (project, Preview) |
| Windsurf | best-effort | `~/.codeium/windsurf/mcp_config.json` | `~/.codeium/windsurf/memories/global_rules.md` | — |

Files Fida shares with you (`CLAUDE.md`, `AGENTS.md`, `~/.gemini/GEMINI.md`,
Windsurf global rules) are edited through a managed block, so your own content
is preserved on init and uninstall.

PathJail can be relaxed for containers or external mounts with `FIDA_NO_JAIL=1`.

For defense-in-depth, an opt-in **OS sandbox** can wrap commands the gateway runs
(`fida_shell`) so the spawned process is network-isolated and blocked from
reading secret stores at the OS level — set `FIDA_SANDBOX=1`. Backends: Seatbelt
(`sandbox-exec`) on macOS and bubblewrap (`bwrap`, network isolation) on Linux;
no-op elsewhere. It is off by default because a strict profile can break some
commands.

**Honest limit:** the gateway and skill define the sanctioned path; the hook
narrows the bypass. An agent that ignores all three still needs OS-level
controls. In practice modern agents reliably follow an assertive skill (this is
lean-ctx's primary model too), but these layers are a strong guardrail, not an
airtight sandbox. The known boundary and leak cases are covered by a red-team
self-check (`cargo test -p fida-mcp --test redteam_bypass`): workspace escapes
must be blocked and in-workspace secrets must be returned only as redacted views.
It runs in CI, and `fida status` / `fida doctor` report the product-level
protection state (`enforced`, `best_effort`, or `incomplete`) so this README
cannot overstate it.

## What Fida Guards

| Surface | What you can control |
| --- | --- |
| Commands | exact, prefix, regex, working directory, risk, environment |
| Files | repo-level read/write allowlists, ask rules, and hard denies |
| Secrets | redaction in logs, suspicious diff blocking, secret file preflights |
| Network | domains, hosts, CIDRs, private ranges, metadata endpoints |
| MCP tools | tool allow/ask/deny patterns before calls reach a server |
| Sessions | audit logs, diffs, reports, cleanup, and apply gates |

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/ajipurn/fida/main/install.sh | sh
```

This installs `fida` to `~/.local/bin` by default. On a fresh install the script
then hands straight off into `fida init` — the agent picker described in
[Guarding IDE-embedded agents](#guarding-ide-embedded-agents) — so your agents
are wired (gateway + skill + hook) in the same step. That is the whole setup.
Upgrades skip the picker; re-run `fida init` any time.

Verify anytime with:

```bash
fida --version
fida doctor
```

Uninstall Fida's agent integrations and setup metadata with:

```bash
fida uninstall
```

The command preserves your non-Fida config and ends by printing the binary path
to delete manually. Fida does not remove its own running executable.

### Other install methods

Pin a version or choose a different install directory:

```bash
FIDA_VERSION=v0.1.0 FIDA_INSTALL_DIR=/usr/local/bin \
  curl -fsSL https://raw.githubusercontent.com/ajipurn/fida/main/install.sh | sh
```

Install with Cargo:

```bash
cargo install --git https://github.com/ajipurn/fida fida-cli
```

Install from a checkout:

```bash
git clone https://github.com/ajipurn/fida
cd fida
./install.sh
```

## Common Tasks

Create and validate a repo policy:

```bash
cd your-repo
fida init --policy
fida policy check
```

Run an agent through a guarded session:

```bash
fida run --workspace copy --apply auto-if-allowed -- codex
```

Explain why a command would be allowed, denied, or require approval:

```bash
fida policy explain command "pnpm install"
```

Inspect recent activity:

```bash
fida audit tail
fida session export latest --format markdown
```

Fida writes local state under `.fida/`, which is intentionally ignored by git.

Tighten your policy from what an agent actually did, reviewing the diff first:

```bash
fida observe -- codex              # record the agent's observed actions
fida policy suggest                # show a suggested allowlist diff vs. current policy
fida policy suggest --write        # apply it after reviewing the diff
```

The suggested policy keeps sensitive reads available for redaction, always
denies writes to secret files, and asks before network access, package installs,
and `git push`, regardless of what was observed.

## Policy Example

Fida resolves policy in this order:

1. `--config <path>`
2. `.fida/policy.yaml`
3. `fida.yaml`
4. built-in default (allows the common dev loop, denies the clearly dangerous)

Scaffold a starting point with `fida init --policy --preset <name>`. Presets
range from `relaxed` (run anything not explicitly dangerous) through `starter`
(the redaction-first built-in default) to `careful`, `oss-maintainer`, and
`ci-readonly`. Choose `strict-firewall` when sensitive read paths must be denied
instead of returned as redacted safe views. List them with
`fida policy list-presets`.

See [examples/fida.yaml](examples/fida.yaml) for a fuller starter policy.

```yaml
version: 1
default_decision: ask

commands:
  allow:
    - exact: git status
    - exact: git diff
    - prefix: pnpm test
  ask:
    - prefix: pnpm install
      reason: package manager installs can run lifecycle scripts
  deny:
    - regex: "rm\\s+-rf\\s+(/|~|\\.)"
      reason: destructive remove command

files:
  read:
    allow:
      - "**/*"
  write:
    allow:
      - src/**
      - tests/**
      - docs/**
    ask:
      - package.json
      - pnpm-lock.yaml
      - .github/**
    deny:
      - .env
      - "**/*.pem"

network:
  ask:
    - domain: "*"
      reason: arbitrary network access can transmit code or local data
  deny:
    - host: 169.254.169.254
      reason: cloud metadata service
```

## Command Map

```bash
fida init                         # pick agents, wire gateway + skill + hook (global)
fida uninstall                    # remove Fida integrations and setup metadata
fida init --policy                # create .fida/policy.yaml
fida policy check                 # validate policy syntax and schema
fida policy list-presets          # show built-in presets
fida policy explain command "..." # preview a decision
fida exec -- <cmd>                # mediate one shell command
fida run -- <agent>               # run an agent in a Fida session
fida scan                         # scan the repo for exposed secrets and risk
fida scan --mcp --fail-on high    # also flag risky agent MCP servers; exit non-zero on high risk
fida observe -- <agent>           # run an agent and record observed actions
fida policy suggest --write       # propose an allowlist from observations, then write it
fida session list                 # list recorded sessions
fida session show latest          # show session metadata and counts
fida session diff latest          # inspect recorded patch
fida session export latest        # write a report
fida audit tail                   # read recent audit events
fida mcp inspect server.json      # inspect MCP tools through policy
fida mcp serve                    # serve Fida gateway tools (fida_read/fida_shell) over MCP
fida doctor                       # check local setup health
```

## Workspace Layout

Fida is a Rust workspace split by enforcement surface:

- `crates/fida-cli` - CLI front door, commands, exit-code mapping
- `crates/fida-policy` - YAML schema, source resolution, compilation, evaluator
- `crates/fida-broker` - allow/ask/deny mediation and approval flow
- `crates/fida-audit` - JSONL audit store and report rendering
- `crates/fida-session` - session ids, metadata, lifecycle, export helpers
- `crates/fida-diff` - file diff gate and apply safety
- `crates/fida-secrets` - secret detection and redaction
- `crates/fida-exec` - command execution wrapper
- `crates/fida-net` - local network proxy gates
- `crates/fida-mcp` - MCP inspection/proxy preview
- `crates/fida-agent` - agent launch, workspace, and finalize helpers
- `crates/fida-action` - shared action, decision, risk, and result types
- `crates/fida-scan` - repository secret-risk scanner and MCP risk scanner

## Development

Run the same local gates used by CI:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Useful checks while iterating:

```bash
cargo run -p fida-cli -- --help
cargo run -p fida-cli -- doctor
cargo run -p fida-cli -- policy schema --json
```

## Security

Please report security-sensitive issues privately when they could expose
secrets, bypass deny rules, corrupt a workspace, or mislead users about
enforcement. See [SECURITY.md](SECURITY.md).

## License

Licensed under the terms in [LICENSE](LICENSE).
