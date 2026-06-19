# Secret Leak Prevention First

Status: implemented

Verified with `cargo fmt --all`, `cargo test --workspace`, and
`bun run typecheck` in `docs`.

## Decision

Fida's default posture is secret leak prevention, not broad read isolation.

When an agent uses a Fida-mediated read or command:

1. Apply workspace boundaries and explicit policy.
2. Capture the requested content or command output.
3. Scan it for secret material.
4. Redact detected values before returning anything to the agent.
5. Suppress the complete item if redaction fails.
6. Record only redaction-safe audit data.

Sensitive filenames such as `.env`, `*.pem`, and `*.key` are not denied by
default for reads. Writes and deletes to those paths remain hard denied. Users
who need read-path lockdown can opt into the `strict-firewall` preset or add
explicit `files.read.deny` rules.

## Goals

- Preserve useful agent access to repository files and folders.
- Prevent detected secret values from reaching model context, terminal output,
  MCP responses, or audit records.
- Keep explicit policy denies, workspace PathJail, dangerous command denies,
  network controls, and write protection intact.
- Make strict path blocking available without making it the default.
- Keep CLI output, generated agent guidance, README, examples, and frontend docs
  consistent with the runtime behavior.

## Non-goals

- Replacing an OS sandbox or kernel-level filesystem controls.
- Guaranteeing protection when an agent bypasses the gateway, skill, and hook.
- Removing explicit `allow`, `ask`, or `deny` policy controls.
- Returning raw secret values to satisfy a user or agent request.

## Behavior Matrix

| Surface | Default behavior | Strict behavior |
| --- | --- | --- |
| `fida_read` inside workspace | Read, scan, redact, return safe view | Explicit sensitive path deny |
| `fida_shell` output | Capture, scan, redact, then return | Same output redaction plus policy denies |
| `fida exec` output | Capture, scan, redact, then print/audit | Same |
| Native read with hook support | Allow clean content; deny detected secret content and redirect to Fida | Deny matching policy paths before execution |
| Sensitive file write/delete | Hard deny | Hard deny |
| Path outside workspace | PathJail deny | PathJail deny |
| Redaction failure | Suppress complete item | Suppress complete item |

## Implementation Workstreams

### 1. Policy defaults

- Limit built-in sensitive-file hard denies to write and delete actions.
- Keep default file reads broad so they reach the redaction gateway.
- Keep explicit read deny rules authoritative.
- Add `strict-firewall` with sensitive read and write denies.
- Keep policy suggestions redaction-first for reads and strict for writes.

### 2. Safe output boundaries

- Ensure `fida_read` scans and redacts before constructing an MCP response.
- Ensure `fida_shell` captures stdout/stderr and redacts before returning them.
- Ensure `fida exec` never streams raw child output before redaction.
- Fail closed by suppressing content when redaction cannot complete.

### 3. Native tool hooks

- Evaluate explicit policy first.
- Inspect actual file content for native read actions.
- Deny only when policy denies or secret content is detected.
- Explain that native tools cannot provide a redacted view.
- Redirect the agent to `fida_read` or `fida_shell`.

### 4. Product messaging

- Describe Fida as a local-first secret leak prevention layer.
- Replace "sensitive files are always blocked" examples with redacted safe views.
- Document `strict-firewall` as an opt-in compatibility mode.
- Update generated agent instructions to prohibit bypassing redaction, not all
  access to sensitive filenames.
- Update scan recommendations to prefer mediated reads before deny rules.

### 5. Verification

- Policy tests: default sensitive reads continue; writes remain denied.
- Preset tests: every preset validates; `strict-firewall` denies sensitive reads.
- Hook tests: clean sensitive files pass; detected secret content is denied.
- Gateway tests: `.env` and shell output return redacted content under defaults.
- Red-team tests: workspace escapes are blocked and in-workspace secrets never
  appear in successful responses.
- Executor tests: captured output is redacted before audit or terminal emission.
- Full workspace formatting, lint, and test gates pass.

## Acceptance Criteria

- A default `fida_read .env` succeeds when policy allows the path.
- The response preserves non-secret structure and contains no detected value.
- A default `fida_shell` or `fida exec` command cannot print raw detected secrets.
- A clean file is not blocked only because its filename looks sensitive.
- Sensitive writes remain denied without custom configuration.
- Explicit read deny rules still block before file content is returned.
- `strict-firewall` restores the former sensitive read-path blocking behavior.
- README, demo, generated skill text, and frontend docs describe the same model.
