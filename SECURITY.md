# Security Policy

Fida is an MVP-stage local secret leak prevention layer for AI coding agents. Please report security-sensitive issues privately when they could expose secrets, bypass redaction or deny rules, corrupt a workspace, or mislead users about enforcement.

## Reporting a Vulnerability

Until a dedicated security contact is published, please open a private security advisory on GitHub if available for the repository owner. If private advisories are not available, open a minimal public issue that says a security report is available, without exploit details or secret material.

Include:

- Affected Fida version or commit.
- The policy and command/session shape needed to reproduce.
- Expected vs actual behavior.
- Whether secrets, files, network traffic, or MCP tools are involved.

## Scope

High-priority reports include:

- Hard-deny bypasses.
- Dry-run paths that execute side effects.
- Denied file changes that reach the main workspace.
- Secret values written to audit logs or reports.
- Network/MCP policy bypasses where Fida claims enforcement.

## Disclosure

Please give maintainers a reasonable chance to investigate and release a fix before publishing full details.
