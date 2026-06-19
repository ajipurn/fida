//! `fida-approval` — Approval_UI: interactive prompt choices and
//! non-interactive fail-closed policy (see spec tasks 10.x).
//!
//! This crate owns the interactive prompt shown when an [`Action`] resolves to
//! `ask` in an interactive session. The prompt presents the
//! action kind, target, risk, reason, and matched rule and offers exactly four
//! choices: allow once, deny once, remember for session,
//! and view context. Selecting view context displays the full action context
//! and re-presents the same prompt without resolving; unrecognized input
//! likewise re-presents without resolving.
//!
//! In non-interactive sessions the broker never calls the prompt; it resolves
//! `ask` to blocked directly, so that policy lives in the broker
//! rather than here.
//!
//! ## IO abstraction
//!
//! To make the prompt testable with a scripted terminal, the core loop
//! ([`prompt_with_io`]) is generic over any [`BufRead`] input and [`Write`]
//! output. [`TerminalApprovalUi`] is the production implementation that wires
//! the loop to stdin/stdout and satisfies the [`ApprovalUi`] trait.

use std::io::{self, BufRead, Write};

use fida_action::{ActionKind, MatchedRule, Risk};

// ---------------------------------------------------------------------------
// Public model
// ---------------------------------------------------------------------------

/// The four choices offered by the approval prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ApprovalChoice {
    /// Permit the action exactly once.
    AllowOnce,
    /// Block the action, leaving target state unchanged.
    DenyOnce,
    /// Permit and remember an allow decision for matching actions.
    RememberForSession,
    /// Display the full context and re-present the prompt.
    ViewContext,
}

impl ApprovalChoice {
    /// Parse a single line of user input into a choice.
    ///
    /// Accepts the numeric option index (`1`-`4`), a single-letter mnemonic, or
    /// the choice word. Matching is case-insensitive and ignores surrounding
    /// whitespace. Returns `None` for any input that does not match exactly one
    /// of the four offered choices.
    pub fn parse(input: &str) -> Option<ApprovalChoice> {
        match input.trim().to_ascii_lowercase().as_str() {
            "1" | "a" | "allow" | "allow once" => Some(ApprovalChoice::AllowOnce),
            "2" | "d" | "deny" | "deny once" => Some(ApprovalChoice::DenyOnce),
            "3" | "r" | "remember" | "remember for session" => {
                Some(ApprovalChoice::RememberForSession)
            }
            "4" | "v" | "view" | "view context" => Some(ApprovalChoice::ViewContext),
            _ => None,
        }
    }
}

/// The resolved result of an approval prompt.
///
/// `ViewContext` never produces an outcome — it re-presents the prompt — so it
/// is intentionally absent here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ApprovalOutcome {
    /// The user allowed the action once.
    Allowed,
    /// The user allowed the action and asked to remember it.
    AllowedRemembered,
    /// The user denied the action.
    Denied,
}

/// Everything the prompt presents about an action awaiting approval.
///
/// Carries the five fields shown in the single prompt line plus the full
/// `context` block revealed when the user selects view context.
/// The broker constructs this; the UI only renders it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalPresentation {
    /// The kind of action awaiting approval.
    pub kind: ActionKind,
    /// A human-readable description of the action target (e.g. the command
    /// line, file path, or network host).
    pub target: String,
    /// The risk level attached to the decision.
    pub risk: Risk,
    /// The non-empty reason the action requires approval.
    pub reason: String,
    /// The rule that matched, or the no-explicit-rule sentinel.
    pub matched_rule: MatchedRule,
    /// The full action context shown on view context. When empty, a
    /// placeholder is shown instead so the user always gets feedback.
    pub context: String,
}

/// An interactive approval prompt.
pub trait ApprovalUi {
    /// Present the action and block until the user resolves it.
    ///
    /// Re-prompts on view context and on unrecognized input; returns only once
    /// the user selects a resolving choice.
    fn prompt(&self, presentation: &ApprovalPresentation) -> ApprovalOutcome;
}

// ---------------------------------------------------------------------------
// Rendering helpers
// ---------------------------------------------------------------------------

/// The dotted audit label for an action kind, matching the wire schema.
fn kind_label(kind: ActionKind) -> &'static str {
    match kind {
        ActionKind::CommandRun => "command.run",
        ActionKind::FileRead => "file.read",
        ActionKind::FileWrite => "file.write",
        ActionKind::FileDelete => "file.delete",
        ActionKind::NetworkRequest => "network.request",
        ActionKind::McpToolCall => "mcp.tool_call",
        ActionKind::SecretDetected => "secret.detected",
        ActionKind::SessionApplyChanges => "session.apply_changes",
    }
}

/// The lowercase label for a risk level, matching the wire schema.
fn risk_label(risk: Risk) -> &'static str {
    match risk {
        Risk::Low => "low",
        Risk::Medium => "medium",
        Risk::High => "high",
    }
}

/// Write the single prompt presenting kind/target/risk/reason/rule followed by
/// exactly the four offered choices.
fn render_prompt(out: &mut impl Write, p: &ApprovalPresentation) -> io::Result<()> {
    writeln!(out, "Approval required")?;
    writeln!(out, "  kind:   {}", kind_label(p.kind))?;
    writeln!(out, "  target: {}", p.target)?;
    writeln!(out, "  risk:   {}", risk_label(p.risk))?;
    writeln!(out, "  reason: {}", p.reason)?;
    writeln!(out, "  rule:   {}", p.matched_rule.as_str())?;
    writeln!(out, "Choose:")?;
    writeln!(out, "  [1] allow once")?;
    writeln!(out, "  [2] deny once")?;
    writeln!(out, "  [3] remember for session")?;
    writeln!(out, "  [4] view context")?;
    write!(out, "> ")?;
    out.flush()
}

/// Write the full action context shown when the user selects view context
/// Falls back to a placeholder when no extra context is supplied so
/// the user always receives feedback before the prompt is re-presented.
fn render_context(out: &mut impl Write, p: &ApprovalPresentation) -> io::Result<()> {
    writeln!(out, "Context:")?;
    if p.context.trim().is_empty() {
        writeln!(out, "  (no additional context available)")?;
    } else {
        for line in p.context.lines() {
            writeln!(out, "  {line}")?;
        }
    }
    out.flush()
}

// ---------------------------------------------------------------------------
// Core prompt loop (generic over IO for testability)
// ---------------------------------------------------------------------------

/// Run the approval prompt loop over arbitrary line-based IO.
///
/// This is the testable core of the prompt: it renders the presentation
/// reads one line, and either resolves to an
/// [`ApprovalOutcome`] (allow once → [`ApprovalOutcome::Allowed`], deny once →
/// [`ApprovalOutcome::Denied`], remember → [`ApprovalOutcome::AllowedRemembered`]),
/// displays the full context and re-presents on view context, or re-presents on
/// unrecognized input.
///
/// Returns an [`io::ErrorKind::UnexpectedEof`] error if the input stream is
/// exhausted before the user resolves the prompt, so callers (and scripted
/// tests) never hang on an empty stream.
pub fn prompt_with_io(
    presentation: &ApprovalPresentation,
    input: &mut impl BufRead,
    output: &mut impl Write,
) -> io::Result<ApprovalOutcome> {
    loop {
        render_prompt(output, presentation)?;

        let mut line = String::new();
        let read = input.read_line(&mut line)?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "approval input stream closed before a choice was selected",
            ));
        }

        match ApprovalChoice::parse(&line) {
            Some(ApprovalChoice::AllowOnce) => return Ok(ApprovalOutcome::Allowed),
            Some(ApprovalChoice::DenyOnce) => return Ok(ApprovalOutcome::Denied),
            Some(ApprovalChoice::RememberForSession) => {
                return Ok(ApprovalOutcome::AllowedRemembered);
            }
            // View context: show full context, then loop to re-present the same
            // prompt without resolving.
            Some(ApprovalChoice::ViewContext) => render_context(output, presentation)?,
            // Unrecognized input: loop to re-present without resolving.
            None => {}
        }
    }
}

// ---------------------------------------------------------------------------
// Production terminal implementation
// ---------------------------------------------------------------------------

/// The production [`ApprovalUi`] that prompts on stdin and renders to stdout.
#[derive(Debug, Default, Clone, Copy)]
pub struct TerminalApprovalUi;

impl TerminalApprovalUi {
    /// Construct a terminal-backed approval UI.
    pub fn new() -> Self {
        TerminalApprovalUi
    }
}

impl ApprovalUi for TerminalApprovalUi {
    fn prompt(&self, presentation: &ApprovalPresentation) -> ApprovalOutcome {
        let stdin = io::stdin();
        let mut input = stdin.lock();
        let stdout = io::stdout();
        let mut output = stdout.lock();
        match prompt_with_io(presentation, &mut input, &mut output) {
            Ok(outcome) => outcome,
            // The stream closed (e.g. piped/EOF) before a choice was made. Fail
            // closed: treat as a denial rather than allowing an unconfirmed
            // action.
            Err(_) => ApprovalOutcome::Denied,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn presentation() -> ApprovalPresentation {
        ApprovalPresentation {
            kind: ActionKind::CommandRun,
            target: "rm -rf build".to_string(),
            risk: Risk::High,
            reason: "matches an ask rule".to_string(),
            matched_rule: MatchedRule::Rule("commands.ask[0]".to_string()),
            context: "argv: [rm, -rf, build]\ncwd: /repo".to_string(),
        }
    }

    fn run(script: &str) -> io::Result<(ApprovalOutcome, String)> {
        let mut input = Cursor::new(script.as_bytes().to_vec());
        let mut output: Vec<u8> = Vec::new();
        let outcome = prompt_with_io(&presentation(), &mut input, &mut output)?;
        Ok((outcome, String::from_utf8(output).unwrap()))
    }

    #[test]
    fn choice_parse_recognizes_each_offered_choice() {
        assert_eq!(ApprovalChoice::parse("1"), Some(ApprovalChoice::AllowOnce));
        assert_eq!(
            ApprovalChoice::parse(" Allow "),
            Some(ApprovalChoice::AllowOnce)
        );
        assert_eq!(ApprovalChoice::parse("2"), Some(ApprovalChoice::DenyOnce));
        assert_eq!(
            ApprovalChoice::parse("deny"),
            Some(ApprovalChoice::DenyOnce)
        );
        assert_eq!(
            ApprovalChoice::parse("3"),
            Some(ApprovalChoice::RememberForSession)
        );
        assert_eq!(
            ApprovalChoice::parse("remember for session"),
            Some(ApprovalChoice::RememberForSession)
        );
        assert_eq!(
            ApprovalChoice::parse("4"),
            Some(ApprovalChoice::ViewContext)
        );
        assert_eq!(ApprovalChoice::parse(""), None);
        assert_eq!(ApprovalChoice::parse("yes"), None);
    }

    #[test]
    fn allow_once_resolves_allowed() {
        let (outcome, _) = run("1\n").unwrap();
        assert_eq!(outcome, ApprovalOutcome::Allowed);
    }

    #[test]
    fn deny_once_resolves_denied() {
        let (outcome, _) = run("2\n").unwrap();
        assert_eq!(outcome, ApprovalOutcome::Denied);
    }

    #[test]
    fn remember_resolves_allowed_remembered() {
        let (outcome, _) = run("3\n").unwrap();
        assert_eq!(outcome, ApprovalOutcome::AllowedRemembered);
    }

    #[test]
    fn prompt_presents_all_five_fields_and_four_choices() {
        let (_, rendered) = run("1\n").unwrap();
        assert!(rendered.contains("command.run"));
        assert!(rendered.contains("rm -rf build"));
        assert!(rendered.contains("high"));
        assert!(rendered.contains("matches an ask rule"));
        assert!(rendered.contains("commands.ask[0]"));
        assert!(rendered.contains("allow once"));
        assert!(rendered.contains("deny once"));
        assert!(rendered.contains("remember for session"));
        assert!(rendered.contains("view context"));
    }

    #[test]
    fn view_context_displays_context_then_re_presents_without_resolving() {
        // view context, then allow once.
        let (outcome, rendered) = run("4\n1\n").unwrap();
        assert_eq!(outcome, ApprovalOutcome::Allowed);
        assert!(rendered.contains("Context:"));
        assert!(rendered.contains("cwd: /repo"));
        // The prompt header appears twice: once before view-context and once
        // after re-presenting.
        assert_eq!(rendered.matches("Approval required").count(), 2);
    }

    #[test]
    fn unrecognized_input_re_presents_without_resolving() {
        // garbage, garbage, then deny once.
        let (outcome, rendered) = run("huh\nwhat\n2\n").unwrap();
        assert_eq!(outcome, ApprovalOutcome::Denied);
        assert_eq!(rendered.matches("Approval required").count(), 3);
    }

    #[test]
    fn exhausted_input_errors_instead_of_looping() {
        // Only unrecognized input then EOF: must terminate, not hang.
        let err = run("nope\n").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }
}
